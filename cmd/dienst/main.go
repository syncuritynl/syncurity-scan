// syncurity-keuring: de gratis domeinscan achter nginx (/scan). De dienst
// heet intern nog keuring; voor bezoekers heet alles scan.
//
// Ontwerpuitgangspunten:
//   - luistert op een unix socket, nginx staat ervoor; geen netwerkpoort
//   - doet zelf alleen uitgaande verbindingen, naar publieke adressen op 80 en
//     443 (Kiezer) en naar de eigen resolver; systemd dwingt dat ook af
//   - geen database: uitslagen staan 15 minuten in het geheugen, daarna weg
//   - logt geen IP-adressen; nginx doet dat al, en fail2ban kijkt daar
//   - toont op /scan alleen de gratis uitslag (Uitslag.Openbaar); het
//     volledige rapport verlaat deze dienst alleen via de interne socket voor
//     de inlogdienst, en pas na domeinbewijs (intern.go)
package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"syncurity.nl/keuring/keuring"
)

//go:embed sjablonen/*.html
var sjabloonBestanden embed.FS

var sjablonen = template.Must(template.ParseFS(sjabloonBestanden, "sjablonen/*.html"))

const (
	bewaarTijd     = 15 * time.Minute // zo lang geldt een uitslag
	perBezoeker    = 8                // scans per venster per adres
	venster        = 10 * time.Minute
	tegelijk       = 3 // scans die tegelijk mogen lopen
	maxFormulier   = 1 << 10
	wachtOpPlek    = 20 * time.Second
	oorsprongEigen = "https://syncurity.nl"
)

var amsterdam, _ = time.LoadLocation("Europe/Amsterdam")

// versie wordt bij het bouwen gezet met -ldflags "-X main.versie=..." (zie bouw.sh),
// zodat na een incident te zeggen is welke commit er draaide (A.8.32).
var versie = "onbekend"

var maanden = [...]string{"januari", "februari", "maart", "april", "mei", "juni", "juli", "augustus", "september", "oktober", "november", "december"}

func wanneer(t time.Time) string {
	t = t.In(amsterdam)
	return t.Format("2") + " " + maanden[t.Month()-1] + " " + t.Format("2006, 15:04")
}

type bewaard struct {
	u   *keuring.Uitslag
	tot time.Time
}

// keurFunctie is keuring.Keur; in tests een nepversie zonder netwerk.
type keurFunctie func(ctx context.Context, invoer string, in keuring.Instellingen) (*keuring.Uitslag, error)

type dienst struct {
	in   keuring.Instellingen
	keur keurFunctie

	// Voor de interne socket (intern.go).
	txt        txtFunctie
	volledig   volledigFunctie
	volPlekken chan struct{}

	mu       sync.Mutex
	uitslag  map[string]bewaard
	bezig    map[string]chan struct{}
	pogingen map[string][]time.Time
	plekken  chan struct{}
	wachtend atomic.Int32 // verzoeken die op een plek wachten
}

// maxWachtend: staan er al zoveel in de rij, dan meteen "druk" in plaats van
// nog een wachtende verbinding erbij (een rem per /64 houdt niet iedereen tegen).
const maxWachtend = 10

func nieuweDienst(in keuring.Instellingen) *dienst {
	d := &dienst{
		in:       in,
		keur:     keuring.Keur,
		txt:      keuring.ControleerTXT,
		volledig: keuring.KeurVolledig,
		uitslag:  map[string]bewaard{},
		bezig:    map[string]chan struct{}{},
		pogingen: map[string][]time.Time{},
		plekken:  make(chan struct{}, tegelijk),

		volPlekken: make(chan struct{}, volledigTegelijk),
	}
	go d.opruimen()
	return d
}

// opruimen gooit verlopen uitslagen en oude pogingen weg, zodat het geheugen
// niet volloopt en er na een kwartier niets meer van een keuring over is.
func (d *dienst) opruimen() {
	for range time.Tick(time.Minute) {
		nu := time.Now()
		d.mu.Lock()
		for k, b := range d.uitslag {
			if nu.After(b.tot) {
				delete(d.uitslag, k)
			}
		}
		for ip, ts := range d.pogingen {
			if len(ts) == 0 || nu.Sub(ts[len(ts)-1]) > venster {
				delete(d.pogingen, ip)
			}
		}
		d.mu.Unlock()
	}
}

func (d *dienst) bewaarde(domein string) *keuring.Uitslag {
	d.mu.Lock()
	defer d.mu.Unlock()
	if b, ok := d.uitslag[domein]; ok && time.Now().Before(b.tot) {
		return b.u
	}
	return nil
}

// magNog telt een echte keuring voor dit adres en zegt of het nog mag.
func (d *dienst) magNog(ip string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	grens := time.Now().Add(-venster)
	ts := d.pogingen[ip][:0]
	for _, t := range d.pogingen[ip] {
		if t.After(grens) {
			ts = append(ts, t)
		}
	}
	if len(ts) >= perBezoeker {
		d.pogingen[ip] = ts
		return false
	}
	d.pogingen[ip] = append(ts, time.Now())
	return true
}

var errDruk = errors.New("Het is even druk. Probeer het over een minuut nog eens.")
var errTeVaak = errors.New("Je hebt in korte tijd veel scans gestart. Probeer het over een paar minuten nog eens.")

// uitslagVoor levert een uitslag: bewaard als die er is, anders een nieuwe keuring.
// Twee bezoekers die tegelijk hetzelfde domein vragen, delen één keuring.
func (d *dienst) uitslagVoor(ctx context.Context, domein, ip string) (*keuring.Uitslag, error) {
	for {
		if u := d.bewaarde(domein); u != nil {
			return u, nil
		}
		d.mu.Lock()
		wacht, loopt := d.bezig[domein]
		if !loopt {
			klaar := make(chan struct{})
			d.bezig[domein] = klaar
			d.mu.Unlock()
			u, err := d.voerUit(ctx, domein, ip)
			d.mu.Lock()
			delete(d.bezig, domein)
			if err == nil {
				d.uitslag[domein] = bewaard{u: u, tot: time.Now().Add(bewaarTijd)}
			}
			d.mu.Unlock()
			close(klaar)
			return u, err
		}
		d.mu.Unlock()
		select {
		case <-wacht:
			if u := d.bewaarde(domein); u != nil {
				return u, nil
			}
			return nil, errDruk
		case <-ctx.Done():
			return nil, errDruk
		}
	}
}

func (d *dienst) voerUit(ctx context.Context, domein, ip string) (*keuring.Uitslag, error) {
	if !d.magNog(ip) {
		return nil, errTeVaak
	}
	if d.wachtend.Add(1) > maxWachtend {
		d.wachtend.Add(-1)
		return nil, errDruk
	}
	defer d.wachtend.Add(-1)
	select {
	case d.plekken <- struct{}{}:
		defer func() { <-d.plekken }()
	case <-time.After(wachtOpPlek):
		return nil, errDruk
	case <-ctx.Done():
		return nil, errDruk
	}
	u, err := d.keur(context.WithoutCancel(ctx), domein, d.in)
	if err == nil {
		// Nooit Detail of Oplossing bewaren of tonen: die zijn alleen voor de
		// eigenaar, na domeinbewijs via de interne socket. Keur geeft ze al
		// niet, maar dit is de plek waar het zeker moet.
		u = u.Openbaar()
		// Geen domeinnaam en geen IP in het logboek: nginx houdt het opgevraagde
		// adres al 14 dagen bij voor de beveiliging (zie /privacy/).
		log.Printf("scan klaar %d/%d %.1fs", u.InOrde, u.Totaal, u.Duur.Seconds())
	}
	return u, err
}

// ---------------------------------------------------------------- http

type vraagPagina struct {
	Titel, Beschrijving, Kop, Lead, Fout, Invoer string
}

type rapportPagina struct {
	Titel, Beschrijving, Domein, Wanneer, Sub, PDF, Versie string
	Rest                                                   int
	U                                                      *keuring.Uitslag
}

func kopregels(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex")
}

func toon(w http.ResponseWriter, status int, naam string, data any) {
	kopregels(w)
	w.WriteHeader(status)
	if err := sjablonen.ExecuteTemplate(w, naam, data); err != nil {
		log.Printf("sjabloon %s: %v", naam, err)
	}
}

func vraag(w http.ResponseWriter, status int, invoer, fout string) {
	toon(w, status, "vraag", vraagPagina{
		Titel: "Scan · Syncurity", Kop: "Hoe staat jouw domeinnaam ervoor?",
		Beschrijving: "Gratis scan van je website, je e-mail en je domeinnaam: veiligheid, vindbaarheid in Google en AI, en snelheid.",
		Lead:         "Vul je domeinnaam in. We kijken alleen naar wat openbaar is en laten zien hoe veilig je website en e-mail zijn, en hoe goed je gevonden wordt in Google en door AI.",
		Fout:         fout, Invoer: invoer,
	})
}

// eigenHerkomst laat alleen formulieren van syncurity.nl zelf toe. Zo kan een
// andere site de browsers van zijn bezoekers geen scans laten starten.
func eigenHerkomst(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "":
		o := r.Header.Get("Origin")
		return o == "" || o == oorsprongEigen
	}
	return false
}

// bezoeker is het adres dat nginx doorgeeft. Te vertrouwen omdat de dienst
// alleen via de unix socket bereikbaar is.
// soortFout vat een fout samen zonder namen of adressen erin.
func soortFout(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "tijd op"
	case errors.Is(err, keuring.ErrBudget):
		return "verbindingsbudget op"
	case errors.As(err, &ne) && ne.Timeout():
		return "time-out"
	case errors.As(err, &ne):
		return "netwerk"
	default:
		return "overig"
	}
}

// bezoeker geeft de sleutel waarop de remmen tellen. Bij IPv6 is dat de /64:
// een gewone aansluiting heeft er 2^64, en per adres tellen zou de rem omzeilen.
func bezoeker(r *http.Request) string {
	a, err := netip.ParseAddr(r.Header.Get("X-Real-IP"))
	if err != nil {
		return "onbekend"
	}
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

func (d *dienst) start(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		// Een bladwijzer of oude link naar /scan: gewoon de vraagpagina.
		vraag(w, http.StatusOK, "", "")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, HEAD, POST")
		vraag(w, http.StatusMethodNotAllowed, "", "")
		return
	}
	if !eigenHerkomst(r) {
		vraag(w, http.StatusForbidden, "", "Start de scan vanaf deze pagina: vul hieronder je domeinnaam in.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormulier)
	if err := r.ParseForm(); err != nil {
		vraag(w, http.StatusBadRequest, "", keuring.ErrOngeldig.Error())
		return
	}
	invoer := strings.TrimSpace(r.PostForm.Get("domein"))
	domein, err := keuring.Normaliseer(invoer)
	if err != nil {
		vraag(w, http.StatusBadRequest, invoer, err.Error())
		return
	}
	ctx, stop := context.WithTimeout(r.Context(), 50*time.Second)
	defer stop()
	if _, err := d.uitslagVoor(ctx, domein, bezoeker(r)); err != nil {
		status := http.StatusBadGateway
		switch {
		case errors.Is(err, errTeVaak):
			status = http.StatusTooManyRequests
		case errors.Is(err, errDruk):
			status = http.StatusServiceUnavailable
		case errors.Is(err, keuring.ErrBestaatNiet):
			status = http.StatusNotFound
		default:
			if !errors.Is(err, keuring.ErrBestaatNiet) {
				// Alleen het soort fout: de melding zelf kan de domeinnaam bevatten.
				log.Printf("scan mislukt (%s)", soortFout(err))
				err = errors.New("De scan lukte niet. Probeer het over een minuut nog eens.")
			}
		}
		vraag(w, status, invoer, err.Error())
		return
	}
	// Post/Redirect/Get: vernieuwen start dan geen nieuwe keuring. Vulde
	// iemand een subdomein in, dan zeggen we in het rapport dat de scan over
	// de hele domeinnaam gaat.
	doel := "/scan/" + url.PathEscape(domein)
	if sub := subdomein(invoer, domein); sub != "" {
		doel += "?invoer=" + url.QueryEscape(sub)
	}
	http.Redirect(w, r, doel, http.StatusSeeOther)
}

var hostnaam = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)+$`)

// subdomein geeft de ingevulde naam als die een subdomein van domein is
// (anders dan www), en anders "". Alleen gewone letters, cijfers en punten.
func subdomein(invoer, domein string) string {
	h := strings.ToLower(strings.TrimSpace(invoer))
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#:"); i >= 0 {
		h = h[:i]
	}
	h = strings.TrimSuffix(strings.TrimPrefix(h, "www."), ".")
	if len(h) > 253 || !hostnaam.MatchString(h) || h == domein || !strings.HasSuffix(h, "."+domein) {
		return ""
	}
	return h
}

func (d *dienst) rapport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		vraag(w, http.StatusMethodNotAllowed, "", "")
		return
	}
	ruw := strings.TrimPrefix(r.URL.Path, "/scan/")
	alsPDF := strings.HasSuffix(ruw, "/pdf")
	ruw = strings.TrimSuffix(ruw, "/pdf")
	domein, err := keuring.Normaliseer(ruw)
	if err != nil {
		vraag(w, http.StatusNotFound, ruw, err.Error())
		return
	}
	u := d.bewaarde(domein)
	if u == nil && alsPDF {
		// Verlopen: terug naar de pagina, die zegt dat er geen uitslag meer is.
		http.Redirect(w, r, "/scan/"+url.PathEscape(domein), http.StatusSeeOther)
		return
	}
	if u == nil {
		// Nooit vanzelf keuren op een GET: een link of een zoekmachine mag
		// geen keuring kunnen starten.
		toon(w, http.StatusOK, "vraag", vraagPagina{
			Titel:        "Scan " + keuring.Weergave(domein) + " · Syncurity",
			Beschrijving: "Start een gratis scan van " + keuring.Weergave(domein) + ".",
			Kop:          "Scan van " + keuring.Weergave(domein),
			Lead:         "Er is geen recente uitslag van deze domeinnaam. Start de scan, dan heb je hem binnen enkele seconden.",
			Invoer:       keuring.Weergave(domein),
		})
		return
	}
	u = u.Openbaar()
	if alsPDF {
		stuurPDF(w, r, u)
		return
	}
	rest := 402
	if u.Totaal > 0 {
		rest = 402 - 402*u.InOrde/u.Totaal
	}
	toon(w, http.StatusOK, "rapport", rapportPagina{
		Titel:        "Scan " + keuring.Weergave(u.Domein) + " · Syncurity",
		Beschrijving: fmt.Sprintf("Scan van %s: %d van de %d punten in orde.", keuring.Weergave(u.Domein), u.InOrde, u.Totaal),
		Domein:       keuring.Weergave(u.Domein),
		Wanneer:      wanneer(u.Tijd),
		Sub:          subdomein(r.URL.Query().Get("invoer"), u.Domein),
		Rest:         rest,
		U:            u,
		PDF:          pdfAdres(u.Domein, r.URL.Query().Get("invoer")),
		Versie:       openbareVersie(),
	})
}

// openbareVersie is de commit waarmee deze dienst gebouwd is, als die op
// GitHub te vinden is (een schone build, zie bouw.sh). Onder elk rapport staat
// een link naar precies die code; met dezelfde commit bouwt iedereen hetzelfde
// programma na. Een build met niet vastgelegd werk ("-dirty") krijgt geen link.
func openbareVersie() string {
	if commitVorm.MatchString(versie) {
		return versie
	}
	return ""
}

var commitVorm = regexp.MustCompile(`^[0-9a-f]{7,40}$`)

// pdfAdres is de link achter de downloadknop; een ingevuld subdomein gaat mee,
// zodat de pdf dezelfde opmerking heeft als de pagina.
func pdfAdres(domein, invoer string) string {
	a := "/scan/" + url.PathEscape(domein) + "/pdf"
	if sub := subdomein(invoer, domein); sub != "" {
		a += "?invoer=" + url.QueryEscape(sub)
	}
	return a
}

// stuurPDF geeft de uitslag als pdf om te downloaden. Alleen de openbare
// uitslag: u is hier al door Openbaar gegaan.
func stuurPDF(w http.ResponseWriter, r *http.Request, u *keuring.Uitslag) {
	b := maakPDF(u, subdomein(r.URL.Query().Get("invoer"), u.Domein))
	h := w.Header()
	h.Set("Content-Type", "application/pdf")
	naam := "syncurity-scan-" + u.Domein + "-" + u.Tijd.In(amsterdam).Format("2006-01-02") + ".pdf"
	h.Set("Content-Disposition", `attachment; filename="`+naam+`"`)
	h.Set("Content-Length", fmt.Sprint(len(b)))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(b)
}

// routes is de publieke kant, achter nginx. /intern/ bestaat hier niet: dat
// staat alleen op de interne socket (intern.go).
func (d *dienst) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/scan", d.start)
	mux.HandleFunc("/scan/", d.rapport)
	// De eerste versie heette /keuring. Oude links en een homepage die nog in
	// een browser staat, blijven zo werken.
	mux.HandleFunc("/keuring", d.start)
	mux.HandleFunc("/keuring/", func(w http.ResponseWriter, r *http.Request) {
		// Alleen naar een geldige domeinnaam: een pad als /\\evil.com zou
		// anders een open redirect zijn, als nginx er ooit niet voor staat.
		dom, err := keuring.Normaliseer(strings.TrimPrefix(r.URL.Path, "/keuring/"))
		if err != nil {
			http.Redirect(w, r, "/scan", http.StatusMovedPermanently)
			return
		}
		http.Redirect(w, r, "/scan/"+url.PathEscape(dom), http.StatusMovedPermanently)
	})
	return mux
}

func main() {
	sock := flag.String("socket", "/run/syncurity-keuring/keuring.sock", "pad van de unix socket")
	resolvers := flag.String("resolver", "127.0.0.1:53", "validerende resolvers, komma-gescheiden")
	tcp := flag.String("tcp", "", "alleen om te testen: luister op dit TCP-adres in plaats van de socket")
	intern := flag.String("intern", "", "pad van de interne socket voor de inlogdienst, bijv. /run/syncurity-keuring-intern/intern.sock (leeg: uit)")
	tcpIntern := flag.String("tcp-intern", "", "alleen om te testen: de interne API op dit TCP-adres")
	flag.Parse()
	log.SetFlags(0) // journald zet zelf de tijd erbij

	in := keuring.Standaard
	in.Resolvers = strings.Split(*resolvers, ",")
	d := nieuweDienst(in)

	srv := &http.Server{
		Handler:           d.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      70 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	// De publieke socket: nginx (www-data) moet erbij kunnen, verder niemand.
	ln, err := luister(*tcp, *sock)
	if err != nil {
		log.Fatal(err)
	}
	if *intern != "" || *tcpIntern != "" {
		// De interne socket: alleen de groep syncurity-intern (de map
		// regelt systemd, met setgid). Een volledig rapport duurt tot 90 s.
		iln, err := luister(*tcpIntern, *intern)
		if err != nil {
			log.Fatal(err)
		}
		isrv := &http.Server{
			Handler:           d.intern(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      keuring.VolledigTotaal + 10*time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    16 << 10,
		}
		log.Printf("interne API luistert op %s", iln.Addr())
		go func() { log.Fatal(isrv.Serve(iln)) }()
	}
	log.Printf("syncurity-keuring %s luistert op %s", versie, ln.Addr())
	log.Fatal(srv.Serve(ln))
}

// luister opent een TCP-adres (om te testen) of anders een unix socket met
// rechten 0660.
func luister(tcp, sock string) (net.Listener, error) {
	if tcp != "" {
		return net.Listen("tcp", tcp)
	}
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(sock, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}
