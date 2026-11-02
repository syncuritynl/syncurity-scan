package keuring

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Instellingen voor een keuring.
type Instellingen struct {
	Resolvers []string      // validerende resolvers, host:poort
	Timeout   time.Duration // per verbinding of DNS-vraag
	Totaal    time.Duration // de hele keuring
	UserAgent string
}

// Standaard is wat de dienst gebruikt als er niets anders is opgegeven.
var Standaard = Instellingen{
	Resolvers: []string{"127.0.0.1:53"},
	Timeout:   5 * time.Second,
	Totaal:    25 * time.Second,
	// De gangbare vorm voor crawlers: we zeggen wie we zijn, en worden zo niet
	// door elke botbeveiliging als onbekend script geweigerd.
	UserAgent: "Mozilla/5.0 (compatible; SyncurityScan/1.0; +https://syncurity.nl/over/)",
}

type keurder struct {
	domein  string
	r       *Resolver
	kiezer  *Kiezer
	web     *http.Client // volgt doorverwijzingen binnen het domein
	eenStap *http.Client // volgt geen doorverwijzingen
	vrij    *http.Client // volgt https-doorverwijzingen naar elk domein
	timeout time.Duration
	ua      string // dezelfde User-Agent als in de http-clients
	vol     bool   // volledige keuring: een paar extra metingen voor de details

	w     *web // wat we van de website haalden, voor de voorstellen
	mu    sync.Mutex
	stand stand // wat de controles zagen, voor de voorstellen
}

// stand is wat de controles onderweg vastleggen voor de berekende
// voorstellen (voorstel.go). Alleen voor de volledige keuring van belang.
type stand struct {
	dmarc      []string          // gevonden DMARC-regels
	dmarcTags  map[string]string // van de eerste
	spf        []string          // gevonden SPF-regels
	mx         []string
	secContact []string // Contact-regels uit een bestaande security.txt
	stsMode    string   // mode uit het MTA-STS-beleid, als dat er is
	stsMX      []string // mx-regels uit dat beleid
}

func (k *keurder) leg(f func(s *stand)) {
	k.mu.Lock()
	defer k.mu.Unlock()
	f(&k.stand)
}

type agent struct {
	t  http.RoundTripper
	ua string
}

func (a agent) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("User-Agent", a.ua)
	return a.t.RoundTrip(r)
}

// Keur voert de gratis keuring uit. invoer mag alles zijn wat iemand intypt;
// de fout is dan een zin die je aan de bezoeker kunt laten zien. De uitslag
// is altijd Openbaar(): zonder Detail en Oplossing.
func Keur(ctx context.Context, invoer string, in Instellingen) (*Uitslag, error) {
	domein, err := Normaliseer(invoer)
	if err != nil {
		return nil, err
	}
	ctx, stop := context.WithTimeout(ctx, in.Totaal)
	defer stop()
	r := &Resolver{Servers: in.Resolvers, Timeout: in.Timeout}
	if err := bestaat(ctx, r, domein); err != nil {
		return nil, err
	}
	u, _ := keur(ctx, domein, r, in, false)
	return u.Openbaar(), nil
}

// bestaat geeft ErrBestaatNiet als het domein geen DNS heeft.
func bestaat(ctx context.Context, r *Resolver, domein string) error {
	_, _, rcode, err := r.Records(ctx, domein, dns.TypeSOA)
	if err != nil {
		return err
	}
	if rcode == dns.RcodeNameError {
		return ErrBestaatNiet
	}
	return nil
}

// keur doet het werk. vol: de volledige keuring, met een paar extra
// handdrukken om de zwakke versleuteling precies te benoemen.
func keur(ctx context.Context, domein string, r *Resolver, in Instellingen, vol bool) (*Uitslag, *keurder) {
	// Een scan doet zo'n 30 verbindingen (waarvan hooguit 4 om elk adres van
	// de website apart te meten); 60 laat ruimte voor een tweede adres, en
	// houdt misbruik als verkeersversterker klein. De volledige
	// keuring meet zwakke suites één voor één (hooguit 13 handdrukken extra),
	// en mag daarom 80. De subdomeinen hebben een eigen budget (subdomein.go).
	budget := int32(60)
	if vol {
		budget = 80
	}
	kiezer := &Kiezer{R: r, Timeout: in.Timeout, Max: budget}
	tr := &http.Transport{
		DialContext:            kiezer.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    in.Timeout,
		ResponseHeaderTimeout:  in.Timeout,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 << 10,
	}
	rt := agent{t: tr, ua: in.UserAgent}
	k := &keurder{
		domein:  domein,
		r:       r,
		kiezer:  kiezer,
		web:     &http.Client{Transport: rt, Timeout: 2 * in.Timeout, CheckRedirect: zelfdeDomein(domein)},
		vrij:    &http.Client{Transport: rt, Timeout: 2 * in.Timeout, CheckRedirect: naarSecurityTxt},
		eenStap: &http.Client{Transport: rt, Timeout: in.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		timeout: in.Timeout,
		ua:      in.UserAgent,
		vol:     vol,
	}

	begin := time.Now()

	// De website één keer ophalen, terwijl de DNS-groepen al lopen.
	groepen := make([]Groep, 10)
	var wg sync.WaitGroup
	start := func(i int, f func() Groep) {
		wg.Add(1)
		go func() { defer wg.Done(); groepen[i] = f() }()
	}
	start(2, func() Groep { return k.mail(ctx) })
	start(3, func() Groep { return k.domeinnaam(ctx) })
	w := k.haalWeb(ctx, k.webhost(ctx))
	k.w = w
	start(0, func() Groep { return k.verbinding(w) })
	start(1, func() Groep { return k.instellingen(ctx, w) })
	start(4, func() Groep { return k.modern(ctx, w) })
	start(5, func() Groep { return k.seo(w) })
	start(6, func() Groep { return k.geo(w) })
	start(7, func() Groep { return k.snelheid(w) })
	start(8, func() Groep { return k.vertrouwen(w) })
	start(9, func() Groep { return k.toegankelijkheid(w) })
	var feiten []Feit
	wg.Add(1)
	go func() { defer wg.Done(); feiten = k.feiten(ctx, w) }()
	wg.Wait()
	// Na de rest: vergelijkt de CAA-regel met het certificaat van de website.
	groepen[3].Punten = naPunt(groepen[3].Punten, "caa", k.caaCA(ctx, w))

	for i := range feiten {
		feiten[i].Waarde = kort(schoon(feiten[i].Waarde), 80)
	}
	for i := range groepen {
		for j := range groepen[i].Punten {
			groepen[i].Punten[j].Detail = schoonDetail(groepen[i].Punten[j].Detail)
		}
	}
	u := &Uitslag{Domein: domein, Tijd: begin, Duur: time.Since(begin), Groepen: groepen, Feiten: feiten}
	switch {
	case w.weg != "":
		u.Melding = fmt.Sprintf("Je homepage stuurt nieuwe bezoekers door naar een ander domein (%s), bijvoorbeeld voor een cookiemuur. De punten over je pagina zelf konden we daardoor niet meten en tellen niet mee.", w.weg)
	case w.geweigerd != 0:
		u.Melding = fmt.Sprintf("Je website liet onze scan niet binnen: een beveiliging tegen bots gaf een tussenpagina (HTTP %d). De punten over je pagina zelf konden we daardoor niet meten en tellen niet mee. Let erop dat Google, Bing en AI-assistenten wel binnen mogen, anders ben je ook voor hen moeilijk te vinden.", w.geweigerd)
	}
	u.tel()
	return u, k
}
