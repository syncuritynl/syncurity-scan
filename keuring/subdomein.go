package keuring

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// Subdomeinen uit de openbare certificaatlogs (Certificate Transparency):
// elk certificaat dat een leverancier uitgeeft, staat daar met alle namen
// erin. Zo vinden we ook vergeten subdomeinen. Per subdomein kijken we of het
// nog werkt, en of het door een ander kan worden overgenomen (dangling DNS:
// een record dat naar een dienst wijst die er niet meer is).
//
// Alles passief: alleen DNS, één handdruk en één GET van / per subdomein,
// zonder doorverwijzingen te volgen. Geen poortscans, geen andere paden.
// crt.sh en certspotter zijn de enige externe diensten die de domeinnaam
// krijgen (zie de privacyverklaring).

// Subdomein is één naam uit de certificaatlogs.
type Subdomein struct {
	Naam     string   `json:"naam"`
	Adressen []string `json:"adressen,omitempty"` // A/AAAA, hooguit 4
	CNAME    string   `json:"cname,omitempty"`
	Status   Status   `json:"status"`  // Goed, Matig, Slecht, NVT (bestaat niet meer, geen website) of Fout
	Oordeel  string   `json:"oordeel"` // korte zin in B1
	Uitleg   string   `json:"uitleg,omitempty"`
	HTTPS    string   `json:"https,omitempty"` // "geldig tot 3 maart 2027", "verlopen", "geen", "naam klopt niet", "niet vertrouwd"

	uitgever string // van een geldig certificaat, voor het CAA-voorstel
}

const (
	maxSubdomeinen = 50
	subTegelijk    = 8
	subTotaal      = 45 * time.Second // alle proeven samen
	subBudget      = 120              // verbindingen, los van de 60 van de gewone scan
	maxLogAntwoord = 8 << 20
	maxSubBody     = 64 << 10
)

// vrager is de DNS-kant; *Resolver, of een nepversie in de tests.
type vrager interface {
	Vraag(ctx context.Context, naam string, soort uint16) (*dns.Msg, error)
}

type logBron struct {
	naam string
	url  func(domein string) string
	tijd time.Duration
	lees func(r io.Reader) ([]string, error)
}

// De twee bronnen, in volgorde. crt.sh is volledig maar traag en geeft vaak
// 502 of een time-out; certspotter (zonder sleutel, beperkt aantal per uur)
// is de reserve.
var logBronnen = []logBron{
	{"crt.sh", func(d string) string { return "https://crt.sh/?q=%25." + d + "&output=json" }, 20 * time.Second, leesCrtsh},
	{"certspotter", func(d string) string {
		return "https://api.certspotter.com/v1/issuances?domain=" + d + "&include_subdomains=true&expand=dns_names"
	}, 15 * time.Second, leesCertspotter},
}

type subZoeker struct {
	domein   string
	dns      vrager
	dial     func(ctx context.Context, a netip.Addr, poort string) (net.Conn, error)
	roots    *x509.CertPool // nil: die van het systeem
	logs     *http.Client
	bronnen  []logBron
	ua       string
	timeout  time.Duration // per proef
	totaal   time.Duration
	tegelijk int
	nu       func() time.Time
}

type subUitslag struct {
	lijst   []Subdomein
	bron    string
	melding string
}

// info vat samen wat de voorstellen (CAA, HSTS) aan de subdomeinen hebben.
func (s subUitslag) info() subInfo {
	i := subInfo{allesHTTPS: true}
	for _, sd := range s.lijst {
		if sd.uitgever != "" {
			i.uitgevers = append(i.uitgevers, sd.uitgever)
		}
		if sd.HTTPS != "" && sd.HTTPS != "geen" {
			i.gemeten++
			if sd.Status != Goed {
				i.allesHTTPS = false
			}
		}
	}
	return i
}

// nieuweSubZoeker: een eigen Kiezer met een eigen budget, zodat de
// subdomeinen de gewone scan niet opmaken (en andersom).
func nieuweSubZoeker(domein string, r *Resolver, in Instellingen) *subZoeker {
	kiezer := &Kiezer{R: r, Timeout: in.Timeout, Max: subBudget}
	tr := &http.Transport{
		DialContext:            kiezer.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    in.Timeout,
		ResponseHeaderTimeout:  20 * time.Second, // crt.sh denkt lang na
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 << 10,
	}
	return &subZoeker{
		domein: domein, dns: r, dial: kiezer.DialAdres, bronnen: logBronnen, ua: in.UserAgent,
		logs: &http.Client{Transport: agent{t: tr, ua: in.UserAgent},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		timeout: 2 * in.Timeout, totaal: subTotaal, tegelijk: subTegelijk, nu: time.Now,
	}
}

func (z *subZoeker) zoek(ctx context.Context) subUitslag {
	var uit subUitslag
	var ruw []string
	for _, b := range z.bronnen {
		namen, err := z.haalLog(ctx, b)
		if err == nil || len(namen) > 0 {
			ruw, uit.bron = namen, b.naam
			break
		}
	}
	if uit.bron == "" {
		uit.melding = "De certificaatlogs waren niet bereikbaar, dus we konden je subdomeinen niet opzoeken. Probeer het later nog eens."
		return uit
	}
	namen, wildcard := namenOnder(z.domein, ruw)
	var melding []string
	if wildcard {
		melding = append(melding, "Je hebt een wildcardcertificaat (*."+z.domein+"). Namen die daaronder vallen, staan niet apart in de logs; die kunnen we dus niet allemaal zien.")
	}
	if len(namen) > maxSubdomeinen {
		melding = append(melding, fmt.Sprintf("We vonden %d namen; hieronder staan de eerste %d.", len(namen), maxSubdomeinen))
		namen = namen[:maxSubdomeinen]
	}
	if len(namen) == 0 {
		melding = append(melding, "In de certificaatlogs staan geen subdomeinen van "+Weergave(z.domein)+".")
	}
	uit.melding = strings.Join(melding, " ")

	ctx, stop := context.WithTimeout(ctx, z.totaal)
	defer stop()
	uit.lijst = make([]Subdomein, len(namen))
	plek := make(chan struct{}, z.tegelijk)
	var wg sync.WaitGroup
	for i, n := range namen {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case plek <- struct{}{}:
				defer func() { <-plek }()
				uit.lijst[i] = z.beoordeel(ctx, n)
			case <-ctx.Done():
				uit.lijst[i] = Subdomein{Naam: n, Status: Fout, Oordeel: "Niet gemeten", Uitleg: "De tijd was op."}
			}
		}()
	}
	wg.Wait()
	sort.SliceStable(uit.lijst, func(i, j int) bool { return ernst(uit.lijst[i].Status) > ernst(uit.lijst[j].Status) })
	return uit
}

func ernst(s Status) int {
	switch s {
	case Slecht:
		return 4
	case Matig:
		return 3
	case Goed:
		return 2
	case Fout:
		return 1
	}
	return 0
}

func (z *subZoeker) haalLog(ctx context.Context, b logBron) ([]string, error) {
	ctx, stop := context.WithTimeout(ctx, b.tijd)
	defer stop()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.url(z.domein), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := z.logs.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", b.naam, resp.StatusCode)
	}
	return b.lees(io.LimitReader(resp.Body, maxLogAntwoord))
}

// leesJSONLijst leest een JSON-array element voor element: de antwoorden
// kunnen megabytes groot zijn, en een afgebroken antwoord levert zo nog
// op wat er al binnen was.
func leesJSONLijst[T any](r io.Reader, namen func(T) []string) ([]string, error) {
	dec := json.NewDecoder(bufio.NewReader(r))
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := t.(json.Delim); !ok || d != '[' {
		return nil, errors.New("geen JSON-lijst")
	}
	var uit []string
	for dec.More() {
		var e T
		if err := dec.Decode(&e); err != nil {
			return uit, err
		}
		uit = append(uit, namen(e)...)
		if len(uit) > 100000 {
			break
		}
	}
	return uit, nil
}

func leesCrtsh(r io.Reader) ([]string, error) {
	type regel struct {
		NameValue  string `json:"name_value"`
		CommonName string `json:"common_name"`
	}
	return leesJSONLijst(r, func(e regel) []string {
		return append(strings.Split(e.NameValue, "\n"), e.CommonName)
	})
}

func leesCertspotter(r io.Reader) ([]string, error) {
	type uitgifte struct {
		DNSNames []string `json:"dns_names"`
	}
	return leesJSONLijst(r, func(e uitgifte) []string { return e.DNSNames })
}

// namenOnder ontdubbelt en houdt alleen geldige namen onder het domein over,
// zonder het domein zelf en zonder wildcards. Ondiepe namen eerst.
func namenOnder(domein string, ruw []string) (namen []string, wildcard bool) {
	gezien := map[string]bool{}
	for _, n := range ruw {
		n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
		if strings.HasPrefix(n, "*.") {
			if n == "*."+domein || strings.HasSuffix(n, "."+domein) {
				wildcard = true
			}
			continue
		}
		if n == domein || !strings.HasSuffix(n, "."+domein) || len(n) > 253 || !hostnaamRe.MatchString(n) || gezien[n] {
			continue
		}
		gezien[n] = true
		namen = append(namen, n)
	}
	sort.Slice(namen, func(i, j int) bool {
		a, b := strings.Count(namen[i], "."), strings.Count(namen[j], ".")
		if a != b {
			return a < b
		}
		return namen[i] < namen[j]
	})
	return
}

// overneembaar zijn diensten waar een vergeten naam door een ander te claimen
// is, met de tekst die ze tonen als de naam er niet (meer) is ingesteld.
// Zonder tekst: de dienst geeft NXDOMAIN voor een naam die weg is (Azure),
// en dat vangt de algemene NXDOMAIN-regel al.
var overneembaar = []struct {
	dienst string
	achter []string
	tekst  string
}{
	{"GitHub Pages", []string{"github.io"}, "There isn't a GitHub Pages site here"},
	{"Heroku", []string{"herokuapp.com", "herokudns.com", "herokussl.com"}, "No such app"},
	{"Amazon S3", []string{"amazonaws.com"}, "NoSuchBucket"},
	{"Shopify", []string{"myshopify.com"}, "Sorry, this shop is currently unavailable"},
	{"Netlify", []string{"netlify.app", "netlify.com"}, "Not Found - Request ID"},
	{"Fastly", []string{"fastly.net", "fastlylb.net"}, "Fastly error: unknown domain"},
	{"Pantheon", []string{"pantheonsite.io"}, "The gods are wise"},
	{"Zendesk", []string{"zendesk.com"}, "Help Center Closed"},
	{"Webflow", []string{"webflow.io", "webflow.com"}, "The page you are looking for doesn't exist or has been moved"},
	{"Microsoft Azure", []string{"azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "blob.core.windows.net", "azureedge.net"}, ""},
}

func dienstVan(naam string) (dienst, tekst string) {
	for _, o := range overneembaar {
		for _, a := range o.achter {
			if naam == a || strings.HasSuffix(naam, "."+a) {
				return o.dienst, o.tekst
			}
		}
	}
	return "", ""
}

// registreerbaar geeft het domein dat iemand kan registreren (eTLD+1).
func registreerbaar(naam string) string {
	if r, err := publicsuffix.EffectiveTLDPlusOne(naam); err == nil {
		return r
	}
	return naam
}

// vrijTeRegistreren: het domein boven de naam bestaat niet (NXDOMAIN), dus
// iedereen kan het registreren.
func (z *subZoeker) vrijTeRegistreren(ctx context.Context, naam string) bool {
	r, err := publicsuffix.EffectiveTLDPlusOne(naam)
	if err != nil {
		return false
	}
	m, err := z.dns.Vraag(ctx, r, dns.TypeNS)
	return err == nil && m.Rcode == dns.RcodeNameError
}

// keten volgt de CNAME-records in een antwoord vanaf naam.
func keten(m *dns.Msg, naam string) []string {
	doel := map[string]string{}
	for _, rr := range m.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			doel[strings.ToLower(dns.Fqdn(c.Hdr.Name))] = strings.ToLower(c.Target)
		}
	}
	var uit []string
	n := dns.Fqdn(naam)
	for i := 0; i < 8; i++ {
		d, ok := doel[n]
		if !ok {
			break
		}
		uit = append(uit, strings.TrimSuffix(d, "."))
		n = d
	}
	return uit
}

func (z *subZoeker) beoordeel(ctx context.Context, naam string) Subdomein {
	sd := Subdomein{Naam: naam}
	m4, err := z.dns.Vraag(ctx, naam, dns.TypeA)
	if err != nil || m4.Rcode == dns.RcodeServerFailure {
		sd.Status, sd.Oordeel, sd.Uitleg = Fout, "Niet te meten", "De DNS gaf geen bruikbaar antwoord voor deze naam."
		return sd
	}
	cnames := keten(m4, naam)
	laatste := ""
	if len(cnames) > 0 {
		sd.CNAME, laatste = cnames[0], cnames[len(cnames)-1]
	}
	var alle []netip.Addr
	for _, rr := range m4.Answer {
		if a, ok := rr.(*dns.A); ok {
			if x, ok := netip.AddrFromSlice(a.A.To4()); ok {
				alle = append(alle, x)
			}
		}
	}
	if m6, err := z.dns.Vraag(ctx, naam, dns.TypeAAAA); err == nil {
		for _, rr := range m6.Answer {
			if a, ok := rr.(*dns.AAAA); ok {
				if x, ok := netip.AddrFromSlice(a.AAAA); ok {
					alle = append(alle, x)
				}
			}
		}
	}
	var publiek []netip.Addr
	for i, a := range alle {
		if i < 4 {
			sd.Adressen = append(sd.Adressen, a.String())
		}
		if Publiek(a) {
			publiek = append(publiek, a)
		}
	}
	dienst, tekst := dienstVan(laatste)
	switch {
	case laatste != "" && m4.Rcode == dns.RcodeNameError && (laatste == z.domein || strings.HasSuffix(laatste, "."+z.domein)):
		sd.Status, sd.Oordeel = Matig, "Verwijst naar een naam die niet bestaat"
		sd.Uitleg = "Dit record wijst naar " + laatste + ", en die naam bestaat niet. Het record kan weg."
		return sd
	case laatste != "" && m4.Rcode == dns.RcodeNameError && (dienst != "" || z.vrijTeRegistreren(ctx, laatste)):
		sd.Status, sd.Oordeel = Slecht, "Kan door een ander worden overgenomen"
		if dienst != "" {
			sd.Uitleg = "Dit subdomein wijst naar " + laatste + " bij " + dienst + ", maar die naam bestaat daar niet meer. Iedereen met een account bij " + dienst + " kan hem aanmaken, en bepaalt dan wat er op jouw subdomein staat. Haal het record weg, of zet de dienst weer op."
		} else {
			sd.Uitleg = "Dit subdomein wijst naar " + laatste + ", maar de domeinnaam daarvan is niet meer geregistreerd. Iedereen kan hem registreren, en bepaalt dan wat er op jouw subdomein staat. Haal het record weg."
		}
		return sd
	case laatste != "" && m4.Rcode == dns.RcodeNameError:
		// De naam bestaat niet, maar het domein erboven wel: alleen de
		// beheerder daarvan (vaak een dienst die je ooit gebruikte) kan hem
		// aanmaken. Geen bewezen overname, wel een record dat niets meer doet.
		sd.Status, sd.Oordeel = Matig, "Verwijst naar een naam die niet bestaat"
		sd.Uitleg = "Dit subdomein wijst naar " + laatste + ", maar die naam bestaat niet. Alleen wie " + registreerbaar(laatste) + " beheert, kan hem aanmaken; gebruik je die dienst niet meer, haal het record dan weg."
		return sd
	case m4.Rcode == dns.RcodeNameError:
		sd.Status, sd.Oordeel = NVT, "Bestaat niet meer"
		sd.Uitleg = "Deze naam staat in oude certificaten, maar niet meer in je DNS. Hier hoef je niets mee."
		return sd
	case len(alle) == 0 && laatste != "":
		sd.Status, sd.Oordeel = Matig, "Wijst nergens meer heen"
		sd.Uitleg = "Dit record wijst naar " + laatste + ", maar daar staat geen adres meer. Het record kan weg."
		return sd
	case len(alle) == 0:
		sd.Status, sd.Oordeel = NVT, "Geen website"
		sd.Uitleg = "Deze naam heeft geen adres meer. Staan er nog andere records op die je niet gebruikt, dan kunnen die weg."
		return sd
	case len(publiek) == 0:
		sd.Status, sd.Oordeel = Matig, "Wijst naar een intern adres"
		sd.Uitleg = "Deze naam wijst naar een adres in een intern netwerk. Van buiten werkt dat niet, en het verraadt iets over je netwerk. Zet zo'n naam in je interne DNS, niet in de openbare."
		return sd
	}

	staat, body, err := z.proef(ctx, naam, publiek)
	if tekst != "" && body != nil && strings.Contains(string(body), tekst) {
		sd.Status, sd.Oordeel = Slecht, "Kan door een ander worden overgenomen"
		sd.Uitleg = "Dit subdomein wijst naar " + dienst + ", maar daar is het niet (meer) ingesteld. Iemand anders kan het daar aanmaken, en dan staat zijn site op jouw naam. Haal het record weg, of stel het bij " + dienst + " weer in."
		if staat != nil {
			sd.HTTPS = z.httpsTekst(staat, naam)
		}
		return sd
	}
	if err != nil || staat == nil {
		sd.Status, sd.Oordeel, sd.HTTPS = NVT, "Geen website via https", "geen"
		sd.Uitleg = "Op deze naam antwoordt geen beveiligde website. Gebruik je hem niet meer, haal het record dan weg."
		return sd
	}
	sd.HTTPS = z.httpsTekst(staat, naam)
	switch sd.HTTPS {
	case "verlopen":
		sd.Status, sd.Oordeel = Matig, "Het certificaat is verlopen"
		sd.Uitleg = "Bezoekers krijgen een waarschuwing. Vernieuw het certificaat, of haal de naam weg als je hem niet meer gebruikt."
	case "naam klopt niet":
		sd.Status, sd.Oordeel = Matig, "Het certificaat hoort bij een andere naam"
		sd.Uitleg = "Bezoekers krijgen een waarschuwing. Vaak een naam die nog naar een oude dienst wijst; haal hem weg als je hem niet meer gebruikt."
	case "niet vertrouwd":
		sd.Status, sd.Oordeel = Matig, "Het certificaat wordt niet vertrouwd"
		sd.Uitleg = "Browsers vertrouwen dit certificaat niet, bijvoorbeeld omdat het zelf ondertekend is."
	default:
		blad := staat.PeerCertificates[0]
		sd.uitgever = uitgever(blad)
		if blad.NotAfter.Sub(z.nu()) < 14*24*time.Hour {
			sd.Status, sd.Oordeel = Matig, "Het certificaat verloopt binnenkort"
			sd.Uitleg = "Wordt het niet op tijd vernieuwd, dan krijgen bezoekers een waarschuwing."
		} else {
			sd.Status, sd.Oordeel = Goed, "Werkt, met een geldig certificaat"
		}
	}
	return sd
}

// httpsTekst beoordeelt het certificaat dat de proef zag.
func (z *subZoeker) httpsTekst(staat *tls.ConnectionState, naam string) string {
	if len(staat.PeerCertificates) == 0 {
		return "niet vertrouwd"
	}
	blad := staat.PeerCertificates[0]
	tussen := x509.NewCertPool()
	for _, c := range staat.PeerCertificates[1:] {
		tussen.AddCert(c)
	}
	_, err := blad.Verify(x509.VerifyOptions{DNSName: naam, Intermediates: tussen, Roots: z.roots, CurrentTime: z.nu()})
	var ongeldig x509.CertificateInvalidError
	var verkeerd x509.HostnameError
	switch {
	case errors.As(err, &ongeldig) && ongeldig.Reason == x509.Expired:
		return "verlopen"
	case errors.As(err, &verkeerd):
		return "naam klopt niet"
	case err != nil:
		return "niet vertrouwd"
	}
	return "geldig tot " + datum(blad.NotAfter)
}

// proef: één TLS-handdruk en één GET van /, zonder doorverwijzingen te volgen,
// hooguit 64 KiB. Het certificaat beoordelen we zelf (httpsTekst), zodat we
// ook bij een fout certificaat de pagina van een clouddienst kunnen lezen.
func (z *subZoeker) proef(ctx context.Context, naam string, adressen []netip.Addr) (*tls.ConnectionState, []byte, error) {
	var laatste error = errors.New("geen adres")
	for _, a := range adressen[:min(len(adressen), maxPerFamilie)] {
		staat, body, err := z.proefAdres(ctx, naam, a)
		if staat != nil {
			return staat, body, err
		}
		laatste = err
	}
	return nil, nil, laatste
}

func (z *subZoeker) proefAdres(ctx context.Context, naam string, a netip.Addr) (*tls.ConnectionState, []byte, error) {
	c, err := z.dial(ctx, a, "443")
	if err != nil {
		return nil, nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(z.nu().Add(z.timeout))
	t := tls.Client(c, &tls.Config{ServerName: naam, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) // zie httpsTekst
	if err := t.HandshakeContext(ctx); err != nil {
		return nil, nil, err
	}
	staat := t.ConnectionState()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+naam+"/", nil)
	if err != nil {
		return &staat, nil, err
	}
	req.Header.Set("User-Agent", z.ua)
	req.Close = true
	if err := req.Write(t); err != nil {
		return &staat, nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(t), req)
	if err != nil {
		return &staat, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxSubBody))
	return &staat, body, nil
}

var maandNamen = [...]string{"januari", "februari", "maart", "april", "mei", "juni", "juli", "augustus", "september", "oktober", "november", "december"}

// datum: "3 maart 2027".
func datum(t time.Time) string {
	return fmt.Sprintf("%d %s %d", t.Day(), maandNamen[t.Month()-1], t.Year())
}
