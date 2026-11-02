package keuring

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"
)

// web bevat alles wat we één keer van de website ophalen. De controles in
// web_verbinding.go en web_instellingen.go oordelen daarna alleen nog.
type web struct {
	host       string
	staat      *tls.ConnectionState // gewone handdruk, TLS 1.2 tot 1.3, met ALPN
	fout       error
	oud        []string       // aangeboden versies van vóór TLS 1.2
	zwak       string         // geaccepteerde onveilige suite (RC4, 3DES), leeg als geen
	verouder   string         // geaccepteerde verouderde suite (CBC, RSA-sleuteluitwisseling)
	verouderID uint16         // en het nummer daarvan
	oudeTLS    oudeTLS        // eigen TLS 1.2-proef: DH, volgorde, compressie, heronderhandeling, SHA-1
	preload    string         // op de HSTS-preloadlijst: "ja", "ja, via x", "nee"; leeg als de lijst er niet is
	suitesAlle []string       // alle geaccepteerde zwakke en verouderde suites (alleen volledige keuring)
	eerste     *http.Response // https://host/ zonder doorverwijzingen te volgen
	httpLoc    string         // waar http://host/ naartoe stuurt
	httpCode   int
	pagina     *http.Response // de pagina waar je uiteindelijk uitkomt
	body       []byte
	info       paginaInfo    // ontlede HTML van die pagina
	geweigerd  int           // HTTP-status als de site de scan niet binnenliet (botbeveiliging), anders 0
	weg        string        // naar welk ander domein de homepage doorstuurde (cookiemuur), als dat zo is
	ttfb       time.Duration // tijd tot de eerste byte van https://host/, inclusief verbinding
	gecodeerd  string        // Content-Encoding als we br en gzip aanbieden
	robots     string        // inhoud van /robots.txt, leeg als die er niet is
	robotsOK   bool
	sitemap    int // aantal adressen in de sitemap, -1 als er geen is
	sitemapURL string
	llms       string // inhoud van /llms.txt
	eind       string // de naam waar je na doorverwijzingen uitkomt
	andere     string // naam van de www- of kale variant
	andereLoc  string // waar die naartoe stuurt
	andereCode int
	cache      string // Cache-Control van een stylesheet of script
	cacheURL   string
	stijl      string // inhoud van het eerste eigen stylesheet, hooguit maxStijl
	stijlAdres string // waar dat stylesheet staat
	stijlAf    bool   // het stylesheet was groter dan maxStijl
	corsOrigin string // Access-Control-Allow-Origin op een verzoek met Origin: proefOrigin
	corsCreds  bool   // en Access-Control-Allow-Credentials: true

	// toegevoegd met de tweede reeks punten
	andereAdres bool                 // de andere variant (met of zonder www) heeft een adres
	andereStaat *tls.ConnectionState // handdruk met die naam, om het certificaat te controleren
	andereFout  error
	robotsCode  int           // HTTP-status van /robots.txt
	gewicht     []afbGewicht  // grootte van de eerste afbeeldingen op het eigen domein
	perAdres    []adresMeting // handdruk en GET / op elk adres apart (tls-adressen)

	// roots: de vertrouwde basiscertificaten. nil betekent die van het
	// systeem, zoals een browser; alleen de tests zetten hier een eigen CA.
	roots *x509.CertPool
}

type afbGewicht struct {
	pad   string
	bytes int64
}

// alleSuites probeert de zwakke en verouderde suites één voor één, zodat de
// eigenaar precies weet wat er uit moet. Alleen in de volledige keuring, en
// alleen als de gewone meting er al een vond: zo kost het meestal niets.
func (k *keurder) alleSuites(ctx context.Context, host string, zwak, oud bool) []string {
	var uit []string
	probeer := func(lijst []uint16, minV uint16) {
		for _, s := range lijst {
			if _, err := k.handdruk(ctx, host, &tls.Config{MinVersion: minV, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{s}}); err == nil {
				uit = append(uit, tls.CipherSuiteName(s))
			}
		}
	}
	if zwak {
		probeer(onveilig, tls.VersionTLS10)
	}
	if oud {
		probeer(verouderd, tls.VersionTLS12)
	}
	return uit
}

// webhost kiest de naam van de website: het domein zelf, of www als het
// domein zelf geen adres heeft. Leeg als er geen website is.
func (k *keurder) webhost(ctx context.Context) string {
	for _, h := range []string{k.domein, "www." + k.domein} {
		v4, v6 := k.kiezer.Adressen(ctx, h)
		if len(v4)+len(v6) > 0 {
			return h
		}
	}
	return ""
}

// onveilig zijn suites die nooit meer aangeboden horen te worden.
var onveilig = []uint16{
	tls.TLS_RSA_WITH_RC4_128_SHA, tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA, tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
}

// verouderd zijn suites zonder forward secrecy of met CBC. Nog niet gekraakt,
// maar internet.nl noemt ze "uit te faseren".
var verouderd = []uint16{
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
}

func (k *keurder) haalWeb(ctx context.Context, host string) *web {
	w := &web{host: host}
	if host == "" {
		return w
	}
	w.staat, w.fout = k.handdruk(ctx, host, &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}})
	if w.fout != nil {
		w.haalHTTP(ctx, k)
		return w
	}
	for _, v := range []struct {
		v    uint16
		naam string
	}{{tls.VersionTLS10, "TLS 1.0"}, {tls.VersionTLS11, "TLS 1.1"}} {
		if _, err := k.handdruk(ctx, host, &tls.Config{MinVersion: v.v, MaxVersion: v.v}); err == nil {
			w.oud = append(w.oud, v.naam)
		}
	}
	if s, err := k.handdruk(ctx, host, &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12, CipherSuites: onveilig}); err == nil {
		w.zwak = tls.CipherSuiteName(s.CipherSuite)
	}
	if s, err := k.handdruk(ctx, host, &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: verouderd}); err == nil {
		w.verouder, w.verouderID = tls.CipherSuiteName(s.CipherSuite), s.CipherSuite
	}
	w.oudeTLS = k.oudeTLS(ctx, w)
	if k.vol {
		w.suitesAlle = k.alleSuites(ctx, host, w.zwak != "", w.verouder != "")
	}
	w.perAdres = k.meetAdressen(ctx, host)

	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/", nil); err == nil {
		begin := time.Now()
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
			GotFirstResponseByte: func() { w.ttfb = time.Since(begin) },
		}))
		if r, err := k.eenStap.Do(req); err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 64<<10))
			r.Body.Close()
			w.eerste = r
		}
	}
	// De homepage tot 2 MiB: grote sites zetten veel code in de HTML, en de
	// kop, schema en tekst kunnen daarachter staan.
	w.pagina, w.body = k.haalMax(ctx, k.web, "https://"+host+"/", maxPagina)
	w.info = ontleed(w.body)
	if w.pagina != nil && (w.pagina.StatusCode != http.StatusOK || uitdaging(w.body)) {
		// Een botbeveiliging of cookiemuur geeft een tussenpagina. Die
		// beoordelen we niet: dan zouden we de echte site afkeuren om iets
		// wat er niet op staat.
		w.geweigerd = w.pagina.StatusCode
		if w.geweigerd == http.StatusOK {
			w.geweigerd = 403
		}
		if w.geweigerd/100 == 3 {
			if u, err := w.pagina.Location(); err == nil {
				// De naam komt van de site zelf en staat straks onder onze naam in
				// het rapport: kort en zonder stuur- of bidi-tekens.
				w.weg = kort(schoon(u.Hostname()), 80)
			}
		}
		w.info.geldig = false
	}
	w.haalHTTP(ctx, k)
	w.haalVindbaarheid(ctx, k)
	return w
}

// haalVindbaarheid doet de paar extra verzoeken voor SEO, AI en snelheid:
// robots.txt, de sitemap, llms.txt, de andere variant van de naam (met of
// zonder www), de compressie van de pagina en de cache van één bestand.
func (w *web) haalVindbaarheid(ctx context.Context, k *keurder) {
	basis := "https://" + w.host
	if w.pagina != nil && w.pagina.Request != nil && w.pagina.Request.URL != nil {
		basis = w.pagina.Request.URL.Scheme + "://" + w.pagina.Request.URL.Host
	}
	if r, b := k.pagina(ctx, basis+"/robots.txt"); r != nil {
		w.robotsCode = r.StatusCode
		if r.StatusCode == http.StatusOK && !strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "html") {
			w.robots, w.robotsOK = string(b), true
		}
	}
	w.sitemap = -1
	kandidaten := []string{}
	for _, regel := range strings.Split(w.robots, "\n") {
		if kv := strings.SplitN(strings.TrimSpace(regel), ":", 2); len(kv) == 2 && strings.EqualFold(kv[0], "sitemap") {
			kandidaten = append(kandidaten, strings.TrimSpace(kv[1]))
		}
	}
	kandidaten = append(kandidaten, basis+"/sitemap.xml", basis+"/sitemap_index.xml")
	for _, u := range kandidaten[:min(len(kandidaten), 2)] {
		// Alleen sitemaps op het eigen domein, zoals Google ook doet zonder
		// aparte verificatie. Anders haalt de scan URL's naar keuze bij derden op.
		pu, err := url.Parse(u)
		if err != nil || pu.Scheme != "https" || (pu.Hostname() != k.domein && !strings.HasSuffix(pu.Hostname(), "."+k.domein)) {
			continue
		}
		if r, b := k.haal(ctx, k.web, u); r != nil && r.StatusCode == http.StatusOK && bytes.Contains(b, []byte("<loc>")) {
			w.sitemap, w.sitemapURL = bytes.Count(b, []byte("<loc>")), u
			break
		}
	}
	if r, b := k.pagina(ctx, basis+"/llms.txt"); r != nil && r.StatusCode == http.StatusOK && !strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "html") {
		w.llms = string(b)
	}

	// De andere variant: www.domein als je site op domein staat, en andersom.
	w.eind = w.host
	if w.pagina != nil && w.pagina.Request != nil && w.pagina.Request.URL != nil {
		w.eind = w.pagina.Request.URL.Hostname()
	}
	w.andere = "www." + k.domein
	if w.eind == "www."+k.domein {
		w.andere = k.domein
	}
	// Het certificaat van de andere naam: een fout daarin zou anders op
	// "geen antwoord" lijken (en de kale naam dan ten onrechte in orde).
	if v4, v6 := k.kiezer.Adressen(ctx, w.andere); len(v4)+len(v6) > 0 {
		w.andereAdres = true
		w.andereStaat, w.andereFout = k.handdruk(ctx, w.andere, &tls.Config{MinVersion: tls.VersionTLS12})
	}
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+w.andere+"/", nil); err == nil {
		if r, err := k.eenStap.Do(req); err == nil {
			r.Body.Close()
			w.andereCode = r.StatusCode
			if loc, err := r.Location(); err == nil {
				w.andereLoc = loc.String()
			}
		}
	}

	// Compressie: br en gzip aanbieden en alleen naar de kop kijken. In
	// hetzelfde verzoek doen we ons voor als een andere site (Origin), om te
	// zien of de server elke site toegang geeft (cors). Geen extra verzoek.
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, basis+"/", nil); err == nil {
		req.Header.Set("Accept-Encoding", "br, gzip")
		req.Header.Set("Origin", proefOrigin)
		if r, err := k.eenStap.Do(req); err == nil {
			r.Body.Close()
			w.gecodeerd = strings.ToLower(r.Header.Get("Content-Encoding"))
			w.corsOrigin = r.Header.Get("Access-Control-Allow-Origin")
			w.corsCreds = strings.EqualFold(strings.TrimSpace(r.Header.Get("Access-Control-Allow-Credentials")), "true")
		}
	}

	w.haalStijl(ctx, k, basis)

	// Gewicht van de eerste afbeeldingen op het eigen domein: hooguit vijf
	// HEAD-verzoeken, alleen de kop (Content-Length).
	doel, _ := url.Parse(basis + "/")
	gedaan := map[string]bool{}
	for _, src := range w.info.x.afbeeldingSrc {
		if len(gedaan) >= 5 {
			break
		}
		u, err := url.Parse(strings.TrimSpace(src))
		if err != nil {
			continue
		}
		u = doel.ResolveReference(u)
		if u.Scheme != "https" || (u.Hostname() != k.domein && !strings.HasSuffix(u.Hostname(), "."+k.domein)) || gedaan[u.String()] {
			continue
		}
		gedaan[u.String()] = true
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
		if err != nil {
			continue
		}
		if r, err := k.web.Do(req); err == nil {
			r.Body.Close()
			if r.StatusCode == http.StatusOK && r.ContentLength > 0 {
				w.gewicht = append(w.gewicht, afbGewicht{u.Path, r.ContentLength})
			}
		}
	}
}

// haalStijl: de cache van het eerste stylesheet op hetzelfde domein, of
// anders van het eerste script. Eén verzoek. Het stylesheet halen we op
// (hooguit maxStijl) voor de lettertypen en het verkleinen; van een script
// alleen de kop.
func (w *web) haalStijl(ctx context.Context, k *keurder, basis string) {
	doel, _ := url.Parse(basis + "/")
	eigen := func(bron string) *url.URL {
		u, err := url.Parse(strings.TrimSpace(bron))
		if err != nil || bron == "" {
			return nil
		}
		u = doel.ResolveReference(u)
		if u.Scheme != "https" || (u.Hostname() != k.domein && !strings.HasSuffix(u.Hostname(), "."+k.domein)) {
			return nil
		}
		return u
	}
	var bestand *url.URL
	methode := http.MethodGet
	for _, b := range w.info.stijlen {
		if bestand = eigen(b); bestand != nil {
			break
		}
	}
	if bestand == nil {
		methode = http.MethodHead
		for _, b := range w.info.bronnen {
			if bestand = eigen(b); bestand != nil {
				break
			}
		}
	}
	if bestand == nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, methode, bestand.String(), nil)
	if err != nil {
		return
	}
	r, err := k.web.Do(req)
	if err != nil {
		return
	}
	inhoud, _ := io.ReadAll(io.LimitReader(r.Body, maxStijl+1))
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return
	}
	w.cache = r.Header.Get("Cache-Control")
	if w.cache == "" && (r.Header.Get("ETag") != "" || r.Header.Get("Last-Modified") != "") {
		w.cache = "alleen ETag/Last-Modified"
	}
	w.cacheURL = bestand.Path
	if methode == http.MethodGet && !strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "html") {
		w.stijlAf = len(inhoud) > maxStijl
		w.stijl = string(inhoud[:min(len(inhoud), maxStijl)])
		w.stijlAdres = r.Request.URL.String()
	}
}

func (w *web) haalHTTP(ctx context.Context, k *keurder) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+w.host+"/", nil)
	if err != nil {
		return
	}
	r, err := k.eenStap.Do(req)
	if err != nil {
		return
	}
	r.Body.Close()
	w.httpCode = r.StatusCode
	if loc, err := r.Location(); err == nil {
		w.httpLoc = loc.String()
	}
}

var uitdagingen = [][]byte{[]byte("cf-chl"), []byte("challenge-platform"), []byte("_Incapsula_Resource"),
	[]byte("px-captcha"), []byte("captcha-delivery.com"), []byte("Attention Required! | Cloudflare"),
	[]byte("<title>Just a moment...</title>"), []byte("sgcaptcha")}

// uitdaging herkent de tussenpagina van een botbeveiliging.
func uitdaging(body []byte) bool {
	if len(body) > 64<<10 {
		return false // een echte pagina, geen tussenpagina
	}
	for _, u := range uitdagingen {
		if bytes.Contains(body, u) {
			return true
		}
	}
	return false
}

// kop geeft een kopregel van de eerste pagina, of van het eerste antwoord.
func (w *web) kop(naam string) string {
	if w.pagina != nil {
		if v := w.pagina.Header.Get(naam); v != "" {
			return v
		}
	}
	if w.eerste != nil {
		return w.eerste.Header.Get(naam)
	}
	return ""
}

func (k *keurder) handdruk(ctx context.Context, host string, cfg *tls.Config) (*tls.ConnectionState, error) {
	c, err := k.kiezer.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(k.timeout))
	cfg.ServerName = host
	cfg.InsecureSkipVerify = true // we beoordelen het certificaat zelf, zie certificaat()
	t := tls.Client(c, cfg)
	if err := t.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	s := t.ConnectionState()
	return &s, nil
}

// pagina haalt een URL op en volgt doorverwijzingen binnen hetzelfde domein.
func (k *keurder) pagina(ctx context.Context, adres string) (*http.Response, []byte) {
	return k.haal(ctx, k.web, adres)
}

const maxPagina = 2 << 20

// maxStijl: zoveel van het stylesheet lezen we. Genoeg voor de meeste
// sites; wat erachter staat, laten we liggen.
const maxStijl = 512 << 10

// haal haalt een URL op met de gegeven client, hooguit 512 KiB.
func (k *keurder) haal(ctx context.Context, c *http.Client, adres string) (*http.Response, []byte) {
	return k.haalMax(ctx, c, adres, 512<<10)
}

// haalMax haalt een URL op, hooguit max bytes.
func (k *keurder) haalMax(ctx context.Context, c *http.Client, adres string, max int64) (*http.Response, []byte) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, adres, nil)
	if err != nil {
		return nil, nil
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, max))
	return resp, body
}

// zelfdeAdres zegt of een doorverwijzing naar https op dezelfde naam uitkomt.
// Hoofdletters en de standaardpoort :443 maken geen verschil.
func zelfdeAdres(loc, host string) bool {
	u, err := url.Parse(strings.TrimSpace(loc))
	if err != nil || u.Scheme != "https" || !strings.EqualFold(strings.TrimSuffix(u.Hostname(), "."), host) {
		return false
	}
	return u.Port() == "" || u.Port() == "443"
}

// naarSecurityTxt volgt doorverwijzingen naar elk domein, maar alleen via
// https en alleen naar /.well-known/security.txt of /security.txt, zonder query.
// security.txt mag naar een ander domein verwijzen (RFC 9116); een willekeurig
// pad bij een ander niet: dan zou de scan namens ons verzoeken naar keuze bij
// derden kunnen doen.
func naarSecurityTxt(req *http.Request, via []*http.Request) error {
	pad := req.URL.Path
	if len(via) >= 3 || req.URL.Scheme != "https" || (pad != "/.well-known/security.txt" && pad != "/security.txt") || req.URL.RawQuery != "" {
		return http.ErrUseLastResponse
	}
	return nil
}

// zelfdeDomein laat doorverwijzingen alleen toe binnen het gekeurde domein.
func zelfdeDomein(domein string) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		h := req.URL.Hostname()
		if h != domein && !strings.HasSuffix(h, "."+domein) {
			return http.ErrUseLastResponse
		}
		return nil
	}
}

func leegAls(s, anders string) string {
	if s == "" {
		return anders
	}
	return s
}
