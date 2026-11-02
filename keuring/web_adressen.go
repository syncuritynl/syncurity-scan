package keuring

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// adresMeting is wat één adres van de website antwoordde: dezelfde handdruk
// en hetzelfde GET / als voor iedereen, maar op dat ene adres.
type adresMeting struct {
	adres  netip.Addr
	versie uint16
	keten  []*x509.Certificate
	code   int    // HTTP-status van GET /
	loc    string // Location bij een doorverwijzing
	fout   error  // geen verbinding, geen handdruk of geen antwoord
}

type dialFunc func(ctx context.Context, a netip.Addr, poort string) (net.Conn, error)

// meetAdressen meet hooguit maxPerFamilie IPv4- en IPv6-adressen van host,
// tegelijk: per adres één verbinding. Adressen waar de scanner zelf geen
// route naartoe heeft (geen IPv6), laten we weg; dat zegt niets over de site.
func (k *keurder) meetAdressen(ctx context.Context, host string) []adresMeting {
	v4, v6 := k.kiezer.Adressen(ctx, host)
	lijst := slices.Concat(v4[:min(len(v4), maxPerFamilie)], v6[:min(len(v6), maxPerFamilie)])
	return meetAdressen(ctx, host, lijst, k.kiezer.DialAdres, k.timeout, k.ua)
}

func meetAdressen(ctx context.Context, host string, lijst []netip.Addr, dial dialFunc, timeout time.Duration, ua string) []adresMeting {
	uit := make([]adresMeting, len(lijst))
	var wg sync.WaitGroup
	for i, a := range lijst {
		wg.Add(1)
		go func() { defer wg.Done(); uit[i] = meetAdres(ctx, host, a, dial, timeout, ua) }()
	}
	wg.Wait()
	gemeten := uit[:0]
	for _, m := range uit {
		if !geenRoute(m.fout) {
			gemeten = append(gemeten, m)
		}
	}
	return gemeten
}

func meetAdres(ctx context.Context, host string, a netip.Addr, dial dialFunc, timeout time.Duration, ua string) adresMeting {
	m := adresMeting{adres: a}
	c, err := dial(ctx, a, "443")
	if err != nil {
		m.fout = err
		return m
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	t := tls.Client(c, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"}, InsecureSkipVerify: true}) // het certificaat beoordelen we zelf
	if err := t.HandshakeContext(ctx); err != nil {
		m.fout = err
		return m
	}
	s := t.ConnectionState()
	m.versie, m.keten = s.Version, s.PeerCertificates

	// Eén gewoon verzoek over dezelfde verbinding. We lezen alleen de
	// status en Location; de inhoud laten we liggen.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/", nil)
	if err != nil {
		m.fout = err
		return m
	}
	req.Header.Set("User-Agent", ua)
	req.Close = true
	if err := req.Write(t); err != nil {
		m.fout = fmt.Errorf("verzoek niet verstuurd: %w", err)
		return m
	}
	r, err := http.ReadResponse(bufio.NewReader(io.LimitReader(t, 64<<10)), req)
	if err != nil {
		m.fout = fmt.Errorf("geen antwoord op GET /: %w", err)
		return m
	}
	// r.Body niet sluiten: dat leest de rest van de inhoud. De verbinding
	// gaat hierboven toch dicht.
	m.code, m.loc = r.StatusCode, r.Header.Get("Location")
	return m
}

func tlsAdressen(w *web) Punt {
	const id, tech, titel = "tls-adressen", "IPv4 · IPv6", "Elk adres even veilig"
	ms := w.perAdres
	if len(ms) <= 1 {
		return punt(id, tech, NVT, titel, "Je website heeft één adres dat we konden meten, en dat is hierboven al bekeken.")
	}
	var detail []string
	werkt := 0
	certs, versies, antwoorden := map[[32]byte]bool{}, map[uint16]bool{}, map[string]bool{}
	for _, m := range ms {
		var certFout error
		if m.fout == nil && len(m.keten) > 0 {
			certFout = controleerKeten(m.keten, w.host, w.roots)
		}
		detail = append(detail, m.regel(certFout))
		if m.fout != nil || len(m.keten) == 0 || certFout != nil {
			continue
		}
		werkt++
		certs[sha256.Sum256(m.keten[0].Raw)] = true
		versies[m.versie] = true
		antwoorden[fmt.Sprintf("%d %s", m.code, m.loc)] = true
	}
	n := len(ms)
	switch {
	case werkt == 0:
		return punt(id, tech, Fout, titel, "Op geen van de adressen kregen we een geldige beveiligde verbinding. Zie de punten hierboven.").metDetail(detail...)
	case werkt < n:
		return punt(id, tech, Slecht, "Niet elk adres is even veilig",
			"Je website heeft meerdere adressen (IPv4 en IPv6, of meerdere servers). Op een deel ervan mislukt de beveiligde verbinding of klopt het certificaat niet. Een deel van je bezoekers krijgt dan een waarschuwing of een lege pagina, terwijl jij zelf misschien niets merkt.").
			met(fmt.Sprintf("%d van de %d adressen %s niet goed", n-werkt, n, map[bool]string{true: "werkt", false: "werken"}[n-werkt == 1])).metDetail(detail...)
	}
	var anders []string
	if len(certs) > 1 {
		anders = append(anders, "certificaat")
	}
	if len(versies) > 1 {
		anders = append(anders, "TLS-versie")
	}
	if len(antwoorden) > 1 {
		anders = append(anders, "antwoord")
	}
	if len(anders) > 0 {
		return punt(id, tech, Matig, "Niet elk adres geeft dezelfde website",
			"Je website heeft meerdere adressen, maar die geven niet allemaal hetzelfde: een ander certificaat, een andere versie van de versleuteling of een ander antwoord. Vaak draait er op één adres nog een oude server of een vergeten instelling. internet.nl controleert dit ook (gelijke website op IPv4 en IPv6).").
			met(fmt.Sprintf("%d adressen: verschil in %s", n, enLijst(anders))).metDetail(detail...)
	}
	return punt(id, tech, Goed, titel,
		"Op elk adres van je website kregen we hetzelfde certificaat, dezelfde versleuteling en hetzelfde antwoord. Iedere bezoeker krijgt dus dezelfde, beveiligde site.").
		met(fmt.Sprintf("%d adressen: overal hetzelfde certificaat, %s en antwoord", n, tls.VersionName(ms[0].versie))).metDetail(detail...)
}

// regel: één adres voor het volledige rapport.
func (m adresMeting) regel(certFout error) string {
	if m.fout != nil {
		return fmt.Sprintf("%s: mislukt (%v)", m.adres, m.fout)
	}
	if len(m.keten) == 0 {
		return fmt.Sprintf("%s: %s, geen certificaat", m.adres, tls.VersionName(m.versie))
	}
	blad := m.keten[0]
	cert := fmt.Sprintf("certificaat %s tot %s", kort(leegAls(blad.Subject.CommonName, strings.Join(blad.DNSNames, " ")), 40), blad.NotAfter.Format("2-1-2006"))
	if certFout != nil {
		cert += " (ongeldig)"
	}
	antwoord := fmt.Sprintf("HTTP %d", m.code)
	if m.loc != "" {
		antwoord += " naar " + kort(m.loc, 60)
	}
	return fmt.Sprintf("%s: %s, %s, %s", m.adres, tls.VersionName(m.versie), cert, antwoord)
}

// enLijst: "a", "a en b", "a, b en c".
func enLijst(s []string) string {
	if len(s) <= 1 {
		return strings.Join(s, "")
	}
	return strings.Join(s[:len(s)-1], ", ") + " en " + s[len(s)-1]
}
