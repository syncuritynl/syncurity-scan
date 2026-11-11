package keuring

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// STARTTLS op de mailservers, zoals de mailtest van internet.nl. We doen
// alleen wat elke verzendende mailserver doet: verbinden met poort 25, de
// begroeting lezen, EHLO, kijken of STARTTLS wordt aangeboden, STARTTLS, de
// TLS-handdruk, en dan QUIT. Nooit MAIL FROM, RCPT, DATA, AUTH of VRFY.
//
// Per scan hooguit twee mailservers (laagste voorkeur eerst), één adres elk
// (IPv6 eerst, IPv4 als dat niet lukt), en per mailserver drie sessies: de gewone (versie, suite, certificaat), één
// met alleen TLS 1.0 en 1.1, en één eigen proef met alleen verouderde suites
// (tlsproef.go). De uitkomst per mailserver bewaren we 15 minuten, net zo lang als
// een uitslag (de naam van een mailserver bevat vaak de domeinnaam), gedeeld door
// alle scans: veel domeinen delen dezelfde mailservers.

const (
	smtpBegroeting = 15 * time.Second // zo lang wachten we op de 220
	smtpSessie     = 30 * time.Second // en zo lang duurt een sessie hooguit
	smtpMaxRegel   = 1000             // RFC 5321 zegt 512; wat ruimte voor slordige servers
	smtpMaxRegels  = 64
	mxGeheugenTijd = 15 * time.Minute
	mxGeheugenMax  = 2000
)

var (
	errGeenEHLO    = errors.New("geen naam voor EHLO ingesteld")
	errSMTP        = errors.New("onverwacht antwoord van de mailserver")
	errInspuiting  = errors.New("de mailserver stuurde al tekst na het antwoord op STARTTLS")
	errSMTPTeLaat  = errors.New("de meting van de mailserver duurde te lang")
	errGeenAdresMX = errors.New("de mailserver heeft geen publiek adres")
)

// leesSMTP leest één antwoord, ook als het uit meer regels bestaat
// ("250-..." tot "250 ..."). Het antwoord is onbetrouwbaar: regels hooguit
// smtpMaxRegel lang, hooguit smtpMaxRegels regels, overal dezelfde code.
func leesSMTP(r *bufio.Reader) (code int, regels []string, err error) {
	for {
		regel, err := r.ReadSlice('\n')
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				return 0, nil, fmt.Errorf("%w: regel te lang", errSMTP)
			}
			return 0, nil, err
		}
		s := strings.TrimRight(string(regel), "\r\n")
		if len(s) < 3 || (len(s) > 3 && s[3] != ' ' && s[3] != '-') {
			return 0, nil, fmt.Errorf("%w: %q", errSMTP, kort(s, 60))
		}
		c, err := strconv.Atoi(s[:3])
		if err != nil || c < 200 || c > 599 || (code != 0 && c != code) {
			return 0, nil, fmt.Errorf("%w: %q", errSMTP, kort(s, 60))
		}
		code = c
		if len(regels) == smtpMaxRegels {
			return 0, nil, fmt.Errorf("%w: te veel regels", errSMTP)
		}
		tekst := ""
		if len(s) > 4 {
			tekst = s[4:]
		}
		regels = append(regels, tekst)
		if len(s) == 3 || s[3] == ' ' {
			return code, regels, nil
		}
	}
}

// startTLS doet het gesprek tot en met "220" op STARTTLS. starttls is false
// als de server STARTTLS niet aanbiedt; dan sturen we QUIT.
func startTLS(c net.Conn, ehlo string) (starttls bool, err error) {
	_ = c.SetDeadline(time.Now().Add(smtpBegroeting))
	r := bufio.NewReaderSize(c, smtpMaxRegel)
	if code, _, err := leesSMTP(r); err != nil || code != 220 {
		return false, fmt.Errorf("begroeting: %w", leegDanFout(err, code))
	}
	_ = c.SetDeadline(time.Now().Add(smtpSessie))
	if _, err := fmt.Fprintf(c, "EHLO %s\r\n", ehlo); err != nil {
		return false, err
	}
	code, regels, err := leesSMTP(r)
	if err != nil || code != 250 {
		return false, fmt.Errorf("EHLO: %w", leegDanFout(err, code))
	}
	for _, regel := range regels[1:] {
		if f := strings.Fields(regel); len(f) > 0 && strings.EqualFold(f[0], "STARTTLS") {
			starttls = true
		}
	}
	if !starttls {
		_, _ = fmt.Fprintf(c, "QUIT\r\n")
		return false, nil
	}
	if _, err := fmt.Fprintf(c, "STARTTLS\r\n"); err != nil {
		return true, err
	}
	if code, _, err := leesSMTP(r); err != nil || code != 220 {
		return true, fmt.Errorf("STARTTLS: %w", leegDanFout(err, code))
	}
	if r.Buffered() > 0 {
		// Tekst die vóór de handdruk al klaarstaat, zou anders als versleuteld
		// gelden (STARTTLS-inspuiting).
		return true, errInspuiting
	}
	return true, nil
}

func leegDanFout(err error, code int) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("%w: code %d", errSMTP, code)
}

// mxMeting is wat één mailserver liet zien.
type mxMeting struct {
	naam    string
	adres   netip.Addr
	fout    error // geen verbinding of geen gesprek: niet te meten
	geenTLS bool  // STARTTLS niet aangeboden
	tlsFout error // STARTTLS aangeboden, maar de handdruk mislukte
	versie  uint16
	suite   uint16
	keten   []*x509.Certificate
	oud     string // geaccepteerde versie van vóór TLS 1.2
	zwak    string // geaccepteerde onveilige of verouderde suite
	dhBits  int    // als dat een DHE-suite was

	alleenV4 bool // de mailserver heeft geen IPv6-adres
}

type smtpDialer func(ctx context.Context, naam string, a netip.Addr) (net.Conn, error)

// Poort 25 over IPv4 kan vanaf de scanserver dicht zitten: sommige
// hostingpartijen blokkeren uitgaand verkeer op poort 25 over IPv4, en dan
// loopt elke verbinding vast tot de time-out (gezien op 2-11-2026, bij alle
// mailservers tegelijk, terwijl IPv6 gewoon werkte). Loopt een verbinding
// over IPv4 op poort 25 één keer vast, dan slaan we IPv4 op poort 25 een
// kwartier over, voor alle scans: anders wacht elke scan op dezelfde
// time-out. Daarna proberen we het weer.
var v4poort25 struct {
	sync.Mutex
	dichtTot time.Time
}

const v4DichtTijd = 15 * time.Minute

func v4Dicht(nu time.Time) bool {
	v4poort25.Lock()
	defer v4poort25.Unlock()
	return nu.Before(v4poort25.dichtTot)
}

func zetV4Dicht(nu time.Time) {
	v4poort25.Lock()
	defer v4poort25.Unlock()
	v4poort25.dichtTot = nu.Add(v4DichtTijd)
}

// errOnbereikbaar: we kwamen niet bij de mailserver (time-out, geen route,
// of IPv4 op poort 25 staat dicht vanaf onze kant). Dat ligt niet aan de
// mailserver.
var errOnbereikbaar = errors.New("niet bereikbaar vanaf de scanserver")

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

// kiesAdressen: per mailserver eerst IPv6, dan IPv4; van elk het eerste.
func kiesAdressen(v4, v6 []netip.Addr) []netip.Addr {
	var uit []netip.Addr
	if len(v6) > 0 {
		uit = append(uit, v6[0])
	}
	if len(v4) > 0 {
		uit = append(uit, v4[0])
	}
	return uit
}

// verbind probeert de adressen op volgorde en geeft de eerste verbinding.
// Elke poging telt mee voor maxSMTP (DialSMTP telt). IPv4 slaan we over als
// poort 25 daar net dicht bleek.
func verbind(ctx context.Context, naam string, adressen []netip.Addr, dial smtpDialer) (net.Conn, netip.Addr, error) {
	var fouten []string
	for _, a := range adressen {
		if a.Is4() && v4Dicht(time.Now()) {
			fouten = append(fouten, a.String()+": poort 25 over IPv4 staat vanaf onze kant dicht")
			continue
		}
		c, err := dial(ctx, naam, a)
		if err == nil {
			return c, a, nil
		}
		if a.Is4() && isTimeout(err) {
			zetV4Dicht(time.Now())
		}
		if !geenRoute(err) && !isTimeout(err) {
			return nil, a, err // een echte weigering: niet nog een adres proberen
		}
		fouten = append(fouten, fmt.Sprintf("%s: %v", a, err))
	}
	return nil, netip.Addr{}, fmt.Errorf("%w (%s)", errOnbereikbaar, strings.Join(fouten, "; "))
}

// meetMX doet de drie sessies met één mailserver: de eerste op het eerste
// adres dat antwoordt (IPv6 voor IPv4), de andere twee op datzelfde adres.
func meetMX(ctx context.Context, naam string, adressen []netip.Addr, dial smtpDialer, ehlo string) mxMeting {
	m := mxMeting{naam: naam, alleenV4: true}
	for _, a := range adressen {
		if a.Is6() {
			m.alleenV4 = false
		}
	}
	eerste := true
	// sessie opent een verbinding en doet het gesprek tot de handdruk.
	sessie := func() (net.Conn, bool, error) {
		var c net.Conn
		var err error
		if eerste {
			eerste = false
			c, m.adres, err = verbind(ctx, naam, adressen, dial)
		} else {
			c, err = dial(ctx, naam, m.adres)
		}
		if err != nil {
			return nil, false, err
		}
		ok, err := startTLS(c, ehlo)
		if err != nil || !ok {
			c.Close()
			return nil, ok, err
		}
		return c, true, nil
	}
	handdruk := func(c net.Conn, cfg *tls.Config) (*tls.ConnectionState, error) {
		defer c.Close()
		cfg.ServerName, cfg.InsecureSkipVerify = naam, true // het certificaat beoordelen we zelf
		t := tls.Client(c, cfg)
		if err := t.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		_, _ = t.Write([]byte("QUIT\r\n"))
		s := t.ConnectionState()
		return &s, nil
	}

	c, ok, err := sessie()
	switch {
	case err != nil && !ok:
		m.fout = err
		return m
	case err != nil:
		m.tlsFout = err
		return m
	case !ok:
		m.geenTLS = true
		return m
	}
	s, err := handdruk(c, &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS13})
	if err != nil {
		m.tlsFout = err
		return m
	}
	m.versie, m.suite, m.keten = s.Version, s.CipherSuite, s.PeerCertificates
	if m.versie < tls.VersionTLS12 {
		m.oud = tls.VersionName(m.versie)
	}

	var wg sync.WaitGroup
	if m.oud == "" {
		wg.Go(func() {
			if c, ok, err := sessie(); err == nil && ok {
				if s, err := handdruk(c, &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}); err == nil {
					m.oud = tls.VersionName(s.Version)
				}
			}
		})
	}
	wg.Go(func() {
		c, ok, err := sessie()
		if err != nil || !ok {
			return
		}
		defer c.Close()
		suites := append(append(append([]uint16{}, onveilig...), verouderd...), dheSuites...)
		if a, err := tlsProef(c, proefHello{naam: naam, suites: suites}, smtpSessie); err == nil && !a.geweigerd && !a.tls13 && a.suite != 0 {
			m.zwak, m.dhBits = suiteNaam(a.suite), a.dhBits
		}
	})
	wg.Wait()
	return m
}

// mxGeheugen bewaart de meting per mailserver 15 minuten, voor alle scans.
var mxGeheugen = struct {
	sync.Mutex
	m map[string]mxBewaard
}{m: map[string]mxBewaard{}}

type mxBewaard struct {
	tijd   time.Time
	meting mxMeting
}

func uitGeheugen(naam string, nu time.Time) (mxMeting, bool) {
	mxGeheugen.Lock()
	defer mxGeheugen.Unlock()
	b, ok := mxGeheugen.m[naam]
	if !ok || nu.Sub(b.tijd) > mxGeheugenTijd {
		return mxMeting{}, false
	}
	return b.meting, true
}

func inGeheugen(m mxMeting, nu time.Time) {
	mxGeheugen.Lock()
	defer mxGeheugen.Unlock()
	if len(mxGeheugen.m) >= mxGeheugenMax {
		for n, b := range mxGeheugen.m {
			if nu.Sub(b.tijd) > mxGeheugenTijd {
				delete(mxGeheugen.m, n)
			}
		}
		for n := range mxGeheugen.m {
			if len(mxGeheugen.m) < mxGeheugenMax {
				break
			}
			delete(mxGeheugen.m, n) // vol met verse metingen: een willekeurige eruit
		}
	}
	mxGeheugen.m[m.naam] = mxBewaard{nu, m}
}

// mailTLS meet de eerste twee mailservers, of haalt ze uit het geheugen.
// De meting loopt los van de scan door (hooguit 40 seconden), zodat een
// trage mailserver de volgende scan wel uit het geheugen komt; de scan zelf
// wacht hooguit tot zijn eigen tijd op is.
func (k *keurder) mailTLS(ctx context.Context) ([]mxMeting, error) {
	if k.ehlo == "" || !hstsNaam(strings.ToLower(k.ehlo)) {
		return nil, errGeenEHLO // ook een naam met spaties of regeleinden niet
	}
	namen := eerste(k.mxOpVoorkeur(ctx), 2)
	k.kiezer.StaMailToe(namen)
	uit := make([]mxMeting, len(namen))
	klaar := make([]chan struct{}, len(namen))
	for i, n := range namen {
		klaar[i] = make(chan struct{})
		// Bij een nieuwe scan op verzoek meten we opnieuw: misschien is juist
		// de mailserver aangepast. De nieuwe meting gaat wel in het geheugen.
		if m, ok := uitGeheugen(n, time.Now()); ok && !k.opnieuw {
			uit[i] = m
			close(klaar[i])
			continue
		}
		a := kiesAdressen(k.kiezer.Adressen(ctx, n))
		if len(a) == 0 {
			uit[i] = mxMeting{naam: n, fout: errGeenAdresMX}
			close(klaar[i])
			continue
		}
		los, stop := context.WithTimeout(context.WithoutCancel(ctx), 40*time.Second)
		go func() {
			defer stop()
			m := meetMX(los, n, a, k.smtpDial, k.ehlo)
			if !errors.Is(m.fout, ErrBudget) && !errors.Is(m.fout, ErrGeenMailserver) {
				inGeheugen(m, time.Now())
			}
			uit[i] = m
			close(klaar[i])
		}()
	}
	for i := range klaar {
		select {
		case <-klaar[i]:
		case <-ctx.Done():
			// Wat nog loopt, schrijft straks in het geheugen; hier telt het niet.
			return metTeLaat(uit, klaar, namen), nil
		}
	}
	return uit, nil
}

// metTeLaat: wat klaar is, en "te laat" voor de rest.
func metTeLaat(uit []mxMeting, klaar []chan struct{}, namen []string) []mxMeting {
	kopie := make([]mxMeting, len(uit))
	for i := range uit {
		select {
		case <-klaar[i]:
			kopie[i] = uit[i]
		default:
			kopie[i] = mxMeting{naam: namen[i], fout: errSMTPTeLaat}
		}
	}
	return kopie
}
