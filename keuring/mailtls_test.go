package keuring

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// nepMX is een mailserver die STARTTLS spreekt, en alarm slaat als de scan
// iets anders probeert dan EHLO, STARTTLS en QUIT.
type nepMX struct {
	starttls bool
	cfg      *tls.Config
	extra    string // meteen na "220" op STARTTLS meegestuurd (inspuiting)
	sessies  atomic.Int32
}

func (n *nepMX) start(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			n.sessies.Add(1)
			go n.gesprek(t, c)
		}
	}()
	return l.Addr().String()
}

func (n *nepMX) gesprek(t *testing.T, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte("220 mx.voorbeeld.nl ESMTP klaar\r\n"))
	r := bufio.NewReader(c)
	for {
		regel, err := r.ReadString('\n')
		if err != nil {
			return
		}
		opdracht := strings.ToUpper(strings.Fields(regel + " x")[0])
		switch opdracht {
		case "EHLO":
			if regel != "EHLO scan.voorbeeld.nl\r\n" {
				t.Errorf("EHLO: %q", regel)
			}
			antwoord := "250-mx.voorbeeld.nl hallo\r\n250-SIZE 35882577\r\n250 8BITMIME\r\n"
			if n.starttls {
				antwoord = "250-mx.voorbeeld.nl hallo\r\n250-SIZE 35882577\r\n250-starttls\r\n250 8BITMIME\r\n"
			}
			_, _ = c.Write([]byte(antwoord))
		case "STARTTLS":
			_, _ = c.Write([]byte("220 2.0.0 Ga je gang\r\n" + n.extra))
			s := tls.Server(c, n.cfg)
			if s.Handshake() != nil {
				return
			}
			if regel, _ := bufio.NewReader(s).ReadString('\n'); regel != "QUIT\r\n" {
				t.Errorf("na de handdruk: %q", regel)
			}
			return
		case "QUIT":
			_, _ = c.Write([]byte("221 doei\r\n"))
			return
		default:
			t.Errorf("de scan stuurde %q; alleen EHLO, STARTTLS en QUIT mogen", strings.TrimSpace(regel))
			return
		}
	}
}

func TestMeetMX(t *testing.T) {
	ca := nieuweCA(t)
	jaar := time.Now().Add(365 * 24 * time.Hour)
	cert := ca.blad(t, jaar, "mx.voorbeeld.nl")
	gcm := []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}
	for _, tc := range []struct {
		naam     string
		mx       *nepMX
		dicht    bool
		starttls Status
		cert     Status
		sessies  int32
		gezien   string
	}{
		{"goed", &nepMX{starttls: true, cfg: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, CipherSuites: gcm}}, false, Goed, Goed, 3,
			"1 mailserver: STARTTLS met TLS 1.3"},
		{"geen STARTTLS", &nepMX{cfg: &tls.Config{Certificates: []tls.Certificate{cert}}}, false, Slecht, NVT, 1, "Geen STARTTLS: mx.voorbeeld.nl"},
		{"TLS 1.0 aan", &nepMX{starttls: true, cfg: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10,
			CipherSuites: append(gcm, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)}}, false, Matig, Goed, 3, // TLS 1.0 kan niet met GCM
			"mx.voorbeeld.nl accepteert TLS 1.1"}, // de hoogste oude versie
		{"CBC aan", &nepMX{starttls: true, cfg: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
			CipherSuites: append(gcm, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)}}, false, Matig, Goed, 3, "mx.voorbeeld.nl accepteert TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"},
		{"andere naam", &nepMX{starttls: true, cfg: &tls.Config{Certificates: []tls.Certificate{ca.blad(t, jaar, "mail.hoster.nl")}, MinVersion: tls.VersionTLS12, CipherSuites: gcm}}, false, Goed, Matig, 3, ""},
		{"inspuiting", &nepMX{starttls: true, extra: "250 nep\r\n", cfg: &tls.Config{Certificates: []tls.Certificate{cert}}}, false, Slecht, NVT, 1, "Mislukt: mx.voorbeeld.nl"},
		{"poort 25 dicht", &nepMX{}, true, Fout, Fout, 0, ""},
	} {
		adres := tc.mx.start(t)
		dial := func(ctx context.Context, naam string, a netip.Addr) (net.Conn, error) {
			if naam != "mx.voorbeeld.nl" || a != netip.MustParseAddr("192.0.2.25") {
				t.Errorf("%s: dial naar %s %s", tc.naam, naam, a)
			}
			if tc.dicht {
				return nil, errors.New("connection refused")
			}
			return net.Dial("tcp", adres)
		}
		m := meetMX(context.Background(), "mx.voorbeeld.nl", netip.MustParseAddr("192.0.2.25"), dial, "scan.voorbeeld.nl")
		ms := []mxMeting{m}
		s, c := starttlsPunt(ms, nil, "Eigen server"), mxCert(ms, nil, ca.pool)
		if s.Status != tc.starttls || c.Status != tc.cert {
			t.Errorf("%s: starttls %s (%s), mx-cert %s (%s); meting %+v", tc.naam, s.Status, s.Gezien, c.Status, c.Titel, m)
		}
		if tc.gezien != "" && !strings.Contains(s.Gezien, tc.gezien) {
			t.Errorf("%s: gezien %q, verwacht %q", tc.naam, s.Gezien, tc.gezien)
		}
		time.Sleep(20 * time.Millisecond) // de laatste sessie telt op de server
		if n := tc.mx.sessies.Load(); n != tc.sessies {
			t.Errorf("%s: %d sessies, verwacht %d", tc.naam, n, tc.sessies)
		}
	}
	// Bij Microsoft 365 staat erbij dat het de instelling van de leverancier is.
	zwak := []mxMeting{{naam: "voorbeeld-nl.mail.protection.outlook.com", versie: tls.VersionTLS12, oud: "TLS 1.0"}}
	if p := starttlsPunt(zwak, nil, "Microsoft 365"); p.Status != Matig || !strings.Contains(p.Uitleg, "Dit stelt Microsoft 365 zelf in") {
		t.Errorf("Microsoft 365: %s %q", p.Status, p.Uitleg)
	}
	if p := starttlsPunt(nil, errGeenEHLO, ""); p.Status != Fout || !strings.Contains(p.Uitleg, "staat uit") {
		t.Errorf("uit: %s %q", p.Status, p.Uitleg)
	}
}

func TestLeesSMTP(t *testing.T) {
	for _, tc := range []struct {
		in     string
		code   int
		regels int
		fout   bool
	}{
		{"220 klaar\r\n", 220, 1, false},
		{"250-a\r\n250-b\r\n250 c\r\n", 250, 3, false},
		{"250\r\n", 250, 1, false},
		{"250-a\r\n251 b\r\n", 0, 0, true}, // andere code
		{"25x klaar\r\n", 0, 0, true},
		{"220klaar\r\n", 0, 0, true},
		{"220 " + strings.Repeat("x", 2000) + "\r\n", 0, 0, true},
		{strings.Repeat("250-x\r\n", 100) + "250 x\r\n", 0, 0, true},
		{"250-a\r\n", 0, 0, true}, // afgebroken
		{"999 hoi\r\n", 0, 0, true},
	} {
		code, regels, err := leesSMTP(bufio.NewReaderSize(strings.NewReader(tc.in), smtpMaxRegel))
		if (err != nil) != tc.fout || code != tc.code || len(regels) != tc.regels {
			t.Errorf("%q: %d %d %v", kort(tc.in, 40), code, len(regels), err)
		}
	}
}

func TestMXGeheugen(t *testing.T) {
	nu := time.Now()
	inGeheugen(mxMeting{naam: "mx.geheugen.nl", versie: tls.VersionTLS13}, nu)
	if m, ok := uitGeheugen("mx.geheugen.nl", nu.Add(59*time.Minute)); !ok || m.versie != tls.VersionTLS13 {
		t.Error("binnen het uur niet uit het geheugen")
	}
	if _, ok := uitGeheugen("mx.geheugen.nl", nu.Add(61*time.Minute)); ok {
		t.Error("na een uur nog uit het geheugen")
	}
	for i := 0; i < mxGeheugenMax+10; i++ {
		inGeheugen(mxMeting{naam: "vol" + strconv.Itoa(i) + ".nl"}, nu)
	}
	mxGeheugen.Lock()
	n := len(mxGeheugen.m)
	mxGeheugen.Unlock()
	if n > mxGeheugenMax {
		t.Errorf("%d in het geheugen, hooguit %d", n, mxGeheugenMax)
	}
}

// Poort 25 alleen naar toegestane mailservers, en nooit naar een andere poort.
func TestDialSMTP(t *testing.T) {
	k := &Kiezer{}
	k.StaMailToe([]string{"mx.voorbeeld.nl"})
	if _, err := k.DialSMTP(context.Background(), "www.ander.nl", netip.MustParseAddr("192.0.2.1")); !errors.Is(err, ErrGeenMailserver) {
		t.Errorf("andere naam: %v", err)
	}
	if err := controleSMTP("tcp", "1.1.1.1:443", nil); err == nil {
		t.Error("poort 443 via de SMTP-weg")
	}
	if err := controleSMTP("tcp", "10.0.0.1:25", nil); err == nil {
		t.Error("een intern adres op poort 25")
	}
	if err := controleSMTP("tcp", "1.1.1.1:25", nil); err != nil {
		t.Errorf("1.1.1.1:25: %v", err)
	}
	if err := controle("tcp", "1.1.1.1:25", nil); err == nil {
		t.Error("de gewone weg laat poort 25 toe")
	}
}

// Het DANE-record van de mailserver moet passen bij het certificaat uit STARTTLS.
func TestDANEMX(t *testing.T) {
	ca := nieuweCA(t)
	tussen := ca.tussen(t)
	jaar := time.Now().Add(365 * 24 * time.Hour)
	blad, _ := x509.ParseCertificate(tussen.blad(t, jaar, "mx.voorbeeld.nl").Certificate[0])
	ander, _ := x509.ParseCertificate(tussen.blad(t, jaar, "mx.voorbeeld.nl").Certificate[0])
	record := func(c *x509.Certificate) []dns.RR {
		r := &dns.TLSA{Hdr: dns.RR_Header{Name: "_25._tcp.mx.voorbeeld.nl.", Rrtype: dns.TypeTLSA, Class: dns.ClassINET}}
		_ = r.Sign(3, 1, 1, c)
		return []dns.RR{r}
	}
	ms := []mxMeting{{naam: "mx.voorbeeld.nl", keten: []*x509.Certificate{blad, tussen.cert}}}
	if r := daneMX("mx.voorbeeld.nl", record(blad), ms); r != "" {
		t.Errorf("past: %q", r)
	}
	if r := daneMX("mx.voorbeeld.nl", record(ander), ms); r == "" {
		t.Error("past niet, maar geen melding")
	}
	if r := daneMX("mx.voorbeeld.nl", record(ander), nil); r != "" {
		t.Errorf("niet gemeten: %q", r)
	}
}
