package keuring

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// adresServer: een https-server die op / antwoordt met deze status, en
// controleert dat de scan zich gewoon voorstelt.
func adresServer(t *testing.T, cert tls.Certificate, code int, loc string, maxVersie uint16) string {
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" || r.Host != "voorbeeld.nl" || r.UserAgent() != "proef-agent" {
			t.Errorf("verzoek %s %s, Host %q, User-Agent %q", r.Method, r.URL.Path, r.Host, r.UserAgent())
		}
		if loc != "" {
			w.Header().Set("Location", loc)
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(strings.Repeat("inhoud ", 1000)))
	}))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MaxVersion: maxVersie}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s.Listener.Addr().String()
}

func TestTLSAdressen(t *testing.T) {
	ca := nieuweCA(t)
	jaar := time.Now().Add(365 * 24 * time.Hour)
	cert := ca.blad(t, jaar, "voorbeeld.nl")
	gewoon := adresServer(t, cert, 200, "", 0)
	anderCert := adresServer(t, ca.blad(t, jaar, "voorbeeld.nl"), 200, "", 0)
	stuurtDoor := adresServer(t, cert, 301, "https://voorbeeld.nl/nl/", 0)
	oudeTLS := adresServer(t, cert, 200, "", tls.VersionTLS12)
	verkeerdeNaam := adresServer(t, ca.blad(t, jaar, "oud.hosting.nl"), 200, "", 0)

	a1, a2 := netip.MustParseAddr("93.184.215.1"), netip.MustParseAddr("93.184.215.2")
	a6 := netip.MustParseAddr("2a00:1450:4001::1")
	for _, tc := range []struct {
		naam    string
		servers map[netip.Addr]string // "" geeft "verbinding geweigerd", "geen route" geeft ENETUNREACH
		wil     Status
		gezien  string
	}{
		{"overal gelijk", map[netip.Addr]string{a1: gewoon, a2: gewoon, a6: gewoon}, Goed, "3 adressen: overal hetzelfde certificaat, TLS 1.3 en hetzelfde antwoord"},
		{"ander certificaat", map[netip.Addr]string{a1: gewoon, a6: anderCert}, Goed, "2 adressen: overal een geldig certificaat, TLS 1.3 en hetzelfde antwoord"},
		{"ander antwoord", map[netip.Addr]string{a1: gewoon, a6: stuurtDoor}, Matig, "2 adressen: verschil in antwoord"},
		{"andere versie", map[netip.Addr]string{a1: gewoon, a2: oudeTLS}, Matig, "2 adressen: verschil in TLS-versie"},
		{"verkeerd certificaat", map[netip.Addr]string{a1: gewoon, a6: verkeerdeNaam}, Slecht, "1 van de 2 adressen werkt niet goed"},
		{"adres dicht", map[netip.Addr]string{a1: gewoon, a2: ""}, Slecht, "1 van de 2 adressen werkt niet goed"},
		{"scanner zonder IPv6", map[netip.Addr]string{a1: gewoon, a6: "geen route"}, NVT, ""},
		{"één adres", map[netip.Addr]string{a1: gewoon}, NVT, ""},
		{"nergens geldig", map[netip.Addr]string{a1: verkeerdeNaam, a2: verkeerdeNaam}, Fout, ""},
	} {
		var lijst []netip.Addr
		for _, a := range []netip.Addr{a1, a2, a6} {
			if _, ok := tc.servers[a]; ok {
				lijst = append(lijst, a)
			}
		}
		dial := func(ctx context.Context, a netip.Addr, poort string) (net.Conn, error) {
			if poort != "443" {
				t.Errorf("%s: proef naar poort %s", tc.naam, poort)
			}
			switch adres := tc.servers[a]; adres {
			case "":
				return nil, errors.New("verbinding geweigerd")
			case "geen route":
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ENETUNREACH)}
			default:
				return net.Dial("tcp", adres)
			}
		}
		w := &web{host: "voorbeeld.nl", roots: ca.pool,
			perAdres: meetAdressen(context.Background(), "voorbeeld.nl", lijst, dial, 2*time.Second, "proef-agent")}
		p := tlsAdressen(w)
		if p.Status != tc.wil || p.Gezien != tc.gezien {
			t.Errorf("%s: %s %q (%s), verwacht %s %q", tc.naam, p.Status, p.Gezien, p.Titel, tc.wil, tc.gezien)
		}
		if p.Status == Matig || p.Status == Slecht {
			if len(p.Detail) != len(w.perAdres) || !strings.Contains(p.Detail[0], "93.184.215.1: TLS 1.3, certificaat voorbeeld.nl tot ") {
				t.Errorf("%s: detail %q", tc.naam, p.Detail)
			}
			if strings.Contains(p.Gezien, "93.184") {
				t.Errorf("%s: adressen horen alleen in het detail: %q", tc.naam, p.Gezien)
			}
		}
	}
}

// Zonder https: het punt staat er wel, maar telt niet mee.
func TestTLSAdressenZonderHTTPS(t *testing.T) {
	k := &keurder{domein: "voorbeeld.nl"}
	for _, w := range []*web{{}, {host: "voorbeeld.nl", fout: errors.New("geen handdruk")}} {
		g := k.verbinding(w)
		gevonden := false
		for _, p := range g.Punten {
			if p.ID == "tls-adressen" {
				gevonden = p.Status == NVT || p.Status == Fout
			}
		}
		if !gevonden {
			t.Errorf("host %q: tls-adressen ontbreekt of telt mee: %+v", w.host, g.Punten)
		}
	}
}
