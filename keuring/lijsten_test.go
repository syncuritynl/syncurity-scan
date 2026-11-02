package keuring

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func schrijfGzip(t testing.TB, pad, inhoud string) {
	t.Helper()
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	_, _ = z.Write([]byte(inhoud))
	_ = z.Close()
	if err := os.WriteFile(pad, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func vandaag() string { return time.Now().Format("2006-01-02") }

const proefRPKI = "1.0.0.0/24 24 13335\n92.5.224.0/20 24 31898\n10.0.0.0/8 8 0\n2001:db8::/32 48 64496\n2001:db8:1::/48 48 64497\n0.0.0.0/0 0 0\n"

func TestLeesRPKI(t *testing.T) {
	l, err := leesRPKI(strings.NewReader("# rpki " + vandaag() + " 6\n" + proefRPKI))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		prefix string
		asn    uint32
		wil    rpkiStatus
	}{
		{"1.0.0.0/24", 13335, rpkiGeldig},
		{"1.0.0.0/24", 666, rpkiOngeldig},      // ander AS
		{"92.5.232.0/24", 31898, rpkiGeldig},   // specifieker, binnen maxlen 24
		{"92.5.232.0/25", 31898, rpkiOngeldig}, // te specifiek
		{"8.8.8.0/24", 15169, rpkiOngeldig},    // alleen 0.0.0.0/0 met AS 0 dekt: ongeldig
		{"2001:db8:5::/48", 64496, rpkiGeldig},
		{"2001:db8:1::/48", 64496, rpkiGeldig}, // gedekt door beide, één past
		{"2001:db8:1::/48", 64497, rpkiGeldig},
		{"2001:db8:1::/56", 64497, rpkiOngeldig}, // langer dan maxlen 48
		{"2001:db9::/32", 64496, rpkiOnbekend},
	} {
		if s := l.valideer(netip.MustParsePrefix(tc.prefix), tc.asn); s != tc.wil {
			t.Errorf("%s AS%d: %s, verwacht %s", tc.prefix, tc.asn, s, tc.wil)
		}
	}
	for naam, inhoud := range map[string]string{
		"geen kopregel":    "1.0.0.0/24 24 13335\n",
		"verkeerde soort":  "# hsts " + vandaag() + " 1\n1.0.0.0/24 24 13335\n",
		"te weinig regels": "# rpki " + vandaag() + " 2\n1.0.0.0/24 24 13335\n",
		"te veel regels":   "# rpki " + vandaag() + " 1\n1.0.0.0/24 24 13335\n1.0.1.0/24 24 13335\n",
		"niet gemaskeerd":  "# rpki " + vandaag() + " 1\n1.0.0.1/24 24 13335\n",
		"maxlen te kort":   "# rpki " + vandaag() + " 1\n1.0.0.0/24 23 13335\n",
		"maxlen te lang":   "# rpki " + vandaag() + " 1\n1.0.0.0/24 33 13335\n",
		"asn geen getal":   "# rpki " + vandaag() + " 1\n1.0.0.0/24 24 AS13335\n",
		"extra veld":       "# rpki " + vandaag() + " 1\n1.0.0.0/24 24 13335 x\n",
		"absurd aantal":    "# rpki " + vandaag() + " 99999999\n",
		"datum kapot":      "# rpki 2026-13-40 1\n1.0.0.0/24 24 13335\n",
		"regel te lang":    "# rpki " + vandaag() + " 1\n" + strings.Repeat("1", 300) + "\n",
	} {
		if _, err := leesRPKI(strings.NewReader(inhoud)); err == nil {
			t.Errorf("%s: geen fout", naam)
		}
	}
}

func TestHSTSPreload(t *testing.T) {
	h, err := leesHSTS(strings.NewReader("# hsts " + vandaag() + " 3\nvoorbeeld.nl 0\ndev 1\nbank.nl 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	for naam, wil := range map[string]string{"voorbeeld.nl": "ja", "mijnsite.dev": "ja, via dev", "app.bank.nl": "ja, via bank.nl", "sub.voorbeeld.nl": "nee", "ander.nl": "nee"} {
		if p := h.preload(naam); p != wil {
			t.Errorf("%s: %q, verwacht %q", naam, p, wil)
		}
	}
	for _, kapot := range []string{"Voorbeeld.nl 1", "voorbeeld..nl 1", "voorbeeld.nl 2", "voorbeeld.nl", "voorbeeld nl 1"} {
		if _, err := leesHSTS(strings.NewReader("# hsts " + vandaag() + " 1\n" + kapot + "\n")); err == nil {
			t.Errorf("%q: geen fout", kapot)
		}
	}
	p := metPreload(Punt{Gezien: "Strict-Transport-Security: max-age=63072000"}, "ja, via dev")
	if p.Gezien != "Strict-Transport-Security: max-age=63072000 · op de HSTS-preloadlijst, via dev" {
		t.Errorf("gezien: %q", p.Gezien)
	}
}

// Opnieuw laden: alleen na tien minuten en een andere wijzigingstijd; een
// kapot bestand laat de oude lijst staan; een oude lijst telt niet.
func TestLijstenOpnieuwLaden(t *testing.T) {
	map_ := t.TempDir()
	pad := filepath.Join(map_, "rpki.txt.gz")
	schrijfGzip(t, pad, "# rpki "+vandaag()+" 1\n1.0.0.0/24 24 13335\n")
	l := NieuweLijsten(map_)
	nu := time.Now()
	l.nu = func() time.Time { return nu }
	r, err := l.RPKI()
	if err != nil || len(r.v4) != 1 {
		t.Fatalf("eerste keer: %v %v", r, err)
	}
	if _, err := l.HSTS(); !errors.Is(err, errGeenLijst) {
		t.Errorf("hsts zonder bestand: %v", err)
	}
	schrijfGzip(t, pad, "# rpki "+vandaag()+" 2\n1.0.0.0/24 24 13335\n2.0.0.0/24 24 1\n")
	_ = os.Chtimes(pad, nu.Add(time.Minute), nu.Add(time.Minute))
	if r, _ := l.RPKI(); len(r.v4) != 1 {
		t.Error("binnen tien minuten opnieuw geladen")
	}
	nu = nu.Add(11 * time.Minute)
	if r, _ := l.RPKI(); len(r.v4) != 2 {
		t.Error("na tien minuten niet opnieuw geladen")
	}
	schrijfGzip(t, pad, "kapot")
	_ = os.Chtimes(pad, nu.Add(2*time.Minute), nu.Add(2*time.Minute))
	nu = nu.Add(11 * time.Minute)
	if r, err := l.RPKI(); err != nil || len(r.v4) != 2 {
		t.Errorf("kapotte lijst verving de oude: %v", err)
	}
	nu = nu.Add(4 * 24 * time.Hour)
	if _, err := l.RPKI(); !errors.Is(err, errLijstOud) {
		t.Errorf("oude lijst: %v", err)
	}
	if _, err := (*Lijsten)(nil).RPKI(); !errors.Is(err, errGeenLijst) {
		t.Errorf("zonder lijsten: %v", err)
	}
}

func TestCymru(t *testing.T) {
	if n := cymruNaam(netip.MustParseAddr("92.5.232.178")); n != "178.232.5.92.origin.asn.cymru.com" {
		t.Errorf("v4: %s", n)
	}
	if n := cymruNaam(netip.MustParseAddr("2603:c022:c00b:2000::80")); !strings.HasPrefix(n, "0.8.0.0.0.0.0.0.") || !strings.HasSuffix(n, ".2.2.0.c.3.0.6.2.origin6.asn.cymru.com") {
		t.Errorf("v6: %s", n)
	}
	a := netip.MustParseAddr("92.5.232.178")
	for txt, wil := range map[string]bool{
		"31898 | 92.5.224.0/20 | SE | ripencc | 2007-06-28": true,
		"13335 209242 | 92.5.224.0/20 | US | arin |":        true,
		"31898 | 1.0.0.0/24 | SE | ripencc |":               false, // adres valt er niet in
		"AS31898 | 92.5.224.0/20 |":                         false,
		"0 | 92.5.224.0/20 |":                               false,
		"31898 | 92.5.232.178/20 |":                         false, // niet gemaskeerd
		"31898":                                             false,
		"1 2 3 4 5 6 7 8 9 | 92.5.224.0/20 |":               false,
	} {
		if _, ok := leesCymru(txt, a); ok != wil {
			t.Errorf("%q: %v, verwacht %v", txt, ok, wil)
		}
	}
}

func TestRPKIPunten(t *testing.T) {
	lijst, err := leesRPKI(strings.NewReader("# rpki " + vandaag() + " 6\n" + proefRPKI))
	if err != nil {
		t.Fatal(err)
	}
	r := nieuwNepDNS(t,
		`178.232.5.92.origin.asn.cymru.com. 300 IN TXT "31898 | 92.5.224.0/20 | SE | ripencc | 2007-06-28"`,
		`178.232.5.92.origin.asn.cymru.com. 300 IN TXT "31898 | 92.5.0.0/16 | SE | ripencc | 2007-06-28"`,
		`1.0.0.1.origin.asn.cymru.com. 300 IN TXT "13335 | 1.0.0.0/24 | AU | apnic | 2011-08-11"`,
		`8.8.8.8.origin.asn.cymru.com. 300 IN TXT "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"`,
		`4.4.4.4.origin.asn.cymru.com. 300 IN TXT "3356 | 4.0.0.0/9 | US | arin |"`,
		`2.2.2.2.origin.asn.cymru.com. 300 IN TXT "13335 666 | 2.2.2.0/24 | AU | apnic |"`,
		`3.3.3.3.origin.asn.cymru.com. 300 IN TXT "13335 | 1.0.0.0/24 | AU | apnic |"`,
	)
	ad := func(h, a string) hostAdres { return hostAdres{h, netip.MustParseAddr(a)} }
	for _, tc := range []struct {
		naam     string
		adressen []hostAdres
		wil      Status
		gezien   string
	}{
		{"geldig", []hostAdres{ad("www.voorbeeld.nl", "92.5.232.178"), ad("www.voorbeeld.nl", "1.0.0.1")}, Goed, "1.0.0.0/24 via AS13335: geldig, 92.5.224.0/20 via AS31898: geldig"},
		{"één ongeldig", []hostAdres{ad("mx.voorbeeld.nl", "92.5.232.178"), ad("mx2.voorbeeld.nl", "8.8.8.8")}, Slecht, ""},
		{"niet vastgelegd", []hostAdres{ad("ns.voorbeeld.nl", "92.5.232.178"), ad("ns2.voorbeeld.nl", "4.4.4.4")}, Slecht, ""}, // 0.0.0.0/0 AS0 dekt alles
		{"geen route", []hostAdres{ad("x.voorbeeld.nl", "9.9.9.9")}, Fout, ""},
		{"geen adressen", nil, NVT, ""},
	} {
		p := rpkiOordeel("rpki-web", "RPKI · ROA", "Route naar je website beveiligd", "je website", nil, meetRPKI(context.Background(), r, lijst, tc.adressen))
		if p.Status != tc.wil || (tc.gezien != "" && p.Gezien != tc.gezien) {
			t.Errorf("%s: %s %q, verwacht %s %q", tc.naam, p.Status, p.Gezien, tc.wil, tc.gezien)
		}
	}
	// Zonder het vangnet 0.0.0.0/0: niet vastgelegd is "kan beter".
	zonder, _ := leesRPKI(strings.NewReader("# rpki " + vandaag() + " 2\n1.0.0.0/24 24 13335\n2.2.2.0/24 24 13335\n"))
	if p := rpkiOordeel("rpki-ns", "RPKI · NS", "x", "je nameservers", nil, meetRPKI(context.Background(), r, zonder, []hostAdres{ad("ns", "4.4.4.4")})); p.Status != Matig {
		t.Errorf("niet vastgelegd: %s", p.Status)
	}
	// Twee netwerken op één prefix, een ervan hoort er niet bij: het slechtste telt.
	if p := rpkiOordeel("rpki-ns", "RPKI · NS", "x", "je nameservers", nil, meetRPKI(context.Background(), r, zonder, []hostAdres{ad("ns", "2.2.2.2")})); p.Status != Slecht {
		t.Errorf("twee netwerken: %s", p.Status)
	}
	// Een antwoord met een prefix waar het adres niet in valt, telt niet.
	if p := rpkiOordeel("rpki-ns", "RPKI · NS", "x", "je nameservers", nil, meetRPKI(context.Background(), r, zonder, []hostAdres{ad("ns", "3.3.3.3")})); p.Status != Fout {
		t.Errorf("prefix zonder het adres: %s", p.Status)
	}
	if p := rpkiOordeel("rpki-ns", "RPKI · NS", "x", "je nameservers", fmt.Errorf("%w", errLijstOud), nil); p.Status != Fout || !strings.Contains(p.Uitleg, "te oud") {
		t.Errorf("oude lijst: %s %q", p.Status, p.Uitleg)
	}
}

// Met een lijst zo groot als de echte (ruim een miljoen regels) moet het
// geheugen ruim onder de 60 MiB blijven.
func TestRPKIGeheugen(t *testing.T) {
	if testing.Short() {
		t.Skip("maakt een lijst van een miljoen regels")
	}
	const n4, n6 = 800_000, 230_000
	var b strings.Builder
	fmt.Fprintf(&b, "# rpki %s %d\n", vandaag(), n4+n6)
	for i := 0; i < n4; i++ {
		fmt.Fprintf(&b, "%d.%d.%d.0/24 24 %d\n", 1+i>>16&0x7f, i>>8&0xff, i&0xff, 64496+i%1000)
	}
	for i := 0; i < n6; i++ {
		fmt.Fprintf(&b, "2a%02x:%x::/32 48 %d\n", i>>16&0xff, i&0xffff, 64496+i%1000)
	}
	map_ := t.TempDir()
	schrijfGzip(t, filepath.Join(map_, "rpki.txt.gz"), b.String())
	b.Reset()
	runtime.GC()
	var voor, na runtime.MemStats
	runtime.ReadMemStats(&voor)
	l := NieuweLijsten(map_)
	runtime.GC()
	runtime.ReadMemStats(&na)
	r, err := l.RPKI()
	if err != nil || len(r.v4)+len(r.v6) != n4+n6 {
		t.Fatalf("%v", err)
	}
	mib := float64(int64(na.HeapAlloc)-int64(voor.HeapAlloc)) / (1 << 20)
	t.Logf("%d routes: %.1f MiB in het geheugen", n4+n6, mib)
	if mib > 60 {
		t.Errorf("%.1f MiB, meer dan 60", mib)
	}
	if s := r.valideer(netip.MustParsePrefix("1.0.5.0/24"), 64496+5); s != rpkiGeldig {
		t.Errorf("opzoeken in de grote lijst: %s", s)
	}
	runtime.KeepAlive(l)
}
