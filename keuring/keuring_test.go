package keuring

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestNormaliseer(t *testing.T) {
	goed := map[string]string{
		"syncurity.nl":                     "syncurity.nl",
		"  Syncurity.NL  ":                 "syncurity.nl",
		"https://www.syncurity.nl/pad?x=1": "syncurity.nl",
		"http://syncurity.nl:8080":         "syncurity.nl",
		"mail.bakkerij.co.uk":              "bakkerij.co.uk",
		"münchen.de":                       "xn--mnchen-3ya.de",
		"syncurity.nl.":                    "syncurity.nl",
	}
	for in, wil := range goed {
		kreeg, err := Normaliseer(in)
		if err != nil || kreeg != wil {
			t.Errorf("Normaliseer(%q) = %q, %v; wil %q", in, kreeg, err, wil)
		}
	}
	fout := map[string]error{
		"":                ErrLeeg,
		"192.168.1.1":     ErrIPAdres,
		"[::1]:443":       ErrIPAdres,
		"localhost":       ErrOngeldig,
		"printer.local":   ErrOngeldig,
		"server.internal": ErrOngeldig,
		"-fout-.nl":       ErrOngeldig,
		"a_b.nl":          ErrOngeldig,
		"co.uk":           ErrOngeldig,
	}
	for in, wil := range fout {
		if _, err := Normaliseer(in); !errors.Is(err, wil) {
			t.Errorf("Normaliseer(%q) gaf %v; wil %v", in, err, wil)
		}
	}
}

// Deze adressen mogen nooit benaderd worden, wat een domein er ook naar laat wijzen.
func TestPubliek(t *testing.T) {
	nooit := []string{
		"127.0.0.1", "10.20.30.40", "192.168.0.10", "172.16.0.1", "169.254.169.254",
		"100.64.0.1", "0.0.0.0", "255.255.255.255", "224.0.0.1",
		"::1", "fe80::1", "fd00:c1::a9fe:a9fe", "fddb:1063::1", "::ffff:127.0.0.1", "2001:db8::1",
	}
	for _, s := range nooit {
		if Publiek(netip.MustParseAddr(s)) {
			t.Errorf("%s geldt als publiek, dat mag niet", s)
		}
	}
	for _, s := range []string{"9.9.9.9", "1.1.1.1", "2620:fe::fe"} {
		if !Publiek(netip.MustParseAddr(s)) {
			t.Errorf("%s geldt niet als publiek", s)
		}
	}
}

func TestControleWeigertPoorten(t *testing.T) {
	if err := controle("tcp", "1.1.1.1:22", nil); err == nil {
		t.Error("poort 22 werd toegestaan")
	}
	if err := controle("tcp", "169.254.169.254:80", nil); err == nil {
		t.Error("de metadata-dienst werd toegestaan")
	}
	if err := controle("tcp", "1.1.1.1:443", nil); err != nil {
		t.Errorf("1.1.1.1:443 geweigerd: %v", err)
	}
}

func TestTagLijst(t *testing.T) {
	m := tagLijst("v=DMARC1; p=reject; pct=100")
	if m["p"] != "reject" || m["pct"] != "100" {
		t.Errorf("tagLijst: %v", m)
	}
}

// Elk punt moet naar een uitlegpagina kunnen linken.
func TestElkPuntHeeftUitleg(t *testing.T) {
	ids := []string{"tls-modern", "tls-oud", "cipher-zwak", "cert", "cert-sleutel", "https", "hsts",
		"csp", "nosniff", "frame", "referrer", "cookies", "versie", "mixed", "trackers", "securitytxt",
		"dmarc", "dmarc-rua", "spf", "spf-lookups", "dkim", "mta-sts", "tls-rpt", "dane",
		"dnssec", "dnssec-alg", "caa", "ns", "ipv6-web", "ipv6-mail", "ipv6-ns", "http2",
		"seo-titel", "seo-beschrijving", "seo-index", "seo-canonical", "seo-sitemap", "seo-h1", "seo-mobiel",
		"seo-taal", "seo-schema", "seo-delen", "seo-alt", "seo-www",
		"geo-crawlers", "geo-llms", "geo-entiteit", "geo-tekst", "geo-snippet", "geo-contact",
		"snel-ttfb", "snel-grootte", "snel-compressie", "snel-cache", "snel-blokkerend", "snel-afbeeldingen", "snel-extern",
		"privacy", "kvk", "toestemming"}
	for _, p := range nieuwePunten {
		ids = append(ids, p.ID)
	}
	if len(ids) != 114 {
		t.Fatalf("%d punten in de test, verwacht 114", len(ids))
	}
	if len(uitleg) != len(ids) {
		t.Errorf("de uitleg-tabel heeft %d punten, de test %d", len(uitleg), len(ids))
	}
	dubbel := map[string]bool{}
	for _, id := range ids {
		if dubbel[id] {
			t.Errorf("punt %s staat er twee keer in", id)
		}
		dubbel[id] = true
	}
	for _, id := range ids {
		if uitleg[id] == "" {
			t.Errorf("punt %s heeft geen uitlegpagina", id)
		}
	}
}

func TestRobotsGroep(t *testing.T) {
	r := "User-agent: *\nDisallow: /scan\n\nUser-agent: GPTBot\nUser-agent: CCBot\nDisallow: /\n"
	if g, _ := robotsGroep(r, "gptbot"); !geblokkeerd(normRegels(g)) {
		t.Error("GPTBot hoort geblokkeerd te zijn")
	}
	if g, _ := robotsGroep(r, "ccbot"); !geblokkeerd(normRegels(g)) {
		t.Error("CCBot hoort geblokkeerd te zijn (tweede regel van dezelfde groep)")
	}
	if g, _ := robotsGroep(r, "claudebot"); geblokkeerd(normRegels(g)) {
		t.Error("ClaudeBot valt onder * en is niet geblokkeerd")
	}
}

func TestOntleed(t *testing.T) {
	p := ontleed([]byte(`<!doctype html><html lang="nl"><head><title>Bakkerij De Vries in Utrecht</title>
<meta name="description" content="x"><script src="/a.js"></script><script type="application/ld+json">{"@type":"Bakery"}</script></head>
<body><h1>Brood</h1><img src="a.webp"><p>Bel 030 123 45 67 of mail ons. KvK 12345678.</p><script>var verborgen = "geen tekst";</script></body></html>`))
	if p.lang != "nl" || p.h1 != 1 || p.blokkerendJS != 1 || p.modern != 1 || len(p.schemaTypen) != 1 {
		t.Errorf("ontleed: %+v", p)
	}
	if strings.Contains(p.tekst, "verborgen") || strings.Contains(p.tekst, "Bakery") {
		t.Error("tekst uit scripts telt als zichtbare tekst")
	}
	if kvkRe.FindStringSubmatch(p.tekst) == nil || !telefoonRe.MatchString(p.tekst) {
		t.Error("KvK of telefoon niet herkend")
	}
}

func TestZelfdeAdres(t *testing.T) {
	for _, g := range []struct {
		loc  string
		goed bool
	}{
		{"https://bol.com/", true}, {"https://bol.com:443/", true}, {"https://Bol.com/", true},
		{"https://bol.com", true}, {"https://bol.com?x=1", true}, {"https://www.bol.com/", false},
		{"http://bol.com/", false}, {"https://bol.com:8443/", false}, {"https://bol.com.evil.nl/", false},
	} {
		if zelfdeAdres(g.loc, "bol.com") != g.goed {
			t.Errorf("zelfdeAdres(%q) = %v", g.loc, !g.goed)
		}
	}
}

func TestPubliekSpeciaal(t *testing.T) {
	for _, s := range []string{"::7f00:1", "::ffff:0:7f00:1", "64:ff9b:1::a00:10", "2002:7f00:1::1", "2001:0:4136:e378::1", "fec0::1", "192.88.99.1", "2001:2::1", "3fff::1", "5f00::1"} {
		if Publiek(netip.MustParseAddr(s)) {
			t.Errorf("%s hoort niet publiek te zijn", s)
		}
	}
	if !Publiek(netip.MustParseAddr("2a00:1450:4001::1")) || !Publiek(netip.MustParseAddr("9.9.9.9")) {
		t.Error("een gewoon publiek adres wordt geweigerd")
	}
}

func TestBijzondereNamen(t *testing.T) {
	for _, n := range []string{"home.arpa", "10.in-addr.arpa", "test.onion", "iets.test", "x.example", "a.invalid"} {
		if _, err := Normaliseer(n); err == nil {
			t.Errorf("%s hoort geweigerd te worden", n)
		}
	}
	if Weergave("xn--pypal-4ve.com") == "pаypal.com" {
		t.Error("een lookalike wordt zonder punycode getoond")
	}
	if Weergave("xn--bcher-kva.nl") != "bücher.nl" {
		t.Errorf("Weergave(bücher) = %q", Weergave("xn--bcher-kva.nl"))
	}
}

func TestBudget(t *testing.T) {
	k := &Kiezer{Max: 2}
	een, twee, drie := k.mag(), k.mag(), k.mag()
	if een != nil || twee != nil || drie == nil {
		t.Error("het budget houdt niet op na 2")
	}
}

func TestSchoon(t *testing.T) {
	p := Punt{}.met("factuur\u202efdp.exe" + strings.Repeat("x", 500))
	if strings.ContainsRune(p.Gezien, '\u202e') || len([]rune(p.Gezien)) > 301 {
		t.Errorf("met() schoont of kort niet: %d", len([]rune(p.Gezien)))
	}
}

// Regressietest: met x/net v0.30.0 kostte 512 KiB geneste divs meer dan een
// minuut. Een homepage van 2 MiB moet ruim binnen de tijd blijven.
func TestOntleedSnel(t *testing.T) {
	for _, stuk := range []string{"<div>", "<a>", "<table><tr><td>", "<b><i>"} {
		body := []byte(strings.Repeat(stuk, (2<<20)/len(stuk)))
		begin := time.Now()
		ontleed(body)
		if d := time.Since(begin); d > 3*time.Second {
			t.Errorf("%s x %d kostte %s", stuk, len(body)/len(stuk), d)
		}
	}
}

// Openbaar laat Detail en Oplossing weg, ook in Eerst, en laat het origineel heel.
func TestOpenbaar(t *testing.T) {
	p := Punt{ID: "dmarc", Status: Slecht, Detail: []string{"geheim"}, Oplossing: &Oplossing{Voorstel: "v=DMARC1"}}
	u := &Uitslag{Domein: "voorbeeld.nl", Groepen: []Groep{{ID: "mail", Punten: []Punt{p}}}, Eerst: []Punt{p}, Feiten: []Feit{{"E-mail", "x"}}}
	o := u.Openbaar()
	if o.Groepen[0].Punten[0].Detail != nil || o.Groepen[0].Punten[0].Oplossing != nil || o.Eerst[0].Detail != nil || o.Eerst[0].Oplossing != nil {
		t.Errorf("Openbaar laat details staan: %+v", o)
	}
	if u.Groepen[0].Punten[0].Detail == nil || u.Eerst[0].Oplossing == nil {
		t.Error("Openbaar veranderde het origineel")
	}
	o.Feiten[0].Waarde = "y"
	if u.Feiten[0].Waarde != "x" {
		t.Error("Openbaar deelt de feiten met het origineel")
	}
	if (*Uitslag)(nil).Openbaar() != nil {
		t.Error("Openbaar van nil")
	}
}

func TestSchoonDetail(t *testing.T) {
	var regels []string
	for i := 0; i < 20; i++ {
		regels = append(regels, "regel\u202e"+strings.Repeat("x", 300))
	}
	d := schoonDetail(append(regels, ""))
	if len(d) != maxDetail+1 || strings.ContainsRune(d[0], '\u202e') || len([]rune(d[0])) > 201 {
		t.Errorf("schoonDetail: %d regels, eerste %d tekens", len(d), len([]rune(d[0])))
	}
	if l := lijstje([]string{"a", "b", "c", "d"}, 3); len(l) != 3 || l[2] != "en nog 2" {
		t.Errorf("lijstje: %v", l)
	}
}

func TestNaarSecurityTxt(t *testing.T) {
	for adres, mag := range map[string]bool{
		"https://ncsc.nl/.well-known/security.txt":                 true,
		"https://ander.example/security.txt":                       true,
		"http://ander.example/.well-known/security.txt":            false,
		"https://slachtoffer.example/admin/verwijder/security.txt": false,
		"https://ander.example/.well-known/security.txt?id=1":      false,
		"https://ander.example/.well-known/security.txt.php":       false,
	} {
		req, _ := http.NewRequest("GET", adres, nil)
		if got := naarSecurityTxt(req, nil) == nil; got != mag {
			t.Errorf("%s: volgen %v, verwacht %v", adres, got, mag)
		}
	}
}
