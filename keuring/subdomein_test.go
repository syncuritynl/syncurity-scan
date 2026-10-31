package keuring

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------- subdomeinen

func TestNamenOnder(t *testing.T) {
	namen, wildcard := namenOnder("voorbeeld.nl", []string{
		"www.voorbeeld.nl", "WWW.voorbeeld.nl.", "*.voorbeeld.nl", "voorbeeld.nl", "a.b.voorbeeld.nl",
		"mail.andere.nl", "slechtvoorbeeld.nl", "x_y.voorbeeld.nl", "iemand@voorbeeld.nl", "api.voorbeeld.nl",
	})
	if !wildcard || strings.Join(namen, ",") != "api.voorbeeld.nl,www.voorbeeld.nl,a.b.voorbeeld.nl" {
		t.Errorf("namenOnder: %v %v", namen, wildcard)
	}
}

func TestLeesLogs(t *testing.T) {
	n, err := leesCrtsh(strings.NewReader(`[{"name_value":"a.voorbeeld.nl\nb.voorbeeld.nl","common_name":"a.voorbeeld.nl"},{"name_value":"c.voorbeeld.nl"}]`))
	if err != nil || len(n) != 5 {
		t.Errorf("crt.sh: %v %v", n, err)
	}
	// Afgebroken antwoord: wat binnen was, telt.
	n, err = leesCrtsh(strings.NewReader(`[{"name_value":"a.voorbeeld.nl"},{"name_va`))
	if err == nil || len(n) != 2 {
		t.Errorf("afgebroken crt.sh: %v %v", n, err)
	}
	n, err = leesCertspotter(strings.NewReader(`[{"id":"1","dns_names":["x.voorbeeld.nl","*.voorbeeld.nl"]}]`))
	if err != nil || len(n) != 2 {
		t.Errorf("certspotter: %v %v", n, err)
	}
	if _, err := leesCrtsh(strings.NewReader(`{"fout":1}`)); err == nil {
		t.Error("een object in plaats van een lijst gaf geen fout")
	}
}

// Valt crt.sh om (502), dan certspotter.
func TestLogTerugval(t *testing.T) {
	crt := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	defer crt.Close()
	spot := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("domain") != "voorbeeld.nl" {
			t.Errorf("certspotter kreeg %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`[{"dns_names":["weg.voorbeeld.nl","*.voorbeeld.nl"]}]`))
	}))
	defer spot.Close()
	z := &subZoeker{domein: "voorbeeld.nl", dns: nieuwNepDNS(t), logs: crt.Client(), totaal: 5 * time.Second, tegelijk: 2, nu: time.Now,
		bronnen: []logBron{
			{"crt.sh", func(d string) string { return crt.URL + "/?q=%25." + d + "&output=json" }, time.Second, leesCrtsh},
			{"certspotter", func(d string) string { return spot.URL + "/?domain=" + d }, time.Second, leesCertspotter},
		}}
	// Beide servers hebben hetzelfde testcertificaat; één client is genoeg.
	u := z.zoek(context.Background())
	if u.bron != "certspotter" || len(u.lijst) != 1 || u.lijst[0].Status != NVT || !strings.Contains(u.melding, "wildcard") {
		t.Errorf("terugval: %+v", u)
	}
	z.bronnen = z.bronnen[:1]
	if u := z.zoek(context.Background()); u.bron != "" || !strings.Contains(u.melding, "niet bereikbaar") {
		t.Errorf("beide weg: %+v", u)
	}
}

func TestDangling(t *testing.T) {
	ca := nieuweCA(t)
	jaar := time.Now().Add(365 * 24 * time.Hour)
	servers := map[string]string{
		"blog.voorbeeld.nl":  tlsServer(t, ca.blad(t, jaar, "*.github.io"), "<h1>404</h1><p>There isn't a GitHub Pages site here.</p>"),
		"goed.voorbeeld.nl":  tlsServer(t, ca.blad(t, jaar, "goed.voorbeeld.nl"), "hallo"),
		"oud.voorbeeld.nl":   tlsServer(t, ca.blad(t, time.Now().Add(-time.Hour), "oud.voorbeeld.nl"), "hallo"),
		"ander.voorbeeld.nl": tlsServer(t, ca.blad(t, jaar, "iets.anders.nl"), "hallo"),
		"gh.voorbeeld.nl":    tlsServer(t, ca.blad(t, jaar, "gh.voorbeeld.nl"), "<p>Welkom op mijn GitHub Pages site</p>"),
	}
	r := nieuwNepDNS(t,
		"blog.voorbeeld.nl. 300 IN CNAME voorbeeld.github.io.",
		"voorbeeld.github.io. 300 IN A 185.199.108.153",
		"gh.voorbeeld.nl. 300 IN CNAME echt.github.io.",
		"echt.github.io. 300 IN A 185.199.108.154",
		"azure.voorbeeld.nl. 300 IN CNAME weg.azurewebsites.net.",
		"azurewebsites.net. 300 IN NS ns1-01.azure-dns.com.",
		"oudedienst.voorbeeld.nl. 300 IN CNAME klant-12.verlopen-domein.nl.",
		"saas.voorbeeld.nl. 300 IN CNAME klant-12.bestaande-dienst.nl.",
		"bestaande-dienst.nl. 300 IN NS ns1.bestaande-dienst.nl.",
		"intern-weg.voorbeeld.nl. 300 IN CNAME bestaatniet.voorbeeld.nl.",
		"leeg.voorbeeld.nl. 300 IN CNAME leeg.cdn.nl.",
		"leeg.cdn.nl. 300 IN TXT \"geen adres\"",
		"lan.voorbeeld.nl. 300 IN A 192.168.1.10",
		"goed.voorbeeld.nl. 300 IN A 93.184.215.1",
		"oud.voorbeeld.nl. 300 IN A 93.184.215.2",
		"ander.voorbeeld.nl. 300 IN A 93.184.215.3",
		"dicht.voorbeeld.nl. 300 IN A 93.184.215.4",
		"txt.voorbeeld.nl. 300 IN TXT \"alleen tekst\"",
	)
	r.nx["weg.azurewebsites.net."] = true
	r.nx["bestaatniet.voorbeeld.nl."] = true
	r.fout["kapot.voorbeeld.nl."] = true

	z := &subZoeker{domein: "voorbeeld.nl", dns: r, roots: ca.pool, timeout: 2 * time.Second, nu: time.Now, ua: "test"}
	// Per naam een eigen nep-dial naar de bijbehorende testserver.
	wil := map[string]Status{
		"blog.voorbeeld.nl": Slecht, "azure.voorbeeld.nl": Slecht, "intern-weg.voorbeeld.nl": Matig,
		"leeg.voorbeeld.nl": Matig, "lan.voorbeeld.nl": Matig, "goed.voorbeeld.nl": Goed, "oud.voorbeeld.nl": Matig,
		"ander.voorbeeld.nl": Matig, "dicht.voorbeeld.nl": NVT, "weg.voorbeeld.nl": NVT, "txt.voorbeeld.nl": NVT,
		"gh.voorbeeld.nl": Goed, "kapot.voorbeeld.nl": Fout,
		"oudedienst.voorbeeld.nl": Slecht, "saas.voorbeeld.nl": Matig,
	}
	for naam, status := range wil {
		adres := servers[naam]
		z.dial = func(ctx context.Context, a netip.Addr, poort string) (net.Conn, error) {
			if !Publiek(a) || poort != "443" {
				t.Errorf("%s: proef naar %s:%s", naam, a, poort)
			}
			if adres == "" {
				return nil, errors.New("verbinding geweigerd")
			}
			return net.Dial("tcp", adres)
		}
		sd := z.beoordeel(context.Background(), naam)
		if sd.Status != status {
			t.Errorf("%s: %s (%s, https %q), wil %s", naam, sd.Status, sd.Oordeel, sd.HTTPS, status)
		}
		if naam == "goed.voorbeeld.nl" && (!strings.HasPrefix(sd.HTTPS, "geldig tot ") || sd.uitgever != "Let's Encrypt") {
			t.Errorf("goed: https %q, uitgever %q", sd.HTTPS, sd.uitgever)
		}
		if naam == "oud.voorbeeld.nl" && sd.HTTPS != "verlopen" || naam == "ander.voorbeeld.nl" && sd.HTTPS != "naam klopt niet" {
			t.Errorf("%s: https %q", naam, sd.HTTPS)
		}
		if naam == "blog.voorbeeld.nl" && sd.CNAME != "voorbeeld.github.io" {
			t.Errorf("blog: cname %q", sd.CNAME)
		}
	}
}

func TestDatum(t *testing.T) {
	if d := datum(time.Date(2027, 3, 3, 0, 0, 0, 0, time.UTC)); d != "3 maart 2027" {
		t.Errorf("datum: %s", d)
	}
}
