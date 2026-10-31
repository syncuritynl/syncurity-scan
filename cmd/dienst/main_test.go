package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"syncurity.nl/keuring/keuring"
)

// Geheimen die alleen in het volledige rapport horen. Staat er een in de
// HTML van de publieke dienst, dan lekt Detail of Oplossing.
var geheimen = []string{"GEHEIM-DETAIL", "GEHEIM-STAP", "GEHEIM-VOORSTEL", "GEHEIM-NAAM", "GEHEIM-WIE", "GEHEIM-TOELICHTING"}

// nepUitslag is een uitslag vol Detail en Oplossing, zonder netwerk.
func nepUitslag(domein string) *keuring.Uitslag {
	opl := &keuring.Oplossing{Wie: "GEHEIM-WIE", Stappen: []string{"GEHEIM-STAP"}, Voorstel: "GEHEIM-VOORSTEL", Naam: "GEHEIM-NAAM", Toelichting: "GEHEIM-TOELICHTING"}
	p := keuring.Punt{ID: "dmarc", Titel: "Een ander kan mailen namens jou", Status: keuring.Slecht, Oordeel: "Niet in orde",
		Uitleg: "Er staat geen DMARC-regel.", Gezien: "openbaar gezien", Techniek: "DMARC", Detail: []string{"GEHEIM-DETAIL"}, Oplossing: opl}
	return &keuring.Uitslag{
		Domein: domein, Tijd: time.Now(), Feiten: []keuring.Feit{{Naam: "E-mail", Waarde: "Microsoft 365"}},
		Groepen: []keuring.Groep{{ID: "mail", Naam: "Je e-mail", Kort: "E-mail", Punten: []keuring.Punt{p}, Totaal: 1}},
		Eerst:   []keuring.Punt{p}, Totaal: 1,
	}
}

func nepDienst(keur keurFunctie) *dienst {
	d := nieuweDienst(keuring.Standaard)
	d.keur = keur
	return d
}

func postScan(h http.Handler, domein, ip string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(url.Values{"domein": {domein}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("X-Real-IP", ip)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func get(h http.Handler, pad string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, pad, nil))
	return w
}

// De publieke dienst toont en bewaart nooit Detail of Oplossing, ook niet als
// de keurfunctie ze wel teruggeeft.
func TestPubliekToontGeenDetails(t *testing.T) {
	d := nepDienst(func(_ context.Context, invoer string, _ keuring.Instellingen) (*keuring.Uitslag, error) {
		return nepUitslag(invoer), nil
	})
	h := d.routes()
	if w := postScan(h, "voorbeeld.nl", "192.0.2.10"); w.Code != http.StatusSeeOther {
		t.Fatalf("POST /scan gaf %d", w.Code)
	}
	w := get(h, "/scan/voorbeeld.nl")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "openbaar gezien") {
		t.Fatalf("rapport gaf %d zonder de uitslag", w.Code)
	}
	for _, g := range geheimen {
		if strings.Contains(w.Body.String(), g) {
			t.Errorf("%s staat in de publieke HTML", g)
		}
	}
	u := d.bewaarde("voorbeeld.nl")
	for _, ps := range [][]keuring.Punt{u.Groepen[0].Punten, u.Eerst} {
		for _, p := range ps {
			if p.Detail != nil || p.Oplossing != nil {
				t.Errorf("bewaarde uitslag heeft nog Detail of Oplossing: %+v", p)
			}
		}
	}

	// Ook als er (door een fout elders) toch iets met details in het
	// geheugen staat, toont het rapport ze niet.
	d.mu.Lock()
	d.uitslag["voorbeeld.nl"] = bewaard{u: nepUitslag("voorbeeld.nl"), tot: time.Now().Add(time.Minute)}
	d.mu.Unlock()
	body := get(h, "/scan/voorbeeld.nl").Body.String()
	for _, g := range geheimen {
		if strings.Contains(body, g) {
			t.Errorf("%s staat in de HTML van een bewaarde uitslag", g)
		}
	}
}

func TestEigenHerkomst(t *testing.T) {
	for _, g := range []struct {
		site, origin string
		goed         bool
	}{
		{"same-origin", "", true}, {"none", "", true}, {"", "", true}, {"", "https://syncurity.nl", true},
		{"cross-site", "", false}, {"same-site", "", false}, {"cross-site", "https://syncurity.nl", false},
		{"", "null", false}, {"", "https://evil.com", false}, {"", "https://syncurity.nl.evil.com", false},
		{"", "http://syncurity.nl", false},
	} {
		r := httptest.NewRequest(http.MethodPost, "/scan", nil)
		if g.site != "" {
			r.Header.Set("Sec-Fetch-Site", g.site)
		}
		if g.origin != "" {
			r.Header.Set("Origin", g.origin)
		}
		if eigenHerkomst(r) != g.goed {
			t.Errorf("Sec-Fetch-Site %q, Origin %q: %v", g.site, g.origin, !g.goed)
		}
	}
}

// De rem telt per IPv4-adres en per IPv6-/64.
func TestRemPer64(t *testing.T) {
	sleutel := func(ip string) string {
		r := httptest.NewRequest(http.MethodPost, "/scan", nil)
		r.Header.Set("X-Real-IP", ip)
		return bezoeker(r)
	}
	if a, b := sleutel("2001:db8:1:2::1"), sleutel("2001:db8:1:2:ffff:ffff:ffff:ffff"); a != b || a != "2001:db8:1:2::/64" {
		t.Errorf("zelfde /64 geeft %q en %q", a, b)
	}
	if sleutel("2001:db8:1:3::1") == sleutel("2001:db8:1:2::1") {
		t.Error("een andere /64 telt mee met de eerste")
	}
	if sleutel("::ffff:192.0.2.7") != "192.0.2.7" || sleutel("onzin") != "onbekend" || sleutel("") != "onbekend" {
		t.Error("IPv4 in IPv6 of een ongeldig adres wordt niet goed geteld")
	}
	d := nepDienst(nil)
	for i := 0; i < perBezoeker; i++ {
		if !d.magNog(sleutel(fmt.Sprintf("2001:db8:1:2::%x", i+1))) {
			t.Fatalf("poging %d geweigerd", i+1)
		}
	}
	if d.magNog(sleutel("2001:db8:1:2::abcd")) {
		t.Error("na het maximum mag een ander adres in dezelfde /64 nog steeds")
	}
	if !d.magNog(sleutel("2001:db8:9::1")) {
		t.Error("een andere /64 wordt ook geremd")
	}
	// Oude pogingen vallen buiten het venster.
	d.mu.Lock()
	for i := range d.pogingen["2001:db8:1:2::/64"] {
		d.pogingen["2001:db8:1:2::/64"][i] = time.Now().Add(-venster - time.Second)
	}
	d.mu.Unlock()
	if !d.magNog("2001:db8:1:2::/64") {
		t.Error("na het venster mag het weer niet")
	}
}

// Twee gelijktijdige verzoeken voor hetzelfde domein delen één keuring.
func TestSamenEenKeuring(t *testing.T) {
	var keer atomic.Int32
	los := make(chan struct{})
	d := nepDienst(func(_ context.Context, invoer string, _ keuring.Instellingen) (*keuring.Uitslag, error) {
		keer.Add(1)
		<-los
		return nepUitslag(invoer), nil
	})
	uit := make(chan *keuring.Uitslag, 2)
	for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		go func() {
			u, err := d.uitslagVoor(context.Background(), "voorbeeld.nl", ip)
			if err != nil {
				t.Error(err)
			}
			uit <- u
		}()
	}
	// Wachten tot de tweede ook wacht: de eerste staat in bezig.
	for i := 0; i < 100; i++ {
		d.mu.Lock()
		_, bezig := d.bezig["voorbeeld.nl"]
		d.mu.Unlock()
		if bezig && keer.Load() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	close(los)
	a, b := <-uit, <-uit
	if keer.Load() != 1 || a == nil || a != b {
		t.Errorf("%d keuringen, zelfde uitslag: %v", keer.Load(), a == b)
	}
}

func TestCacheVerloopt(t *testing.T) {
	var keer atomic.Int32
	d := nepDienst(func(_ context.Context, invoer string, _ keuring.Instellingen) (*keuring.Uitslag, error) {
		keer.Add(1)
		return nepUitslag(invoer), nil
	})
	ctx := context.Background()
	if _, err := d.uitslagVoor(ctx, "voorbeeld.nl", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if _, _ = d.uitslagVoor(ctx, "voorbeeld.nl", "192.0.2.1"); keer.Load() != 1 {
		t.Errorf("binnen de bewaartijd opnieuw gekeurd (%d)", keer.Load())
	}
	d.mu.Lock()
	b := d.uitslag["voorbeeld.nl"]
	b.tot = time.Now().Add(-time.Second)
	d.uitslag["voorbeeld.nl"] = b
	d.mu.Unlock()
	if d.bewaarde("voorbeeld.nl") != nil {
		t.Error("een verlopen uitslag wordt nog getoond")
	}
	if w := get(d.routes(), "/scan/voorbeeld.nl"); strings.Contains(w.Body.String(), "openbaar gezien") {
		t.Error("het rapport toont een verlopen uitslag")
	}
	if _, _ = d.uitslagVoor(ctx, "voorbeeld.nl", "192.0.2.1"); keer.Load() != 2 {
		t.Errorf("na de bewaartijd niet opnieuw gekeurd (%d)", keer.Load())
	}
}

// /keuring/ stuurt alleen door naar /scan op dezelfde site.
func TestKeuringDoorverwijzing(t *testing.T) {
	h := nepDienst(nil).routes()
	for _, pad := range []string{
		"/keuring/..%2f..%2f%5cevil.com", "/keuring/%5cevil.com", "/keuring//evil.com", "/keuring/https:%2f%2fevil.com",
		"/keuring/%2f%2fevil.com", "/keuring/voorbeeld.nl", "/keuring/..%2f..%2f%2fevil.com", "/keuring/\\evil.com",
	} {
		r := httptest.NewRequest(http.MethodGet, "http://syncurity.nl/", nil)
		r.URL.Path = ""
		u, err := url.Parse(pad)
		if err != nil {
			t.Fatal(err)
		}
		r.URL = u
		r.RequestURI = pad
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		loc := w.Header().Get("Location")
		if w.Code/100 != 3 {
			continue // 404 is ook goed
		}
		doel, err := url.Parse("https://syncurity.nl" + pad)
		if err != nil {
			t.Fatal(err)
		}
		naar, err := doel.Parse(loc)
		if err != nil || naar.Host != "syncurity.nl" || strings.HasPrefix(loc, "//") || strings.HasPrefix(loc, "/\\") || strings.Contains(loc, "\\") {
			t.Errorf("%s stuurt naar %q", pad, loc)
		}
		if !strings.HasPrefix(naar.Path, "/scan") && !strings.HasPrefix(naar.Path, "/keuring") {
			t.Errorf("%s stuurt naar %q", pad, loc)
		}
	}
	if w := get(h, "/keuring/Voorbeeld.NL"); w.Header().Get("Location") != "/scan/voorbeeld.nl" {
		t.Errorf("gewone doorverwijzing: %q", w.Header().Get("Location"))
	}
}

func TestMethoden(t *testing.T) {
	d := nepDienst(func(_ context.Context, invoer string, _ keuring.Instellingen) (*keuring.Uitslag, error) {
		return nepUitslag(invoer), nil
	})
	h := d.routes()
	for _, g := range []struct {
		methode, pad string
		code         int
	}{
		{http.MethodGet, "/scan", 200}, {http.MethodHead, "/scan", 200}, {http.MethodPut, "/scan", 405},
		{http.MethodDelete, "/scan", 405}, {http.MethodPost, "/scan/voorbeeld.nl", 405}, {http.MethodGet, "/intern/txt", 404},
		{http.MethodPost, "/intern/volledig", 404}, {http.MethodGet, "/intern/", 404},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(g.methode, g.pad, nil))
		if w.Code != g.code {
			t.Errorf("%s %s: %d, wil %d", g.methode, g.pad, w.Code, g.code)
		}
		if w.Code == 405 && w.Header().Get("Allow") == "" {
			t.Errorf("%s %s: 405 zonder Allow", g.methode, g.pad)
		}
	}
	// Een formulier van een andere site: 403, en er wordt niets gekeurd.
	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader("domein=voorbeeld.nl"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || d.bewaarde("voorbeeld.nl") != nil {
		t.Errorf("cross-site: %d", w.Code)
	}
	// GET op een rapport start nooit een keuring.
	if get(h, "/scan/ander.nl"); d.bewaarde("ander.nl") != nil {
		t.Error("een GET startte een keuring")
	}
}

// Wat een site aanlevert, komt geëscaped in de HTML.
func TestEscaping(t *testing.T) {
	kwaad := `"><script>alert(1)</script><img src=x onerror=alert(2)>`
	d := nepDienst(func(_ context.Context, invoer string, _ keuring.Instellingen) (*keuring.Uitslag, error) {
		u := nepUitslag(invoer)
		u.Groepen[0].Punten[0].Titel = kwaad
		u.Groepen[0].Punten[0].Gezien = kwaad
		u.Groepen[0].Punten[0].Uitleg = kwaad
		u.Feiten[0].Waarde = kwaad
		u.Melding = kwaad
		u.Eerst = u.Groepen[0].Punten
		return u, nil
	})
	h := d.routes()
	postScan(h, "voorbeeld.nl", "192.0.2.1")
	body := get(h, "/scan/voorbeeld.nl").Body.String()
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("de kwaadaardige tekst staat niet (geëscaped) in de pagina")
	}
	if strings.Contains(body, "<script>alert") || strings.Contains(body, "<img src=x") {
		t.Error("ongeëscapete HTML uit de uitslag in de pagina")
	}
}

// ---------------------------------------------------------------- interne API

const goedToken = "abcdefghijklmnopqrstuv"

func internDienst(gevonden bool) (*dienst, *atomic.Int32) {
	var keer atomic.Int32
	d := nepDienst(nil)
	d.txt = func(_ context.Context, domein, token string, _ keuring.Instellingen) (bool, string, []string, error) {
		return gevonden && token == goedToken, domein, []string{"v=spf1 -all"}, nil
	}
	d.volledig = func(_ context.Context, domein string, _ keuring.Instellingen) (*keuring.Volledig, error) {
		keer.Add(1)
		return &keuring.Volledig{Uitslag: *nepUitslag(domein), Subdomeinen: []keuring.Subdomein{{Naam: "www." + domein, Status: keuring.Goed}}, SubBron: "crt.sh"}, nil
	}
	return d, &keer
}

func internPost(h http.Handler, pad, soort, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, pad, strings.NewReader(body))
	if soort != "" {
		req.Header.Set("Content-Type", soort)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestInternFouten(t *testing.T) {
	d, keer := internDienst(true)
	h := d.intern()
	js := "application/json"
	for _, g := range []struct {
		naam, pad, soort, body string
		code                   int
	}{
		{"verkeerd token", "/intern/txt", js, `{"domein":"voorbeeld.nl","token":"kort"}`, 400},
		{"token met teken", "/intern/volledig", js, `{"domein":"voorbeeld.nl","token":"abcdefghijklmnopqrstu/"}`, 400},
		{"onbekend veld", "/intern/txt", js, `{"domein":"voorbeeld.nl","token":"` + goedToken + `","x":1}`, 400},
		{"twee objecten", "/intern/txt", js, `{"domein":"voorbeeld.nl","token":"` + goedToken + `"}{}`, 400},
		{"ongeldig domein", "/intern/volledig", js, `{"domein":"192.168.1.1","token":"` + goedToken + `"}`, 400},
		{"geen json", "/intern/txt", "text/plain", `{"domein":"voorbeeld.nl","token":"` + goedToken + `"}`, 415},
		{"te groot", "/intern/volledig", js, `{"domein":"voorbeeld.nl","token":"` + goedToken + `","x":"` + strings.Repeat("a", 5000) + `"}`, 413},
		{"onbekend pad", "/intern/iets", js, `{}`, 404},
	} {
		if w := internPost(h, g.pad, g.soort, g.body); w.Code != g.code {
			t.Errorf("%s: %d, wil %d (%s)", g.naam, w.Code, g.code, w.Body)
		}
	}
	for _, pad := range []string{"/intern/txt", "/intern/volledig"} {
		w := get(h, pad)
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "POST" {
			t.Errorf("GET %s: %d", pad, w.Code)
		}
	}
	if keer.Load() != 0 {
		t.Error("een fout verzoek startte een volledige keuring")
	}
}

func TestInternVerificatie(t *testing.T) {
	d, keer := internDienst(false)
	w := internPost(d.intern(), "/intern/volledig", "application/json", `{"domein":"voorbeeld.nl","token":"`+goedToken+`"}`)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `"fout":"verificatie"`) || keer.Load() != 0 {
		t.Errorf("zonder record: %d %s, %d keuringen", w.Code, w.Body, keer.Load())
	}
	w = internPost(d.intern(), "/intern/txt", "application/json", `{"domein":"https://www.Voorbeeld.nl/x","token":"`+goedToken+`"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"gevonden":false`) || !strings.Contains(w.Body.String(), `"gezien":["v=spf1 -all"]`) {
		t.Errorf("txt niet gevonden: %d %s", w.Code, w.Body)
	}
}

func TestInternVolledig(t *testing.T) {
	d, keer := internDienst(true)
	h := d.intern()
	w := internPost(h, "/intern/txt", "application/json; charset=utf-8", `{"domein":"www.voorbeeld.nl","token":"`+goedToken+`"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"gevonden":true,"waar":"voorbeeld.nl"`) {
		t.Errorf("txt: %d %s", w.Code, w.Body)
	}
	w = internPost(h, "/intern/volledig", "application/json", `{"domein":"voorbeeld.nl","token":"`+goedToken+`"}`)
	body := w.Body.String()
	if w.Code != 200 || keer.Load() != 1 || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("volledig: %d %s", w.Code, body)
	}
	// Hier horen de details wél in.
	for _, wil := range []string{`"domein":"voorbeeld.nl"`, `"detail":["GEHEIM-DETAIL"]`, `"voorstel":"GEHEIM-VOORSTEL"`, `"subdomeinen":[{"naam":"www.voorbeeld.nl"`, `"sub_bron":"crt.sh"`} {
		if !strings.Contains(body, wil) {
			t.Errorf("antwoord mist %s", wil)
		}
	}
	// Hooguit twee tegelijk.
	d.volPlekken <- struct{}{}
	d.volPlekken <- struct{}{}
	if w := internPost(h, "/intern/volledig", "application/json", `{"domein":"voorbeeld.nl","token":"`+goedToken+`"}`); w.Code != http.StatusServiceUnavailable {
		t.Errorf("derde tegelijk: %d", w.Code)
	}
}
