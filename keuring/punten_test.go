package keuring

import (
	"net/http"
	"strings"
	"testing"
)

const proefPagina = `<!doctype html><html lang="nl"><head>
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<meta name="generator" content="WordPress 5.2.1">
<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Open+Sans">
<script src="https://code.jquery.com/jquery-1.8.3.min.js"></script>
<script src="https://www.googletagmanager.com/gtag/js?id=G-ABC123"></script>
<script>gtag('config','UA-1234567-1');</script>
<script type="application/ld+json">{"@type":"LocalBusiness","name":"Bakkerij","sameAs":["https://www.linkedin.com/company/x"]}</script>
<script type="application/ld+json">{kapot</script>
</head><body>
<a href="#inhoud">Naar de inhoud</a>
<a href="/"><img src="/logo.png"></a>
<a href="/meer">Klik hier</a><a href="/x">lees meer</a><a href="/y">Hier</a>
<button class="menu"><svg></svg></button>
<form action="http://voorbeeld.nl/verstuur"><input name="email" placeholder="E-mail"><label>Naam <input name="naam"></label></form>
<h1>Brood</h1><h3>Te diep</h3>
<img src="/a.jpg" loading="lazy">
<iframe src="https://www.youtube.com/embed/abc"></iframe>
<script src="https://static.hotjar.com/c/hotjar-1.js"></script>
<p>Bakkerijstraat 1, 1234 AB Utrecht. KvK 12345678. &copy; 2019</p>
</body></html>`

func proefWeb(t *testing.T) *web {
	t.Helper()
	w := &web{host: "voorbeeld.nl", body: []byte(proefPagina), pagina: &http.Response{StatusCode: 200, Header: http.Header{}}}
	w.info = ontleed(w.body)
	return w
}

func TestNieuwePuntenOpProefpagina(t *testing.T) {
	w := proefWeb(t)
	verwacht := map[string]Status{}
	check := func(p Punt, s Status) {
		t.Helper()
		verwacht[p.ID] = s
		if p.Status != s {
			t.Errorf("%s: %s (%s), verwacht %s", p.ID, p.Status, p.Titel, s)
		}
	}
	check(software(w), Slecht)
	check(bibliotheken(w), Matig) // jQuery 1.8.3: ernstigste lek is medium
	check(formulieren(w), Slecht)
	check(sri("voorbeeld.nl", w), Matig)
	check(seoLinks(w), Matig)
	check(geoProfielen(w), Goed)
	check(geoVersheid(w), Matig)
	check(geoSchemaGeldig(w), Slecht)
	check(snelAfmetingen(w), Matig)
	check(snelLCP(w), Goed)         // de eerste afbeelding (het logo) is niet lazy
	check(snelOudeScripts(w), Goed) // G-tag erbij: geen dode Analytics
	check(opname(w), Matig)
	check(ingesloten(w), Matig)
	check(a11yKnoppen(w), Matig)
	check(a11yLinks(w), Matig)
	check(a11yLabels(w), Matig)
	check(a11yZoom(w), Slecht)
	check(a11yOverslaan(w), Goed)
	check(a11yKoppen(w), Matig)
	check(a11yIframes(w), Matig)
	check(a11yOverlay(w), Goed)
	tracker := trackers("voorbeeld.nl", w)
	check(vooraf(w, tracker), Matig)
}

func TestNettePaginaIsInOrde(t *testing.T) {
	body := `<!doctype html><html lang="nl"><head><meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body><main><h1>Welkom</h1><h2>Wat we doen</h2><a href="/diensten">Onze diensten</a>
<button>Zoeken</button><label for="z">Zoek</label><input id="z" name="z"><img src="/a.webp" width="10" height="10" alt="Foto">
<p>&copy; 2026</p></main></body></html>`
	w := &web{host: "voorbeeld.nl", body: []byte(body), pagina: &http.Response{StatusCode: 200, Header: http.Header{}}}
	w.info = ontleed(w.body)
	for _, p := range []Punt{a11yKnoppen(w), a11yLinks(w), a11yLabels(w), a11yZoom(w), a11yOverslaan(w), a11yKoppen(w),
		snelAfmetingen(w), snelLCP(w), geoVersheid(w), seoLinks(w), opname(w), ingesloten(w)} {
		if p.Status != Goed {
			t.Errorf("%s: %s (%s), verwacht goed", p.ID, p.Status, p.Titel)
		}
	}
}

func TestVergelijkVersie(t *testing.T) {
	for _, c := range []struct {
		a, b string
		v    int
	}{{"1.10.0", "1.9.9", 1}, {"3.5", "3.5.0", 0}, {"1.12.4", "3.5.0", -1}, {"2.0.0-beta", "2.0.0", 0}} {
		if g := vergelijkVersie(c.a, c.b); g != c.v {
			t.Errorf("vergelijk(%s, %s) = %d, verwacht %d", c.a, c.b, g, c.v)
		}
	}
}

func TestBekendeLekkenJQuery(t *testing.T) {
	v := bekendeLekken([]string{"https://code.jquery.com/jquery-1.8.3.min.js", "/js/jquery-3.7.1.min.js"})
	if len(v) != 1 || v[0].naam != "jquery" || v[0].versie != "1.8.3" {
		t.Fatalf("bekendeLekken: %+v", v)
	}
}

func TestSPFFouten(t *testing.T) {
	if p := spfFouten("v=spf1 include:spf.protection.outlook.com -all"); p.Status != Goed {
		t.Errorf("nette regel: %s", p.Status)
	}
	if p := spfFouten("v=spf1 ptr -all include:x.nl"); p.Status != Matig || len(p.Detail) != 2 {
		t.Errorf("ptr en iets na all: %s %v", p.Status, p.Detail)
	}
}

func TestStsMX(t *testing.T) {
	mx := []string{"syncurity-nl.mail.protection.outlook.com"}
	if p := stsMX(mx, "enforce", []string{"*.mail.protection.outlook.com"}); p.Status != Goed {
		t.Errorf("wildcard: %s", p.Status)
	}
	if p := stsMX(mx, "enforce", []string{"mx.voorbeeld.nl"}); p.Status != Slecht {
		t.Errorf("mismatch enforce: %s", p.Status)
	}
	if p := stsMX(mx, "enforce", []string{"*.outlook.com"}); p.Status != Slecht {
		t.Errorf("wildcard mag maar één label dekken: %s", p.Status)
	}
}

func TestDmarcSub(t *testing.T) {
	if p := dmarcSub("v.nl", map[string]string{"p": "reject", "sp": "none"}); p.Status != Matig || !strings.Contains(p.Uitleg, "factuur.v.nl") {
		t.Errorf("sp=none: %s %s", p.Status, p.Uitleg)
	}
	if p := dmarcSub("v.nl", map[string]string{"p": "reject"}); p.Status != Goed {
		t.Errorf("zonder sp: %s", p.Status)
	}
}

func TestCatalogusCompleet(t *testing.T) {
	for _, p := range nieuwePunten {
		if uitleg[p.ID] == "" {
			t.Errorf("%s heeft geen uitlegpagina", p.ID)
		}
	}
}

// Een garage met alleen AutoRepair: beide punten moeten hem als bedrijf zien.
// Tot 1-11-2026 zei "Duidelijk wie je bent" hier "Niet vastgelegd", terwijl
// "Gestructureerde gegevens kloppen" twee regels verder AutoRepair vond.
func TestSubtypesVanLocalBusiness(t *testing.T) {
	for _, tc := range []struct {
		jsonld string
		wie    Status // geo-entiteit
		schema Status // geo-schema
	}{
		{`{"@type":"AutoRepair","name":"Garage","address":"Weg 1","telephone":"010"}`, Goed, Goed},
		{`{"@type":"AutoRepair","name":"Garage"}`, Goed, Matig}, // lokaal: adres en telefoon horen erbij
		{`{"@type":"https://schema.org/Dentist","name":"Tandarts","address":"x","telephone":"y"}`, Goed, Goed},
		{`{"@graph":[{"@type":"WebSite"},{"@type":["Notary"],"name":"Notaris","address":"x","telephone":"y"}]}`, Goed, Goed},
		{`{"@type":"OnlineStore","name":"Webwinkel"}`, Goed, Goed}, // geen LocalBusiness: geen adres nodig
		{`{"@type":"NGO","name":"Stichting"}`, Goed, Goed},
		{`{"@type":"Person","name":"Jan"}`, Goed, NVT},
		{`{"@type":"WebSite","name":"Site"}`, Matig, NVT},
		{`{"@type":"Service","name":"Taxi"}`, Matig, NVT}, // een dienst is geen organisatie
	} {
		body := `<!doctype html><html><head><script type="application/ld+json">` + tc.jsonld + `</script></head><body></body></html>`
		w := &web{host: "voorbeeld.nl", body: []byte(body), pagina: &http.Response{StatusCode: 200, Header: http.Header{}}}
		w.info = ontleed(w.body)
		if p := geoEntiteit(w); p.Status != tc.wie {
			t.Errorf("%s: geo-entiteit %s (%s), verwacht %s", tc.jsonld, p.Status, p.Titel, tc.wie)
		}
		if p := geoSchemaGeldig(w); p.Status != tc.schema {
			t.Errorf("%s: geo-schema %s (%s), verwacht %s", tc.jsonld, p.Status, p.Titel, tc.schema)
		}
	}
}

func TestOrganisatieType(t *testing.T) {
	for typ, wil := range map[string]bool{
		"AutoRepair": true, "autorepair": true, "https://schema.org/Hotel": true, "schema:Plumber": true,
		"Organization": true, "Corporation": true, "MedicalClinic": true, "SportsClub": true,
		"WebSite": false, "Service": false, "Person": false, "Product": false, "": false,
	} {
		if organisatieType(typ) != wil {
			t.Errorf("organisatieType(%q) = %v, verwacht %v", typ, !wil, wil)
		}
	}
}

// Alleen een echte verklaring telt. Tot 1-11-2026 was elke link met
// "toegankelijk" genoeg, ook de uitlegpagina op syncurity.nl zelf.
func TestVerklaringLink(t *testing.T) {
	for _, tc := range []struct {
		naam, href string
		wil        bool
	}{
		{"Toegankelijkheid", "/toegankelijkheid/", true},
		{"Toegankelijkheidsverklaring", "https://www.toegankelijkheidsverklaring.nl/register/123", true},
		{"Over deze site", "/over/toegankelijkheidsverklaring", true},
		{"Accessibility", "/en/accessibility", true},
		{"Accessibility statement", "/about/accessibility", true},
		{"Toegankelijkheid", "/toegankelijkheid.html", true},
		{"Toegankelijkheidsverklaring", "/uitleg/toegankelijkheid/", false}, // syncurity.nl: uitleg, geen verklaring
		{"Toegankelijke fietsen", "/producten/toegankelijke-fietsen", false},
		{"Waarom toegankelijkheid telt", "/blog/toegankelijkheid", false},
		{"Rolstoeltoegankelijk", "/locatie", false},
		{"Meer", "/over/toegankelijkheid-van-ons-pand", false},
	} {
		if got := verklaringLink(tc.naam, tc.href); got != tc.wil {
			t.Errorf("verklaringLink(%q, %q) = %v, verwacht %v", tc.naam, tc.href, got, tc.wil)
		}
	}
}
