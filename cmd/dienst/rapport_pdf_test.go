package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	"syncurity.nl/keuring/keuring"
)

func voorbeeldUitslag() *keuring.Uitslag {
	return &keuring.Uitslag{
		Domein: "voorbeeld.nl", Tijd: time.Date(2026, 10, 31, 9, 30, 0, 0, amsterdam),
		Feiten: []keuring.Feit{{Naam: "E-mail", Waarde: "Microsoft 365"}},
		Groepen: []keuring.Groep{{ID: "verbinding", Naam: "Je website: de verbinding", Kort: "Verbinding", Samen: "Helemaal in orde.", InOrde: 1, Totaal: 2,
			Punten: []keuring.Punt{
				{ID: "tls13", Titel: "Moderne versleuteling", Status: keuring.Goed, Oordeel: "In orde", Uitleg: "Je website biedt TLS 1.3 aan.", Gezien: "301 → https (Ç ë ü)", Techniek: "TLS 1.3", Meer: "/uitleg/tls/"},
				{ID: "hsts", Titel: "De browser onthoudt https", Status: keuring.Slecht, Oordeel: "Niet in orde", Uitleg: "Geen HSTS (een (haakje) en \\ backslash)."},
			}}},
		Eerst:  []keuring.Punt{{ID: "hsts", Titel: "De browser onthoudt https", Status: keuring.Slecht, Uitleg: "Geen HSTS."}},
		InOrde: 1, Totaal: 2,
	}
}

// De pdf moet een geldige opbouw hebben: kop, xref-tabel met de juiste
// plekken, en de verwijzing naar de xref klopt.
func TestPDFOpbouw(t *testing.T) {
	b := maakPDF(voorbeeldUitslag(), "")
	if !bytes.HasPrefix(b, []byte("%PDF-1.7")) || !bytes.HasSuffix(b, []byte("%%EOF\n")) {
		t.Fatal("geen pdf-kop of -einde")
	}
	m := regexp.MustCompile(`startxref\n(\d+)\n`).FindSubmatch(b)
	if m == nil {
		t.Fatal("geen startxref")
	}
	xref, _ := strconv.Atoi(string(m[1]))
	if !bytes.HasPrefix(b[xref:], []byte("xref\n")) {
		t.Fatalf("startxref %d wijst niet naar de xref", xref)
	}
	for _, r := range regexp.MustCompile(`(\d{10}) 00000 n `).FindAllSubmatch(b, -1) {
		plek, _ := strconv.Atoi(string(r[1]))
		if !regexp.MustCompile(`^\d+ 0 obj\n`).Match(b[plek:]) {
			t.Fatalf("xref-plek %d wijst niet naar een object", plek)
		}
	}
	if n := bytes.Count(b, []byte("/Type /Page ")); n < 2 {
		t.Fatalf("%d pagina's, verwacht minstens 2 (voorblad en onderdelen)", n)
	}
	// Haakjes en backslash zijn ge-escaped, de pijl is vervangen.
	if !bytes.Contains(b, []byte(`\(haakje\)`)) || !bytes.Contains(b, []byte(`\\ backslash`)) || !bytes.Contains(b, []byte("301 -> https")) {
		t.Fatal("tekst niet goed omgezet")
	}
}

func TestPDFRoute(t *testing.T) {
	d := nieuweDienst(keuring.Instellingen{})
	u := voorbeeldUitslag()
	d.uitslag[u.Domein] = bewaard{u: u, tot: time.Now().Add(time.Minute)}
	h := d.routes()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/scan/voorbeeld.nl/pdf", nil))
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/pdf" {
		t.Fatalf("pdf: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="syncurity-scan-voorbeeld.nl-2026-10-31.pdf"` {
		t.Fatalf("Content-Disposition %q", cd)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("pdf mag niet bewaard worden")
	}

	// De rapportpagina linkt naar de pdf.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/scan/voorbeeld.nl", nil))
	if !bytes.Contains(rec.Body.Bytes(), []byte(`href="/scan/voorbeeld.nl/pdf"`)) {
		t.Fatal("rapport zonder link naar de pdf")
	}

	// Geen uitslag (meer): terug naar de pagina, en nooit zelf een scan.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/scan/anders.nl/pdf", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/scan/anders.nl" {
		t.Fatalf("zonder uitslag: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

// Voorbeeld-pdf van een echte uitslag (JSON van cmd/keur -json), alleen met de hand:
// PDF_VOORBEELD=uitslag.json go test -run TestPDFVoorbeeld ./cmd/dienst
func TestPDFVoorbeeld(t *testing.T) {
	pad := os.Getenv("PDF_VOORBEELD")
	if pad == "" {
		t.Skip("PDF_VOORBEELD niet gezet")
	}
	j, err := os.ReadFile(pad)
	if err != nil {
		t.Fatal(err)
	}
	var u keuring.Uitslag
	if err := json.Unmarshal(j, &u); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pad+".pdf", maakPDF(u.Openbaar(), ""), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Onder het rapport staat de versie met een link naar de code, maar alleen
// bij een schone build. Ook met een tag of git describe blijft de link werken.
func TestVersieOnderRapport(t *testing.T) {
	oud := versie
	defer func() { versie = oud }()
	d := nieuweDienst(keuring.Instellingen{})
	u := voorbeeldUitslag()
	d.uitslag[u.Domein] = bewaard{u: u, tot: time.Now().Add(time.Minute)}
	const code = `href="https://github.com/syncuritynl/syncurity-scan/tree/`
	for _, tc := range []struct {
		versie string
		link   string // "" = geen link
	}{
		{"15a2f51", "15a2f51"},
		{"15a2f51c0ffe", "15a2f51c0ffe"},
		{"v1.2.0-3-g15a2f51", "15a2f51"},
		{"v1.2.0", "v1.2.0"},
		{"15a2f51-dirty", ""},
		{"v1.2.0-3-g15a2f51-dirty", ""},
		{"onbekend", ""},
	} {
		versie = tc.versie
		rec := httptest.NewRecorder()
		d.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/scan/voorbeeld.nl", nil))
		body := rec.Body.Bytes()
		if tc.link == "" {
			if bytes.Contains(body, []byte(code)) {
				t.Errorf("versie %q: link onder het rapport, verwacht geen", tc.versie)
			}
			continue
		}
		if !bytes.Contains(body, []byte(code+tc.link+`"`)) {
			t.Errorf("versie %q: geen link naar %s", tc.versie, tc.link)
		}
		if p := maakPDF(u.Openbaar(), ""); !bytes.Contains(p, []byte("versie "+tc.link)) {
			t.Errorf("versie %q: de pdf noemt %s niet", tc.versie, tc.link)
		}
	}
}

// versieVoorLink geeft alleen iets terug dat als commit of nette tag in een
// adres op GitHub past; al het andere geeft "".
func TestVersieVoorLink(t *testing.T) {
	for in, wil := range map[string]string{
		"15a2f51":                                "15a2f51",
		"15a2f51c0ffee15a2f51c0ffee15a2f51c0ffe": "15a2f51c0ffee15a2f51c0ffee15a2f51c0ffe",
		"v1.2.0-3-g15a2f51":                      "15a2f51",
		"v1.2.0-0-g15a2f51":                      "15a2f51", // git describe --long op de tag zelf
		"v1.2-3-gabc1234":                        "abc1234",
		"release-2026-11-12-gabc1234":            "abc1234", // tag met streepjes en cijfers
		"v1.2.0":                                 "v1.2.0",
		"v1":                                     "v1",
		"15a2f51-dirty":                          "",
		"v1.2.0-dirty":                           "",
		"v1.2-3-gabc1234-dirty":                  "",
		"onbekend":                               "",
		"":                                       "",
		"15A2F51":                                "", // git geeft kleine letters
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": "", // te lang
		"15a2f5":                 "", // te kort
		"v1.2.0-3-g15a2f5":       "", // te kort
		"v1.2.0-rc1":             "", // geen nette tag
		"v1.2.0-3-g15a2f51/../x": "", // niets achter de commit
		"v1.2.0/../../x":         "",
		"<script>":               "",
		"15a2f51\n":              "",
	} {
		if g := versieVoorLink(in); g != wil {
			t.Errorf("versieVoorLink(%q) = %q, wil %q", in, g, wil)
		}
	}
}
