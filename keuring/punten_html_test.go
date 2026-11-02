package keuring

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestDoctypeCharset(t *testing.T) {
	for _, tc := range []struct {
		naam, body, contentType string
		wil                     Status
		gezien                  string
	}{
		{"netjes", `<!DOCTYPE html><html><head><meta charset="utf-8"></head></html>`, "text/html", Goed, ""},
		{"kleine letters, opmerking ervoor", "\n<!-- hallo -->\n<!doctype html>\n<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">", "", Goed, ""},
		{"BOM", "\xef\xbb\xbf<!DOCTYPE html><html><head></head></html>", "text/html", Goed, ""},
		{"charset in de kopregel", `<!DOCTYPE html><html><head></head></html>`, "text/html; charset=UTF-8", Goed, ""},
		{"geen doctype", `<html><head><meta charset="utf-8"></head></html>`, "", Matig, "Ontbreekt: <!DOCTYPE html>"},
		{"oud doctype", `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"><html><head><meta charset="utf-8">`, "", Matig, "Ontbreekt: <!DOCTYPE html>"},
		{"charset te laat", "<!DOCTYPE html><html><head><title>x</title>" + strings.Repeat(" ", 1100) + `<meta charset="utf-8">`, "text/html", Matig, "Ontbreekt: tekenset (charset)"},
		{"allebei weg", `<html><head></head></html>`, "text/html", Matig, "Ontbreekt: <!DOCTYPE html> en tekenset (charset)"},
	} {
		w := &web{host: "voorbeeld.nl", body: []byte(tc.body), pagina: &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {tc.contentType}}}}
		if p := doctypeCharset(w); p.Status != tc.wil || p.Gezien != tc.gezien {
			t.Errorf("%s: %s %q, verwacht %s %q", tc.naam, p.Status, p.Gezien, tc.wil, tc.gezien)
		}
	}
}

func TestHreflang(t *testing.T) {
	for _, tc := range []struct {
		naam, links string
		wil         Status
		gezien      string
	}{
		{"geen", ``, NVT, ""},
		{"netjes", `<link rel="alternate" hreflang="nl" href="https://www.voorbeeld.nl/"><link rel="alternate" hreflang="en-GB" href="https://www.voorbeeld.nl/en/"><link rel="alternate" hreflang="x-default" href="https://www.voorbeeld.nl/">`,
			Goed, "3 taalversies: en-GB, nl, x-default"},
		{"zelf via canonical", `<link rel="canonical" href="https://voorbeeld.nl/home"><link rel="alternate" hreflang="nl" href="https://voorbeeld.nl/home/"><link rel="alternate" hreflang="zh-Hant-TW" href="https://voorbeeld.nl/zh/">`,
			Goed, "2 taalversies: nl, zh-Hant-TW"},
		{"en-UK en een kaal pad", `<link rel="alternate" hreflang="nl" href="https://www.voorbeeld.nl/"><link rel="alternate" hreflang="en-UK" href="/en/">`,
			Matig, "ongeldige taalcode: en-UK; geen volledig adres: /en/"},
		{"zonder zichzelf", `<link rel="alternate" hreflang="en" href="https://www.voorbeeld.nl/en/"><link rel="alternate" hreflang="de" href="https://www.voorbeeld.nl/de/">`,
			Matig, "de pagina staat zelf niet in de lijst"},
		{"onzin als taal", `<link rel="alternate" hreflang="nederlands" href="https://www.voorbeeld.nl/"><link rel="alternate" hreflang="" href="https://www.voorbeeld.nl/x/">`,
			Matig, "ongeldige taalcode: (leeg), nederlands"},
	} {
		body := "<!doctype html><html><head>" + tc.links + "</head><body></body></html>"
		adres, _ := url.Parse("https://www.voorbeeld.nl/")
		w := &web{host: "voorbeeld.nl", body: []byte(body), pagina: &http.Response{StatusCode: 200, Header: http.Header{}, Request: &http.Request{URL: adres}}}
		w.info = ontleed(w.body)
		if p := seoHreflang(w); p.Status != tc.wil || p.Gezien != tc.gezien {
			t.Errorf("%s: %s %q, verwacht %s %q", tc.naam, p.Status, p.Gezien, tc.wil, tc.gezien)
		}
	}
}

// Onder de groep snelheid staat dat het een schatting is, met de weg naar een echte meting.
func TestSnelheidIsSchatting(t *testing.T) {
	u := &Uitslag{Groepen: []Groep{{ID: "snelheid", Punten: []Punt{{ID: "snel-ttfb", Status: Goed}}}, {ID: "seo", Punten: []Punt{{ID: "seo-h1", Status: Goed}}}}}
	u.tel()
	if !strings.Contains(u.Groepen[0].Samen, "https://pagespeed.web.dev/") || strings.Contains(u.Groepen[1].Samen, "pagespeed") {
		t.Errorf("samen: %q / %q", u.Groepen[0].Samen, u.Groepen[1].Samen)
	}
}
