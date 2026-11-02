package keuring

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// snelWeb: een pagina met dit stuk head en dit eigen stylesheet, zoals
// haalWeb die zou opleveren voor https://www.voorbeeld.nl/.
func snelWeb(head, stijl string) *web {
	body := "<!doctype html><html><head>" + head + "</head><body><p>Hallo</p></body></html>"
	adres, _ := url.Parse("https://www.voorbeeld.nl/")
	w := &web{host: "voorbeeld.nl", body: []byte(body),
		pagina: &http.Response{StatusCode: 200, Header: http.Header{}, Request: &http.Request{URL: adres}}}
	w.info = ontleed(w.body)
	if stijl != "" {
		w.stijl, w.stijlAdres, w.cacheURL = stijl, "https://www.voorbeeld.nl/css/stijl.css", "/css/stijl.css"
	}
	return w
}

// gewoneCSS: zoals een webbouwer hem schrijft, met inspringen en opmerkingen.
func gewoneCSS(n int) string {
	var b strings.Builder
	b.WriteString("/* Stijl van de site */\n\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, `/* Knop %d */
.knop-%d {
  display: inline-block;
  padding: 0.5rem 1rem;
  color: #ffffff;
  background-color: #1e3a8a;
  border-radius: 4px;
}

.knop-%d:hover,
.knop-%d:focus {
  background-color: #172554;
}

`, i, i, i, i)
	}
	return b.String()
}

// verkleindeCSS: dezelfde regels zoals een minifier ze schrijft.
func verkleindeCSS(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, ".knop-%d{display:inline-block;padding:.5rem 1rem;color:#fff;background-color:#1e3a8a;border-radius:4px}.knop-%d:hover,.knop-%d:focus{background-color:#172554}", i, i, i)
	}
	return b.String()
}

// perRegel: half verkleind, één regel per selector, zoals veel thema's.
func perRegel(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, ".knop-%d{display:inline-block;padding:.5rem 1rem;color:#fff;background-color:#1e3a8a;border-radius:4px}\n.knop-%d:hover,.knop-%d:focus{background-color:#172554}\n", i, i, i)
	}
	return b.String()
}

func TestVerkleindSchatting(t *testing.T) {
	for _, tc := range []struct {
		naam  string
		css   string
		max   int // procent besparing
		min   int
		matig bool
	}{
		{"gewoon", gewoneCSS(80), 100, 15, true},
		{"verkleind", verkleindeCSS(40), 3, 0, false},
		{"per regel", perRegel(40), 3, 0, false},
		{"klein en gewoon", gewoneCSS(3), 100, 15, false}, // onder de 2 KiB winst
	} {
		d := stijlDeel{tc.naam, len(tc.css), len(tc.css) - verkleind(tc.css)}
		deel := d.besparing * 100 / d.grootte
		t.Logf("%s: %d bytes, %d%% te besparen", tc.naam, d.grootte, deel)
		if deel < tc.min || deel > tc.max || d.teVerkleinen() != tc.matig {
			t.Errorf("%s: %d%% te besparen (%d bytes), niet verkleind: %v", tc.naam, deel, d.besparing, d.teVerkleinen())
		}
	}
	// Tekst tussen aanhalingstekens en licenties blijven staan.
	for css, wil := range map[string]int{
		`a { content: "  /* geen opmerking */  "; }`: len(`a{content:"  /* geen opmerking */  "}`),
		"/*! MIT */\na  b { color : red ; }":         len("/*! MIT */ a b{color:red}"),
		"a{x:1}/* weg */\n\n":                        len("a{x:1}"),
		`a{content:"open`:                            len(`a{content:"open`),
	} {
		if n := verkleind(css); n != wil {
			t.Errorf("verkleind(%q) = %d, verwacht %d", css, n, wil)
		}
	}
}

func TestSnelheidNieuw(t *testing.T) {
	const swap = `@font-face { font-family: "Inter"; src: url(/fonts/inter.woff2) format("woff2"); font-display: swap; }`
	const zonder = `@font-face { font-family: 'Merriweather'; src: url("https://cdn.fonts.nl/m.woff2"); }`
	for _, tc := range []struct {
		naam, head, stijl                 string
		letters, verkleind, voorverbinden Status
		gezien                            string // in een van de drie
	}{
		{"kale pagina", `<title>x</title>`, "", NVT, NVT, NVT, ""},
		{"eigen lettertype met swap, verkleind", `<link rel="stylesheet" href="/css/stijl.css">`, swap + verkleindeCSS(40),
			Goed, Goed, NVT, "1 lettertype, met font-display"},
		{"lettertype zonder swap in de head", `<style>` + zonder + `</style>`, "",
			Matig, NVT, Matig, "1 lettertype zonder font-display: Merriweather"},
		{"gewone css", `<link rel="stylesheet" href="/css/stijl.css">`, gewoneCSS(80),
			NVT, Matig, NVT, "/css/stijl.css: 16 kB, ongeveer 3 kB te besparen"},
		{"Google Fonts zonder display", `<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;700">`, "",
			Matig, NVT, Matig, "Niet vooraf verbonden: https://fonts.googleapis.com, https://fonts.gstatic.com"},
		{"Google Fonts met display en preconnect", `<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter&amp;display=swap">`, "",
			Goed, NVT, Goed, "Vooraf verbonden: https://fonts.googleapis.com, https://fonts.gstatic.com"},
		{"Google Fonts via @import", `<link rel="stylesheet" href="/css/stijl.css">`, `@import url("https://fonts.googleapis.com/css?family=Lato&display=optional");` + verkleindeCSS(1),
			Goed, Goed, Matig, "Niet vooraf verbonden: https://fonts.gstatic.com"},
		{"script van een andere server, alleen dns-prefetch", `<link rel="dns-prefetch" href="//cdn.ander.nl"><script src="https://cdn.ander.nl/a.js"></script><script async src="https://laat.nl/b.js"></script>`, "",
			NVT, NVT, Matig, "Niet vooraf verbonden: https://cdn.ander.nl (alleen dns-prefetch)"},
		{"preload telt als verbonden", `<link rel="preload" as="font" href="https://cdn.fonts.nl/m.woff2" crossorigin><style>` + zonder + `</style>`, "",
			Matig, NVT, Goed, ""},
		{"eigen subdomein is een andere server", `<link rel="stylesheet" href="https://voorbeeld.nl/a.css"><link rel="stylesheet" href="/b.css">`, "",
			NVT, NVT, Matig, "Niet vooraf verbonden: https://voorbeeld.nl"},
	} {
		w := snelWeb(tc.head, tc.stijl)
		ps := []Punt{snelLettertypen(w), snelVerkleind(w), snelVoorverbinden(w)}
		for i, wil := range []Status{tc.letters, tc.verkleind, tc.voorverbinden} {
			if ps[i].Status != wil {
				t.Errorf("%s: %s %s (%s %q), verwacht %s", tc.naam, ps[i].ID, ps[i].Status, ps[i].Titel, ps[i].Gezien, wil)
			}
		}
		if tc.gezien != "" && ps[0].Gezien != tc.gezien && ps[1].Gezien != tc.gezien && ps[2].Gezien != tc.gezien {
			t.Errorf("%s: gezien %q / %q / %q, verwacht %q", tc.naam, ps[0].Gezien, ps[1].Gezien, ps[2].Gezien, tc.gezien)
		}
	}
}
