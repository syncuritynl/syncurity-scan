package keuring

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Lettertypen, verkleinen en vooraf verbinden. Alles uit wat de scan toch al
// heeft: de homepage en het eerste eigen stylesheet (haalStijl). PageSpeed
// meet dit in een browser; wij lezen alleen de bestanden en schatten.

var (
	fontFaceRe    = regexp.MustCompile(`(?is)@font-face\s*\{([^}]*)\}`)
	fontDisplayRe = regexp.MustCompile(`(?i)font-display\s*:\s*(?:swap|optional|fallback)\b`)
	fontFamilieRe = regexp.MustCompile(`(?i)font-family\s*:\s*['"]?([^;'"}]+)`)
	cssURLRe      = regexp.MustCompile(`(?i)url\(\s*['"]?([^'")\s]+)`)
	googleFontsRe = regexp.MustCompile(`(?i)(?:https?:)?//fonts\.googleapis\.com/css2?\?[^'")\s]*`)
)

// googleBestanden: de lettertypebestanden van Google Fonts komen van een
// andere server dan het stylesheet zelf.
const googleBestanden = "https://fonts.gstatic.com"

// paginaAdres: waar de homepage uiteindelijk stond.
func (w *web) paginaAdres() *url.URL {
	if w.pagina != nil && w.pagina.Request != nil && w.pagina.Request.URL != nil {
		return w.pagina.Request.URL
	}
	return &url.URL{Scheme: "https", Host: w.host, Path: "/"}
}

// herkomst geeft scheme://host[:poort] van ref, opgezocht vanaf basis, of ""
// als het geen http(s) is.
func herkomst(basis *url.URL, ref string) string {
	u, err := url.Parse(strings.TrimSpace(ref))
	if err != nil || ref == "" {
		return ""
	}
	u = basis.ResolveReference(u)
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + strings.ToLower(u.Host)
}

type stijlBron struct {
	css   string
	basis *url.URL // waar url(...) in deze CSS vandaan rekent
}

// stijlBronnen: de <style>-blokken van de homepage en het eerste eigen stylesheet.
func (w *web) stijlBronnen() []stijlBron {
	pagina := w.paginaAdres()
	var uit []stijlBron
	for _, b := range w.info.stijlBlokken {
		uit = append(uit, stijlBron{b, pagina})
	}
	if w.stijl != "" {
		basis := pagina
		if u, err := url.Parse(w.stijlAdres); err == nil && u.Host != "" {
			basis = u
		}
		uit = append(uit, stijlBron{w.stijl, basis})
	}
	return uit
}

// webfont is één lettertype dat de pagina zelf laadt.
type webfont struct {
	naam string // font-family, of het adres bij Google Fonts
	goed bool   // font-display swap, optional of fallback
	bron string // herkomst van het bestand, als we die weten
}

func webfonts(w *web) []webfont {
	var uit []webfont
	google := func(adres string) {
		if strings.HasPrefix(adres, "//") {
			adres = "https:" + adres
		}
		u, err := url.Parse(adres)
		if err != nil {
			return
		}
		d := strings.ToLower(u.Query().Get("display"))
		uit = append(uit, webfont{"Google Fonts (" + kort(u.Query().Get("family"), 60) + ")", d == "swap" || d == "optional" || d == "fallback", googleBestanden})
	}
	for _, s := range w.info.stijlen {
		if googleFontsRe.MatchString(s) {
			google(strings.TrimSpace(s))
		}
	}
	for _, b := range w.stijlBronnen() {
		for _, m := range googleFontsRe.FindAllString(b.css, -1) {
			google(m) // @import van Google Fonts
		}
		for _, m := range fontFaceRe.FindAllStringSubmatch(b.css, -1) {
			f := webfont{naam: "onbekend lettertype", goed: fontDisplayRe.MatchString(m[1])}
			if n := fontFamilieRe.FindStringSubmatch(m[1]); n != nil {
				f.naam = strings.TrimSpace(n[1])
			}
			if u := cssURLRe.FindStringSubmatch(m[1]); u != nil && !strings.HasPrefix(u[1], "data:") {
				f.bron = herkomst(b.basis, u[1])
			}
			uit = append(uit, f)
		}
	}
	return uit
}

func snelLettertypen(w *web) Punt {
	const id, tech, titel = "snel-lettertypen", "font-display", "Tekst meteen zichtbaar"
	// Per familie: goed als elke regel ervan font-display heeft.
	goed := map[string]bool{}
	for _, f := range webfonts(w) {
		if v, ok := goed[f.naam]; !ok || v {
			goed[f.naam] = f.goed
		}
	}
	if len(goed) == 0 {
		return punt(id, tech, NVT, titel, "We vonden geen eigen lettertypen (webfonts) op je homepage of in je eerste stylesheet.")
	}
	var zonder []string
	for _, n := range sleutels(goed) {
		if !goed[n] {
			zonder = append(zonder, n)
		}
	}
	if len(zonder) == 0 {
		gezien := "1 lettertype, met font-display"
		if len(goed) > 1 {
			gezien = fmt.Sprintf("%d lettertypen, alle met font-display", len(goed))
		}
		return punt(id, tech, Goed, titel,
			"Zolang je lettertypen nog laden, toont de browser de tekst al in een gewoon lettertype. Bezoekers kunnen meteen lezen.").met(gezien)
	}
	gezien := "1 lettertype zonder font-display: "
	if len(goed) > 1 {
		gezien = fmt.Sprintf("%d van de %d lettertypen zonder font-display: ", len(zonder), len(goed))
	}
	return punt(id, tech, Matig, "Tekst wacht op het lettertype",
		"Een deel van je lettertypen heeft geen font-display. Op een trage verbinding zien bezoekers dan even geen tekst, tot het lettertype binnen is. PageSpeed noemt dit 'Ensure text remains visible during webfont load'.").
		met(gezien + strings.Join(lijstje(zonder, 4), ", ")).
		metDetail(append([]string{"Lettertypen zonder font-display:"}, lijstje(zonder, maxDetail-1)...)...)
}

// Verkleinen. verkleind() schat de grootte na verkleinen; een bestand geldt
// als niet verkleind als dat minstens 2 KiB en 10% scheelt. Een verkleind
// bestand komt met deze schatting onder de 3% uit, gewone CSS met inspringen,
// regeleinden en opmerkingen op 15 tot 30%; 10% zit daar ruim tussen. De
// 2 KiB is dezelfde ondergrens als in PageSpeed: kleinere winst telt niet.
const (
	verkleinMinBytes = 2 << 10
	verkleinMinDeel  = 10 // procent
)

// verkleind schat hoe groot css is na verkleinen: zonder opmerkingen (behalve
// /*! licenties */), witruimte samengevoegd tot één spatie en weg rond
// { } ; : , >, en zonder de laatste ; voor }. Tekst tussen aanhalingstekens
// blijft staan. Een echte minifier haalt nog iets meer weg, dus de winst is
// eerder groter dan kleiner.
func verkleind(css string) int {
	const scheiders = "{};:,>"
	n := 0
	var vorige byte
	spatie := false
	schrijf := func(c byte, lengte int) {
		if spatie && vorige != 0 && !strings.ContainsRune(scheiders, rune(vorige)) && !strings.ContainsRune(scheiders, rune(c)) {
			n++
		}
		if c == '}' && vorige == ';' {
			n--
		}
		spatie = false
		n += lengte
		vorige = c
	}
	for i := 0; i < len(css); i++ {
		c := css[i]
		switch {
		case c == '/' && i+1 < len(css) && css[i+1] == '*':
			eind := strings.Index(css[i+2:], "*/")
			if eind < 0 {
				return n
			}
			if i+2 < len(css) && css[i+2] == '!' {
				schrijf('/', eind+4)
			} else {
				spatie = true
			}
			i += eind + 3
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f':
			spatie = true
		case c == '"' || c == '\'':
			j := i + 1
			for j < len(css) && css[j] != c {
				if css[j] == '\\' {
					j++
				}
				j++
			}
			j = min(j, len(css)-1)
			schrijf(c, j-i+1)
			i = j
		default:
			schrijf(c, 1)
		}
	}
	return n
}

type stijlDeel struct {
	naam      string
	grootte   int
	besparing int
}

func (d stijlDeel) teVerkleinen() bool {
	return d.besparing >= verkleinMinBytes && d.besparing*100 >= d.grootte*verkleinMinDeel
}

func snelVerkleind(w *web) Punt {
	const id, tech, titel = "snel-verkleind", "minify", "Bestanden verkleind"
	var delen []stijlDeel
	if w.stijl != "" {
		delen = append(delen, stijlDeel{naam: leegAls(w.cacheURL, "stylesheet")})
		delen[0].grootte = len(w.stijl)
		delen[0].besparing = len(w.stijl) - verkleind(w.stijl)
	}
	for _, b := range w.info.stijlBlokken {
		if len(b) >= verkleinMinBytes {
			delen = append(delen, stijlDeel{"stijl in de HTML", len(b), len(b) - verkleind(b)})
		}
	}
	if len(delen) == 0 {
		return punt(id, tech, NVT, titel, "We vonden geen stylesheet op je eigen domein om te meten.")
	}
	sort.SliceStable(delen, func(i, j int) bool { return delen[i].besparing > delen[j].besparing })
	var detail []string
	for _, d := range delen {
		detail = append(detail, fmt.Sprintf("%s: %d kB, ongeveer %d kB te besparen", kort(d.naam, 100), d.grootte/1024, d.besparing/1024))
	}
	d := delen[0]
	grootte := fmt.Sprintf("%d kB", d.grootte/1024)
	if w.stijlAf && d.grootte == len(w.stijl) {
		grootte = "meer dan 512 kB"
	}
	if d.teVerkleinen() {
		return punt(id, tech, Matig, "Bestanden niet verkleind",
			"Je stylesheet staat vol spaties, regeleinden en opmerkingen. Het bestand is daardoor groter dan nodig, dus de pagina verschijnt later. PageSpeed noemt dit 'Minify CSS'.").
			met(fmt.Sprintf("%s: %s, ongeveer %d kB te besparen", d.naam, grootte, max(1, d.besparing/1024))).metDetail(detail...)
	}
	return punt(id, tech, Goed, titel, "Je stylesheet is verkleind: zonder overbodige spaties en opmerkingen, dus zo snel mogelijk binnen.").
		met(fmt.Sprintf("%s: %s", d.naam, grootte))
}

// snelVoorverbinden: welke andere servers zijn nodig voor het eerste beeld
// (stylesheets en scripts zonder async/defer in de head, en lettertypen),
// en laat de pagina de browser daar vooraf mee verbinden?
func snelVoorverbinden(w *web) Punt {
	const id, tech, titel = "snel-voorverbinden", "preconnect", "Andere servers op tijd verbonden"
	pagina := w.paginaAdres()
	eigen := herkomst(pagina, "/")
	nodig := map[string]bool{}
	for _, b := range w.info.kritiek {
		if h := herkomst(pagina, b); h != "" && h != eigen {
			nodig[h] = true
		}
	}
	for _, f := range webfonts(w) {
		if f.bron != "" && f.bron != eigen {
			nodig[f.bron] = true
		}
	}
	if len(nodig) == 0 {
		return punt(id, tech, NVT, titel, "Wat nodig is om je pagina te tonen, komt van je eigen server. Er hoeft nergens vooraf verbinding mee gemaakt te worden.")
	}
	vooraf, dns := map[string]bool{}, map[string]bool{}
	for _, b := range w.info.voorverbind {
		vooraf[herkomst(pagina, b)] = true
	}
	for _, b := range w.info.dnsVooraf {
		dns[herkomst(pagina, b)] = true
	}
	var zonder []string
	for _, h := range sleutels(nodig) {
		switch {
		case vooraf[h]:
		case dns[h]:
			zonder = append(zonder, h+" (alleen dns-prefetch)")
		default:
			zonder = append(zonder, h)
		}
	}
	if len(zonder) == 0 {
		return punt(id, tech, Goed, titel,
			"Je pagina laat de browser meteen verbinden met de andere servers die nodig zijn om hem te tonen. Dat scheelt wachttijd.").
			met("Vooraf verbonden: " + strings.Join(lijstje(sleutels(nodig), 5), ", "))
	}
	return punt(id, tech, Matig, "Andere servers niet op tijd verbonden",
		"Je pagina heeft bestanden van andere servers nodig voordat hij iets kan tonen, zoals lettertypen, stylesheets of scripts. De browser maakt pas verbinding als hij ze tegenkomt, en dat kost per server een paar honderd milliseconden. Met preconnect begint hij meteen. PageSpeed noemt dit 'Preconnect to required origins'.").
		met("Niet vooraf verbonden: " + strings.Join(lijstje(zonder, 5), ", ")).metDetail(zonder...)
}
