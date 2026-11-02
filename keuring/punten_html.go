package keuring

import (
	"bytes"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Twee punten over hoe de HTML zich aankondigt: doctype en tekenset, en de
// taalversies (hreflang). Alleen uit de homepage die de scan al ophaalde.

var (
	doctypeRe = regexp.MustCompile(`(?is)^\x{FEFF}?\s*(?:<!--.*?-->\s*)*<!doctype\s+html\s*>`)
	charsetRe = regexp.MustCompile(`(?i)<meta[^>]+charset\s*=`)
)

// doctypeCharset volgt Lighthouse: precies <!DOCTYPE html> (anders kan de
// browser in de oude quirks-modus gaan), en een tekenset in de kopregel,
// met een BOM, of in een <meta> binnen de eerste 1024 bytes.
func doctypeCharset(w *web) Punt {
	const id, tech, titel = "doctype-charset", "<!doctype> · charset", "Pagina goed aangekondigd"
	doctype := doctypeRe.Match(w.body)
	begin := w.body[:min(len(w.body), 1024)]
	charset := charsetRe.Match(begin) || bytes.HasPrefix(begin, []byte{0xEF, 0xBB, 0xBF})
	if w.pagina != nil && strings.Contains(strings.ToLower(w.pagina.Header.Get("Content-Type")), "charset=") {
		charset = true
	}
	var mist, uitleg []string
	if !doctype {
		mist = append(mist, "<!DOCTYPE html>")
		uitleg = append(uitleg, "Bovenaan je pagina staat geen <!DOCTYPE html>. Dan kan de browser je pagina in een oude modus tonen, waarin de opmaak verspringt en per browser verschilt.")
	}
	if !charset {
		mist = append(mist, "tekenset (charset)")
		uitleg = append(uitleg, "Je pagina zegt niet vooraan welke tekenset hij gebruikt. De browser moet dan raden hoe hij letters als é en € leest; soms begint hij opnieuw, of ziet een bezoeker vreemde tekens.")
	}
	if len(mist) == 0 {
		return punt(id, tech, Goed, titel, "Je pagina begint met <!DOCTYPE html> en zegt meteen welke tekenset hij gebruikt. De browser kan hem zonder omwegen tonen.")
	}
	return punt(id, tech, Matig, "Pagina niet goed aangekondigd", strings.Join(uitleg, " ")).met("Ontbreekt: " + strings.Join(mist, " en "))
}

// taalcodeRe: taal (ISO 639), eventueel schrift en land of regio, zoals
// Google hreflang leest: nl, nl-BE, zh-Hant-TW, es-419.
var taalcodeRe = regexp.MustCompile(`(?i)^[a-z]{2,3}(?:-[a-z]{4})?(?:-(?:[a-z]{2}|\d{3}))?$`)

func geldigeTaal(t string) bool {
	l := strings.ToLower(t)
	// en-UK is de bekendste fout: het landnummer van het Verenigd Koninkrijk is GB.
	return l == "x-default" || (taalcodeRe.MatchString(l) && !strings.HasSuffix(l, "-uk"))
}

// zelfdeURL vergelijkt twee adressen zonder #, hoofdletters in de naam en een
// slash aan het eind.
func zelfdeURL(a, b *url.URL) bool {
	n := func(u *url.URL) string {
		return strings.ToLower(u.Scheme+"://"+u.Host) + strings.TrimSuffix(u.EscapedPath(), "/") + "?" + u.RawQuery
	}
	return n(a) == n(b)
}

func seoHreflang(w *web) Punt {
	const id, tech, titel = "seo-hreflang", "hreflang", "Talen goed gekoppeld"
	alt := w.info.hreflang
	if len(alt) == 0 {
		return punt(id, tech, NVT, titel, "Je homepage wijst geen andere taalversies aan. Heb je maar één taal, dan is dat ook niet nodig.")
	}
	pagina := w.paginaAdres()
	var canon *url.URL
	if c, err := url.Parse(strings.TrimSpace(w.info.canonical)); err == nil && c.IsAbs() {
		canon = c
	}
	var talen, fouteCode, nietVolledig []string
	zelf := false
	for _, a := range alt {
		talen = append(talen, a.taal)
		if !geldigeTaal(a.taal) {
			fouteCode = append(fouteCode, leegAls(a.taal, "(leeg)"))
		}
		u, err := url.Parse(a.href)
		if err != nil || !u.IsAbs() || u.Host == "" {
			nietVolledig = append(nietVolledig, leegAls(a.href, "(leeg)"))
			continue
		}
		if zelfdeURL(u, pagina) || (canon != nil && zelfdeURL(u, canon)) {
			zelf = true
		}
	}
	var fout []string
	if len(fouteCode) > 0 {
		fout = append(fout, "ongeldige taalcode: "+strings.Join(lijstje(uniek(fouteCode), 3), ", "))
	}
	if len(nietVolledig) > 0 {
		fout = append(fout, "geen volledig adres: "+strings.Join(lijstje(uniek(nietVolledig), 3), ", "))
	}
	if !zelf {
		fout = append(fout, "de pagina staat zelf niet in de lijst")
	}
	if len(fout) > 0 {
		return punt(id, tech, Matig, "Talen niet goed gekoppeld",
			"Je homepage wijst taalversies aan, maar Google kan ze niet allemaal gebruiken. Dan toont Google bezoekers soms de verkeerde taal, of negeert de koppeling helemaal.").
			met(kort(strings.Join(fout, "; "), 280)).metDetail(fout...)
	}
	return punt(id, tech, Goed, titel,
		"Je homepage wijst zijn taalversies goed aan. Google toont zo iedere bezoeker de versie in de eigen taal.").
		met(fmt.Sprintf("%d taalversies: %s", len(alt), strings.Join(lijstje(uniek(talen), 6), ", ")))
}
