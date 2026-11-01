package keuring

import (
	"encoding/json"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// paginaExtra is wat de latere controles uit de homepage
// halen: toegankelijkheid, privacy, software, snelheid en vertrouwen. Een
// tweede wandeling door dezelfde boom, zodat ontleed() overzichtelijk blijft.
type paginaExtra struct {
	knoppenZonderNaam []string // tekst om de knop te herkennen
	knoppen           int
	linksZonderNaam   []string // href
	links             int
	vaag              []string // linkteksten als "klik hier"
	jsLinks           int      // href="javascript:..."
	veldenZonderLabel []string // naam of id van het veld
	velden            int
	koppen            []int // niveaus in volgorde
	heeftMain         bool
	overslaanLink     bool // een van de eerste links springt naar een anker op de pagina
	iframes           []string
	iframesZonderTit  []string
	formulieren       []string // action
	zonderMaat        []string // img zonder width en height
	eersteLazy        bool     // de eerste afbeelding heeft loading=lazy
	eersteAfbeelding  string
	afbeeldingSrc     []string // de eerste afbeeldingen, voor het gewicht
	knopen            int      // elementen in de pagina
	scripts           []scriptInfo
	inline            string // inhoud van inline scripts, ingekort
	jsonldFout        int    // JSON-LD-blokken die niet te lezen zijn
	org               orgInfo
	sameAs            []string
	profielLinks      []string
	voorwaardenLink   bool
	toegankelijkLink  bool
	winkel            bool
	generator         string
	jaren             []int // jaartallen achter © of copyright
	datumGewijzigd    string
}

type scriptInfo struct {
	src     string
	typ     string
	attrs   map[string]string
	content string // eerste deel van een inline script
}

// orgInfo: of het Organization- of LocalBusiness-blok de basis heeft.
type orgInfo struct {
	gevonden, lokaal      bool
	naam, adres, telefoon bool
	typen                 []string
}

var vageLinkteksten = map[string]bool{
	"klik hier": true, "hier": true, "lees meer": true, "meer": true, "read more": true, "click here": true,
	"meer info": true, "meer informatie": true, "link": true, "verder": true, "verder lezen": true, "bekijk": true,
}

var profielDomeinen = []string{"linkedin.com", "facebook.com", "instagram.com", "x.com", "twitter.com", "youtube.com", "tiktok.com", "pinterest.com", "kvk.nl"}

var winkelTekens = []string{"woocommerce", "/cart", "/winkelwagen", "winkelmandje", "winkelwagen", "add-to-cart", "cdn.shopify.com", "lightspeed", "ccvshop", "mijnwebwinkel", "/checkout", "afrekenen", "in winkelwagen"}

var copyrightRe = regexp.MustCompile(`(?i)(?:©|&copy;|copyright)\s*(?:\d{4}\s*[-–]\s*)?((?:19|20)\d{2})`)

func ontleedExtra(doc *html.Node, body []byte) paginaExtra {
	x := paginaExtra{}
	labelVoor := map[string]bool{}
	type veld struct {
		id, naam string
		gelabeld bool
	}
	var velden []veld
	linkNr := 0
	var inline strings.Builder

	var loop func(n *html.Node, inLabel bool)
	loop = func(n *html.Node, inLabel bool) {
		if n.Type == html.ElementNode {
			x.knopen++
			a := attrs(n)
			switch n.Data {
			case "label":
				if f := a["for"]; f != "" {
					labelVoor[f] = true
				}
				inLabel = true
			case "main":
				x.heeftMain = true
			case "h1", "h2", "h3", "h4", "h5", "h6":
				x.koppen = append(x.koppen, int(n.Data[1]-'0'))
			case "a":
				href := strings.TrimSpace(a["href"])
				if _, ok := a["href"]; ok {
					x.links++
					linkNr++
					naam := toegankelijkeNaam(n, a)
					if naam == "" && strings.ToLower(a["aria-hidden"]) != "true" {
						x.linksZonderNaam = append(x.linksZonderNaam, kort(href, 120))
					}
					if vageLinkteksten[strings.ToLower(strings.Trim(naam, " .!:…>»→"))] {
						x.vaag = append(x.vaag, naam)
					}
					l := strings.ToLower(href)
					if strings.HasPrefix(l, "javascript:") {
						x.jsLinks++
					}
					if linkNr <= 3 && strings.HasPrefix(href, "#") && len(href) > 1 {
						x.overslaanLink = true
					}
					for _, d := range profielDomeinen {
						if strings.Contains(l, "://"+d) || strings.Contains(l, "://www."+d) || strings.Contains(l, "."+d+"/") {
							x.profielLinks = append(x.profielLinks, d)
						}
					}
					tekst := strings.ToLower(naam + " " + l)
					if strings.Contains(tekst, "voorwaarden") || strings.Contains(tekst, "terms") {
						x.voorwaardenLink = true
					}
					if strings.Contains(tekst, "toegankelijkheid") || strings.Contains(tekst, "accessibility") || strings.Contains(tekst, "toegankelijk") {
						x.toegankelijkLink = true
					}
				}
			case "button":
				x.knoppen++
				if toegankelijkeNaam(n, a) == "" {
					x.knoppenZonderNaam = append(x.knoppenZonderNaam, knopHerkenning(a))
				}
			case "input":
				typ := strings.ToLower(a["type"])
				switch typ {
				case "hidden":
				case "submit", "button", "reset":
					x.knoppen++
					if strings.TrimSpace(a["value"]) == "" && a["aria-label"] == "" && a["title"] == "" && typ != "submit" && typ != "reset" {
						x.knoppenZonderNaam = append(x.knoppenZonderNaam, knopHerkenning(a))
					}
				case "image":
					x.knoppen++
					if strings.TrimSpace(a["alt"]) == "" && a["aria-label"] == "" && a["title"] == "" {
						x.knoppenZonderNaam = append(x.knoppenZonderNaam, knopHerkenning(a))
					}
				default:
					velden = append(velden, veld{a["id"], leegAls(a["name"], leegAls(a["id"], typ)), inLabel || a["aria-label"] != "" || a["aria-labelledby"] != "" || a["title"] != ""})
				}
			case "select", "textarea":
				velden = append(velden, veld{a["id"], leegAls(a["name"], leegAls(a["id"], n.Data)), inLabel || a["aria-label"] != "" || a["aria-labelledby"] != "" || a["title"] != ""})
			case "iframe":
				src := a["src"]
				if src == "" {
					src = a["data-src"]
				}
				x.iframes = append(x.iframes, src)
				if strings.TrimSpace(a["title"]) == "" && strings.ToLower(a["aria-hidden"]) != "true" {
					x.iframesZonderTit = append(x.iframesZonderTit, kort(leegAls(src, "(zonder adres)"), 120))
				}
			case "form":
				x.formulieren = append(x.formulieren, strings.TrimSpace(a["action"]))
			case "img":
				src := leegAls(a["src"], a["data-src"])
				if x.eersteAfbeelding == "" {
					x.eersteAfbeelding = src
					x.eersteLazy = strings.ToLower(a["loading"]) == "lazy"
				}
				if len(x.afbeeldingSrc) < 12 && src != "" && !strings.HasPrefix(src, "data:") {
					x.afbeeldingSrc = append(x.afbeeldingSrc, src)
				}
				if a["width"] == "" && a["height"] == "" && !strings.HasPrefix(src, "data:") && !strings.Contains(strings.ToLower(a["style"]), "width") {
					x.zonderMaat = append(x.zonderMaat, kort(src, 120))
				}
			case "meta":
				if strings.EqualFold(a["name"], "generator") && x.generator == "" {
					x.generator = strings.TrimSpace(a["content"])
				}
			case "script":
				typ := strings.ToLower(a["type"])
				if typ == "application/ld+json" {
					leesJSONLD(tekstVan(n), &x)
					break
				}
				s := scriptInfo{src: strings.TrimSpace(a["src"]), typ: typ, attrs: a}
				if s.src == "" {
					t := tekstVan(n)
					s.content = kort(t, 4000)
					if inline.Len() < 128<<10 {
						inline.WriteString(t)
						inline.WriteByte('\n')
					}
				}
				x.scripts = append(x.scripts, s)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			loop(c, inLabel)
		}
	}
	loop(doc, false)

	for _, v := range velden {
		x.velden++
		if !v.gelabeld && !(v.id != "" && labelVoor[v.id]) {
			x.veldenZonderLabel = append(x.veldenZonderLabel, v.naam)
		}
	}
	x.inline = inline.String()
	laag := strings.ToLower(string(body))
	for _, t := range winkelTekens {
		if strings.Contains(laag, t) {
			x.winkel = true
			break
		}
	}
	for _, m := range copyrightRe.FindAllSubmatch(body, -1) {
		var j int
		for _, c := range m[1] {
			j = j*10 + int(c-'0')
		}
		x.jaren = append(x.jaren, j)
	}
	return x
}

// toegankelijkeNaam: wat een schermlezer voorleest voor een link of knop.
// aria-label, aria-labelledby (we kunnen niet zien wat erachter staat, dus
// tellen het als naam), title, de tekst, en alt van afbeeldingen erin.
func toegankelijkeNaam(n *html.Node, a map[string]string) string {
	for _, k := range []string{"aria-label", "aria-labelledby", "title"} {
		if v := strings.TrimSpace(a[k]); v != "" {
			return v
		}
	}
	var b strings.Builder
	var loop func(*html.Node)
	loop = func(n *html.Node) {
		switch n.Type {
		case html.TextNode:
			b.WriteString(n.Data)
		case html.ElementNode:
			ca := attrs(n)
			if strings.ToLower(ca["aria-hidden"]) == "true" {
				return
			}
			switch n.Data {
			case "img":
				b.WriteString(" " + ca["alt"] + " ")
			case "svg":
				// alleen een <title> of aria-label in de svg telt
				if v := ca["aria-label"]; v != "" {
					b.WriteString(" " + v + " ")
					return
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			loop(c)
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		loop(c)
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

func knopHerkenning(a map[string]string) string {
	for _, k := range []string{"id", "class", "name", "src"} {
		if v := strings.TrimSpace(a[k]); v != "" {
			return k + "=\"" + kort(v, 60) + "\""
		}
	}
	return "knop zonder kenmerken"
}

// leesJSONLD telt blokken die niet te lezen zijn en zoekt het
// Organization/LocalBusiness-blok, sameAs en dateModified.
func leesJSONLD(s string, x *paginaExtra) {
	var v any
	if json.Unmarshal([]byte(strings.TrimSpace(s)), &v) != nil {
		x.jsonldFout++
		return
	}
	var loop func(any)
	loop = func(v any) {
		switch o := v.(type) {
		case map[string]any:
			typen := jsonTypen(o["@type"])
			for _, t := range typen {
				if organisatieType(t) {
					x.org.gevonden = true
					x.org.typen = append(x.org.typen, t)
					if lokaalType(t) {
						x.org.lokaal = true
					}
					if _, ok := o["name"]; ok {
						x.org.naam = true
					}
					if _, ok := o["address"]; ok {
						x.org.adres = true
					}
					if _, ok := o["telephone"]; ok {
						x.org.telefoon = true
					}
				}
			}
			switch s := o["sameAs"].(type) {
			case string:
				x.sameAs = append(x.sameAs, s)
			case []any:
				for _, e := range s {
					if t, ok := e.(string); ok {
						x.sameAs = append(x.sameAs, t)
					}
				}
			}
			if d, ok := o["dateModified"].(string); ok && d > x.datumGewijzigd {
				x.datumGewijzigd = d
			}
			for _, w := range o {
				loop(w)
			}
		case []any:
			for _, e := range o {
				loop(e)
			}
		}
	}
	loop(v)
}

func jsonTypen(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var uit []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				uit = append(uit, s)
			}
		}
		return uit
	}
	return nil
}
