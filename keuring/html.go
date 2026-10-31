package keuring

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// pagina is wat we uit de HTML van de homepage halen. Eén keer ontleden; de
// controles voor vindbaarheid, AI, snelheid en vertrouwen lezen alleen.
type paginaInfo struct {
	geldig       bool
	lang         string
	titel        string
	beschrijving string
	canonical    string
	robots       string // meta robots, kleine letters
	viewport     string
	h1           int
	ogTitel      bool
	ogAfbeelding bool
	schemaTypen  []string // uit JSON-LD en microdata
	afbeeldingen int
	zonderAlt    int
	zonderAltSrc []string // de eerste afbeeldingen zonder alt, voor het volledige rapport
	lazy         int
	modern       int      // webp, avif of <picture>/<source type=image/...>
	blokkerendJS int      // <script src> in de head zonder async/defer/module
	blokkerend   []string // de eerste daarvan
	stijlbladen  int      // <link rel=stylesheet> in de head
	scripts      int
	woorden      int
	mailto, tel  bool
	privacyLink  bool
	tekst        string // zichtbare tekst, ingekort
	bronnen      []string
	eersteStijl  string      // eerste stylesheet of script op hetzelfde domein
	x            paginaExtra // toegankelijkheid, privacy, software (html_extra.go)
}

var woordRe = regexp.MustCompile(`[\p{L}\p{N}]{2,}`)

func ontleed(body []byte) paginaInfo {
	p := paginaInfo{}
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil || len(body) == 0 {
		return p
	}
	p.geldig = true
	var zicht strings.Builder
	var loop func(n *html.Node, inHead, verborgen bool)
	loop = func(n *html.Node, inHead, verborgen bool) {
		if n.Type == html.ElementNode {
			a := attrs(n)
			switch n.Data {
			case "html":
				p.lang = a["lang"]
			case "head":
				inHead = true
			case "title":
				if n.FirstChild != nil && p.titel == "" {
					p.titel = strings.TrimSpace(tekstVan(n))
				}
			case "meta":
				naam := strings.ToLower(a["name"])
				prop := strings.ToLower(a["property"])
				switch {
				case naam == "description":
					p.beschrijving = strings.TrimSpace(a["content"])
				case naam == "robots" || naam == "googlebot":
					p.robots += strings.ToLower(a["content"]) + ","
				case naam == "viewport":
					p.viewport = strings.ToLower(a["content"])
				case prop == "og:title":
					p.ogTitel = true
				case prop == "og:image":
					p.ogAfbeelding = true
				}
			case "link":
				rel := strings.ToLower(a["rel"])
				if strings.Contains(rel, "canonical") {
					p.canonical = a["href"]
				}
				if strings.Contains(rel, "stylesheet") {
					if inHead && a["media"] != "print" {
						p.stijlbladen++
					}
					p.bronnen = append(p.bronnen, a["href"])
					if p.eersteStijl == "" {
						p.eersteStijl = a["href"]
					}
				}
			case "script":
				verborgen = true
				typ := strings.ToLower(a["type"])
				if typ == "application/ld+json" {
					p.schemaTypen = append(p.schemaTypen, jsonldTypen(tekstVan(n))...)
					break
				}
				if src := a["src"]; src != "" {
					p.scripts++
					p.bronnen = append(p.bronnen, src)
					_, async := a["async"]
					_, defer_ := a["defer"]
					if inHead && !async && !defer_ && typ != "module" {
						p.blokkerendJS++
						if len(p.blokkerend) < maxDetail {
							p.blokkerend = append(p.blokkerend, kort(src, 160))
						}
					}
				}
			case "style", "noscript", "template", "svg":
				verborgen = true
			case "h1":
				p.h1++
			case "img":
				p.afbeeldingen++
				if _, ok := a["alt"]; !ok {
					p.zonderAlt++
					if len(p.zonderAltSrc) < maxDetail {
						p.zonderAltSrc = append(p.zonderAltSrc, kort(leegAls(a["src"], a["data-src"]), 160))
					}
				}
				if strings.ToLower(a["loading"]) == "lazy" {
					p.lazy++
				}
				src := strings.ToLower(a["src"] + " " + a["srcset"])
				if strings.Contains(src, ".webp") || strings.Contains(src, ".avif") {
					p.modern++
				}
			case "source":
				if t := strings.ToLower(a["type"]); t == "image/webp" || t == "image/avif" {
					p.modern++
				}
			case "a":
				href := strings.ToLower(strings.TrimSpace(a["href"]))
				switch {
				case strings.HasPrefix(href, "mailto:"):
					p.mailto = true
				case strings.HasPrefix(href, "tel:"):
					p.tel = true
				}
				if strings.Contains(href, "privacy") || strings.Contains(href, "gegevensbescherming") {
					p.privacyLink = true
				}
			}
			if it := a["itemtype"]; it != "" {
				for _, t := range strings.Fields(it) {
					p.schemaTypen = append(p.schemaTypen, t[strings.LastIndex(t, "/")+1:])
				}
			}
		}
		if n.Type == html.TextNode && !verborgen && !inHead {
			zicht.WriteString(n.Data)
			zicht.WriteByte(' ')
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			loop(c, inHead, verborgen)
		}
	}
	loop(doc, false, false)
	p.x = ontleedExtra(doc, body)
	t := strings.Join(strings.Fields(zicht.String()), " ")
	p.woorden = len(woordRe.FindAllString(t, -1))
	p.tekst = kort(t, 60000)
	return p
}

func attrs(n *html.Node) map[string]string {
	m := map[string]string{}
	for _, a := range n.Attr {
		m[strings.ToLower(a.Key)] = a.Val
	}
	return m
}

func tekstVan(n *html.Node) string {
	var b strings.Builder
	var loop func(*html.Node)
	loop = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			loop(c)
		}
	}
	loop(n)
	return b.String()
}

// jsonldTypen haalt alle @type-waarden uit een JSON-LD-blok, ook uit @graph.
func jsonldTypen(s string) []string {
	var v any
	if json.Unmarshal([]byte(s), &v) != nil {
		return nil
	}
	var uit []string
	var loop func(any)
	loop = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			switch t := x["@type"].(type) {
			case string:
				uit = append(uit, t)
			case []any:
				for _, e := range t {
					if s, ok := e.(string); ok {
						uit = append(uit, s)
					}
				}
			}
			for _, w := range x {
				loop(w)
			}
		case []any:
			for _, e := range x {
				loop(e)
			}
		}
	}
	loop(v)
	return uit
}
