package keuring

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Lijsten voor verouderde software. Ze zitten in het programma: de scandienst
// haalt zelf niets op. Bijwerken met data-bijwerken.sh (in de hoofdmap),
// daarna opnieuw bouwen. Herkomst: data/HERKOMST.txt.

//go:embed data/wordpress.json
var wordpressJSON []byte

//go:embed data/retire.json
var retireJSON []byte

type wordpressLijst struct {
	Bijgewerkt string            `json:"bijgewerkt"`
	Versies    map[string]string `json:"versies"` // "6.4.2": latest | outdated | insecure
}

type retireLek struct {
	Below        string   `json:"below"`
	AtOrAbove    string   `json:"atOrAbove"`
	Severity     string   `json:"severity"`
	CVE          []string `json:"cve"`
	Samenvatting string   `json:"samenvatting"`
}

type retireBib struct {
	Patronen []string    `json:"patronen"`
	Lekken   []retireLek `json:"lekken"`
	re       []*regexp.Regexp
}

type retireLijst struct {
	Bijgewerkt   string                `json:"bijgewerkt"`
	Bibliotheken map[string]*retireBib `json:"bibliotheken"`
}

var (
	softwareEens sync.Once
	wpLijst      wordpressLijst
	jsLijst      retireLijst
	wpNieuwste   string
)

// versieDeel is de vorm van een versie in de patronen van retire.js (§§version§§).
const versieDeel = `[0-9][0-9.a-z_\-]+`

func laadSoftware() {
	softwareEens.Do(func() {
		_ = json.Unmarshal(wordpressJSON, &wpLijst)
		for v, s := range wpLijst.Versies {
			if s == "latest" {
				wpNieuwste = v
			}
		}
		_ = json.Unmarshal(retireJSON, &jsLijst)
		for _, b := range jsLijst.Bibliotheken {
			for _, p := range b.Patronen {
				p = strings.ReplaceAll(p, "§§version§§", versieDeel)
				if re, err := regexp.Compile("(?i)" + p); err == nil {
					b.re = append(b.re, re)
				}
			}
		}
	})
}

// vergelijkVersie: -1, 0 of 1, zoals strings.Compare, maar per getal
// ("1.10" is nieuwer dan "1.9"). Achtervoegsels als -beta tellen als ouder.
func vergelijkVersie(a, b string) int {
	ad, bd := versieDelen(a), versieDelen(b)
	for i := 0; i < max(len(ad), len(bd)); i++ {
		var x, y int
		if i < len(ad) {
			x = ad[i]
		}
		if i < len(bd) {
			y = bd[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func versieDelen(v string) []int {
	v = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "v")
	if i := strings.IndexAny(v, "-+_ab"); i > 0 {
		v = v[:i]
	}
	var uit []int
	for _, d := range strings.Split(v, ".") {
		n, err := strconv.Atoi(d)
		if err != nil {
			break
		}
		uit = append(uit, n)
	}
	return uit
}

// jsVondst is een bibliotheek met een versie waarvoor lekken bekend zijn.
type jsVondst struct {
	naam, versie, ernst string
	cve                 []string
	samenvatting        string
	lekken              int
}

// bekendeLekken zoekt in de adressen van scripts naar bibliotheken met een
// versie, en geeft die met bekende lekken.
func bekendeLekken(adressen []string) []jsVondst {
	laadSoftware()
	gezien := map[string]bool{}
	var uit []jsVondst
	for _, a := range adressen {
		for naam, b := range jsLijst.Bibliotheken {
			for _, re := range b.re {
				m := re.FindStringSubmatch(a)
				if len(m) < 2 {
					continue
				}
				v := strings.Trim(m[1], ".-_")
				for _, staart := range []string{".js", ".min", ".slim", ".prod", ".production"} {
					v = strings.TrimSuffix(v, staart)
				}
				if gezien[naam+"@"+v] || versieDelen(v) == nil {
					break
				}
				gezien[naam+"@"+v] = true
				vd := jsVondst{naam: naam, versie: v}
				for _, l := range b.Lekken {
					if l.Below != "" && vergelijkVersie(v, l.Below) >= 0 {
						continue
					}
					if l.AtOrAbove != "" && vergelijkVersie(v, l.AtOrAbove) < 0 {
						continue
					}
					vd.lekken++
					if ernstGewicht[l.Severity] > ernstGewicht[vd.ernst] {
						vd.ernst = l.Severity
					}
					if len(vd.cve) < 3 {
						vd.cve = append(vd.cve, l.CVE...)
					}
					if vd.samenvatting == "" {
						vd.samenvatting = l.Samenvatting
					}
				}
				if vd.lekken > 0 {
					uit = append(uit, vd)
				}
				break
			}
		}
	}
	return uit
}

var ernstGewicht = map[string]int{"": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// Versies van PHP en het einde van hun ondersteuning (php.net/supported-versions).
// Daarna komen er ook geen beveiligingsupdates meer.
var phpEinde = map[string]string{
	"8.1": "2025-12-31", "8.2": "2026-12-31", "8.3": "2027-12-31", "8.4": "2028-12-31", "8.5": "2029-12-31",
}

var phpRe = regexp.MustCompile(`(?i)\bPHP/(\d+)\.(\d+)(?:\.(\d+))?`)

var wpVersieRe = []*regexp.Regexp{
	regexp.MustCompile(`(?i)WordPress\s+(\d+\.\d+(?:\.\d+)?)`),
	regexp.MustCompile(`(?i)/wp-includes/css/[^"'\s]*\?ver=(\d+\.\d+(?:\.\d+)?)`),
	regexp.MustCompile(`(?i)wp-emoji-release\.min\.js\?ver=(\d+\.\d+(?:\.\d+)?)`),
}
