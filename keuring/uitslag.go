// Package keuring voert de gratis domeinscan van syncurity.nl uit: ruim honderd
// passieve controles op de website, de e-mail en de domeinnaam. Alles wat hier
// gemeten wordt, kan iedereen op internet ook zien; er wordt niets geprobeerd.
package keuring

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Status is de uitslag van één punt.
type Status string

const (
	Goed   Status = "goed"   // in orde
	Matig  Status = "matig"  // kan beter
	Slecht Status = "slecht" // niet in orde
	NVT    Status = "nvt"    // niet van toepassing, telt niet mee
	Fout   Status = "fout"   // kon niet gemeten worden, telt niet mee
)

// Punt is één controle.
//
// Uitleg en Gezien zijn voor iedereen zichtbaar: Gezien is wat we openbaar
// aantroffen, zoals een SPF-regel of een vervaldatum. Detail staat alleen in
// het volledige rapport, na domeinbewijs: dat zijn de dingen die vooral een
// aanvaller helpen.
type Punt struct {
	ID       string   `json:"id"`
	Titel    string   `json:"titel"`
	Status   Status   `json:"status"`
	Oordeel  string   `json:"oordeel"`
	Uitleg   string   `json:"uitleg"`
	Gezien   string   `json:"gezien,omitempty"`
	Techniek string   `json:"techniek"`
	Meer     string   `json:"meer,omitempty"` // pad van de uitlegpagina
	Detail   []string `json:"detail,omitempty"`

	// Oplossing staat alleen in het volledige rapport, en alleen bij Matig en
	// Slecht. Zie KeurVolledig.
	Oplossing *Oplossing `json:"oplossing,omitempty"`
}

// Oplossing zegt wie iets moet doen en hoe. Wie en Stappen komen uit
// oplossingen.json (vaste tekst, per punt en status); Voorstel, Naam en
// Toelichting rekent de code uit op basis van wat er nu staat.
type Oplossing struct {
	Wie         string   `json:"wie"`                   // "je webbouwer", "wie je e-mail beheert", "wie je domeinnaam beheert", "jijzelf"
	Stappen     []string `json:"stappen"`               // 2 tot 5 korte stappen, B1
	Voorstel    string   `json:"voorstel,omitempty"`    // een kant-en-klaar record of regel; kan meerdere regels hebben
	Naam        string   `json:"naam,omitempty"`        // waar het voorstel komt, bijv. "_dmarc.voorbeeld.nl (TXT)"
	Toelichting string   `json:"toelichting,omitempty"` // één zin bij het voorstel, bijv. waarom eerst p=none
}

// Groep is een van de onderdelen.
type Groep struct {
	ID     string `json:"id"`
	Naam   string `json:"naam"`
	Kort   string `json:"kort"`
	Samen  string `json:"samen"`
	InOrde int    `json:"in_orde"`
	Totaal int    `json:"totaal"`
	Punten []Punt `json:"punten"`
}

// Feit is iets wat we over het domein zagen, zonder oordeel.
type Feit struct {
	Naam   string `json:"naam"`
	Waarde string `json:"waarde"`
}

// Uitslag is de hele scan van één domein.
type Uitslag struct {
	Domein  string        `json:"domein"`
	Tijd    time.Time     `json:"tijd"`
	Duur    time.Duration `json:"duur_ns"`
	Feiten  []Feit        `json:"feiten"`
	Groepen []Groep       `json:"groepen"`
	Eerst   []Punt        `json:"eerst"`
	Melding string        `json:"melding,omitempty"` // één keer bovenaan, bijvoorbeeld als de site de scan weigerde
	InOrde  int           `json:"in_orde"`
	Totaal  int           `json:"totaal"`
}

// Openbaar geeft een diepe kopie zonder Detail en Oplossing: wat iedereen
// mag zien. De publieke scan (/scan) bewaart en toont alleen wat hier
// uitkomt. Een kopie, zodat het origineel heel blijft.
func (u *Uitslag) Openbaar() *Uitslag {
	if u == nil {
		return nil
	}
	o := *u
	o.Feiten = append([]Feit(nil), u.Feiten...)
	o.Groepen = make([]Groep, len(u.Groepen))
	for i, g := range u.Groepen {
		g.Punten = openbarePunten(g.Punten)
		o.Groepen[i] = g
	}
	o.Eerst = openbarePunten(u.Eerst)
	return &o
}

func openbarePunten(ps []Punt) []Punt {
	if ps == nil {
		return nil
	}
	uit := make([]Punt, len(ps))
	for i, p := range ps {
		p.Detail, p.Oplossing = nil, nil
		uit[i] = p
	}
	return uit
}

// Telling geeft het aantal punten in orde en het aantal dat meetelt.
func (g Groep) Telling() (inOrde, totaal int) {
	for _, p := range g.Punten {
		switch p.Status {
		case Goed:
			inOrde++
			totaal++
		case Matig, Slecht:
			totaal++
		}
	}
	return
}

// uitleg koppelt elk punt aan zijn pagina in de kennisbank (/uitleg/<slug>/).
var uitleg = map[string]string{
	"tls-modern": "tls", "tls-oud": "tls", "cipher-zwak": "tls", "http2": "tls",
	"cert": "ssl-certificaat", "cert-sleutel": "ssl-certificaat",
	"https": "https-en-hsts", "hsts": "https-en-hsts",
	"csp": "beveiligingsheaders", "nosniff": "beveiligingsheaders", "frame": "beveiligingsheaders",
	"referrer": "beveiligingsheaders", "versie": "beveiligingsheaders",
	"cookies": "cookies-en-trackers", "trackers": "cookies-en-trackers",
	"mixed": "mixed-content", "securitytxt": "security-txt",
	"dmarc": "dmarc", "dmarc-rua": "dmarc", "spf": "spf", "spf-lookups": "spf", "dkim": "dkim",
	"mta-sts": "mta-sts", "tls-rpt": "mta-sts", "dane": "mta-sts",
	"dnssec": "dnssec", "dnssec-alg": "dnssec", "caa": "caa", "ns": "nameservers",
	"ipv6-web": "ipv6", "ipv6-mail": "ipv6", "ipv6-ns": "ipv6",
	"seo-titel": "vindbaar-in-google", "seo-beschrijving": "vindbaar-in-google", "seo-index": "vindbaar-in-google",
	"seo-canonical": "vindbaar-in-google", "seo-sitemap": "vindbaar-in-google", "seo-h1": "vindbaar-in-google",
	"seo-mobiel": "vindbaar-in-google", "seo-taal": "vindbaar-in-google", "seo-schema": "vindbaar-in-google",
	"seo-delen": "vindbaar-in-google", "seo-alt": "vindbaar-in-google", "seo-www": "vindbaar-in-google",
	"geo-crawlers": "vindbaar-voor-ai", "geo-llms": "vindbaar-voor-ai", "geo-entiteit": "vindbaar-voor-ai",
	"geo-tekst": "vindbaar-voor-ai", "geo-snippet": "vindbaar-voor-ai", "geo-contact": "vindbaar-voor-ai",
	"snel-ttfb": "snelheid", "snel-grootte": "snelheid", "snel-compressie": "snelheid", "snel-cache": "snelheid",
	"snel-blokkerend": "snelheid", "snel-afbeeldingen": "snelheid", "snel-extern": "snelheid",
	"privacy": "privacy-en-kvk", "kvk": "privacy-en-kvk", "toestemming": "privacy-en-kvk",
	// toegevoegd met de tweede reeks punten
	"cert-www": "ssl-certificaat", "tls-adressen": "tls", "dane-web": "ssl-certificaat",
	"software": "verouderde-software", "bibliotheken": "verouderde-software", "php": "verouderde-software", "sri": "verouderde-software",
	"formulieren": "mixed-content",
	"cors":        "beveiligingsheaders", "corp-coop": "beveiligingsheaders", "permissions": "beveiligingsheaders",
	"dmarc-sub": "dmarc", "dmarc-extern": "dmarc", "spf-fouten": "spf", "geen-mail": "spf",
	"mx-geldig": "mta-sts", "mx-dnssec": "mta-sts", "mta-sts-mx": "mta-sts",
	"caa-ca": "caa", "txt-schoon": "spf",
	"seo-hreflang": "vindbaar-in-google", "doctype-charset": "snelheid",
	"seo-robots": "vindbaar-in-google", "seo-links": "vindbaar-in-google", "seo-omleidingen": "vindbaar-in-google",
	"geo-profielen": "vindbaar-voor-ai", "geo-versheid": "vindbaar-voor-ai", "geo-schema": "vindbaar-voor-ai",
	"snel-afmetingen": "snelheid", "snel-eerste": "snelheid", "snel-onderdelen": "snelheid", "snel-gewicht": "snelheid", "snel-overbodig": "snelheid",
	"snel-lettertypen": "snelheid", "snel-verkleind": "snelheid", "snel-voorverbinden": "snelheid",
	"bedrijfsgegevens": "privacy-en-kvk", "voorwaarden": "privacy-en-kvk",
	"vooraf": "cookies-en-trackers", "opname": "cookies-en-trackers", "ingesloten": "cookies-en-trackers",
	"a11y-knoppen": "toegankelijkheid", "a11y-links": "toegankelijkheid", "a11y-labels": "toegankelijkheid", "a11y-zoom": "toegankelijkheid",
	"a11y-overslaan": "toegankelijkheid", "a11y-koppen": "toegankelijkheid", "a11y-frames": "toegankelijkheid", "a11y-overlay": "toegankelijkheid",
	"a11y-verklaring": "toegankelijkheid",
}

// gewicht bepaalt wat bovenaan "Eerst aanpakken" komt: hoe groter het risico
// voor een ondernemer, hoe hoger. Punten die er niet in staan, wegen 1.
var gewicht = map[string]int{
	"dmarc": 10, "spf": 9, "cert": 9, "tls-oud": 8, "cipher-zwak": 8, "https": 8,
	"cookies": 7, "mixed": 7, "dnssec": 6, "spf-lookups": 6, "hsts": 5, "csp": 5,
	"trackers": 5, "mta-sts": 4, "versie": 4, "frame": 4, "nosniff": 3, "caa": 3,
	"seo-index": 9, "toestemming": 7, "geo-crawlers": 6, "geo-tekst": 5, "seo-mobiel": 5,
	"seo-titel": 4, "snel-ttfb": 4, "snel-compressie": 4, "seo-beschrijving": 3,
	"referrer": 1, "ipv6-web": 1, "ipv6-mail": 1, "ipv6-ns": 1,
	"software": 9, "bibliotheken": 7, "php": 7, "cert-www": 7, "tls-adressen": 6, "dane-web": 6, "caa-ca": 8, "mta-sts-mx": 7, "formulieren": 7, "cors": 3,
	"vooraf": 7, "mx-geldig": 6, "geen-mail": 5, "dmarc-sub": 4, "dmarc-extern": 3, "spf-fouten": 4,
	"opname": 5, "ingesloten": 4, "a11y-zoom": 4, "a11y-labels": 4, "a11y-knoppen": 4, "a11y-links": 3,
	"snel-gewicht": 4, "seo-robots": 5, "bedrijfsgegevens": 3,
}

// Groepen waar het om beveiliging gaat. Alleen daar heet een groep met
// meerdere rode punten "het grootste risico"; elders valt er vooral te winnen.
var beveiliging = map[string]bool{"verbinding": true, "instellingen": true, "mail": true, "domein": true}

func (u *Uitslag) tel() {
	u.InOrde, u.Totaal = 0, 0
	var open []Punt
	for i := range u.Groepen {
		g := &u.Groepen[i]
		g.InOrde, g.Totaal = g.Telling()
		u.InOrde += g.InOrde
		u.Totaal += g.Totaal
		g.Samen = samenvatting(g)
		if g.ID == "snelheid" {
			g.Samen += " " + snelheidSchatting
		}
		for j := range g.Punten {
			if s, ok := uitleg[g.Punten[j].ID]; ok {
				g.Punten[j].Meer = "/uitleg/" + s + "/"
			}
		}
		for _, p := range g.Punten {
			if p.Status == Slecht || p.Status == Matig {
				open = append(open, p)
			}
		}
	}
	waarde := func(p Punt) int {
		w := gewicht[p.ID]
		if w == 0 {
			w = 1
		}
		if p.Status == Slecht {
			w += 20
		}
		return w
	}
	sort.SliceStable(open, func(i, j int) bool { return waarde(open[i]) > waarde(open[j]) })
	if len(open) > 3 {
		open = open[:3]
	}
	u.Eerst = open
}

// snelheidSchatting staat onder de groep snelheid: wij lezen de code van de
// pagina, een browser die echt laadt meet nauwkeuriger.
const snelheidSchatting = "Dit is een schatting uit de code van je pagina; meet het echt met PageSpeed Insights (https://pagespeed.web.dev/)."

func samenvatting(g *Groep) string {
	a, b := g.Telling()
	slecht := 0
	for _, p := range g.Punten {
		if p.Status == Slecht {
			slecht++
		}
	}
	switch {
	case b == 0:
		return "Hier viel niets te meten."
	case a == b:
		return "Helemaal in orde."
	case slecht >= 2 && beveiliging[g.ID]:
		return "Hier zit het grootste risico."
	case slecht >= 2:
		return "Hier valt het meeste te winnen."
	case slecht == 1:
		return "Eén ding is niet in orde."
	default:
		return "Grotendeels in orde, het kan nog beter."
	}
}

func oordeel(s Status) string {
	switch s {
	case Goed:
		return "In orde"
	case Matig:
		return "Kan beter"
	case Slecht:
		return "Niet in orde"
	case NVT:
		return "Niet van toepassing"
	default:
		return "Niet te meten"
	}
}

// punt bouwt een Punt en vult het oordeel bij de status.
func punt(id, techniek string, s Status, titel, uitleg string, detail ...string) Punt {
	return Punt{ID: id, Techniek: techniek, Status: s, Oordeel: oordeel(s), Titel: titel, Uitleg: uitleg, Detail: detail}
}

// met zet wat we zagen op een punt (voor iedereen zichtbaar).
// Wat een site zelf aanlevert (titels, kopregels) wordt ingekort en ontdaan
// van stuur- en richtingstekens: anders kan iemand onder onze naam een lap
// tekst naar keuze laten zien.
func (p Punt) met(gezien string) Punt {
	p.Gezien = kort(schoon(gezien), 300)
	return p
}

// maxDetail: zoveel regels Detail per punt, plus eventueel "en nog n".
// Kort houden: het rapport is voor een ondernemer, niet voor een pentester.
const maxDetail = 10

// metDetail zet de details van een punt. Die zijn alleen voor de eigenaar,
// na domeinbewijs (zie Openbaar). Ook hier geldt: wat een site aanlevert,
// wordt ingekort en geschoond.
func (p Punt) metDetail(regels ...string) Punt {
	p.Detail = schoonDetail(regels)
	return p
}

// schoonDetail kort elke regel in, haalt stuurtekens weg, laat lege regels
// weg en houdt hooguit maxDetail regels over.
func schoonDetail(regels []string) []string {
	var uit []string
	for _, r := range regels {
		r = strings.TrimSpace(kort(schoon(r), 200))
		if r == "" {
			continue
		}
		if len(uit) == maxDetail {
			uit = append(uit, "…")
			break
		}
		uit = append(uit, r)
	}
	return uit
}

// lijstje geeft hooguit max items, en een laatste regel "en nog n" als er
// meer zijn.
func lijstje(items []string, max int) []string {
	if len(items) <= max {
		return items
	}
	uit := append([]string(nil), items[:max-1]...)
	return append(uit, fmt.Sprintf("en nog %d", len(items)-max+1))
}

// schoon haalt stuurtekens (Cc) en onzichtbare opmaaktekens (Cf, zoals
// bidi-overrides en zero-width) uit tekst.
func schoon(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			if r == '\n' || r == '\t' {
				return ' '
			}
			return -1
		}
		return r
	}, s)
}
