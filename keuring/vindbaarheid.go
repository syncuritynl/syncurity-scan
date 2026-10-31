package keuring

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Vindbaarheid, AI, snelheid en vertrouwen. Allemaal uit wat de scan toch al
// ophaalt: de homepage, robots.txt, de sitemap en llms.txt (zie haalVindbaarheid).

func geenPagina(w *web) (Status, string) {
	switch {
	case w.host == "":
		return NVT, geenWebsite
	case w.weg != "":
		return Fout, "Niet te meten: je homepage stuurt door naar een ander domein."
	case w.geweigerd != 0:
		return Fout, "Niet te meten: je website liet onze scan niet binnen."
	default:
		return Fout, "We konden je homepage niet ophalen om dit te meten."
	}
}

func leeg(id, tech, titel string, w *web) Punt {
	s, r := geenPagina(w)
	return punt(id, tech, s, titel, r)
}

// ---------------------------------------------------------------- Google

func (k *keurder) seo(w *web) Groep {
	g := Groep{ID: "seo", Naam: "Vindbaar in Google", Kort: "Vindbaar in Google"}
	if !w.info.geldig {
		for _, p := range [][3]string{
			{"seo-titel", "<title>", "Paginatitel"}, {"seo-beschrijving", "meta description", "Beschrijving in Google"},
			{"seo-index", "robots", "Google mag je site tonen"}, {"seo-canonical", "canonical", "Eén vast adres per pagina"},
			{"seo-sitemap", "sitemap.xml", "Sitemap"}, {"seo-h1", "<h1>", "Duidelijke hoofdkop"},
			{"seo-mobiel", "viewport", "Geschikt voor mobiel"}, {"seo-taal", "lang", "Taal aangegeven"},
			{"seo-schema", "schema.org", "Rijke zoekresultaten"}, {"seo-delen", "Open Graph", "Mooi gedeeld op sociale media"},
			{"seo-alt", "alt", "Afbeeldingen beschreven"}, {"seo-www", "www", "Eén voorkeursadres"},
		} {
			g.Punten = append(g.Punten, leeg(p[0], p[1], p[2], w))
		}
		g.Punten = append(g.Punten, leegNieuw("seo", w)...)
		return g
	}
	g.Punten = []Punt{seoTitel(w), seoBeschrijving(w), seoIndex(w), seoCanonical(w), seoSitemap(w), seoH1(w),
		seoMobiel(w), seoTaal(w), seoSchema(w), seoDelen(w), seoAlt(w), k.seoWWW(w),
		seoRobots(w), seoLinks(w), seoOmleidingen(w)}
	return g
}

func seoTitel(w *web) Punt {
	t := w.info.titel
	n := utf8.RuneCountInString(t)
	switch {
	case n == 0:
		return punt("seo-titel", "<title>", Slecht, "Je homepage heeft geen titel",
			"Google laat de titel zien als blauwe kop in de zoekresultaten. Zonder titel verzint Google er zelf een, of sta je lager.")
	case n < 15:
		return punt("seo-titel", "<title>", Matig, "De paginatitel is erg kort",
			"De titel is de blauwe kop in Google. Een paar woorden meer over wat je doet en waar, helpt mensen je te vinden.").met(t)
	case n > 65:
		return punt("seo-titel", "<title>", Matig, "De paginatitel is te lang",
			fmt.Sprintf("Google laat ongeveer 60 tekens zien; je titel heeft er %d en wordt dus afgekapt.", n)).met(kort(t, 120))
	default:
		return punt("seo-titel", "<title>", Goed, "Goede paginatitel",
			"Je homepage heeft een titel van een goede lengte, die Google als kop in de zoekresultaten kan tonen.").met(t)
	}
}

func seoBeschrijving(w *web) Punt {
	b := w.info.beschrijving
	n := utf8.RuneCountInString(b)
	switch {
	case n == 0:
		return punt("seo-beschrijving", "meta description", Matig, "Geen beschrijving voor Google",
			"Er staat geen korte beschrijving van je site. Google pakt dan zelf een stuk tekst, en dat is vaak niet het stuk dat mensen overhaalt om te klikken.")
	case n < 50:
		return punt("seo-beschrijving", "meta description", Matig, "De beschrijving is erg kort",
			"De beschrijving staat onder je titel in Google. Gebruik die ruimte om in één of twee zinnen te vertellen wat je doet.").met(b)
	case n > 165:
		return punt("seo-beschrijving", "meta description", Matig, "De beschrijving is te lang",
			fmt.Sprintf("Google toont ongeveer 155 tekens; je beschrijving heeft er %d en wordt afgekapt.", n)).met(kort(b, 200))
	default:
		return punt("seo-beschrijving", "meta description", Goed, "Goede beschrijving voor Google",
			"Er staat een beschrijving van een goede lengte, die Google onder je titel kan laten zien.").met(b)
	}
}

// robotsGroep geeft de regels uit robots.txt die gelden voor een crawler.
func robotsGroep(robots, agent string) (regels []string, gevonden bool) {
	agent = strings.ToLower(agent)
	var huidig []string
	var groepen [][2][]string // [agents, regels]
	nieuweGroep := true
	for _, r := range strings.Split(robots, "\n") {
		if i := strings.Index(r, "#"); i >= 0 {
			r = r[:i]
		}
		kv := strings.SplitN(strings.TrimSpace(r), ":", 2)
		if len(kv) != 2 {
			continue
		}
		sleutel, waarde := strings.ToLower(strings.TrimSpace(kv[0])), strings.TrimSpace(kv[1])
		if sleutel == "user-agent" {
			if nieuweGroep || len(groepen) == 0 {
				groepen = append(groepen, [2][]string{})
				nieuweGroep = false
			}
			groepen[len(groepen)-1][0] = append(groepen[len(groepen)-1][0], strings.ToLower(waarde))
			continue
		}
		nieuweGroep = true
		if len(groepen) > 0 && (sleutel == "allow" || sleutel == "disallow") {
			groepen[len(groepen)-1][1] = append(groepen[len(groepen)-1][1], sleutel+":"+waarde)
		}
	}
	for _, g := range groepen {
		for _, a := range g[0] {
			if a == agent {
				return g[1], true
			}
		}
	}
	for _, g := range groepen {
		for _, a := range g[0] {
			if a == "*" {
				huidig = g[1]
			}
		}
	}
	return huidig, false
}

// geblokkeerd zegt of de regels de hele site afsluiten.
func geblokkeerd(regels []string) bool {
	dicht := false
	for _, r := range regels {
		switch r {
		case "disallow:/", "disallow:/*":
			dicht = true
		case "allow:/", "allow:/*":
			return false
		}
	}
	return dicht
}

func normRegels(regels []string) []string {
	uit := make([]string, len(regels))
	for i, r := range regels {
		uit[i] = strings.ToLower(strings.ReplaceAll(r, " ", ""))
	}
	return uit
}

func seoIndex(w *web) Punt {
	meta := w.info.robots
	kop := strings.ToLower(w.kop("X-Robots-Tag"))
	regels, _ := robotsGroep(w.robots, "googlebot")
	switch {
	case strings.Contains(meta, "noindex") || strings.Contains(kop, "noindex"):
		return punt("seo-index", "robots", Slecht, "Google mag je homepage niet tonen",
			"Je homepage vraagt zoekmachines om hem niet op te nemen (noindex). Dan ben je in Google niet te vinden. Staat dat er nog van tijdens het bouwen?").met("robots: " + strings.Trim(meta+kop, ","))
	case geblokkeerd(normRegels(regels)):
		return punt("seo-index", "robots", Slecht, "Je robots.txt sluit Google buiten",
			"Je robots.txt verbiedt zoekmachines je site te lezen. Daardoor raak je je plek in Google kwijt.").met("Disallow: /")
	default:
		return punt("seo-index", "robots", Goed, "Google mag je site tonen",
			"Niets houdt zoekmachines tegen om je homepage op te nemen.")
	}
}

func seoCanonical(w *web) Punt {
	c := strings.TrimSpace(w.info.canonical)
	if c == "" {
		return punt("seo-canonical", "canonical", Matig, "Geen vast adres opgegeven",
			"Je pagina zegt niet wat zijn vaste adres is. Bereikt Google je site via meerdere adressen (met en zonder www, met extra tekens), dan kan de waardering over die adressen verdeeld raken.")
	}
	u, err := url.Parse(c)
	if err != nil || !u.IsAbs() {
		return punt("seo-canonical", "canonical", Matig, "Het vaste adres is niet volledig",
			"Het vaste adres van je pagina is geen volledig adres met https://. Google raadt een volledig adres aan.").met(c)
	}
	if u.Scheme != "https" {
		return punt("seo-canonical", "canonical", Matig, "Het vaste adres gebruikt http",
			"Het vaste adres van je pagina begint met http://. Daarmee wijs je Google naar de onbeveiligde versie.").met(c)
	}
	return punt("seo-canonical", "canonical", Goed, "Eén vast adres per pagina",
		"Je pagina vertelt Google wat zijn vaste adres is, zodat alle waardering op één plek terechtkomt.").met(c)
}

func seoSitemap(w *web) Punt {
	switch {
	case w.sitemap > 0:
		return punt("seo-sitemap", "sitemap.xml", Goed, "Er is een sitemap",
			"Een sitemap is een lijst van al je pagina's voor zoekmachines. Zo vinden ze ook pagina's die diep in je site zitten.").met(fmt.Sprintf("%d adressen in %s", w.sitemap, w.sitemapURL))
	default:
		return punt("seo-sitemap", "sitemap.xml", Matig, "Geen sitemap gevonden",
			"We vonden geen sitemap: de lijst van al je pagina's die je aan zoekmachines geeft. Zonder sitemap vinden ze nieuwe of diepe pagina's later of niet.")
	}
}

func seoH1(w *web) Punt {
	switch n := w.info.h1; {
	case n == 0:
		return punt("seo-h1", "<h1>", Matig, "Geen hoofdkop op de homepage",
			"Je homepage heeft geen hoofdkop (h1). Die vertelt Google en schermlezers in één zin waar de pagina over gaat.")
	case n > 1:
		return punt("seo-h1", "<h1>", Matig, "Meerdere hoofdkoppen",
			fmt.Sprintf("Je homepage heeft %d hoofdkoppen (h1). Eén duidelijke hoofdkop maakt beter zichtbaar waar de pagina over gaat.", n))
	default:
		return punt("seo-h1", "<h1>", Goed, "Duidelijke hoofdkop",
			"Je homepage heeft precies één hoofdkop.")
	}
}

func seoMobiel(w *web) Punt {
	if strings.Contains(w.info.viewport, "width=device-width") || strings.Contains(w.info.viewport, "initial-scale") {
		return punt("seo-mobiel", "viewport", Goed, "Geschikt voor mobiel",
			"Je pagina past zich aan het scherm van een telefoon aan. Google kijkt eerst naar de mobiele versie.").met("viewport: " + w.info.viewport)
	}
	return punt("seo-mobiel", "viewport", Slecht, "Niet ingericht voor mobiel",
		"Je pagina geeft niet aan dat hij zich aan een telefoonscherm aanpast. Op mobiel moet je dan inzoomen, en Google waardeert je site lager.")
}

func seoTaal(w *web) Punt {
	if l := strings.TrimSpace(w.info.lang); l != "" {
		return punt("seo-taal", "lang", Goed, "Taal aangegeven",
			"Je pagina zegt in welke taal hij is. Dat helpt zoekmachines, vertaalknoppen en voorleessoftware.").met("lang=\"" + l + "\"")
	}
	return punt("seo-taal", "lang", Matig, "Taal niet aangegeven",
		"Je pagina zegt niet in welke taal hij is. Voorleessoftware spreekt hem dan mogelijk in de verkeerde taal uit.")
}

func seoSchema(w *web) Punt {
	t := uniek(w.info.schemaTypen)
	if len(t) == 0 {
		return punt("seo-schema", "schema.org", Matig, "Geen gestructureerde gegevens",
			"Je pagina vertelt zoekmachines niet in hun eigen taal wie je bent: naam, adres, openingstijden, producten. Daarmee kom je in aanmerking voor uitgebreidere zoekresultaten.")
	}
	return punt("seo-schema", "schema.org", Goed, "Gestructureerde gegevens aanwezig",
		"Je pagina vertelt zoekmachines in hun eigen taal wat erop staat. Daarmee kom je in aanmerking voor uitgebreidere zoekresultaten.").met("Gevonden: " + kort(strings.Join(t, ", "), 140))
}

func seoDelen(w *web) Punt {
	switch {
	case w.info.ogTitel && w.info.ogAfbeelding:
		return punt("seo-delen", "Open Graph", Goed, "Mooi gedeeld op sociale media",
			"Deelt iemand je site op WhatsApp, LinkedIn of Facebook, dan verschijnt er een nette titel met een afbeelding.")
	case w.info.ogTitel:
		return punt("seo-delen", "Open Graph", Matig, "Gedeeld zonder afbeelding",
			"Deelt iemand je site op WhatsApp of LinkedIn, dan verschijnt er wel een titel, maar geen afbeelding. Een plaatje valt veel meer op.")
	default:
		return punt("seo-delen", "Open Graph", Matig, "Niet ingericht voor delen",
			"Deelt iemand je site op WhatsApp, LinkedIn of Facebook, dan bepaalt dat programma zelf welke tekst en welk plaatje erbij komen. Vaak is dat niet het mooiste.")
	}
}

func seoAlt(w *web) Punt {
	n, zonder := w.info.afbeeldingen, w.info.zonderAlt
	if n == 0 {
		return punt("seo-alt", "alt", Goed, "Afbeeldingen beschreven", "Je homepage heeft geen losse afbeeldingen die een beschrijving nodig hebben.")
	}
	gezien := fmt.Sprintf("%d van de %d afbeeldingen zonder beschrijving", zonder, n)
	var detail []string
	if zonder > 0 {
		detail = append(detail, "Zonder alt, bijvoorbeeld:")
		detail = append(detail, w.info.zonderAltSrc[:min(len(w.info.zonderAltSrc), maxDetail-2)]...)
		if rest := zonder - min(len(w.info.zonderAltSrc), maxDetail-2); rest > 0 {
			detail = append(detail, fmt.Sprintf("en nog %d", rest))
		}
	}
	switch {
	case zonder == 0:
		return punt("seo-alt", "alt", Goed, "Afbeeldingen beschreven",
			"Al je afbeeldingen hebben een beschrijving. Google begrijpt ze, en blinde bezoekers krijgen ze voorgelezen.").met(gezien)
	case zonder*5 <= n:
		return punt("seo-alt", "alt", Matig, "Een paar afbeeldingen zonder beschrijving",
			"Een paar afbeeldingen hebben geen beschrijving. Google kan ze dan niet plaatsen, en blinde bezoekers missen ze.").met(gezien).metDetail(detail...)
	default:
		return punt("seo-alt", "alt", Slecht, "Veel afbeeldingen zonder beschrijving",
			"Veel afbeeldingen hebben geen beschrijving (alt-tekst). Ze tellen dan niet mee in Google Afbeeldingen, en voor blinde bezoekers is de pagina deels leeg.").met(gezien).metDetail(detail...)
	}
}

func (k *keurder) seoWWW(w *web) Punt {
	gezien := fmt.Sprintf("https://%s/ stuurt naar: %s", w.andere, leegAls(w.andereLoc, "nergens heen"))
	naarHost := zelfdeAdres(w.andereLoc, w.eind)
	switch {
	case w.andereCode == 0:
		if w.andere == "www."+k.domein {
			return punt("seo-www", "www", Matig, "www werkt niet",
				"Wie www. voor je domeinnaam typt, komt nergens uit. Veel mensen typen dat uit gewoonte.").met("https://" + w.andere + "/ geeft geen antwoord")
		}
		return punt("seo-www", "www", Goed, "Eén voorkeursadres",
			"Je site staat op één adres.")
	case naarHost && (w.andereCode == 301 || w.andereCode == 308):
		return punt("seo-www", "www", Goed, "Eén voorkeursadres",
			"Met en zonder www kom je op hetzelfde adres uit, met een permanente doorverwijzing. Zo telt alle waardering voor één adres.").met(gezien)
	case naarHost:
		return punt("seo-www", "www", Matig, "Tijdelijke doorverwijzing",
			fmt.Sprintf("De andere variant stuurt door met een tijdelijke doorverwijzing (%d). Een permanente (301) geeft Google een duidelijker signaal.", w.andereCode)).met(gezien)
	case w.andereCode == 200:
		return punt("seo-www", "www", Matig, "Twee adressen met dezelfde site",
			"Je site staat zowel met als zonder www online. Voor Google zijn dat twee sites met dezelfde inhoud, en dan raakt je waardering verdeeld.").met("https://" + w.andere + "/ geeft dezelfde pagina")
	default:
		return punt("seo-www", "www", Matig, "De andere variant werkt niet goed",
			fmt.Sprintf("Wie de andere variant van je adres typt (%s), komt niet netjes op je site uit.", w.andere)).met(gezien)
	}
}

// ---------------------------------------------------------------- AI

// AI-crawlers en wie ze gebruikt. Zoekcrawlers bepalen of een assistent je site
// kan noemen; trainingscrawlers of je tekst in een model belandt.
var aiCrawlers = []struct {
	agent, wie string
	zoek       bool // zoekt antwoorden voor een gebruiker (anders: verzamelt tekst om een model te trainen)
}{
	{"OAI-SearchBot", "ChatGPT (zoeken)", true}, {"GPTBot", "OpenAI (training)", false},
	{"Claude-SearchBot", "Claude (zoeken)", true}, {"ClaudeBot", "Anthropic (training)", false},
	{"PerplexityBot", "Perplexity (zoeken)", true}, {"DuckAssistBot", "DuckDuckGo AI (zoeken)", true},
	{"MistralAI-User", "Le Chat (zoeken)", true}, {"Applebot", "Siri en Spotlight (zoeken)", true},
	{"Google-Extended", "Gemini (training)", false}, {"Applebot-Extended", "Apple Intelligence (training)", false},
	{"meta-externalagent", "Meta AI (training)", false}, {"CCBot", "Common Crawl (training)", false},
}

func (k *keurder) geo(w *web) Groep {
	g := Groep{ID: "geo", Naam: "Vindbaar voor AI-assistenten", Kort: "Vindbaar voor AI"}
	if !w.info.geldig {
		for _, p := range [][3]string{
			{"geo-crawlers", "robots.txt", "AI-assistenten mogen je site lezen"}, {"geo-llms", "llms.txt", "Samenvatting voor AI"},
			{"geo-entiteit", "schema.org", "Duidelijk wie je bent"}, {"geo-tekst", "HTML", "Genoeg leesbare tekst"},
			{"geo-snippet", "robots", "Tekst mag worden aangehaald"}, {"geo-contact", "mailto · tel", "Bereikbaarheid te vinden"},
		} {
			g.Punten = append(g.Punten, leeg(p[0], p[1], p[2], w))
		}
		g.Punten = append(g.Punten, leegNieuw("geo", w)...)
		return g
	}
	g.Punten = []Punt{geoCrawlers(w), geoLLMS(w), geoEntiteit(w), geoTekst(w), geoSnippet(w), geoContact(w),
		geoProfielen(w), geoVersheid(w), geoSchemaGeldig(w)}
	return g
}

// dichteCrawlers geeft de AI-crawlers die robots.txt helemaal buitensluit, en
// of dat met een eigen groep gebeurt (anders via User-agent: *).
func dichteCrawlers(robots string) (agents []string, apart map[string]bool) {
	apart = map[string]bool{}
	for _, c := range aiCrawlers {
		regels, eigen := robotsGroep(robots, c.agent)
		if geblokkeerd(normRegels(regels)) {
			agents = append(agents, c.agent)
			apart[c.agent] = eigen
		}
	}
	return
}

func geoCrawlers(w *web) Punt {
	var dicht, detail []string
	agents, apart := dichteCrawlers(w.robots)
	for _, a := range agents {
		for _, c := range aiCrawlers {
			if a != c.agent {
				continue
			}
			dicht = append(dicht, c.wie)
			hoe := "via User-agent: *"
			if apart[a] {
				hoe = "met een eigen groep"
			}
			detail = append(detail, fmt.Sprintf("%s (%s): Disallow: / %s", c.agent, c.wie, hoe))
		}
	}
	zoek := 0
	for _, a := range agents {
		for _, c := range aiCrawlers {
			if a == c.agent && c.zoek {
				zoek++
			}
		}
	}
	switch {
	case len(dicht) == 0:
		return punt("geo-crawlers", "robots.txt", Goed, "AI-assistenten mogen je site lezen",
			"ChatGPT, Claude, Gemini en Perplexity mogen je site bekijken, en kunnen je dus noemen als iemand ze om advies vraagt.")
	case zoek > 0:
		return punt("geo-crawlers", "robots.txt", Slecht, "AI-assistenten worden buitengesloten",
			"Je robots.txt houdt de zoekfunctie van AI-assistenten tegen. Vraagt iemand ChatGPT of Perplexity om een bedrijf zoals het jouwe, dan kunnen ze jou niet noemen. Is dat een bewuste keuze, dan kun je dit punt negeren.").met("Geblokkeerd: " + strings.Join(dicht, ", ")).metDetail(detail...)
	default:
		return punt("geo-crawlers", "robots.txt", Matig, "Een deel van de AI-crawlers is buitengesloten",
			"Je robots.txt houdt sommige AI-diensten tegen. Als dat een bewuste keuze is, prima; anders kom je minder vaak in hun antwoorden voor.").met("Geblokkeerd: " + strings.Join(dicht, ", ")).metDetail(detail...)
	}
}

func geoLLMS(w *web) Punt {
	if strings.HasPrefix(strings.TrimSpace(w.llms), "#") {
		titel := strings.TrimSpace(strings.SplitN(strings.TrimSpace(w.llms), "\n", 2)[0])
		return punt("geo-llms", "llms.txt", Goed, "Samenvatting voor AI aanwezig",
			"Je site heeft een llms.txt: een korte, leesbare kaart van je site speciaal voor AI-assistenten.").met(kort(titel, 100))
	}
	return punt("geo-llms", "llms.txt", Matig, "Geen samenvatting voor AI",
		"Er is geen llms.txt: een kort tekstbestand dat AI-assistenten vertelt wat je doet en welke pagina's belangrijk zijn. Het is nieuw, maar snel gemaakt en steeds vaker gelezen.")
}

func geoEntiteit(w *web) Punt {
	t := strings.ToLower(strings.Join(w.info.schemaTypen, " "))
	for _, soort := range []string{"organization", "localbusiness", "store", "restaurant", "professionalservice", "corporation", "person", "onlinestore", "medicalbusiness", "legalservice"} {
		if strings.Contains(t, soort) {
			return punt("geo-entiteit", "schema.org", Goed, "Duidelijk wie je bent",
				"Je site vertelt in gestructureerde vorm wie er achter zit. AI-assistenten en Google kunnen je bedrijf zo goed herkennen en beschrijven.").met("Gevonden: " + kort(strings.Join(uniek(w.info.schemaTypen), ", "), 120))
		}
	}
	return punt("geo-entiteit", "schema.org", Matig, "Niet vastgelegd wie je bent",
		"Je site vertelt niet in gestructureerde vorm wie je bent (naam, soort bedrijf, plaats, contact). AI-assistenten moeten dat dan zelf raden uit de tekst, en halen het soms door elkaar.")
}

func geoTekst(w *web) Punt {
	n := w.info.woorden
	gezien := fmt.Sprintf("%d woorden leesbare tekst op de homepage", n)
	switch {
	case n < 80 && w.info.scripts >= 5:
		return punt("geo-tekst", "HTML", Slecht, "Je homepage is pas leesbaar na JavaScript",
			"In de HTML zelf staat bijna geen tekst; die wordt pas in de browser opgebouwd. Veel AI-crawlers voeren geen JavaScript uit en zien dus een lege pagina.").met(gezien)
	case n < 100:
		return punt("geo-tekst", "HTML", Slecht, "Heel weinig tekst op je homepage",
			"Er staat bijna geen tekst op je homepage. Zoekmachines en AI-assistenten hebben dan weinig om je op te vinden of over je te vertellen.").met(gezien)
	case n < 250:
		return punt("geo-tekst", "HTML", Matig, "Weinig tekst op je homepage",
			"Er staat weinig tekst op je homepage. Vertel in een paar alinea's wat je doet, voor wie en waar: dat is precies wat AI-assistenten overnemen.").met(gezien)
	default:
		return punt("geo-tekst", "HTML", Goed, "Genoeg leesbare tekst",
			"Je homepage heeft genoeg tekst die zonder JavaScript te lezen is. Daar kunnen zoekmachines en AI-assistenten wat mee.").met(gezien)
	}
}

func geoSnippet(w *web) Punt {
	m := w.info.robots + strings.ToLower(w.kop("X-Robots-Tag"))
	switch {
	case strings.Contains(m, "nosnippet") || strings.Contains(m, "max-snippet:0"):
		return punt("geo-snippet", "robots", Matig, "Je tekst mag niet worden aangehaald",
			"Je pagina vraagt zoekmachines geen stukjes tekst te tonen (nosnippet). Dan laat Google geen beschrijving zien en kunnen AI-overzichten je minder goed aanhalen.").met(strings.Trim(m, ","))
	case strings.Contains(m, "noai") || strings.Contains(m, "noimageai"):
		return punt("geo-snippet", "robots", Matig, "Je vraagt AI je site niet te gebruiken",
			"Je pagina bevat een verzoek aan AI-diensten om je inhoud niet te gebruiken (noai). Bewust? Dan prima; anders kom je minder vaak in AI-antwoorden voor.").met(strings.Trim(m, ","))
	default:
		return punt("geo-snippet", "robots", Goed, "Tekst mag worden aangehaald",
			"Zoekmachines en AI-assistenten mogen stukken van je tekst laten zien, met een verwijzing naar jou.")
	}
}

var telefoonRe = regexp.MustCompile(`(?:\+31|0031|\b0)[\s-]?(?:\d[\s-]?){8,9}\b`)

func geoContact(w *web) Punt {
	var gevonden []string
	if w.info.mailto {
		gevonden = append(gevonden, "mailadres")
	}
	if w.info.tel || telefoonRe.MatchString(w.info.tekst) {
		gevonden = append(gevonden, "telefoonnummer")
	}
	if len(gevonden) > 0 {
		return punt("geo-contact", "mailto · tel", Goed, "Bereikbaarheid te vinden",
			"Op je homepage staat hoe mensen je kunnen bereiken. Een AI-assistent kan dat doorgeven aan wie ernaar vraagt.").met("Gevonden: " + strings.Join(gevonden, " en "))
	}
	return punt("geo-contact", "mailto · tel", Matig, "Geen contactgegevens op de homepage",
		"We vonden op je homepage geen mailadres of telefoonnummer. Vraagt iemand een AI-assistent hoe je bereikbaar bent, dan moet die het antwoord schuldig blijven.")
}

// ---------------------------------------------------------------- snelheid

func (k *keurder) snelheid(w *web) Groep {
	g := Groep{ID: "snelheid", Naam: "Snelheid van je website", Kort: "Snelheid"}
	if !w.info.geldig {
		for _, p := range [][3]string{
			{"snel-ttfb", "TTFB", "Snelle reactie van de server"}, {"snel-grootte", "HTML", "Lichte pagina"},
			{"snel-compressie", "br · gzip", "Pagina ingepakt verstuurd"}, {"snel-cache", "Cache-Control", "Bestanden worden onthouden"},
			{"snel-blokkerend", "head", "Niets houdt het tonen tegen"}, {"snel-afbeeldingen", "lazy · webp", "Slimme afbeeldingen"},
			{"snel-extern", "derde partijen", "Weinig andere partijen"},
		} {
			g.Punten = append(g.Punten, leeg(p[0], p[1], p[2], w))
		}
		g.Punten = append(g.Punten, leegNieuw("snelheid", w)...)
		return g
	}
	g.Punten = []Punt{snelTTFB(w), snelGrootte(w), snelCompressie(w), snelCache(w), snelBlokkerend(w), snelAfbeeldingen(w), snelExtern(k.domein, w),
		snelAfmetingen(w), snelLCP(w), snelBestanden(w), snelGewicht(w), snelOudeScripts(w)}
	return g
}

func snelTTFB(w *web) Punt {
	t := w.ttfb
	if t == 0 {
		return punt("snel-ttfb", "TTFB", Fout, "Snelle reactie van de server", "We konden de reactietijd niet meten.")
	}
	gezien := fmt.Sprintf("%d ms tot de eerste byte, gemeten vanuit Amsterdam", t.Milliseconds())
	switch {
	case t <= 800*time.Millisecond:
		return punt("snel-ttfb", "TTFB", Goed, "Snelle reactie van de server",
			"Je server begint snel met antwoorden. Dat is de basis voor een pagina die vlot verschijnt.").met(gezien)
	case t <= 1800*time.Millisecond:
		return punt("snel-ttfb", "TTFB", Matig, "Trage reactie van de server",
			"Je server doet er even over voordat hij begint te antwoorden. Bezoekers zien zo lang een wit scherm, en Google telt snelheid mee.").met(gezien)
	default:
		return punt("snel-ttfb", "TTFB", Slecht, "Zeer trage reactie van de server",
			"Je server doet er lang over om te beginnen met antwoorden. Een deel van je bezoekers is al weg voordat er iets te zien is.").met(gezien)
	}
}

func snelGrootte(w *web) Punt {
	n := len(w.body)
	gezien := fmt.Sprintf("HTML van de homepage: %d kB", n/1024)
	if n >= maxPagina {
		gezien = "HTML van de homepage: meer dan 2 MB"
	}
	switch {
	case n <= 300<<10:
		return punt("snel-grootte", "HTML", Goed, "Lichte pagina",
			"De HTML van je homepage is compact en snel binnen, ook op een trage mobiele verbinding.").met(gezien)
	case n <= 1<<20:
		return punt("snel-grootte", "HTML", Matig, "Zware pagina",
			"De HTML van je homepage is groot. Op een trage mobiele verbinding duurt het daardoor langer voordat de pagina verschijnt.").met(gezien)
	default:
		return punt("snel-grootte", "HTML", Slecht, "Zeer zware pagina",
			"De HTML van je homepage is erg groot, vaak door ingebouwde code of afbeeldingen. Bezoekers op mobiel wachten lang.").met(gezien)
	}
}

func snelCompressie(w *web) Punt {
	switch {
	case strings.Contains(w.gecodeerd, "br"):
		return punt("snel-compressie", "br · gzip", Goed, "Pagina ingepakt verstuurd",
			"Je server pakt pagina's in met Brotli, de zuinigste methode. Ze zijn zo een stuk sneller binnen.").met("Content-Encoding: " + w.gecodeerd)
	case strings.Contains(w.gecodeerd, "gzip") || strings.Contains(w.gecodeerd, "zstd"):
		return punt("snel-compressie", "br · gzip", Goed, "Pagina ingepakt verstuurd",
			"Je server pakt pagina's in voordat hij ze verstuurt, zodat ze sneller binnen zijn.").met("Content-Encoding: " + w.gecodeerd)
	default:
		return punt("snel-compressie", "br · gzip", Slecht, "Pagina niet ingepakt",
			"Je server verstuurt pagina's onverpakt. Met compressie zijn ze vaak drie tot vijf keer kleiner, zonder dat er iets aan de site verandert.")
	}
}

var maxAgeRe = regexp.MustCompile(`(?:^|[,\s])max-age=(\d+)`)

func snelCache(w *web) Punt {
	if w.cacheURL == "" {
		return punt("snel-cache", "Cache-Control", NVT, "Bestanden worden onthouden",
			"We vonden geen stylesheet of script op je eigen domein om te meten.")
	}
	c := strings.ToLower(w.cache)
	gezien := fmt.Sprintf("%s: %s", w.cacheURL, leegAls(w.cache, "geen Cache-Control"))
	leeftijd := 0
	if m := maxAgeRe.FindStringSubmatch(c); m != nil {
		fmt.Sscan(m[1], &leeftijd)
	}
	switch {
	case strings.Contains(c, "no-store"):
		return punt("snel-cache", "Cache-Control", Matig, "Bestanden worden niet onthouden",
			"De browser moet je stylesheets en scripts bij elk bezoek opnieuw ophalen. Terugkerende bezoekers wachten zo onnodig.").met(gezien)
	case maxAgeRe.MatchString(c) && leeftijd == 0, strings.Contains(c, "no-cache"):
		return punt("snel-cache", "Cache-Control", Matig, "Bestanden worden telkens nagevraagd",
			"De browser mag je stylesheets en scripts bewaren, maar moet bij elke pagina eerst navragen of ze nog kloppen. Dat kost bij elke klik een extra rondje naar je server.").met(gezien)
	case leeftijd >= 3600 || strings.Contains(c, "immutable"):
		return punt("snel-cache", "Cache-Control", Goed, "Bestanden worden onthouden",
			"De browser bewaart je stylesheets en scripts, zodat een volgende pagina meteen verschijnt.").met(gezien)
	case leeftijd > 0:
		return punt("snel-cache", "Cache-Control", Matig, "Bestanden worden maar kort onthouden",
			"De browser moet vaak navragen of je stylesheets en scripts nog kloppen. Met een langere bewaartijd is je site voor terugkerende bezoekers sneller.").met(gezien)
	default:
		return punt("snel-cache", "Cache-Control", Matig, "Geen bewaartijd ingesteld",
			"Je server zegt niet hoe lang de browser je bestanden mag bewaren. Dan haalt die ze vaker opnieuw op dan nodig.").met(gezien)
	}
}

func snelBlokkerend(w *web) Punt {
	js, css := w.info.blokkerendJS, w.info.stijlbladen
	gezien := fmt.Sprintf("In de head: %d scripts zonder async/defer, %d stylesheets", js, css)
	var detail []string
	if js > 0 {
		detail = append([]string{"Scripts zonder async of defer:"}, w.info.blokkerend[:min(len(w.info.blokkerend), maxDetail-2)]...)
		if rest := js - min(len(w.info.blokkerend), maxDetail-2); rest > 0 {
			detail = append(detail, fmt.Sprintf("en nog %d", rest))
		}
	}
	switch {
	case js == 0 && css <= 4:
		return punt("snel-blokkerend", "head", Goed, "Niets houdt het tonen tegen",
			"De browser kan je pagina tonen zonder eerst op losse scripts te wachten.").met(gezien)
	case js <= 2 && css <= 8:
		return punt("snel-blokkerend", "head", Matig, "Een paar bestanden houden het tonen op",
			"Voordat je pagina verschijnt, moet de browser eerst een paar scripts of stylesheets ophalen. Met async of defer verschijnt de pagina eerder.").met(gezien).metDetail(detail...)
	default:
		return punt("snel-blokkerend", "head", Slecht, "Veel bestanden houden het tonen op",
			"De browser moet eerst veel scripts en stylesheets ophalen voordat hij iets kan tonen. Bezoekers kijken zo langer naar een leeg scherm.").met(gezien).metDetail(detail...)
	}
}

func snelAfbeeldingen(w *web) Punt {
	n := w.info.afbeeldingen
	if n == 0 {
		return punt("snel-afbeeldingen", "lazy · webp", Goed, "Slimme afbeeldingen", "Je homepage heeft geen losse afbeeldingen om te optimaliseren.")
	}
	gezien := fmt.Sprintf("%d afbeeldingen, %d lazy, %d in WebP/AVIF", n, w.info.lazy, w.info.modern)
	switch {
	case n <= 3 || w.info.lazy > 0 || w.info.modern > 0:
		return punt("snel-afbeeldingen", "lazy · webp", Goed, "Slimme afbeeldingen",
			"Je afbeeldingen worden zuinig geladen.").met(gezien)
	default:
		return punt("snel-afbeeldingen", "lazy · webp", Matig, "Alle afbeeldingen worden meteen geladen",
			"Je homepage laadt al zijn afbeeldingen meteen, in oudere formaten. Met loading=\"lazy\" en WebP of AVIF is hij vaak de helft lichter.").met(gezien)
	}
}

func snelExtern(domein string, w *web) Punt {
	hosts := map[string]bool{}
	for _, b := range w.info.bronnen {
		if u, err := url.Parse(strings.TrimSpace(b)); err == nil && u.Host != "" {
			h := strings.ToLower(u.Hostname())
			if h != domein && !strings.HasSuffix(h, "."+domein) {
				hosts[h] = true
			}
		}
	}
	for _, m := range bron.FindAllSubmatch(w.body, -1) {
		if u, err := url.Parse(strings.TrimSpace(string(m[2]))); err == nil && u.Host != "" {
			h := strings.ToLower(u.Hostname())
			if h != domein && !strings.HasSuffix(h, "."+domein) {
				hosts[h] = true
			}
		}
	}
	n := len(hosts)
	lijst := sleutels(hosts)
	gezien := fmt.Sprintf("%d andere partijen", n)
	detail := lijstje(lijst, maxDetail)
	if n > 0 {
		gezien += ": " + kort(strings.Join(lijst, ", "), 140)
	}
	switch {
	case n <= 3:
		return punt("snel-extern", "derde partijen", Goed, "Weinig andere partijen",
			"Je homepage haalt weinig of niets bij andere partijen op. Dat is sneller en houdt de gegevens van je bezoekers dichtbij.").met(gezien)
	case n <= 8:
		return punt("snel-extern", "derde partijen", Matig, "Een aantal andere partijen",
			"Je homepage haalt onderdelen op bij meerdere andere partijen. Elke partij kost een extra verbinding, en ligt er een plat, dan hapert je site mee.").met(gezien).metDetail(detail...)
	default:
		return punt("snel-extern", "derde partijen", Slecht, "Veel andere partijen",
			"Je homepage haalt onderdelen op bij veel andere partijen. Dat vertraagt je site en maakt hem afhankelijk van diensten waar je geen grip op hebt.").met(gezien).metDetail(detail...)
	}
}

// ---------------------------------------------------------------- vertrouwen

var kvkRe = regexp.MustCompile(`(?i)\bkvk(?:[- ]?(?:nummer|nr\.?|no\.?))?\s*[:.]?\s*(\d{8})\b`)

// Toestemmingsvensters die we herkennen aan hun scripts of kenmerken.
var toestemming = []string{"cookiebot", "consent.cookiebot", "cookieyes", "onetrust", "cookielaw.org", "complianz",
	"cookie-notice", "usercentrics", "iubenda", "didomi", "quantcast", "cookiefirst", "termly", "cookie-script.com",
	"klaro", "osano", "trustarc", "borlabs", "moove_gdpr", "cmplz", "cookie-law-info", "consentmanager"}

func (k *keurder) vertrouwen(w *web) Groep {
	tracker := trackers(k.domein, w)
	g := Groep{ID: "vertrouwen", Naam: "Vertrouwen en regels", Kort: "Vertrouwen en regels"}
	if !w.info.geldig {
		g.Punten = []Punt{leeg("privacy", "AVG", "Privacyverklaring te vinden", w), leeg("kvk", "KvK", "KvK-nummer op de site", w),
			leeg("toestemming", "cookiebanner", "Toestemming voor trackers", w)}
		g.Punten = append(g.Punten, leegNieuw("vertrouwen", w)...)
		return g
	}
	g.Punten = []Punt{privacy(w), k.kvk(w), toestemmingVenster(w, tracker),
		k.bedrijfsgegevens(w), voorwaarden(w), vooraf(w, tracker), opname(w), ingesloten(w)}
	return g
}

func privacy(w *web) Punt {
	if w.info.privacyLink {
		return punt("privacy", "AVG", Goed, "Privacyverklaring te vinden",
			"Vanaf je homepage is een privacyverklaring te vinden. Bezoekers zien zo wat je met hun gegevens doet, zoals de AVG vraagt.")
	}
	return punt("privacy", "AVG", Matig, "Geen privacyverklaring gevonden",
		"We vonden op je homepage geen link naar een privacyverklaring. Verwerk je gegevens van bezoekers (een contactformulier is al genoeg), dan is die verplicht.")
}

func (k *keurder) kvk(w *web) Punt {
	if m := kvkRe.FindStringSubmatch(w.info.tekst); m != nil {
		return punt("kvk", "KvK", Goed, "KvK-nummer op de site",
			"Je KvK-nummer staat op je site. Dat is verplicht voor bedrijven en geeft bezoekers vertrouwen.").met("KvK " + m[1])
	}
	if !strings.HasSuffix(k.domein, ".nl") {
		return punt("kvk", "KvK", NVT, "KvK-nummer op de site", "Dit domein is geen .nl-domein; we controleren het KvK-nummer alleen bij Nederlandse sites.")
	}
	return punt("kvk", "KvK", Matig, "Geen KvK-nummer op de homepage",
		"We vonden geen KvK-nummer op je homepage. Ben je een bedrijf, dan moet het op je website staan, en het geeft bezoekers vertrouwen dat je echt bestaat. Staat het op een andere pagina, dan is dat ook goed.")
}

func toestemmingVenster(w *web, tracker Punt) Punt {
	laag := strings.ToLower(string(w.body))
	var cmp string
	for _, t := range toestemming {
		if strings.Contains(laag, t) {
			cmp = t
			break
		}
	}
	if tracker.Status != Matig { // geen trackers gevonden
		return punt("toestemming", "cookiebanner", NVT, "Toestemming voor trackers",
			"We vonden geen trackers, dus er hoeft ook geen toestemming gevraagd te worden.")
	}
	if cmp != "" {
		return punt("toestemming", "cookiebanner", Goed, "Er wordt toestemming gevraagd",
			"Je site heeft een venster om toestemming te vragen voor trackers. Let erop dat de trackers pas laden nadat iemand ja heeft gezegd.").met("Herkend: " + cmp)
	}
	return punt("toestemming", "cookiebanner", Matig, "Geen bekend toestemmingsvenster gevonden",
		"Je site laadt trackers, maar we herkenden geen bekend venster dat om toestemming vraagt. Heb je er zelf een gebouwd, dan kan dit in orde zijn. Zonder toestemming mogen de meeste trackers volgens de wet niet laden, en de Autoriteit Persoonsgegevens controleert erop.").met(tracker.Gezien)
}

func uniek(s []string) []string {
	m := map[string]bool{}
	var uit []string
	for _, x := range s {
		if x != "" && !m[x] {
			m[x] = true
			uit = append(uit, x)
		}
	}
	sort.Strings(uit)
	return uit
}
