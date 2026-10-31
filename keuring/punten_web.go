package keuring

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Punten die alleen lezen wat de scan van de website al ophaalt.

// ---------------------------------------------------------------- verbinding

// certWWW: het certificaat moet ook kloppen voor de andere naam (met of
// zonder www). Wie die typt, krijgt anders een rode waarschuwing.
func certWWW(w *web) Punt {
	const id, tech, titel = "cert-www", "X.509 · www", "Certificaat ook voor de andere naam"
	if !w.andereAdres {
		return punt(id, tech, NVT, titel, fmt.Sprintf("%s heeft geen adres, dus daar valt geen certificaat te controleren.", w.andere))
	}
	if w.andereStaat == nil {
		return punt(id, tech, Slecht, "De andere naam heeft geen beveiligde verbinding",
			fmt.Sprintf("Wie %s typt, krijgt geen beveiligde verbinding. Veel mensen typen die variant uit gewoonte.", w.andere)).
			metDetail("Handdruk met " + w.andere + " mislukt: " + fmt.Sprint(w.andereFout))
	}
	certs := w.andereStaat.PeerCertificates
	if len(certs) == 0 {
		return punt(id, tech, Slecht, "Geen certificaat voor de andere naam", "De andere naam stuurt geen certificaat mee.")
	}
	tussen := x509.NewCertPool()
	for _, c := range certs[1:] {
		tussen.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{DNSName: w.andere, Intermediates: tussen})
	gezien := fmt.Sprintf("%s: uitgegeven door %s, geldig tot %s", w.andere, uitgever(certs[0]), certs[0].NotAfter.Format("2-1-2006"))
	var naam x509.HostnameError
	var ongeldig x509.CertificateInvalidError
	switch {
	case errors.As(err, &naam):
		return punt(id, tech, Slecht, "Het certificaat geldt niet voor de andere naam",
			fmt.Sprintf("Wie %s typt, krijgt een waarschuwing dat de site niet veilig is: het certificaat is voor een andere naam uitgegeven.", w.andere)).met(gezien).metDetail("Fout: " + err.Error())
	case errors.As(err, &ongeldig) && ongeldig.Reason == x509.Expired:
		return punt(id, tech, Slecht, "Het certificaat van de andere naam is verlopen",
			fmt.Sprintf("Wie %s typt, krijgt een waarschuwing dat de site niet veilig is.", w.andere)).met(gezien)
	case err != nil:
		return punt(id, tech, Slecht, "Het certificaat van de andere naam wordt niet vertrouwd",
			fmt.Sprintf("Browsers vertrouwen het certificaat van %s niet. Bezoekers die die naam typen, krijgen een waarschuwing.", w.andere)).met(gezien).metDetail("Fout: " + err.Error())
	case time.Until(certs[0].NotAfter) < 14*24*time.Hour:
		return punt(id, tech, Matig, "Het certificaat van de andere naam verloopt binnenkort",
			"Wordt het niet op tijd vernieuwd, dan krijgen bezoekers die deze naam typen een waarschuwing.").met(gezien)
	default:
		return punt(id, tech, Goed, "Certificaat ook voor de andere naam",
			fmt.Sprintf("Ook wie %s typt, krijgt een geldige, beveiligde verbinding.", w.andere)).met(gezien)
	}
}

// ---------------------------------------------------------------- beveiliging

// software: WordPress-versie tegen de lijst van wordpress.org.
func software(w *web) Punt {
	const id, tech, titel = "software", "WordPress", "Software bijgewerkt"
	laadSoftware()
	isWP := strings.Contains(string(w.body), "/wp-content/") || strings.Contains(string(w.body), "/wp-includes/") ||
		strings.Contains(strings.ToLower(w.info.x.generator), "wordpress")
	if !isWP {
		gen := w.info.x.generator
		if gen != "" && (strings.Contains(strings.ToLower(gen), "joomla") || strings.Contains(strings.ToLower(gen), "drupal")) {
			return punt(id, tech, NVT, titel, "We herkennen "+kort(gen, 40)+", maar controleren voorlopig alleen WordPress op verouderde versies.")
		}
		return punt(id, tech, NVT, titel, "We herkenden geen WordPress op je homepage. Andere systemen controleren we hier nog niet.")
	}
	var v string
	for _, re := range wpVersieRe {
		bron := w.body
		if m := re.FindSubmatch(bron); m != nil {
			v = string(m[1])
			break
		}
	}
	if v == "" {
		return punt(id, tech, Goed, "WordPress laat zijn versie niet zien",
			"Je site draait op WordPress, maar laat niet zien welke versie. Houd hem wel zelf bijgewerkt: verouderde WordPress is de meest gehackte software op internet.")
	}
	status := wpLijst.Versies[v]
	if status == "" && strings.Count(v, ".") == 1 {
		status = wpLijst.Versies[v+".0"]
	}
	gezien := "WordPress " + v
	if wpNieuwste != "" {
		gezien += " (nieuwste: " + wpNieuwste + ")"
	}
	switch status {
	case "latest":
		return punt(id, tech, Goed, "WordPress is bijgewerkt", "Je site draait op de nieuwste WordPress.").met(gezien)
	case "outdated":
		return punt(id, tech, Matig, "WordPress is niet de nieuwste",
			"Er is een nieuwere WordPress. Je versie heeft geen bekende lekken, maar bijwerken houdt dat zo.").met(gezien)
	case "insecure":
		return punt(id, tech, Slecht, "WordPress heeft bekende lekken",
			"Je site draait op een WordPress-versie met bekende beveiligingslekken. Aanvallers zoeken daar automatisch naar. Werk hem zo snel mogelijk bij.").met(gezien)
	default:
		return punt(id, tech, NVT, titel, "We zagen WordPress "+v+", maar die versie staat niet in onze lijst.").met(gezien)
	}
}

// bibliotheken: scripts zoals jQuery met een versie waarvoor lekken bekend
// zijn, herkend aan bestandsnaam of adres (lijst van retire.js).
func bibliotheken(w *web) Punt {
	const id, tech = "bibliotheken", "retire.js"
	var adressen []string
	for _, s := range w.info.x.scripts {
		if s.src != "" {
			adressen = append(adressen, s.src)
		}
	}
	if len(adressen) == 0 {
		return punt(id, tech, NVT, "Scripts zonder bekende lekken", "Je homepage laadt geen losse scripts.")
	}
	vondsten := bekendeLekken(adressen)
	if len(vondsten) == 0 {
		return punt(id, tech, Goed, "Scripts zonder bekende lekken",
			"We vonden in je scripts geen bibliotheken met een versie waarin lekken bekend zijn.").met(fmt.Sprintf("%d scripts nagekeken", len(adressen)))
	}
	sort.Slice(vondsten, func(i, j int) bool { return ernstGewicht[vondsten[i].ernst] > ernstGewicht[vondsten[j].ernst] })
	var namen, detail []string
	ergst := 0
	for _, v := range vondsten {
		namen = append(namen, v.naam+" "+v.versie)
		regel := fmt.Sprintf("%s %s: %d bekende lekken (ernstigste: %s)", v.naam, v.versie, v.lekken, leegAls(v.ernst, "onbekend"))
		if len(v.cve) > 0 {
			regel += ", bijv. " + strings.Join(v.cve[:min(len(v.cve), 2)], ", ")
		}
		detail = append(detail, regel)
		ergst = max(ergst, ernstGewicht[v.ernst])
	}
	st := Matig
	if ergst >= 3 {
		st = Slecht
	}
	return punt(id, tech, st, "Scripts met bekende lekken",
		"Je site laadt een of meer scripts in een oude versie waarin beveiligingslekken bekend zijn. Een nieuwere versie is meestal een kwestie van bijwerken.").
		met(kort(strings.Join(namen, ", "), 140)).metDetail(lijstje(detail, maxDetail)...)
}

// php: een PHP-versie zonder beveiligingsupdates, als de server hem noemt.
func php(w *web) Punt {
	const id, tech, titel = "php", "X-Powered-By", "Ondersteunde PHP-versie"
	m := phpRe.FindStringSubmatch(w.kop("X-Powered-By"))
	if m == nil {
		return punt(id, tech, NVT, titel, "Je server laat geen PHP-versie zien. Prima: dan valt er hier niets te controleren.")
	}
	v := m[1] + "." + m[2]
	gezien := "X-Powered-By: " + kort(w.kop("X-Powered-By"), 60)
	einde, bekend := phpEinde[v]
	verlopen := !bekend && vergelijkVersie(v, "8.1") < 0
	if bekend {
		if t, err := time.Parse("2006-01-02", einde); err == nil && time.Now().After(t) {
			verlopen = true
		}
	}
	if verlopen {
		return punt(id, tech, Slecht, "PHP krijgt geen beveiligingsupdates meer",
			"Je server draait PHP "+v+". Daarvoor verschijnen geen beveiligingsupdates meer, dus nieuwe lekken blijven open. Vraag je hostingpartij om over te stappen.").met(gezien)
	}
	return punt(id, tech, Goed, "Ondersteunde PHP-versie",
		"Je server draait PHP "+v+", een versie die nog beveiligingsupdates krijgt. Je server laat wel zien welke versie het is; dat hoeft niet.").met(gezien)
}

// Openbare CDN's waar bibliotheken vandaan komen. Daar hoort integrity bij:
// als zo'n CDN wordt gekraakt, draait anders andermans code op jouw site.
var bibliotheekCDN = []string{"cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com", "code.jquery.com", "stackpath.bootstrapcdn.com",
	"maxcdn.bootstrapcdn.com", "ajax.googleapis.com", "ajax.aspnetcdn.com", "cdn.datatables.net", "use.fontawesome.com", "kit.fontawesome.com", "cdn.tailwindcss.com"}

func sri(domein string, w *web) Punt {
	const id, tech, titel = "sri", "integrity", "Scripts van andere sites gecontroleerd"
	var zonder []string
	totaal := 0
	for _, s := range w.info.x.scripts {
		if s.src == "" {
			continue
		}
		u, err := url.Parse(s.src)
		if err != nil || u.Host == "" {
			continue
		}
		h := strings.ToLower(u.Hostname())
		for _, c := range bibliotheekCDN {
			if h == c {
				totaal++
				if strings.TrimSpace(s.attrs["integrity"]) == "" {
					zonder = append(zonder, kort(s.src, 140))
				}
			}
		}
	}
	if totaal == 0 {
		return punt(id, tech, NVT, titel, "Je homepage haalt geen scripts op bij een openbare CDN, dus hier is niets te controleren.")
	}
	if len(zonder) == 0 {
		return punt(id, tech, Goed, titel, "De scripts die je van een openbare CDN haalt, hebben een controlegetal (integrity). Wordt zo'n CDN gekraakt, dan weigert de browser de aangepaste code.")
	}
	return punt(id, tech, Matig, "Scripts van andere sites zonder controle",
		"Je haalt scripts op bij een openbare CDN zonder controlegetal (integrity). Wordt die CDN gekraakt, dan draait andermans code op jouw site.").
		met(fmt.Sprintf("%d van de %d zonder integrity", len(zonder), totaal)).metDetail(lijstje(zonder, maxDetail)...)
}

func formulieren(w *web) Punt {
	const id, tech, titel = "formulieren", "form action", "Formulieren veilig verstuurd"
	if len(w.info.x.formulieren) == 0 {
		return punt(id, tech, NVT, titel, "Je homepage heeft geen formulieren.")
	}
	var open []string
	for _, a := range w.info.x.formulieren {
		if strings.HasPrefix(strings.ToLower(a), "http://") {
			open = append(open, kort(a, 140))
		}
	}
	if len(open) > 0 {
		return punt(id, tech, Slecht, "Een formulier verstuurt onbeveiligd",
			"Een formulier op je homepage stuurt wat bezoekers invullen via http://. Dat gaat leesbaar over internet, en browsers waarschuwen ervoor.").met(open[0]).metDetail(open...)
	}
	return punt(id, tech, Goed, titel, "Wat bezoekers in een formulier invullen, gaat beveiligd naar de server.").met(fmt.Sprintf("%d formulieren", len(w.info.x.formulieren)))
}

// ---------------------------------------------------------------- Google

func seoRobots(w *web) Punt {
	const id, tech, titel = "seo-robots", "robots.txt", "robots.txt in orde"
	switch {
	case w.robotsCode >= 500:
		return punt(id, tech, Slecht, "robots.txt geeft een serverfout",
			"Je robots.txt geeft een serverfout. Google stopt dan tijdelijk met het bezoeken van je hele site.").met(fmt.Sprintf("/robots.txt: HTTP %d", w.robotsCode))
	case !w.robotsOK:
		return punt(id, tech, Goed, titel, "Je hebt geen robots.txt. Dat mag: dan mag elke zoekmachine alles bekijken.").met(fmt.Sprintf("/robots.txt: HTTP %d", w.robotsCode))
	}
	regels, _ := robotsGroep(w.robots, "googlebot")
	var dicht []string
	for _, r := range normRegels(regels) {
		l := strings.ToLower(r)
		if !strings.HasPrefix(l, "disallow:") {
			continue
		}
		pad := strings.TrimSpace(r[len("disallow:"):])
		lp := strings.ToLower(pad)
		if strings.Contains(lp, ".css") || strings.Contains(lp, ".js") || lp == "/wp-includes/" || lp == "/wp-content/" ||
			lp == "/assets/" || lp == "/static/" || lp == "/css/" || lp == "/js/" || lp == "/wp-content/themes/" || lp == "/wp-content/plugins/" {
			dicht = append(dicht, "Disallow: "+pad)
		}
	}
	if len(dicht) > 0 {
		return punt(id, tech, Matig, "robots.txt blokkeert opmaak of scripts",
			"Je robots.txt houdt Google weg bij je stylesheets of scripts. Google ziet je pagina dan niet zoals een bezoeker, en kan hem als slecht geschikt voor mobiel beoordelen.").met(dicht[0]).metDetail(dicht...)
	}
	heeftSitemap := strings.Contains(strings.ToLower(w.robots), "sitemap:")
	uitleg := "Je robots.txt is in orde: zoekmachines mogen je pagina's en de bestanden die ze nodig hebben bekijken."
	if !heeftSitemap {
		uitleg += " Tip: zet er een regel Sitemap: bij, dan vinden zoekmachines je sitemap vanzelf."
	}
	return punt(id, tech, Goed, titel, uitleg)
}

func seoLinks(w *web) Punt {
	const id, tech, titel = "seo-links", "<a>", "Duidelijke linkteksten"
	x := w.info.x
	if x.links == 0 {
		return punt(id, tech, NVT, titel, "Je homepage heeft geen links.")
	}
	gezien := fmt.Sprintf("%d links, %d met een vage tekst, %d met javascript:", x.links, len(x.vaag), x.jsLinks)
	var detail []string
	for _, v := range uniek(x.vaag) {
		detail = append(detail, "Vage linktekst: \""+kort(v, 60)+"\"")
	}
	switch {
	case x.jsLinks > 0 || len(x.vaag) >= 3:
		return punt(id, tech, Matig, "Links die niet zeggen waar ze heen gaan",
			"Een paar links heten \"klik hier\" of \"lees meer\", of werken alleen met JavaScript. Google en schermlezers weten dan niet waar ze naartoe gaan. Zet in de linktekst zelf waar het over gaat.").met(gezien).metDetail(lijstje(detail, maxDetail)...)
	default:
		return punt(id, tech, Goed, titel, "Je links zeggen waar ze naartoe gaan. Dat helpt Google en mensen die een schermlezer gebruiken.").met(gezien)
	}
}

func seoOmleidingen(w *web) Punt {
	const id, tech, titel = "seo-omleidingen", "301 · 302", "Weinig doorverwijzingen"
	if w.pagina == nil {
		return punt(id, tech, Fout, titel, "We konden je homepage niet ophalen.")
	}
	var keten []string
	tijdelijk := false
	for r := w.pagina.Request.Response; r != nil; r = r.Request.Response {
		keten = append([]string{fmt.Sprintf("%d %s", r.StatusCode, r.Request.URL.String())}, keten...)
		if r.StatusCode == http.StatusFound || r.StatusCode == http.StatusTemporaryRedirect {
			tijdelijk = true
		}
	}
	if w.httpCode == http.StatusFound || w.httpCode == http.StatusTemporaryRedirect {
		tijdelijk = true
	}
	stappen := len(keten)
	if w.httpCode/100 == 3 {
		stappen++ // http:// → https:// komt er voor de meeste bezoekers nog bij
	}
	gezien := fmt.Sprintf("%d doorverwijzingen tot je homepage", stappen)
	if stappen == 1 {
		gezien = "1 doorverwijzing tot je homepage"
	}
	switch {
	case tijdelijk:
		return punt(id, tech, Matig, "Een tijdelijke doorverwijzing",
			"Een van je doorverwijzingen is tijdelijk (302 of 307). Google weet dan niet welk adres het blijvende is. Een permanente (301 of 308) is duidelijker.").met(gezien).metDetail(keten...)
	case stappen > 2:
		return punt(id, tech, Matig, "Veel doorverwijzingen",
			"Wie je adres typt, wordt een paar keer doorgestuurd voordat de pagina laadt. Elke stap kost tijd, vooral op mobiel.").met(gezien).metDetail(keten...)
	default:
		return punt(id, tech, Goed, titel, "Bezoekers komen snel op je homepage uit, zonder onnodige tussenstappen.").met(gezien).metDetail(keten...)
	}
}

// ---------------------------------------------------------------- AI

func geoProfielen(w *web) Punt {
	const id, tech, titel = "geo-profielen", "sameAs", "Profielen gekoppeld"
	x := w.info.x
	if len(x.sameAs) > 0 {
		return punt(id, tech, Goed, titel, "Je gestructureerde gegevens noemen je profielen elders (sameAs). Zo weten Google en AI-assistenten dat die bij jouw bedrijf horen.").met(kort(strings.Join(x.sameAs, ", "), 140))
	}
	if len(x.profielLinks) > 0 {
		return punt(id, tech, Goed, titel, "Je homepage linkt naar je profielen elders, zoals LinkedIn of Facebook. Zet ze ook als sameAs in je gestructureerde gegevens, dan is het voor AI-assistenten zeker.").met("Links naar: " + strings.Join(uniek(x.profielLinks), ", "))
	}
	return punt(id, tech, Matig, "Geen profielen gekoppeld",
		"Je homepage verwijst niet naar je profielen elders (LinkedIn, Google, Facebook, KvK). AI-assistenten gebruiken die om te controleren wie je bent.")
}

func geoVersheid(w *web) Punt {
	const id, tech, titel = "geo-versheid", "© · dateModified", "Site oogt bijgehouden"
	jaar := 0
	for _, j := range w.info.x.jaren {
		jaar = max(jaar, j)
	}
	nu := time.Now().Year()
	if d := w.info.x.datumGewijzigd; len(d) >= 4 {
		var j int
		fmt.Sscan(d[:4], &j)
		if j > jaar {
			jaar = j
		}
	}
	if jaar == 0 {
		return punt(id, tech, NVT, titel, "We vonden geen jaartal (zoals © 2026) of wijzigingsdatum op je homepage.")
	}
	gezien := fmt.Sprintf("Nieuwste jaartal: %d", jaar)
	if jaar < nu-1 {
		return punt(id, tech, Matig, "Je site oogt verouderd",
			fmt.Sprintf("Het nieuwste jaartal op je homepage is %d. Bezoekers, Google en AI-assistenten lezen dat als een site die niet meer wordt bijgehouden. Een automatisch jaartal in de voet lost het op.", jaar)).met(gezien)
	}
	return punt(id, tech, Goed, titel, "Je homepage toont een recent jaartal. Dat laat zien dat de site wordt bijgehouden.").met(gezien)
}

func geoSchemaGeldig(w *web) Punt {
	const id, tech, titel = "geo-schema", "JSON-LD", "Gestructureerde gegevens kloppen"
	x := w.info.x
	if x.jsonldFout > 0 {
		return punt(id, tech, Slecht, "Gestructureerde gegevens zijn kapot",
			fmt.Sprintf("%d van je JSON-LD-blokken is niet te lezen. Google en AI-assistenten slaan het dan helemaal over.", x.jsonldFout))
	}
	if !x.org.gevonden {
		return punt(id, tech, NVT, titel, "Je homepage heeft geen gegevens over je organisatie in JSON-LD, dus er valt niets te controleren (zie Duidelijk wie je bent).")
	}
	var mist []string
	if !x.org.naam {
		mist = append(mist, "naam (name)")
	}
	if x.org.lokaal && !x.org.adres {
		mist = append(mist, "adres (address)")
	}
	if x.org.lokaal && !x.org.telefoon {
		mist = append(mist, "telefoon (telephone)")
	}
	gezien := "Gevonden: " + kort(strings.Join(uniek(x.org.typen), ", "), 100)
	if len(mist) > 0 {
		return punt(id, tech, Matig, "Gestructureerde gegevens onvolledig",
			"Het blok over je bedrijf mist: "+strings.Join(mist, ", ")+". Juist die gegevens gebruiken Google en AI-assistenten om je te tonen.").met(gezien)
	}
	return punt(id, tech, Goed, titel, "De gestructureerde gegevens over je bedrijf zijn te lezen en hebben de basis.").met(gezien)
}

// ---------------------------------------------------------------- snelheid

func snelAfmetingen(w *web) Punt {
	const id, tech, titel = "snel-afmetingen", "width · height", "Afbeeldingen met een vaste maat"
	if w.info.afbeeldingen == 0 {
		return punt(id, tech, NVT, titel, "Je homepage heeft geen losse afbeeldingen.")
	}
	n := len(w.info.x.zonderMaat)
	gezien := fmt.Sprintf("%d van de %d afbeeldingen zonder breedte en hoogte", n, w.info.afbeeldingen)
	switch {
	case n == 0:
		return punt(id, tech, Goed, titel, "Je afbeeldingen hebben een breedte en hoogte. De browser houdt er ruimte voor vrij, dus de pagina springt niet tijdens het laden.").met(gezien)
	case n < 3 || n*3 <= w.info.afbeeldingen:
		return punt(id, tech, Matig, "Een paar afbeeldingen zonder vaste maat",
			"Een paar afbeeldingen hebben geen breedte en hoogte. Tijdens het laden springt de tekst dan opzij, en Google telt dat mee (CLS).").met(gezien).metDetail(lijstje(w.info.x.zonderMaat, maxDetail)...)
	default:
		return punt(id, tech, Slecht, "Afbeeldingen zonder vaste maat",
			"De meeste afbeeldingen hebben geen breedte en hoogte. Tijdens het laden springt de pagina, zodat bezoekers verkeerd klikken, en Google telt dat mee (CLS).").met(gezien).metDetail(lijstje(w.info.x.zonderMaat, maxDetail)...)
	}
}

func snelLCP(w *web) Punt {
	const id, tech, titel = "snel-eerste", "loading=lazy", "Eerste afbeelding laadt meteen"
	if w.info.x.eersteAfbeelding == "" {
		return punt(id, tech, NVT, titel, "Je homepage heeft geen losse afbeeldingen.")
	}
	if w.info.x.eersteLazy {
		return punt(id, tech, Matig, "De eerste afbeelding wacht met laden",
			"De eerste afbeelding op je homepage heeft loading=\"lazy\". Dat is vaak de grote foto bovenaan, en die verschijnt daardoor later. Lazy is goed voor afbeeldingen verderop, niet voor de eerste.").met(kort(w.info.x.eersteAfbeelding, 120))
	}
	return punt(id, tech, Goed, titel, "De eerste afbeelding wordt meteen geladen, zodat het bovenste deel van je pagina snel compleet is.")
}

func snelBestanden(w *web) Punt {
	const id, tech, titel = "snel-onderdelen", "DOM · requests", "Niet te veel onderdelen"
	x := w.info.x
	bestanden := w.info.afbeeldingen + len(x.iframes) + len(w.info.bronnen)
	gezien := fmt.Sprintf("%d elementen, ongeveer %d bestanden in de HTML", x.knopen, bestanden)
	switch {
	case x.knopen > 3000 || bestanden > 150:
		return punt(id, tech, Slecht, "Heel veel onderdelen",
			"Je homepage bestaat uit erg veel onderdelen. Vooral op een telefoon kost het opbouwen daarvan merkbaar tijd.").met(gezien)
	case x.knopen > 1500 || bestanden > 80:
		return punt(id, tech, Matig, "Veel onderdelen",
			"Je homepage bestaat uit veel onderdelen. Google raadt minder dan 1500 aan; daarboven wordt de pagina trager, vooral op een telefoon.").met(gezien)
	default:
		return punt(id, tech, Goed, titel, "Je homepage bestaat uit een overzichtelijk aantal onderdelen.").met(gezien)
	}
}

func snelGewicht(w *web) Punt {
	const id, tech, titel = "snel-gewicht", "Content-Length", "Afbeeldingen niet te zwaar"
	if len(w.gewicht) == 0 {
		return punt(id, tech, NVT, titel, "We vonden geen afbeeldingen op je eigen domein om te wegen.")
	}
	var zwaar, detail []string
	grootste := int64(0)
	for _, g := range w.gewicht {
		grootste = max(grootste, g.bytes)
		regel := fmt.Sprintf("%s: %d kB", kort(g.pad, 100), g.bytes/1024)
		detail = append(detail, regel)
		if g.bytes > 300<<10 {
			zwaar = append(zwaar, regel)
		}
	}
	gezien := fmt.Sprintf("Zwaarste afbeelding: %d kB (van %d gewogen)", grootste/1024, len(w.gewicht))
	switch {
	case grootste > 1<<20:
		return punt(id, tech, Slecht, "Zeer zware afbeeldingen",
			"Een afbeelding op je homepage is groter dan 1 MB. Op een telefoon duurt het lang voordat die binnen is. Verklein hem en sla hem op als WebP of AVIF.").met(gezien).metDetail(zwaar...)
	case grootste > 300<<10:
		return punt(id, tech, Matig, "Zware afbeeldingen",
			"Een of meer afbeeldingen zijn groter dan 300 kB. Kleiner opslaan, bijvoorbeeld als WebP, scheelt vaak de helft zonder dat je verschil ziet.").met(gezien).metDetail(zwaar...)
	default:
		return punt(id, tech, Goed, titel, "De afbeeldingen die we wogen, zijn licht genoeg om snel te laden.").met(gezien).metDetail(detail...)
	}
}

var uaRe = regexp.MustCompile(`\bUA-\d{4,10}-\d{1,4}\b`)

func snelOudeScripts(w *web) Punt {
	const id, tech, titel = "snel-overbodig", "analytics.js", "Geen overbodige scripts"
	tekst := w.info.x.inline
	var srcs strings.Builder
	for _, s := range w.info.x.scripts {
		srcs.WriteString(s.src + " ")
	}
	alle := tekst + " " + srcs.String()
	ua := uaRe.FindString(alle)
	oud := strings.Contains(alle, "google-analytics.com/analytics.js") || strings.Contains(alle, "google-analytics.com/ga.js")
	nieuw := regexp.MustCompile(`\bG-[A-Z0-9]{6,12}\b`).MatchString(alle)
	if (ua != "" || oud) && !nieuw {
		g := leegAls(ua, "analytics.js")
		return punt(id, tech, Matig, "Oude Google Analytics laadt nog",
			"Je site laadt nog de oude Google Analytics (Universal Analytics). Die verzamelt sinds juli 2023 niets meer, maar kost bezoekers wel laadtijd en stuurt hun gegevens nog naar Google. Haal hem weg.").met(g)
	}
	return punt(id, tech, Goed, titel, "We vonden geen scripts die niets meer doen, zoals de oude Google Analytics.")
}

// ---------------------------------------------------------------- vertrouwen

var postcodeRe = regexp.MustCompile(`\b[1-9]\d{3}\s?(?:[A-RT-Z][A-Z]|S[BCE-RT-Z])\b`)
var btwRe = regexp.MustCompile(`(?i)\bNL\s?\d{9}\s?B\s?\d{2}\b`)
var mailRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)

func (k *keurder) bedrijfsgegevens(w *web) Punt {
	const id, tech, titel = "bedrijfsgegevens", "art. 3:15d BW", "Bedrijfsgegevens compleet"
	if !strings.HasSuffix(k.domein, ".nl") {
		return punt(id, tech, NVT, titel, "Dit domein is geen .nl-domein; we controleren de Nederlandse bedrijfsgegevens alleen bij Nederlandse sites.")
	}
	t := w.info.tekst
	var heeft, mist []string
	if postcodeRe.MatchString(t) {
		heeft = append(heeft, "adres")
	} else {
		mist = append(mist, "adres")
	}
	if w.info.mailto || mailRe.MatchString(t) {
		heeft = append(heeft, "e-mailadres")
	} else {
		mist = append(mist, "e-mailadres")
	}
	if btwRe.MatchString(t) {
		heeft = append(heeft, "btw-nummer")
	} else {
		mist = append(mist, "btw-nummer")
	}
	gezien := "Gevonden: " + leegAls(strings.Join(heeft, ", "), "niets")
	if len(mist) == 0 {
		return punt(id, tech, Goed, titel, "Je homepage noemt je adres, e-mailadres en btw-nummer, zoals de wet vraagt van bedrijven met een website.").met(gezien)
	}
	return punt(id, tech, Matig, "Bedrijfsgegevens niet compleet",
		"Een bedrijf moet op zijn website zijn adres, e-mailadres, KvK-nummer en btw-nummer noemen (als je btw-plichtig bent). We vonden op je homepage niet: "+strings.Join(mist, ", ")+". Staat het op een andere pagina die vanaf elke pagina bereikbaar is, dan is dat ook goed.").met(gezien)
}

func voorwaarden(w *web) Punt {
	const id, tech, titel = "voorwaarden", "algemene voorwaarden", "Algemene voorwaarden te vinden"
	if w.info.x.voorwaardenLink {
		return punt(id, tech, Goed, titel, "Vanaf je homepage zijn je algemene voorwaarden te vinden.")
	}
	if w.info.x.winkel {
		return punt(id, tech, Matig, "Geen algemene voorwaarden gevonden",
			"Je site lijkt een webshop, maar we vonden geen link naar algemene voorwaarden. Voor een webshop horen die vóór de bestelling te zien te zijn, net als het herroepingsrecht.")
	}
	return punt(id, tech, NVT, titel, "We vonden geen link naar algemene voorwaarden. Voor een site zonder webshop is dat niet verplicht, dus dit punt telt niet mee.")
}

// Kenmerken dat een script pas na toestemming draait: de meeste
// toestemmingsvensters zetten zulke scripts op type="text/plain".
var geblokkeerdTekens = []string{"data-cookieconsent", "data-cookiecategory", "data-category", "data-cookie-consent", "data-cmplz", "data-usercentrics", "data-consent", "data-cookieyes", "data-service", "data-borlabs"}

var consentDefaultRe = regexp.MustCompile(`(?s)gtag\(\s*['"]consent['"]\s*,\s*['"]default['"].{0,400}?denied`)

func vooraf(w *web, tracker Punt) Punt {
	const id, tech, titel = "vooraf", "Consent Mode", "Trackers wachten op toestemming"
	if tracker.Status != Matig {
		return punt(id, tech, NVT, titel, "We vonden geen trackers, dus er hoeft ook niets te wachten.")
	}
	if consentDefaultRe.MatchString(w.info.x.inline) {
		return punt(id, tech, Goed, titel, "Je site zet Google-trackers standaard uit totdat een bezoeker toestemming geeft (Consent Mode).")
	}
	var direct []string
	for _, s := range w.info.x.scripts {
		bron := s.src
		if bron == "" {
			bron = s.content
		}
		if !trackerScript(bron) {
			continue
		}
		wacht := s.typ == "text/plain" || strings.HasPrefix(s.typ, "text/x-")
		for _, t := range geblokkeerdTekens {
			if _, ok := s.attrs[t]; ok {
				wacht = true
			}
		}
		if strings.Contains(s.attrs["class"], "cmplz") || strings.Contains(s.attrs["class"], "optanon") {
			wacht = true
		}
		if !wacht {
			if s.src != "" {
				direct = append(direct, kort(s.src, 120))
			} else {
				direct = append(direct, "inline script: "+kort(strings.TrimSpace(s.content), 80))
			}
		}
	}
	if len(direct) == 0 {
		return punt(id, tech, Goed, titel, "De trackers op je homepage staan zo ingesteld dat ze pas laden na toestemming.")
	}
	return punt(id, tech, Matig, "Trackers laden waarschijnlijk vóór toestemming",
		"Je homepage laadt trackers die niet wachten op toestemming: ze staan gewoon in de pagina, zonder blokkade door een toestemmingsvenster en zonder Consent Mode. Dan volgen ze bezoekers al voordat die ja zeggen. De Autoriteit Persoonsgegevens controleert hier actief op.").
		met(kort(direct[0], 120)).metDetail(lijstje(direct, maxDetail)...)
}

var trackerTekens = []string{"googletagmanager.com", "google-analytics.com", "gtag(", "fbq(", "connect.facebook.net", "hotjar", "clarity.ms",
	"snap.licdn.com", "analytics.tiktok.com", "bat.bing.com", "doubleclick.net", "leadinfo", "hs-scripts.com"}

func trackerScript(s string) bool {
	l := strings.ToLower(s)
	for _, t := range trackerTekens {
		if strings.Contains(l, t) {
			return true
		}
	}
	return false
}

// Diensten die opnemen wat bezoekers doen: muisbewegingen, klikken, typen.
var opnameDiensten = map[string]string{"hotjar.com": "Hotjar", "clarity.ms": "Microsoft Clarity", "fullstory.com": "FullStory",
	"smartlook.com": "Smartlook", "mouseflow.com": "Mouseflow", "logrocket.com": "LogRocket", "mc.yandex.ru": "Yandex Metrica",
	"luckyorange.com": "Lucky Orange", "crazyegg.com": "Crazy Egg", "inspectlet.com": "Inspectlet", "contentsquare.net": "Contentsquare"}

func opname(w *web) Punt {
	const id, tech, titel = "opname", "sessie-opname", "Bezoekers worden niet opgenomen"
	gevonden := map[string]bool{}
	alle := strings.ToLower(w.info.x.inline)
	for _, s := range w.info.x.scripts {
		alle += " " + strings.ToLower(s.src)
	}
	for _, b := range w.info.bronnen {
		alle += " " + strings.ToLower(b)
	}
	for host, naam := range opnameDiensten {
		if strings.Contains(alle, host) {
			gevonden[naam] = true
		}
	}
	if len(gevonden) == 0 {
		return punt(id, tech, Goed, titel, "We vonden geen diensten die opnemen wat bezoekers op je site doen.")
	}
	return punt(id, tech, Matig, "Je site neemt bezoekers op",
		"Je site gebruikt een dienst die opneemt wat bezoekers doen: muisbewegingen, klikken en soms wat ze typen. Dat mag alleen met duidelijke toestemming, en wat ze in formulieren typen hoort er nooit in te staan.").met("Gevonden: " + strings.Join(sleutels(gevonden), ", "))
}

func ingesloten(w *web) Punt {
	const id, tech, titel = "ingesloten", "fonts · iframes", "Ingesloten diensten privacyvriendelijk"
	var vondst []string
	alle := strings.ToLower(strings.Join(w.info.bronnen, " "))
	if strings.Contains(alle, "fonts.googleapis.com") || strings.Contains(alle, "fonts.gstatic.com") || strings.Contains(strings.ToLower(string(w.body)), "fonts.googleapis.com") {
		vondst = append(vondst, "Google Fonts rechtstreeks van Google")
	}
	for _, f := range w.info.x.iframes {
		l := strings.ToLower(f)
		switch {
		case strings.Contains(l, "youtube.com/embed"):
			vondst = append(vondst, "YouTube-video zonder youtube-nocookie.com")
		case strings.Contains(l, "player.vimeo.com") && !strings.Contains(l, "dnt=1"):
			vondst = append(vondst, "Vimeo-video zonder dnt=1")
		case strings.Contains(l, "google.com/maps") || strings.Contains(l, "maps.google."):
			vondst = append(vondst, "Google Maps-kaart")
		case strings.Contains(l, "facebook.com/plugins") || strings.Contains(l, "instagram.com") || strings.Contains(l, "platform.twitter.com") || strings.Contains(l, "twitter.com/embed"):
			vondst = append(vondst, "Insluiting van sociale media")
		}
	}
	vondst = uniek(vondst)
	if len(vondst) == 0 {
		return punt(id, tech, Goed, titel, "Je homepage laadt geen lettertypen, video's of kaarten rechtstreeks bij Google, YouTube of sociale media.")
	}
	return punt(id, tech, Matig, "Ingesloten diensten sturen gegevens weg",
		"Je homepage laadt diensten in die het IP-adres van elke bezoeker meteen naar die partij sturen, ook zonder klik of toestemming. Een Duitse rechter beboette dat al bij Google Fonts. Host lettertypen zelf, en laad video's en kaarten pas na een klik.").met(kort(strings.Join(vondst, ", "), 140)).metDetail(vondst...)
}

// ---------------------------------------------------------------- toegankelijkheid

func (k *keurder) toegankelijkheid(w *web) Groep {
	g := Groep{ID: "toegankelijk", Naam: "Toegankelijkheid", Kort: "Toegankelijkheid"}
	if !w.info.geldig {
		for _, p := range catalogusGroep("toegankelijk") {
			g.Punten = append(g.Punten, leeg(p.ID, p.Techniek, p.Naam, w))
		}
		return g
	}
	g.Punten = []Punt{a11yKnoppen(w), a11yLinks(w), a11yLabels(w), a11yZoom(w), a11yOverslaan(w), a11yKoppen(w), a11yIframes(w), a11yOverlay(w), a11yVerklaring(w)}
	return g
}

func a11yKnoppen(w *web) Punt {
	const id, tech, titel = "a11y-knoppen", "button-name", "Knoppen hebben een naam"
	x := w.info.x
	if x.knoppen == 0 {
		return punt(id, tech, NVT, titel, "Je homepage heeft geen knoppen.")
	}
	n := len(x.knoppenZonderNaam)
	gezien := fmt.Sprintf("%d van de %d knoppen zonder naam", n, x.knoppen)
	if n == 0 {
		return punt(id, tech, Goed, titel, "Elke knop heeft een naam die een schermlezer kan voorlezen.").met(gezien)
	}
	return punt(id, tech, ernstNaarAantal(n, x.knoppen), "Knoppen zonder naam",
		"Er zijn knoppen zonder tekst of beschrijving, bijvoorbeeld een knop met alleen een pictogram. Een schermlezer zegt dan alleen \"knop\", en blinde bezoekers weten niet wat hij doet.").met(gezien).metDetail(lijstje(x.knoppenZonderNaam, maxDetail)...)
}

func a11yLinks(w *web) Punt {
	const id, tech, titel = "a11y-links", "link-name", "Links hebben een naam"
	x := w.info.x
	if x.links == 0 {
		return punt(id, tech, NVT, titel, "Je homepage heeft geen links.")
	}
	n := len(x.linksZonderNaam)
	gezien := fmt.Sprintf("%d van de %d links zonder naam", n, x.links)
	if n == 0 {
		return punt(id, tech, Goed, titel, "Elke link heeft een tekst of beschrijving die een schermlezer kan voorlezen.").met(gezien)
	}
	return punt(id, tech, ernstNaarAantal(n, x.links), "Links zonder naam",
		"Er zijn links zonder tekst of beschrijving, vaak een pictogram of logo zonder alt-tekst. Een schermlezer leest dan alleen het adres voor, of niets.").met(gezien).metDetail(lijstje(uniek(x.linksZonderNaam), maxDetail)...)
}

func a11yLabels(w *web) Punt {
	const id, tech, titel = "a11y-labels", "label", "Invulvelden hebben een label"
	x := w.info.x
	if x.velden == 0 {
		return punt(id, tech, NVT, titel, "Je homepage heeft geen invulvelden.")
	}
	n := len(x.veldenZonderLabel)
	gezien := fmt.Sprintf("%d van de %d velden zonder label", n, x.velden)
	if n == 0 {
		return punt(id, tech, Goed, titel, "Elk invulveld heeft een label, zodat iedereen weet wat erin moet.").met(gezien)
	}
	return punt(id, tech, ernstNaarAantal(n, x.velden), "Invulvelden zonder label",
		"Er zijn invulvelden zonder label. Een tekst die in het veld staat (placeholder) verdwijnt zodra je typt en telt niet als label. Een schermlezer weet dan niet wat er gevraagd wordt.").met(gezien).metDetail(lijstje(x.veldenZonderLabel, maxDetail)...)
}

var maxSchaalRe = regexp.MustCompile(`maximum-scale\s*=\s*([0-9.]+)`)

func a11yZoom(w *web) Punt {
	const id, tech, titel = "a11y-zoom", "viewport", "Inzoomen mogelijk"
	v := w.info.viewport
	if v == "" {
		return punt(id, tech, NVT, titel, "Je homepage heeft geen viewport-instelling, dus inzoomen wordt ook niet tegengehouden.")
	}
	geblokt := strings.Contains(strings.ReplaceAll(v, " ", ""), "user-scalable=no") || strings.Contains(strings.ReplaceAll(v, " ", ""), "user-scalable=0")
	if m := maxSchaalRe.FindStringSubmatch(v); m != nil {
		var f float64
		fmt.Sscan(m[1], &f)
		if f < 2 {
			geblokt = true
		}
	}
	if geblokt {
		return punt(id, tech, Slecht, "Inzoomen geblokkeerd",
			"Je site verbiedt inzoomen op een telefoon. Slechtziende bezoekers kunnen de tekst dan niet groter maken. Haal user-scalable=no en maximum-scale weg.").met(kort(v, 120))
	}
	return punt(id, tech, Goed, titel, "Bezoekers kunnen op hun telefoon inzoomen om de tekst groter te maken.")
}

func a11yOverslaan(w *web) Punt {
	const id, tech, titel = "a11y-overslaan", "<main> · skiplink", "Direct naar de inhoud"
	x := w.info.x
	if x.heeftMain || x.overslaanLink {
		var hoe []string
		if x.heeftMain {
			hoe = append(hoe, "<main>")
		}
		if x.overslaanLink {
			hoe = append(hoe, "link naar de inhoud")
		}
		return punt(id, tech, Goed, titel, "Wie met het toetsenbord of een schermlezer werkt, kan het menu overslaan en direct naar de inhoud.").met("Gevonden: " + strings.Join(hoe, " en "))
	}
	return punt(id, tech, Matig, "Niet direct naar de inhoud",
		"Je homepage heeft geen <main> en geen link om het menu over te slaan. Wie met het toetsenbord werkt, moet dan op elke pagina eerst door het hele menu.")
}

func a11yKoppen(w *web) Punt {
	const id, tech, titel = "a11y-koppen", "h1 · h2 · h3", "Kopjes in een logische volgorde"
	k := w.info.x.koppen
	if len(k) == 0 {
		return punt(id, tech, Matig, "Geen kopjes",
			"Je homepage heeft geen kopjes (h1, h2). Schermlezers springen daarmee door een pagina, en Google ziet er de opbouw aan.")
	}
	var sprong []string
	for i := 1; i < len(k); i++ {
		if k[i] > k[i-1]+1 {
			sprong = append(sprong, fmt.Sprintf("h%d gevolgd door h%d", k[i-1], k[i]))
		}
	}
	gezien := fmt.Sprintf("%d kopjes", len(k))
	if len(sprong) > 0 {
		return punt(id, tech, Matig, "Kopjes slaan een niveau over",
			"Je kopjes slaan een niveau over, bijvoorbeeld van h2 direct naar h4. Wie een schermlezer gebruikt, denkt dan dat er iets ontbreekt. Kies het niveau op opbouw, niet op lettergrootte.").met(gezien).metDetail(lijstje(uniek(sprong), maxDetail)...)
	}
	return punt(id, tech, Goed, titel, "Je kopjes staan in een logische volgorde, zonder niveaus over te slaan.").met(gezien)
}

func a11yIframes(w *web) Punt {
	const id, tech, titel = "a11y-frames", "iframe title", "Ingesloten onderdelen beschreven"
	x := w.info.x
	if len(x.iframes) == 0 {
		return punt(id, tech, NVT, titel, "Je homepage sluit geen video's, kaarten of andere sites in.")
	}
	if len(x.iframesZonderTit) == 0 {
		return punt(id, tech, Goed, titel, "Elk ingesloten onderdeel (video, kaart) heeft een titel die zegt wat het is.")
	}
	return punt(id, tech, Matig, "Ingesloten onderdelen zonder beschrijving",
		"Een ingesloten video, kaart of formulier heeft geen titel. Een schermlezer zegt dan alleen \"frame\".").met(fmt.Sprintf("%d van de %d zonder titel", len(x.iframesZonderTit), len(x.iframes))).metDetail(lijstje(x.iframesZonderTit, maxDetail)...)
}

// Overlay-widgets beloven toegankelijkheid met één script. Dat werkt niet:
// in de VS kreeg accessiBe in 2025 een boete van de FTC voor die belofte.
var overlays = map[string]string{"accessibe.com": "accessiBe", "acsbapp.com": "accessiBe", "userway.org": "UserWay", "equalweb.com": "EqualWeb",
	"audioeye.com": "AudioEye", "maxaccess.io": "Max Access", "accessibilityplugin": "toegankelijkheidsplug-in", "readspeaker.com/webreader": ""}

func a11yOverlay(w *web) Punt {
	const id, tech, titel = "a11y-overlay", "overlay", "Geen schijnoplossing"
	alle := strings.ToLower(string(w.body))
	for host, naam := range overlays {
		if naam != "" && strings.Contains(alle, host) {
			return punt(id, tech, Matig, "Een toegankelijkheidswidget als oplossing",
				"Je site gebruikt een widget die belooft je site toegankelijk te maken. Zo'n widget lost de echte problemen niet op en zit hulpmiddelen soms juist in de weg. In de VS kreeg een leverancier daarvoor een boete. Maak de site zelf toegankelijk.").met("Gevonden: " + naam)
		}
	}
	return punt(id, tech, Goed, titel, "Je site leunt niet op een widget die toegankelijkheid belooft.")
}

func a11yVerklaring(w *web) Punt {
	const id, tech, titel = "a11y-verklaring", "EAA", "Toegankelijkheidsverklaring"
	if w.info.x.toegankelijkLink {
		return punt(id, tech, Goed, titel, "Vanaf je homepage is informatie over de toegankelijkheid van je site te vinden.")
	}
	if w.info.x.winkel {
		return punt(id, tech, Matig, "Geen toegankelijkheidsverklaring",
			"Je site lijkt een webshop. Sinds 28 juni 2025 moeten webshops toegankelijk zijn en uitleggen hoe ze dat zijn (Europese Toegankelijkheidswet). Kleine ondernemingen (minder dan 10 mensen en hooguit 2 miljoen omzet) zijn vrijgesteld.")
	}
	return punt(id, tech, NVT, titel, "We vonden geen toegankelijkheidsverklaring. Die is verplicht voor webshops; je site lijkt er geen, dus dit punt telt niet mee.")
}

// kwantumveilig: werd de sleutel uitgewisseld met X25519MLKEM768?
func kwantumveilig(staat *tls.ConnectionState) bool {
	return staat != nil && staat.CurveID == tls.X25519MLKEM768
}

// ernstNaarAantal: een enkele fout is "kan beter", een patroon "niet in orde".
func ernstNaarAantal(fout, totaal int) Status {
	if fout <= 2 || fout*20 < totaal {
		return Matig
	}
	return Slecht
}
