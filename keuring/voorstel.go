package keuring

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Berekende voorstellen: een record of regel die de eigenaar zo kan
// overnemen, op basis van wat er nu staat. Alleen waar dat echt te berekenen
// is; de vaste teksten in oplossingen.json verwijzen ernaar met "het voorstel
// hieronder". Lukt het in een bepaald geval toch niet (een onbekende
// certificaatleverancier), dan zegt de Toelichting waarom.

// voorstelPunten zijn de punten en statussen waarvoor de code een voorstel
// maakt. TestVoorstelBijTekst houdt dit gelijk met oplossingen.json.
var voorstelPunten = map[string][]Status{
	"dmarc": {Matig, Slecht}, "dmarc-rua": {Matig}, "spf": {Matig, Slecht},
	"mta-sts": {Matig}, "tls-rpt": {Matig}, "caa": {Matig},
	"hsts": {Matig, Slecht}, "csp": {Matig}, "nosniff": {Matig}, "frame": {Matig}, "referrer": {Matig},
	"securitytxt": {Matig}, "geo-crawlers": {Matig, Slecht}, "geo-llms": {Matig}, "geo-entiteit": {Matig},
}

func heeftVoorstel(id string, s Status) bool {
	for _, x := range voorstelPunten[id] {
		if x == s {
			return true
		}
	}
	return false
}

// subInfo is wat de subdomeinen bijdragen aan de voorstellen.
type subInfo struct {
	uitgevers  []string // uitgevers van geldige certificaten op subdomeinen
	gemeten    int      // subdomeinen met een website
	allesHTTPS bool     // al die subdomeinen hebben een geldig certificaat
}

type voorstel struct{ tekst, naam, toelichting string }

// voorstelVoor rekent het voorstel uit voor een punt.
func (k *keurder) voorstelVoor(p Punt, u *Uitslag, sub subInfo) voorstel {
	if !heeftVoorstel(p.ID, p.Status) {
		return voorstel{}
	}
	k.mu.Lock()
	s := k.stand
	k.mu.Unlock()
	host := k.domein
	if k.w != nil && k.w.host != "" {
		host = k.w.host
	}
	kopNaam := "kopregel (header) op https://" + host + "/"
	switch p.ID {
	case "dmarc":
		return k.voorstelDMARC(s, u, false)
	case "dmarc-rua":
		return k.voorstelDMARC(s, u, true)
	case "spf":
		return k.voorstelSPF(s, u)
	case "mta-sts":
		return k.voorstelMTASTS(s)
	case "tls-rpt":
		// Een eigen adres, niet dat van de DMARC-rapporten: dat zijn andere
		// bestanden, en een DMARC-dienst leest ze niet altijd.
		return voorstel{"v=TLSRPTv1; rua=mailto:tls-rapport@" + k.domein, "_smtp._tls." + k.domein + " (TXT)",
			"Het mailadres tls-rapport@" + k.domein + " moet bestaan; vervang het anders door een adres dat je wel leest."}
	case "caa":
		return k.voorstelCAA(u, sub)
	case "hsts":
		return k.voorstelHSTS(sub, kopNaam)
	case "csp":
		return k.voorstelCSP(kopNaam)
	case "nosniff":
		return voorstel{"X-Content-Type-Options: nosniff", kopNaam, ""}
	case "frame":
		if k.w != nil && k.w.kop("Content-Security-Policy") != "" {
			return voorstel{"X-Frame-Options: SAMEORIGIN", kopNaam,
				"Je hebt al een Content-Security-Policy; je kunt ook frame-ancestors 'self' aan dat beleid toevoegen."}
		}
		return voorstel{"Content-Security-Policy: frame-ancestors 'self'", kopNaam,
			"Moet je site wel in een andere site te zien zijn, zet die site dan achter 'self'."}
	case "referrer":
		return voorstel{"Referrer-Policy: strict-origin-when-cross-origin", kopNaam, ""}
	case "securitytxt":
		return voorstelSecurityTxt(s, k.domein, host, time.Now())
	case "geo-crawlers":
		return k.voorstelRobots(p.Status)
	case "geo-llms":
		return k.voorstelLLMS()
	case "geo-entiteit":
		return k.voorstelJSONLD()
	}
	return voorstel{}
}

func status(u *Uitslag, id string) Status {
	for _, g := range u.Groepen {
		for _, p := range g.Punten {
			if p.ID == id {
				return p.Status
			}
		}
	}
	return ""
}

func feit(u *Uitslag, naam string) string {
	for _, f := range u.Feiten {
		if f.Naam == naam {
			return f.Waarde
		}
	}
	return ""
}

// ---------------------------------------------------------------- DMARC

// voorstelDMARC. Het beleid:
//   - zijn SPF en DKIM allebei in orde, dan p=quarantine. Voor het MKB is dat
//     de goede stap: nagemaakte mail gaat naar de spam, en een vergeten
//     afzender ziet het nog terug. reject mag later, maar is niet nodig om
//     beschermd te zijn.
//   - anders eerst p=none met rapporten: een tussenstap. Met quarantine zonder
//     werkende SPF of DKIM komt je eigen mail in de spam.
//   - staat het al strenger (reject, of quarantine met pct onder 100), dan
//     nooit terug naar zwakker; pct gaat eruit.
//
// Bestaande rua, ruf, sp, adkim en aspf blijven staan. Zonder rua komt er
// dmarc@<domein> in. Bij alleenRua (punt dmarc-rua) blijft p zoals het is.
func (k *keurder) voorstelDMARC(s stand, u *Uitslag, alleenRua bool) voorstel {
	tags := s.dmarcTags
	if tags == nil {
		tags = map[string]string{}
	}
	nu := strings.ToLower(tags["p"])
	spfGoed := spfInOrde(s.spf) && status(u, "spf-lookups") != Slecht
	dkimGoed := status(u, "dkim") == Goed
	p := "none"
	var uitleg []string
	switch {
	case alleenRua && nu != "":
		p = nu
	case nu == "reject" || nu == "quarantine":
		p = nu
	case spfGoed && dkimGoed:
		p = "quarantine"
		uitleg = append(uitleg, "SPF en DKIM zijn in orde, dus nagemaakte mail kan meteen naar de spam (quarantine).")
	default:
		wat := "SPF en DKIM zijn"
		switch {
		case spfGoed:
			wat = "DKIM is"
		case dkimGoed:
			wat = "SPF is"
		}
		uitleg = append(uitleg, "Eerst p=none, als tussenstap: "+wat+" nog niet in orde. Lees een paar weken de rapporten, maak SPF en DKIM in orde en zet het daarna op p=quarantine.")
	}
	regel := []string{"v=DMARC1", "p=" + p}
	if tags["rua"] == "" {
		tags["rua"] = "mailto:dmarc@" + k.domein
		uitleg = append(uitleg, "Het adres dmarc@"+k.domein+" moet bestaan; vervang het anders door een adres dat je leest.")
	}
	for _, t := range []string{"sp", "rua", "ruf", "adkim", "aspf", "fo"} {
		if v := tags[t]; v != "" {
			regel = append(regel, t+"="+v)
		}
	}
	if len(s.dmarc) > 1 {
		uitleg = append(uitleg, "Haal de andere DMARC-regels weg: er mag er maar één staan.")
	}
	return voorstel{strings.Join(regel, "; "), "_dmarc." + k.domein + " (TXT)", strings.Join(uitleg, " ")}
}

// dmarcStreng: DMARC staat nu op quarantine of reject voor alle mail.
func dmarcStreng(s stand) bool {
	p := strings.ToLower(s.dmarcTags["p"])
	pct := s.dmarcTags["pct"]
	return len(s.dmarc) == 1 && (p == "reject" || p == "quarantine") && (pct == "" || pct == "100")
}

// spfInOrde: precies één SPF-regel, die netjes afsluit.
func spfInOrde(recs []string) bool {
	if len(recs) != 1 {
		return false
	}
	l := strings.ToLower(recs[0])
	return (strings.Contains(l, "-all") || strings.Contains(l, "~all") || strings.Contains(l, "redirect=")) &&
		!strings.Contains(l, "+all") && !strings.Contains(l, "?all")
}

// ---------------------------------------------------------------- SPF

// spfIncludes zijn de includes van mailleveranciers die we zeker weten.
var spfIncludes = map[string]string{
	"Microsoft 365":    "include:spf.protection.outlook.com",
	"Google Workspace": "include:_spf.google.com",
	"TransIP":          "include:_spf.transip.email",
	"Proton Mail":      "include:_spf.protonmail.ch",
	"Fastmail":         "include:spf.messagingengine.com",
}

// voorstelSPF maakt één SPF-regel van wat er staat: de bestaande
// onderdelen (zonder ptr en zonder de oude afsluiting), de include van de
// mailleverancier als die ontbreekt, en als afsluiting:
//   - ~all als DMARC al streng staat: dan beslist DMARC, en ~all voorkomt
//     dat doorgestuurde mail al op SPF sneuvelt voordat DKIM bekeken is;
//   - -all als DMARC niet streng staat: dan is -all het enige dat ontvangers
//     laat weigeren.
func (k *keurder) voorstelSPF(s stand, u *Uitslag) voorstel {
	naam := k.domein + " (TXT)"
	var delen []string
	gezien := map[string]bool{}
	redirect := ""
	voeg := func(d string) {
		l := strings.ToLower(d)
		if !gezien[l] {
			gezien[l] = true
			delen = append(delen, d)
		}
	}
	for _, r := range s.spf {
		for _, v := range strings.Fields(r)[1:] {
			l := strings.ToLower(strings.TrimLeft(v, "+"))
			switch {
			case strings.TrimLeft(l, "-~?") == "all":
			case l == "ptr" || strings.HasPrefix(l, "ptr:"):
			case strings.HasPrefix(l, "redirect="):
				redirect = v
			default:
				voeg(strings.TrimLeft(v, "+"))
			}
		}
	}
	var uitleg []string
	mail := feit(u, "E-mail")
	for _, w := range strings.Split(mail, " en ") {
		if inc, ok := spfIncludes[w]; ok && !gezien[inc] {
			voeg(inc)
			if len(s.spf) > 0 {
				uitleg = append(uitleg, "We zetten "+inc+" erbij omdat je mail bij "+w+" binnenkomt.")
			}
		}
	}
	if len(s.spf) > 1 {
		uitleg = append(uitleg, "Dit voegt je SPF-regels samen tot één; haal de andere weg.")
	}
	eind := "-all"
	if dmarcStreng(s) {
		eind = "~all"
	}
	switch {
	case len(delen) == 0 && redirect != "":
		return voorstel{"v=spf1 " + redirect, naam, strings.Join(uitleg, " ")}
	case len(delen) == 0 && (mail == "geen mailserver" || mail == "ontvangt bewust geen mail"):
		return voorstel{"v=spf1 -all", naam, "Je ontvangt geen mail op dit domein; deze regel zegt dat niemand namens het domein mag mailen. Verstuur je er wel mail mee, zet dan de include van die dienst vóór -all."}
	case len(delen) == 0:
		// Onbekende leverancier: mx is de veilige gok (de servers die je mail
		// ontvangen, versturen vaak ook), en ~all weigert niets hard.
		return voorstel{"v=spf1 mx ~all", naam, "We weten niet via welke dienst je mailt. Vraag je mailleverancier welke include erbij hoort en zet die vóór ~all."}
	}
	if eind == "-all" && !dmarcStreng(s) {
		uitleg = append(uitleg, "Zet je DMARC op quarantine, dan mag de regel ook op ~all eindigen.")
	}
	return voorstel{"v=spf1 " + strings.Join(delen, " ") + " " + eind, naam, strings.Join(uitleg, " ")}
}

// ---------------------------------------------------------------- MTA-STS

// voorstelMTASTS: eerst testing (een dag), dan enforce (een week). Of de
// mailservers zelf een geldig certificaat hebben, meten we niet (we maken
// geen verbinding met mailservers); daarom altijd eerst testing.
func (k *keurder) voorstelMTASTS(s stand) voorstel {
	mode, maxAge := "testing", 86400
	uitleg := "Eerst testing: er wordt nog niets geweigerd. Staan er na twee weken geen fouten in de TLS-rapporten, zet mode dan op enforce en max_age op 604800, en verhoog het id."
	if s.stsMode == "testing" {
		mode, maxAge = "enforce", 604800
		uitleg = "Verhoog het id in het TXT-record elke keer als je het bestand wijzigt."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "TXT-record op _mta-sts.%s:\nv=STSv1; id=%s\n\nBestand https://mta-sts.%s/.well-known/mta-sts.txt:\nversion: STSv1\nmode: %s\n", k.domein, time.Now().Format("20060102"), k.domein, mode)
	for _, h := range s.mx {
		fmt.Fprintf(&b, "mx: %s\n", h)
	}
	fmt.Fprintf(&b, "max_age: %d", maxAge)
	return voorstel{b.String(), "_mta-sts." + k.domein + " (TXT) en https://mta-sts." + k.domein + "/.well-known/mta-sts.txt",
		uitleg + " De naam mta-sts." + k.domein + " heeft een website met een geldig certificaat nodig."}
}

// ---------------------------------------------------------------- CAA

// caaNamen koppelt de uitgever van een certificaat aan de naam in CAA.
var caaNamen = []struct{ bevat, naam string }{
	{"let's encrypt", "letsencrypt.org"}, {"google trust services", "pki.goog"},
	{"sectigo", "sectigo.com"}, {"comodo", "sectigo.com"}, {"zerossl", "sectigo.com"},
	{"digicert", "digicert.com"}, {"geotrust", "digicert.com"}, {"rapidssl", "digicert.com"}, {"thawte", "digicert.com"},
	{"globalsign", "globalsign.com"}, {"amazon", "amazon.com"}, {"entrust", "entrust.net"},
	{"buypass", "buypass.com"}, {"certum", "certum.pl"}, {"asseco", "certum.pl"}, {"ssl corporation", "ssl.com"},
	{"harica", "harica.gr"}, {"actalis", "actalis.it"},
}

func caaNaam(uitgever string) string {
	l := strings.ToLower(uitgever)
	for _, c := range caaNamen {
		if strings.Contains(l, c.bevat) {
			return c.naam
		}
	}
	return ""
}

// voorstelCAA: alleen issue, voor de leveranciers van de certificaten die we
// echt zagen, op de website en op de subdomeinen.
func (k *keurder) voorstelCAA(u *Uitslag, sub subInfo) voorstel {
	var uitgevers []string
	if k.w != nil && k.w.staat != nil && len(k.w.staat.PeerCertificates) > 0 {
		uitgevers = append(uitgevers, uitgever(k.w.staat.PeerCertificates[0]))
	}
	uitgevers = append(uitgevers, sub.uitgevers...)
	namen := map[string]bool{}
	var onbekend []string
	for _, x := range uniek(uitgevers) {
		if n := caaNaam(x); n != "" {
			namen[n] = true
		} else {
			onbekend = append(onbekend, x)
		}
	}
	naam := k.domein + " (CAA, één record per regel)"
	if len(namen) == 0 {
		t := "We zagen geen certificaat om een voorstel op te baseren. Vraag je webbouwer welke leverancier je certificaat maakt; die zet je dan in een CAA-record als 0 issue \"<leverancier>\"."
		if len(onbekend) > 0 {
			t = "We kennen de CAA-naam van je certificaatleverancier (" + strings.Join(onbekend, ", ") + ") niet. Vraag die leverancier welke naam in het CAA-record hoort."
		}
		return voorstel{"", naam, t}
	}
	var regels []string
	for _, n := range sleutels(namen) {
		regels = append(regels, fmt.Sprintf("0 issue %q", n))
	}
	uitleg := "Gebaseerd op het certificaat van je website"
	if len(sub.uitgevers) > 0 {
		uitleg += " en je subdomeinen"
	}
	uitleg += ". Gebruik je ergens anders nog een andere leverancier, zet die er dan ook bij."
	if len(onbekend) > 0 {
		uitleg += " Van " + strings.Join(onbekend, ", ") + " kennen we de CAA-naam niet."
	}
	if strings.Contains(feit(u, "DNS"), "Cloudflare") {
		uitleg += " Cloudflare zet zelf de records voor zijn eigen leveranciers erbij."
	}
	return voorstel{strings.Join(regels, "\n"), naam, uitleg}
}

// ---------------------------------------------------------------- web

// voorstelHSTS: een jaar. includeSubDomains alleen als het er al stond:
// het geldt ook voor subdomeinen die we niet kennen, en een intern
// subdomein zonder https is dan onbereikbaar.
func (k *keurder) voorstelHSTS(sub subInfo, naam string) voorstel {
	v := "max-age=31536000"
	nu := ""
	if k.w != nil && k.w.eerste != nil {
		nu = strings.ToLower(k.w.eerste.Header.Get("Strict-Transport-Security"))
	}
	uitleg := ""
	if strings.Contains(nu, "includesubdomains") {
		v += "; includeSubDomains"
	} else if sub.gemeten > 0 && sub.allesHTTPS {
		uitleg = "Al je subdomeinen die we vonden werken via https. Weet je zeker dat dat voor álle subdomeinen geldt, zet er dan \"; includeSubDomains\" achter."
	}
	if strings.Contains(nu, "preload") {
		v += "; preload"
	}
	return voorstel{"Strict-Transport-Security: " + v, naam, uitleg}
}

// voorstelCSP: een veilige startregel als Report-Only. Die blokkeert niets;
// de browser meldt alleen wat het beleid zou tegenhouden. De externe hosts
// komen uit de homepage.
func (k *keurder) voorstelCSP(naam string) voorstel {
	soort := map[string]map[string]bool{"script": {}, "style": {}, "img": {}, "font": {}, "frame": {}}
	if k.w != nil {
		for _, m := range bron.FindAllSubmatch(k.w.body, -1) {
			u, err := url.Parse(strings.TrimSpace(string(m[2])))
			if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "") {
				continue
			}
			h := strings.ToLower(u.Hostname())
			if h == k.domein || strings.HasSuffix(h, "."+k.domein) || !hostnaamRe.MatchString(h) {
				continue
			}
			switch strings.ToLower(string(m[1])) {
			case "script":
				soort["script"][h] = true
			case "link":
				if strings.Contains(u.Path, ".css") || strings.Contains(h, "fonts.googleapis") {
					soort["style"][h] = true
				}
			case "img", "source", "video", "audio":
				soort["img"][h] = true
			case "iframe":
				soort["frame"][h] = true
			}
		}
	}
	if soort["style"]["fonts.googleapis.com"] {
		soort["font"]["fonts.gstatic.com"] = true
	}
	hosts := func(s string) string {
		var uit []string
		for _, h := range sleutels(soort[s]) {
			uit = append(uit, "https://"+h)
		}
		if len(uit) > 10 {
			uit = uit[:10]
		}
		return strings.Join(append([]string{""}, uit...), " ")
	}
	frame := hosts("frame")
	if frame == "" {
		frame = " 'none'"
	} else {
		frame = " 'self'" + frame
	}
	beleid := "default-src 'self'; script-src 'self'" + hosts("script") + "; style-src 'self'" + hosts("style") +
		"; img-src 'self' data:" + hosts("img") + "; font-src 'self'" + hosts("font") + "; connect-src 'self'" + hosts("script") +
		"; frame-src" + frame + "; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"
	uitleg := "Eerst als Report-Only: dan blokkeert de browser niets en zie je in de console wat er nog mist. Scripts en stijlen die in de pagina zelf staan, moeten naar een eigen bestand of een nonce krijgen. Klopt alles, zet het dan om naar Content-Security-Policy."
	if k.w != nil && k.w.kop("Content-Security-Policy") != "" {
		uitleg = "Laat je huidige beleid staan en zet dit ernaast als Report-Only. " + uitleg
	}
	return voorstel{"Content-Security-Policy-Report-Only: " + beleid, naam, uitleg}
}

// voorstelSecurityTxt: Contact uit de bestaande security.txt, anders
// security@domein; Expires over een jaar.
func voorstelSecurityTxt(s stand, domein, host string, nu time.Time) voorstel {
	contact := s.secContact
	uitleg := "Het adres security@" + domein + " moet bestaan; vervang het anders door een adres dat je leest. Zet een herinnering om Expires elk jaar bij te werken."
	if len(contact) == 0 {
		contact = []string{"mailto:security@" + domein}
	} else {
		uitleg = "Zet een herinnering om Expires elk jaar bij te werken."
	}
	var b strings.Builder
	for _, c := range contact {
		fmt.Fprintf(&b, "Contact: %s\n", kort(schoon(c), 200))
	}
	verloopt := time.Date(nu.Year()+1, nu.Month(), nu.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -1)
	fmt.Fprintf(&b, "Expires: %s\nPreferred-Languages: nl, en\nCanonical: https://%s/.well-known/security.txt", verloopt.Format(time.RFC3339), host)
	return voorstel{b.String(), "https://" + host + "/.well-known/security.txt (tekstbestand)", uitleg}
}

// zoekCrawlers zijn de AI-crawlers die bepalen of een assistent je kan
// noemen. De rest leest voor training.
var zoekCrawlers = map[string]bool{"OAI-SearchBot": true, "Claude-SearchBot": true, "PerplexityBot": true}

// voorstelRobots: een groep die de dichte AI-crawlers weer toelaat. Bij
// Slecht alleen de zoekcrawlers; training mag de eigenaar zelf kiezen. De
// regels van User-agent: * (behalve Disallow: /) gaan mee, anders mag de
// crawler ineens ook in /admin.
func (k *keurder) voorstelRobots(s Status) voorstel {
	robots := ""
	host := k.domein
	if k.w != nil {
		robots, host = k.w.robots, leegAls(k.w.eind, k.w.host)
	}
	dicht, apart := dichteCrawlers(robots)
	var kies []string
	eigen := false
	for _, a := range dicht {
		if s == Matig || zoekCrawlers[a] {
			kies = append(kies, a)
			eigen = eigen || apart[a]
		}
	}
	if len(kies) == 0 {
		kies = dicht
	}
	var b strings.Builder
	for _, a := range kies {
		fmt.Fprintf(&b, "User-agent: %s\n", a)
	}
	b.WriteString("Allow: /")
	ster, _ := robotsGroep(robots, "*")
	for _, r := range ster {
		kv := strings.SplitN(r, ":", 2)
		if len(kv) != 2 || kv[0] != "disallow" || kv[1] == "" || kv[1] == "/" || kv[1] == "/*" {
			continue
		}
		fmt.Fprintf(&b, "\nDisallow: %s", kort(schoon(kv[1]), 200))
	}
	uitleg := "Zet deze groep in je robots.txt."
	if eigen {
		uitleg += " Er staat al een eigen groep voor een van deze crawlers; vervang die door deze."
	}
	if s == Slecht {
		uitleg += " Crawlers voor training (GPTBot, ClaudeBot, CCBot, Google-Extended) mogen dicht blijven als je dat wilt; voor genoemd worden zijn de zoekcrawlers genoeg."
	} else {
		uitleg += " Alleen als je wilt dat deze diensten je tekst ook gebruiken; dicht laten is ook een prima keuze."
	}
	return voorstel{b.String(), "https://" + host + "/robots.txt", uitleg}
}

// voorstelLLMS: een skelet met de titel en beschrijving van de homepage.
func (k *keurder) voorstelLLMS() voorstel {
	host, titel, besch, sitemap := k.domein, Weergave(k.domein), "Eén of twee zinnen over wat je doet, voor wie en waar.", ""
	if k.w != nil {
		host = leegAls(k.w.eind, leegAls(k.w.host, k.domein))
		titel = leegAls(kort(schoon(strings.TrimSpace(k.w.info.titel)), 80), titel)
		besch = leegAls(kort(schoon(strings.TrimSpace(k.w.info.beschrijving)), 200), besch)
		sitemap = k.w.sitemapURL
	}
	basis := "https://" + host + "/"
	t := fmt.Sprintf("# %s\n\n> %s\n\n## Belangrijkste pagina's\n\n- [Home](%s): wat je doet en voor wie\n- [Diensten](%sdiensten/): wat je aanbiedt\n- [Contact](%scontact/): hoe klanten je bereiken", titel, besch, basis, basis, basis)
	if sitemap != "" {
		t += "\n\n## Meer\n\n- [Sitemap](" + sitemap + ")"
	}
	return voorstel{t, basis + "llms.txt (tekstbestand)", "Pas de pagina's aan naar de adressen op jouw site, en houd het kort."}
}

// voorstelJSONLD: een Organization-skelet met de domeinnaam, en het
// KvK-nummer als dat op de homepage staat.
func (k *keurder) voorstelJSONLD() voorstel {
	host := k.domein
	if k.w != nil {
		host = leegAls(k.w.eind, leegAls(k.w.host, k.domein))
	}
	type waarde struct {
		Type       string `json:"@type"`
		PropertyID string `json:"propertyID"`
		Value      string `json:"value"`
	}
	type adres struct {
		Type     string `json:"@type"`
		Straat   string `json:"streetAddress"`
		Postcode string `json:"postalCode"`
		Plaats   string `json:"addressLocality"`
		Land     string `json:"addressCountry"`
	}
	org := struct {
		Context string  `json:"@context"`
		Type    string  `json:"@type"`
		Name    string  `json:"name"`
		URL     string  `json:"url"`
		Logo    string  `json:"logo"`
		Email   string  `json:"email"`
		Tel     string  `json:"telephone"`
		Adres   adres   `json:"address"`
		KvK     *waarde `json:"identifier,omitempty"`
	}{"https://schema.org", "Organization", "Naam van je bedrijf", "https://" + host + "/", "https://" + host + "/logo.png",
		"info@" + k.domein, "+31 ...", adres{"PostalAddress", "Straat 1", "1234 AB", "Plaats", "NL"}, nil}
	if k.w != nil {
		if m := kvkRe.FindStringSubmatch(k.w.info.tekst); m != nil {
			org.KvK = &waarde{"PropertyValue", "KvK", m[1]}
		}
	}
	j, _ := json.MarshalIndent(org, "", "  ")
	return voorstel{"<script type=\"application/ld+json\">\n" + string(j) + "\n</script>", "in de <head> van je homepage",
		"Vervang naam, logo, mailadres, telefoon en adres door je eigen gegevens. Een winkel of praktijk kan LocalBusiness gebruiken in plaats van Organization."}
}
