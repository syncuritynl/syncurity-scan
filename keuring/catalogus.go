package keuring

// catalogusPunt: de vaste gegevens van een punt uit de tweede reeks, voor als de pagina
// niet te meten is (dan tonen we het punt met een neutrale naam) en voor de
// telling. De punten uit de eerste reeks hebben hun neutrale naam in de groep zelf.
type catalogusPunt struct {
	Groep, ID, Techniek, Naam string
}

var nieuwePunten = []catalogusPunt{
	{"verbinding", "cert-www", "X.509 · www", "Certificaat ook voor de naam met of zonder www"},
	{"verbinding", "tls-adressen", "IPv4 · IPv6", "Elk adres even veilig"},

	{"instellingen", "software", "WordPress", "WordPress bijgewerkt"},
	{"instellingen", "bibliotheken", "retire.js", "Scripts zonder bekende lekken"},
	{"instellingen", "php", "X-Powered-By", "Ondersteunde PHP-versie"},
	{"instellingen", "sri", "integrity", "Scripts van andere sites gecontroleerd"},
	{"instellingen", "formulieren", "form action", "Formulieren veilig verstuurd"},
	{"instellingen", "cors", "Access-Control-Allow-Origin", "Pagina niet voor elke site leesbaar"},
	{"instellingen", "corp-coop", "COOP · CORP", "Pagina afgeschermd van andere sites"},
	{"instellingen", "permissions", "Permissions-Policy", "Camera en microfoon dicht"},

	{"mail", "dmarc-sub", "DMARC sp", "Ook subdomeinen beschermd"},
	{"mail", "dmarc-extern", "DMARC rua", "Rapportadres neemt je rapporten aan"},
	{"mail", "spf-fouten", "SPF", "SPF-regel zonder fouten"},
	{"mail", "geen-mail", "null MX", "Geen mail, en dat vastgelegd"},
	{"mail", "mx-geldig", "MX", "Mailservers goed vastgelegd"},
	{"mail", "mx-dnssec", "DNSSEC · MX", "Mailserver-domein ondertekend"},
	{"mail", "mta-sts-mx", "MTA-STS mx", "MTA-STS klopt met je mailservers"},

	{"domein", "caa-ca", "CAA · issuer", "CAA past bij je certificaat"},
	{"domein", "txt-schoon", "TXT", "DNS-regels zonder verborgen tekens"},

	{"seo", "seo-robots", "robots.txt", "robots.txt in orde"},
	{"seo", "seo-links", "<a>", "Duidelijke linkteksten"},
	{"seo", "seo-omleidingen", "301 · 302", "Weinig doorverwijzingen"},

	{"geo", "geo-profielen", "sameAs", "Profielen gekoppeld"},
	{"geo", "geo-versheid", "© · dateModified", "Site oogt bijgehouden"},
	{"geo", "geo-schema", "JSON-LD", "Gestructureerde gegevens kloppen"},

	{"snelheid", "snel-afmetingen", "width · height", "Afbeeldingen met een vaste maat"},
	{"snelheid", "snel-eerste", "loading=lazy", "Eerste afbeelding laadt meteen"},
	{"snelheid", "snel-onderdelen", "DOM · requests", "Niet te veel onderdelen"},
	{"snelheid", "snel-gewicht", "Content-Length", "Afbeeldingen niet te zwaar"},
	{"snelheid", "snel-overbodig", "analytics.js", "Geen overbodige scripts"},
	{"snelheid", "snel-lettertypen", "font-display", "Tekst meteen zichtbaar"},
	{"snelheid", "snel-verkleind", "minify", "Bestanden verkleind"},
	{"snelheid", "snel-voorverbinden", "preconnect", "Andere servers op tijd verbonden"},

	{"vertrouwen", "bedrijfsgegevens", "art. 3:15d BW", "Bedrijfsgegevens compleet"},
	{"vertrouwen", "voorwaarden", "algemene voorwaarden", "Algemene voorwaarden te vinden"},
	{"vertrouwen", "vooraf", "Consent Mode", "Trackers wachten op toestemming"},
	{"vertrouwen", "opname", "sessie-opname", "Bezoekers worden niet opgenomen"},
	{"vertrouwen", "ingesloten", "fonts · iframes", "Ingesloten diensten privacyvriendelijk"},

	{"toegankelijk", "a11y-knoppen", "button-name", "Knoppen hebben een naam"},
	{"toegankelijk", "a11y-links", "link-name", "Links hebben een naam"},
	{"toegankelijk", "a11y-labels", "label", "Invulvelden hebben een label"},
	{"toegankelijk", "a11y-zoom", "viewport", "Inzoomen mogelijk"},
	{"toegankelijk", "a11y-overslaan", "<main> · skiplink", "Direct naar de inhoud"},
	{"toegankelijk", "a11y-koppen", "h1 · h2 · h3", "Kopjes in een logische volgorde"},
	{"toegankelijk", "a11y-frames", "iframe title", "Ingesloten onderdelen beschreven"},
	{"toegankelijk", "a11y-overlay", "overlay", "Geen schijnoplossing"},
	{"toegankelijk", "a11y-verklaring", "EAA", "Toegankelijkheidsverklaring"},
}

func catalogusGroep(groep string) []catalogusPunt {
	var uit []catalogusPunt
	for _, p := range nieuwePunten {
		if p.Groep == groep {
			uit = append(uit, p)
		}
	}
	return uit
}

// leegNieuw: de nieuwe punten van een groep als de pagina niet te meten is.
func leegNieuw(groep string, w *web) []Punt {
	var uit []Punt
	for _, p := range catalogusGroep(groep) {
		uit = append(uit, leeg(p.ID, p.Techniek, p.Naam, w))
	}
	return uit
}

// metStatus: de nieuwe punten van een groep met een vaste status en reden,
// bijvoorbeeld als er geen website is.
func metStatus(groep string, s Status, reden string) []Punt {
	var uit []Punt
	for _, p := range catalogusGroep(groep) {
		uit = append(uit, punt(p.ID, p.Techniek, s, p.Naam, reden))
	}
	return uit
}

// naPunt zet p direct na het punt met id na (of achteraan als dat er niet is).
func naPunt(ps []Punt, na string, p Punt) []Punt {
	for i, q := range ps {
		if q.ID == na {
			return append(ps[:i+1], append([]Punt{p}, ps[i+1:]...)...)
		}
	}
	return append(ps, p)
}
