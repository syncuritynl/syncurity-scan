package keuring

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"unicode"

	"github.com/miekg/dns"
)

// Punten die alleen DNS gebruiken, via de eigen validerende resolver.
// Geen verbinding met mailservers.

// dmarcExtern: stuurt de DMARC-regel rapporten naar een ander domein, dan
// moet dat domein met een TXT-record laten weten dat het ze aanneemt
// (RFC 7489 7.1). Anders komen de rapporten nooit aan.
func (k *keurder) dmarcExtern(ctx context.Context, tags map[string]string) Punt {
	const id, tech, titel = "dmarc-extern", "DMARC rua", "Rapportadres neemt je rapporten aan"
	if tags == nil {
		return punt(id, tech, NVT, titel, "Zonder DMARC-regel zijn er ook geen rapporten.")
	}
	var extern []string
	for _, veld := range []string{"rua", "ruf"} {
		for _, adres := range strings.Split(tags[veld], ",") {
			adres = strings.TrimSpace(adres)
			if !strings.HasPrefix(strings.ToLower(adres), "mailto:") {
				continue
			}
			at := strings.LastIndex(adres, "@")
			if at < 0 {
				continue
			}
			d := strings.ToLower(strings.TrimRight(strings.SplitN(adres[at+1:], "!", 2)[0], "."))
			if d == k.domein || strings.HasSuffix(d, "."+k.domein) || strings.HasSuffix(k.domein, "."+d) {
				continue
			}
			extern = append(extern, d)
		}
	}
	extern = uniek(extern)
	if len(extern) == 0 {
		return punt(id, tech, NVT, titel, "Je rapporten gaan naar je eigen domein; daar is geen extra toestemming voor nodig.")
	}
	var mist, ok []string
	for _, d := range extern {
		naam := k.domein + "._report._dmarc." + d
		gevonden := false
		for _, t := range k.r.TXT(ctx, naam) {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=dmarc1") {
				gevonden = true
			}
		}
		if gevonden {
			ok = append(ok, d)
		} else {
			mist = append(mist, naam)
		}
	}
	if len(mist) > 0 {
		return punt(id, tech, Matig, "Je rapporten komen waarschijnlijk niet aan",
			"Je DMARC-regel stuurt rapporten naar een ander domein, maar dat domein laat niet weten dat het ze aanneemt. Mailservers sturen de rapporten dan niet. De partij die je rapporten verwerkt, moet één TXT-record zetten.").met("Ontbreekt: " + kort(strings.Join(mist, ", "), 140)).metDetail(mist...)
	}
	return punt(id, tech, Goed, titel, "Je rapporten gaan naar een ander domein, en dat domein laat netjes weten dat het ze aanneemt.").met("Akkoord van: " + strings.Join(ok, ", "))
}

// dmarcSub: subdomeinen vallen onder sp=. Staat die op none terwijl het
// hoofddomein streng is, dan kan iemand mailen als factuur.jouwdomein.nl.
func dmarcSub(domein string, tags map[string]string) Punt {
	const id, tech, titel = "dmarc-sub", "DMARC sp", "Ook subdomeinen beschermd"
	if tags == nil {
		return punt(id, tech, NVT, titel, "Zonder DMARC-regel valt hier niets te beoordelen.")
	}
	p := strings.ToLower(tags["p"])
	if p != "reject" && p != "quarantine" {
		return punt(id, tech, NVT, titel, "Je hoofddomein is nog niet streng beschermd (zie de DMARC-regel); begin daar.")
	}
	for _, veld := range []string{"sp", "np"} {
		if strings.ToLower(tags[veld]) == "none" {
			return punt(id, tech, Matig, "Subdomeinen zijn niet beschermd",
				"Je DMARC-regel beschermt je hoofddomein, maar zet "+veld+"=none voor subdomeinen. Iemand kan dan mailen als bijvoorbeeld factuur."+domein+", en die mail komt gewoon aan.").met(veld + "=none")
		}
	}
	return punt(id, tech, Goed, titel, "Je DMARC-regel beschermt ook alle subdomeinen, zodat niemand mail kan versturen als bijvoorbeeld factuur."+domein+".")
}

// geenMail: een domein dat geen mail ontvangt, hoort dat ook vast te leggen:
// null MX, SPF -all en DMARC reject. Anders is het een makkelijk doelwit.
func (k *keurder) geenMail(ctx context.Context, ontvangt, nullMX bool, spf string, tags map[string]string) Punt {
	const id, tech, titel = "geen-mail", "null MX", "Geen mail, en dat vastgelegd"
	if ontvangt {
		return punt(id, tech, NVT, titel, "Deze domeinnaam ontvangt mail, dus dit punt telt niet mee.")
	}
	var mist []string
	if !nullMX {
		mist = append(mist, "null MX (MX 0 .)")
	}
	if !strings.HasSuffix(strings.ToLower(strings.TrimSpace(spf)), " -all") || strings.Contains(strings.ToLower(spf), "include:") {
		mist = append(mist, "SPF v=spf1 -all")
	}
	if tags == nil || strings.ToLower(tags["p"]) != "reject" {
		mist = append(mist, "DMARC p=reject")
	}
	if len(mist) == 0 {
		return punt(id, tech, Goed, titel, "Deze domeinnaam ontvangt en verstuurt geen mail, en dat staat er ook duidelijk: niemand kan hem gebruiken om nep-mail te sturen.")
	}
	return punt(id, tech, Matig, "Geen mail, maar niet dichtgezet",
		"Deze domeinnaam gebruikt geen mail. Zet dat dan ook vast, anders kan iemand er nep-mail mee sturen. Het ontbreekt nog: "+strings.Join(mist, ", ")+".").met("Ontbreekt: " + strings.Join(mist, ", "))
}

// spfFouten: dingen in de SPF-regel die mailservers afkeuren of die niet
// doen wat de eigenaar denkt (RFC 7208).
func spfFouten(record string) Punt {
	const id, tech, titel = "spf-fouten", "SPF", "SPF-regel zonder fouten"
	if record == "" {
		return punt(id, tech, NVT, titel, "Zonder geldige SPF-regel valt hier niets te controleren.")
	}
	var fout []string
	delen := strings.Fields(strings.ToLower(record))
	for i, d := range delen {
		kaal := strings.TrimLeft(d, "+-~?")
		if kaal == "ptr" || strings.HasPrefix(kaal, "ptr:") {
			fout = append(fout, "ptr: traag en afgeraden; mailservers mogen het negeren")
		}
		if kaal == "all" && i < len(delen)-1 {
			if !strings.HasPrefix(delen[i+1], "exp=") {
				fout = append(fout, "na all staat nog iets ("+strings.Join(delen[i+1:], " ")+"); dat wordt nooit gelezen")
			}
		}
		if d == "+all" {
			fout = append(fout, "+all: iedereen mag mailen namens jou")
		}
	}
	if len(record) > 450 {
		fout = append(fout, fmt.Sprintf("de regel is %d tekens lang; boven de 450 passen niet alle DNS-antwoorden meer", len(record)))
	}
	if len(fout) == 0 {
		return punt(id, tech, Goed, titel, "Je SPF-regel bevat geen onderdelen die mailservers afkeuren.")
	}
	return punt(id, tech, Matig, "Fouten in je SPF-regel",
		"Je SPF-regel bevat onderdelen die mailservers negeren of afkeuren. Dan doet de regel niet helemaal wat je denkt.").met(kort(fout[0], 140)).metDetail(fout...)
}

// mxGeldig: een MX moet naar een naam met een adres wijzen, niet naar een
// IP-adres of een CNAME (RFC 5321 en 2181).
func (k *keurder) mxGeldig(ctx context.Context, mx []string) Punt {
	const id, tech, titel = "mx-geldig", "MX", "Mailservers goed vastgelegd"
	if len(mx) == 0 {
		return punt(id, tech, NVT, titel, "Deze domeinnaam ontvangt geen mail.")
	}
	var fout []string
	for _, h := range mx {
		if _, err := netip.ParseAddr(h); err == nil {
			fout = append(fout, h+" is een IP-adres; een MX moet een naam zijn")
			continue
		}
		if rrs, _, _, _ := k.r.Records(ctx, h, dns.TypeCNAME); len(rrs) > 0 {
			fout = append(fout, h+" is een CNAME; een MX moet direct naar een adres wijzen")
		}
		v4, v6 := k.r.Adressen(ctx, h, true), k.r.Adressen(ctx, h, false)
		if len(v4)+len(v6) == 0 {
			fout = append(fout, h+" heeft geen adres")
		}
	}
	gezien := strings.Join(mx, ", ")
	if len(fout) == 0 {
		return punt(id, tech, Goed, titel, "Je mailservers staan goed in de DNS en zijn te vinden.").met(kort(gezien, 140))
	}
	st := Matig
	if len(fout) >= len(mx) {
		st = Slecht
	}
	return punt(id, tech, st, "Fout in je mailservers",
		"Een of meer van je mailservers staan niet goed in de DNS. Mail kan daardoor vertraagd of geweigerd worden.").met(kort(fout[0], 140)).metDetail(fout...)
}

// mxDNSSEC: staat de zone van de mailserver onder DNSSEC? Nodig voor DANE.
func (k *keurder) mxDNSSEC(ctx context.Context, mx []string) Punt {
	const id, tech, titel = "mx-dnssec", "DNSSEC · MX", "Mailserver-domein ondertekend"
	if len(mx) == 0 {
		return punt(id, tech, NVT, titel, "Deze domeinnaam ontvangt geen mail.")
	}
	var niet, wel []string
	eigen := false
	for _, h := range mx {
		if h == k.domein || strings.HasSuffix(h, "."+k.domein) {
			eigen = true
		}
		_, ad, _, err := k.r.Records(ctx, h, dns.TypeA)
		if err == nil && ad {
			wel = append(wel, h)
		} else {
			niet = append(niet, h)
		}
	}
	if len(niet) > 0 && !eigen {
		return punt(id, tech, NVT, titel, "Je mail loopt via een leverancier waarvan het domein niet ondertekend is. Dat ligt bij hen, niet bij jou, dus dit punt telt niet mee.").met(kort(strings.Join(niet, ", "), 140))
	}
	if len(niet) == 0 {
		return punt(id, tech, Goed, titel, "De domeinen van je mailservers zijn ondertekend met DNSSEC. Andere servers kunnen dus controleren dat ze bij de echte mailserver uitkomen.").met(kort(strings.Join(wel, ", "), 140))
	}
	return punt(id, tech, Matig, "Mailserver-domein niet ondertekend",
		"Je mailserver staat op je eigen domein, maar dat is niet ondertekend met DNSSEC. Daardoor kan je mail niet met DANE worden beschermd.").met(kort(strings.Join(niet, ", "), 140))
}

// caaCA: past de CAA-regel bij de leverancier van het huidige certificaat?
// Anders mislukt de volgende vernieuwing en is de site plots onveilig.
func (k *keurder) caaCA(ctx context.Context, w *web) Punt {
	const id, tech, titel = "caa-ca", "CAA · issuer", "CAA past bij je certificaat"
	rrs, _, _, _ := k.r.Records(ctx, k.domein, dns.TypeCAA)
	var issue []string
	for _, rr := range rrs {
		c := rr.(*dns.CAA)
		if c.Tag == "issue" {
			issue = append(issue, strings.ToLower(strings.TrimSpace(strings.SplitN(c.Value, ";", 2)[0])))
		}
	}
	if len(issue) == 0 {
		return punt(id, tech, NVT, titel, "Er staat geen CAA-regel (of alleen voor wildcards), dus elke leverancier mag certificaten maken.")
	}
	if w.staat == nil || len(w.staat.PeerCertificates) == 0 {
		return punt(id, tech, NVT, titel, "We konden geen certificaat ophalen om te vergelijken.")
	}
	org := strings.ToLower(uitgever(w.staat.PeerCertificates[0]) + " " + strings.Join(w.staat.PeerCertificates[0].Issuer.Organization, " "))
	var verwacht []string
	for naam, domeinen := range caaVanLeverancier {
		if strings.Contains(org, naam) {
			verwacht = append(verwacht, domeinen...)
		}
	}
	gezien := "Certificaat van " + uitgever(w.staat.PeerCertificates[0]) + "; CAA: " + strings.Join(issue, ", ")
	if len(verwacht) == 0 {
		return punt(id, tech, NVT, titel, "We kennen de CAA-naam van je certificaatleverancier niet, dus kunnen dit niet vergelijken.").met(gezien)
	}
	for _, i := range issue {
		for _, v := range verwacht {
			if i == v {
				return punt(id, tech, Goed, titel, "Je CAA-regel staat de leverancier van je huidige certificaat toe. De volgende vernieuwing gaat dus goed.").met(gezien)
			}
		}
	}
	if len(issue) == 1 && issue[0] == "" {
		return punt(id, tech, Slecht, "CAA verbiedt elk certificaat",
			"Je CAA-regel staat geen enkele leverancier toe. Bij de volgende vernieuwing krijgt je site geen nieuw certificaat.").met(gezien)
	}
	return punt(id, tech, Slecht, "CAA past niet bij je certificaat",
		"Je huidige certificaat komt van een leverancier die je CAA-regel niet toestaat. Bij de volgende vernieuwing weigert die leverancier, en dan verloopt je certificaat. Zet de juiste naam in de CAA-regel.").met(gezien).metDetail("Toe te voegen: 0 issue \"" + verwacht[0] + "\"")
}

// De CAA-namen van de bekende certificaatleveranciers (hun eigen documentatie).
var caaVanLeverancier = map[string][]string{
	"let's encrypt": {"letsencrypt.org"}, "sectigo": {"sectigo.com", "comodoca.com", "comodo.com", "usertrust.com", "trust-provider.com"},
	"zerossl": {"sectigo.com", "zerossl.com"}, "digicert": {"digicert.com", "symantec.com", "thawte.com", "geotrust.com", "rapidssl.com"},
	"globalsign": {"globalsign.com"}, "google trust services": {"pki.goog"}, "amazon": {"amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com"},
	"godaddy": {"godaddy.com", "starfieldtech.com"}, "buypass": {"buypass.com", "buypass.no"}, "certum": {"certum.pl", "certum.eu"},
	"entrust": {"entrust.net", "affirmtrust.com"}, "harica": {"harica.gr"}, "ssl.com": {"ssl.com"}, "microsoft": {"digicert.com", "microsoft.com"},
	"cloudflare": {"digicert.com", "letsencrypt.org", "pki.goog", "sectigo.com", "ssl.com"},
}

// txtSchoon: onzichtbare of verkeerd geplakte tekens in TXT-records. Een
// SPF- of verificatieregel met een onzichtbaar teken werkt gewoon niet.
func (k *keurder) txtSchoon(ctx context.Context) Punt {
	const id, tech, titel = "txt-schoon", "TXT", "DNS-regels zonder verborgen tekens"
	var vuil []string
	for _, naam := range []string{k.domein, "_dmarc." + k.domein} {
		for _, t := range k.r.TXT(ctx, naam) {
			for _, r := range t {
				if r == '\u200b' || r == '\u200c' || r == '\u200d' || r == '\ufeff' || r == '\u00a0' || unicode.Is(unicode.Bidi_Control, r) ||
					r == '\u201c' || r == '\u201d' || r == '\u2018' || r == '\u2019' || (unicode.IsControl(r) && r != '\t') {
					vuil = append(vuil, fmt.Sprintf("%s: %q bevat teken U+%04X", naam, kort(t, 60), r))
					break
				}
			}
		}
	}
	if len(vuil) == 0 {
		return punt(id, tech, Goed, titel, "Je TXT-regels (zoals SPF en DMARC) bevatten geen onzichtbare of verkeerd geplakte tekens.")
	}
	return punt(id, tech, Matig, "Verborgen tekens in je DNS",
		"Een of meer TXT-regels bevatten een onzichtbaar of verkeerd geplakt teken, vaak uit een tekstverwerker. Mailservers en andere diensten lezen die regel dan verkeerd.").met(kort(vuil[0], 140)).metDetail(vuil...)
}

// stsMX: de mx-regels in het MTA-STS-beleid moeten alle echte mailservers
// dekken. Anders kaatst mail terug zodra het beleid op enforce staat.
func stsMX(mx []string, mode string, patronen []string) Punt {
	const id, tech, titel = "mta-sts-mx", "MTA-STS mx", "MTA-STS klopt met je mailservers"
	if len(mx) == 0 {
		return punt(id, tech, NVT, titel, "Deze domeinnaam ontvangt geen mail.")
	}
	if mode == "" || len(patronen) == 0 {
		return punt(id, tech, NVT, titel, "Er is geen MTA-STS-beleid om te vergelijken.")
	}
	var buiten []string
	for _, h := range mx {
		ok := false
		for _, p := range patronen {
			p = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p), "."))
			if p == h || (strings.HasPrefix(p, "*.") && strings.HasSuffix(h, p[1:]) && !strings.Contains(strings.TrimSuffix(h, p[1:]), ".")) {
				ok = true
			}
		}
		if !ok {
			buiten = append(buiten, h)
		}
	}
	gezien := "mx in het beleid: " + kort(strings.Join(patronen, ", "), 120)
	if len(buiten) == 0 {
		return punt(id, tech, Goed, titel, "Je MTA-STS-beleid noemt al je mailservers.").met(gezien)
	}
	st := Matig
	if mode == "enforce" {
		st = Slecht
	}
	return punt(id, tech, st, "MTA-STS noemt niet al je mailservers",
		"Je MTA-STS-beleid noemt niet al je mailservers. Staat het beleid op enforce, dan weigeren andere servers mail af te leveren bij de servers die er niet in staan.").met("Niet in het beleid: " + strings.Join(buiten, ", ")).metDetail(append([]string{gezien}, buiten...)...)
}
