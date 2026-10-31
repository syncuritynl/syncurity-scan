package keuring

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// DKIM-selectors kun je niet opvragen, je moet ze raden. Dit zijn de namen van
// de diensten die het MKB het meest gebruikt. Vinden we er geen, dan kijken we
// of _domainkey bestaat (11.5.c).
var dkimSelectors = []string{
	"selector1", "selector2", // Microsoft 365
	"google", // Google Workspace
	"default", "dkim", "mail", "smtp", "key1", "key2",
	"s1", "s2", "k1", "k2", "k3", // Mailchimp, Brevo e.d.
	"mxvault", "zoho", "protonmail", "protonmail2", "fm1", "fm2", "everlytickey1", "sig1", "transip",
}

func (k *keurder) mail(ctx context.Context) Groep {
	mx, nullMX := k.r.MX(ctx, k.domein)
	ontvangt := len(mx) > 0
	k.leg(func(s *stand) { s.mx = mx })
	g := Groep{ID: "mail", Naam: "Je e-mail", Kort: "E-mail"}

	dmarc, tags := k.dmarc(ctx)
	g.Punten = append(g.Punten, dmarc, dmarcRapport(dmarc, tags), dmarcSub(k.domein, tags), k.dmarcExtern(ctx, tags))
	spf, record := k.spf(ctx, ontvangt, dmarc.Status == Goed)
	g.Punten = append(g.Punten, spf, k.spfOpzoekingen(ctx, record), spfFouten(record), k.geenMail(ctx, ontvangt, nullMX, record, tags))

	if !ontvangt {
		reden := "Deze domeinnaam ontvangt geen mail, dus dit punt telt niet mee."
		g.Punten = append(g.Punten,
			punt("dkim", "DKIM", NVT, "Handtekening onder je mail", reden),
			punt("mta-sts", "MTA-STS", NVT, "Mail komt versleuteld aan", reden),
			punt("tls-rpt", "TLS-RPT", NVT, "Meldingen over versleuteling", reden),
			punt("dane", "DANE", NVT, "Mailserver vastgelegd in DNSSEC", reden))
		g.Punten = append(g.Punten, stsMX(nil, "", nil), k.mxGeldig(ctx, nil), k.mxDNSSEC(ctx, nil))
		return g
	}
	dane := k.dane(ctx, mx)
	sts := k.mtaSTS(ctx)
	if sts.Status == Matig && dane.Status == Goed {
		// DANE dwingt versleuteling ook af, en sterker: met DNSSEC in plaats van
		// een bestand op een webserver. Dan is MTA-STS geen tekortkoming.
		sts = punt("mta-sts", "MTA-STS", Goed, "Mail komt versleuteld aan",
			"Versleuteling wordt afgedwongen met DANE. Gmail controleert alleen MTA-STS; zet dat er voor de zekerheid bij.").met("via DANE")
	}
	g.Punten = append(g.Punten, k.dkim(ctx), sts, k.tlsRPT(ctx), dane)
	k.mu.Lock()
	mode, patronen := k.stand.stsMode, k.stand.stsMX
	k.mu.Unlock()
	g.Punten = append(g.Punten, stsMX(mx, mode, patronen), k.mxGeldig(ctx, mx), k.mxDNSSEC(ctx, mx))
	return g
}

func (k *keurder) dmarc(ctx context.Context) (Punt, map[string]string) {
	var recs []string
	for _, t := range k.r.TXT(ctx, "_dmarc."+k.domein) {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=dmarc1") {
			recs = append(recs, t)
		}
	}
	k.leg(func(s *stand) {
		s.dmarc = recs
		if len(recs) > 0 {
			s.dmarcTags = tagLijst(recs[0])
		}
	})
	if len(recs) == 0 {
		return punt("dmarc", "DMARC", Slecht, "Een ander kan mailen namens jou",
			"Er staat geen DMARC-regel. Iedereen kan mail sturen die van jouw domein lijkt te komen, bijvoorbeeld een nep-factuur aan je klanten."), nil
	}
	if len(recs) > 1 {
		return punt("dmarc", "DMARC", Slecht, "De DMARC-regel is ongeldig",
			"Er staan meerdere DMARC-regels. Dan negeren mailservers ze allemaal, alsof er geen staat.").met(kort(strings.Join(recs, " | "), 200)).
			metDetail(append([]string{"Op _dmarc." + k.domein + " staan " + fmt.Sprint(len(recs)) + " regels; er mag er één staan:"}, recs...)...), nil
	}
	tags := tagLijst(recs[0])
	gezien := kort(recs[0], 200)
	switch strings.ToLower(tags["p"]) {
	case "reject", "quarantine":
		if pct := tags["pct"]; pct != "" && pct != "100" {
			return punt("dmarc", "DMARC", Matig, "Je mail is maar deels beschermd",
				"Je DMARC-regel geldt maar voor een deel van de mail. De rest kan nog worden nagemaakt.").met(gezien), tags
		}
		return punt("dmarc", "DMARC", Goed, "Niemand kan mailen namens jou",
			"Mailservers weigeren mail die zich als jou voordoet, of zetten die apart.").met(gezien), tags
	case "none":
		return punt("dmarc", "DMARC", Matig, "Nagemaakte mail wordt nog doorgelaten",
			"Je hebt een DMARC-regel, maar die vraagt mailservers niets te doen. Nagemaakte mail komt dus nog gewoon aan.").met(gezien), tags
	default:
		return punt("dmarc", "DMARC", Slecht, "De DMARC-regel is ongeldig",
			"Je DMARC-regel mist een geldige instructie, dus mailservers doen er niets mee.").met(gezien), tags
	}
}

func dmarcRapport(dmarc Punt, tags map[string]string) Punt {
	if tags == nil {
		return punt("dmarc-rua", "DMARC rua", NVT, "Rapporten over je mail",
			"Zonder DMARC-regel zijn er ook geen rapporten.")
	}
	if rua := tags["rua"]; rua != "" {
		return punt("dmarc-rua", "DMARC rua", Goed, "Je krijgt rapporten over je mail",
			"Mailservers sturen je een overzicht van wie er namens jouw domein mailt. Zo zie je misbruik en vergeten afzenders.").met("Rapporten naar: " + kort(rua, 120))
	}
	return punt("dmarc-rua", "DMARC rua", Matig, "Je krijgt geen rapporten over je mail",
		"Je DMARC-regel vraagt niet om rapporten. Je ziet dus niet wie er namens jouw domein mailt, ook geen misbruik.")
}

// spf beoordeelt de SPF-regel. dmarcStreng is waar als DMARC op reject of
// quarantine staat: dan beslist DMARC wat er met nagemaakte mail gebeurt, en is
// ~all de aanbevolen afsluiting (internet.nl en M3AAWG keuren dat ook goed).
func (k *keurder) spf(ctx context.Context, ontvangt, dmarcStreng bool) (Punt, string) {
	var recs []string
	for _, t := range k.r.TXT(ctx, k.domein) {
		l := strings.ToLower(strings.TrimSpace(t))
		if l == "v=spf1" || strings.HasPrefix(l, "v=spf1 ") {
			recs = append(recs, t)
		}
	}
	k.leg(func(s *stand) { s.spf = recs })
	if len(recs) == 0 {
		uitleg := "Er staat geen SPF-regel. Mailservers weten niet welke servers namens jou mogen versturen."
		if !ontvangt {
			uitleg = "Er staat geen SPF-regel. Ook als je met dit domein niet mailt, hoort er een regel te staan die zegt: niemand mag namens dit domein versturen."
		}
		return punt("spf", "SPF", Slecht, "Niet vastgelegd wie mag mailen", uitleg), ""
	}
	if len(recs) > 1 {
		return punt("spf", "SPF", Slecht, "De SPF-regel is ongeldig",
			"Er staan meerdere SPF-regels. Dan is geen enkele geldig.").met(kort(strings.Join(recs, " | "), 200)).
			metDetail(append([]string{"Op " + k.domein + " staan " + fmt.Sprint(len(recs)) + " SPF-regels; voeg ze samen tot één:"}, recs...)...), ""
	}
	r := recs[0]
	gezien := kort(r, 200)
	l := strings.ToLower(r)
	velden := strings.Fields(l)
	eind := velden[len(velden)-1]
	switch {
	case strings.Contains(l, "+all") || eind == "all":
		return punt("spf", "SPF", Slecht, "Iedereen mag mailen namens jou",
			"Je SPF-regel staat elke server ter wereld toe om namens jou te versturen.").met(gezien), r
	case strings.Contains(l, "?all"):
		return punt("spf", "SPF", Slecht, "Mail van andere servers wordt doorgelaten",
			"Je SPF-regel eindigt met ?all. Dat betekent: we weten het niet, doe maar wat.").met(gezien), r
	case strings.Contains(l, "~all") && dmarcStreng:
		return punt("spf", "SPF", Goed, "Alleen jouw mailservers mogen versturen",
			"Vastgelegd welke servers namens jou mogen mailen. Samen met je DMARC-regel wordt mail van andere servers geweigerd.").met(gezien), r
	case strings.Contains(l, "~all"):
		return punt("spf", "SPF", Matig, "Mail van andere servers is alleen verdacht",
			"Je SPF-regel eindigt met ~all. Zonder strenge DMARC-regel wordt mail van andere servers vaak toch afgeleverd.").met(gezien), r
	case strings.Contains(l, "-all"):
		return punt("spf", "SPF", Goed, "Alleen jouw mailservers mogen versturen",
			"Vastgelegd welke servers namens jou mogen mailen. Mail van andere servers hoort geweigerd te worden.").met(gezien), r
	case strings.Contains(l, "redirect="):
		return punt("spf", "SPF", Goed, "Alleen jouw mailservers mogen versturen",
			"Je SPF-regel verwijst naar die van je mailleverancier.").met(gezien), r
	default:
		return punt("spf", "SPF", Matig, "De SPF-regel is niet afgemaakt",
			"Je SPF-regel zegt niet wat er moet gebeuren met mail van andere servers.").met(gezien), r
	}
}

// spfOpzoekingen telt de DNS-opzoekingen die een mailserver voor je SPF-regel
// moet doen. Boven de tien keurt de ontvanger de hele regel af (RFC 7208 4.6.4),
// en dat merk je pas als mail in de spam belandt.
func (k *keurder) spfOpzoekingen(ctx context.Context, record string) Punt {
	if record == "" {
		return punt("spf-lookups", "SPF lookups", NVT, "SPF blijft binnen de grens",
			"Zonder geldige SPF-regel valt hier niets te tellen.")
	}
	gedaan := map[string]bool{}
	var tel func(rec string, diepte int) int
	tel = func(rec string, diepte int) int {
		if diepte > 10 {
			return 0
		}
		n := 0
		for _, v := range strings.Fields(strings.ToLower(rec))[1:] {
			v = strings.TrimLeft(v, "+-~?")
			switch {
			case strings.HasPrefix(v, "include:"), strings.HasPrefix(v, "redirect="):
				n++
				doel := v[strings.IndexAny(v, ":=")+1:]
				if gedaan[doel] || strings.Contains(doel, "%") {
					continue
				}
				gedaan[doel] = true
				for _, t := range k.r.TXT(ctx, doel) {
					if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
						n += tel(t, diepte+1)
						break
					}
				}
			case v == "a", v == "mx", v == "ptr", strings.HasPrefix(v, "a:"), strings.HasPrefix(v, "a/"),
				strings.HasPrefix(v, "mx:"), strings.HasPrefix(v, "mx/"), strings.HasPrefix(v, "ptr:"), strings.HasPrefix(v, "exists:"):
				n++
			}
		}
		return n
	}
	// Per onderdeel van de bovenste regel tellen, zodat de eigenaar ziet
	// welke include de meeste opzoekingen kost.
	n := 0
	var detail []string
	for _, v := range strings.Fields(strings.ToLower(record))[1:] {
		deel := tel("v=spf1 "+v, 0)
		n += deel
		if deel > 0 && (strings.Contains(v, "include:") || strings.Contains(v, "redirect=")) {
			detail = append(detail, fmt.Sprintf("%s: %d", strings.TrimLeft(v, "+-~?"), deel))
		} else if deel > 0 {
			detail = append(detail, fmt.Sprintf("%s: %d", v, deel))
		}
	}
	gezien := fmt.Sprintf("%d van de maximaal 10 opzoekingen", n)
	switch {
	case n > 10:
		return punt("spf-lookups", "SPF lookups", Slecht, "Je SPF-regel is te lang",
			"Een mailserver moet voor je SPF-regel meer dan tien keer iets opzoeken. Dan wordt de hele regel afgekeurd, en komt je eigen mail in de spam terecht.").met(gezien).metDetail(detail...)
	case n >= 9:
		return punt("spf-lookups", "SPF lookups", Matig, "Je SPF-regel zit tegen de grens",
			"Nog één mailleverancier erbij en je SPF-regel werkt niet meer.").met(gezien).metDetail(detail...)
	default:
		return punt("spf-lookups", "SPF lookups", Goed, "SPF blijft binnen de grens",
			"Je SPF-regel is kort genoeg dat elke mailserver hem helemaal kan nalopen.").met(gezien).metDetail(detail...)
	}
}

func (k *keurder) dkim(ctx context.Context) Punt {
	var (
		mu       sync.Mutex
		gevonden = map[string]string{}
		wg       sync.WaitGroup
	)
	for _, sel := range dkimSelectors {
		wg.Add(1)
		go func(sel string) {
			defer wg.Done()
			for _, t := range k.r.TXT(ctx, sel+"._domainkey."+k.domein) {
				if p, ok := tagLijst(t)["p"]; ok && p != "" {
					mu.Lock()
					gevonden[sel] = p
					mu.Unlock()
					return
				}
			}
		}(sel)
	}
	wg.Wait()
	if len(gevonden) > 0 {
		var namen, zwak, detail []string
		kortste := 0
		for sel, p := range gevonden {
			namen = append(namen, sel)
			b := rsaBits(p)
			if b > 0 {
				detail = append(detail, fmt.Sprintf("%s._domainkey.%s: RSA %d bits", sel, k.domein, b))
			} else {
				detail = append(detail, fmt.Sprintf("%s._domainkey.%s: sleutel gevonden (geen RSA, of niet te lezen)", sel, k.domein))
			}
			if b > 0 {
				if kortste == 0 || b < kortste {
					kortste = b
				}
				if b < 2048 {
					zwak = append(zwak, fmt.Sprintf("%s (%d bits)", sel, b))
				}
			}
		}
		gezien := "Gevonden: " + strings.Join(sorteer(namen), ", ")
		if kortste > 0 {
			gezien += fmt.Sprintf(", kortste sleutel %d bits", kortste)
		}
		detail = sorteer(detail)
		if kortste > 0 && kortste < 1024 {
			return punt("dkim", "DKIM", Slecht, "De handtekening onder je mail is te zwak",
				"Je DKIM-sleutel is korter dan 1024 bits en daarmee na te maken.").met(gezien).metDetail(detail...)
		}
		if len(zwak) > 0 {
			return punt("dkim", "DKIM", Matig, "Je mail is ondertekend, maar met een korte sleutel",
				"Je mail wordt ondertekend, maar met een sleutel van minder dan 2048 bits. Dat is de huidige norm.").met(gezien).metDetail(detail...)
		}
		return punt("dkim", "DKIM", Goed, "Je mail is ondertekend",
			"De ontvanger kan controleren dat een mail echt van jou komt en onderweg niet is veranderd.").met(gezien).metDetail(detail...)
	}
	// Geen bekende naam gevonden. Bestaat _domainkey zelf (NOERROR in plaats van
	// NXDOMAIN), dan staan er sleutels onder een naam die we niet kennen; zo meet
	// internet.nl het ook. Eerst uitsluiten dat het domein alles beantwoordt.
	_, _, rcode, err := k.r.Records(ctx, "_domainkey."+k.domein, dns.TypeTXT)
	_, _, nep, _ := k.r.Records(ctx, "geen-selector-x7q2."+k.domein, dns.TypeTXT)
	if err == nil && rcode == dns.RcodeSuccess && nep == dns.RcodeNameError {
		return punt("dkim", "DKIM", Goed, "Je mail is ondertekend",
			"Er staan DKIM-sleutels voor je domein, zodat de ontvanger kan controleren dat een mail echt van jou komt.").met("Sleutels onder een eigen naam")
	}
	// Antwoordt het domein ook op een naam die niet bestaat met NOERROR (een
	// wildcard, of "black lies" bij sommige DNSSEC-ondertekenaars), dan valt
	// het van buiten niet vast te stellen. Dan niet gokken: het punt telt niet mee.
	if err == nil && rcode == dns.RcodeSuccess && nep == dns.RcodeSuccess {
		return punt("dkim", "DKIM", Fout, "Handtekening onder je mail",
			"Van buiten niet vast te stellen: we vonden de sleutel niet onder een bekende naam, en je DNS geeft geen uitsluitsel. Dit punt telt daarom niet mee.")
	}
	return punt("dkim", "DKIM", Matig, "Geen handtekening gevonden",
		"We vonden geen DKIM-sleutel. Misschien gebruikt je mailleverancier een naam die we niet kennen; vraag het na.").
		metDetail(fmt.Sprintf("Geprobeerd: %d gangbare namen onder _domainkey.%s, zoals selector1, google en default.", len(dkimSelectors), k.domein))
}

// rsaBits geeft de lengte van een RSA-sleutel uit een DKIM-record, of 0.
func rsaBits(p string) int {
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(p), ""))
	if err != nil {
		return 0
	}
	sleutel, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		if r, err2 := x509.ParsePKCS1PublicKey(der); err2 == nil {
			return r.N.BitLen()
		}
		return 0
	}
	if r, ok := sleutel.(*rsa.PublicKey); ok {
		return r.N.BitLen()
	}
	return 0
}

func (k *keurder) mtaSTS(ctx context.Context) Punt {
	heeft := false
	for _, t := range k.r.TXT(ctx, "_mta-sts."+k.domein) {
		if strings.HasPrefix(strings.ToLower(t), "v=stsv1") {
			heeft = true
		}
	}
	nee := punt("mta-sts", "MTA-STS", Matig, "Versleuteling wordt niet afgedwongen",
		"Je mailserver kan versleuteld ontvangen, maar een andere server mag het ook onversleuteld proberen. Met MTA-STS sluit je dat uit.")
	if !heeft {
		return nee.metDetail("Geen TXT-record op _mta-sts." + k.domein)
	}
	adres := "https://mta-sts." + k.domein + "/.well-known/mta-sts.txt"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, adres, nil)
	resp, err := k.web.Do(req)
	if err != nil {
		return punt("mta-sts", "MTA-STS", Slecht, "MTA-STS is kapot",
			"Je DNS zegt dat er een MTA-STS-beleid is, maar dat is niet op te halen. Mailservers kunnen daardoor weigeren je mail af te leveren.").
			metDetail(adres+" gaf geen antwoord: "+err.Error(), "Het beleid moet op die naam staan, met een geldig certificaat voor mta-sts."+k.domein+".")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	mode := ""
	var patronen []string
	beleid := []string{"Beleid op " + adres + ":"}
	for _, regel := range strings.Split(string(body), "\n") {
		kv := strings.SplitN(regel, ":", 2)
		if len(kv) != 2 {
			continue
		}
		switch sleutel := strings.TrimSpace(strings.ToLower(kv[0])); sleutel {
		case "mode":
			mode = strings.ToLower(strings.TrimSpace(kv[1]))
			beleid = append(beleid, sleutel+": "+strings.TrimSpace(kv[1]))
		case "mx":
			patronen = append(patronen, strings.ToLower(strings.TrimSpace(kv[1])))
			fallthrough
		case "version", "max_age":
			beleid = append(beleid, sleutel+": "+strings.TrimSpace(kv[1]))
		}
	}
	k.leg(func(s *stand) { s.stsMode, s.stsMX = mode, patronen })
	gezien := "mode: " + leegAls(mode, "onbekend")
	switch {
	case resp.StatusCode != http.StatusOK:
		return punt("mta-sts", "MTA-STS", Slecht, "MTA-STS is kapot",
			fmt.Sprintf("Het MTA-STS-beleid geeft een fout (HTTP %d). Mailservers kunnen daardoor weigeren je mail af te leveren.", resp.StatusCode)).
			metDetail(fmt.Sprintf("%s geeft HTTP %d", adres, resp.StatusCode))
	case mode == "enforce":
		return punt("mta-sts", "MTA-STS", Goed, "Mail komt versleuteld aan",
			"Afgesproken dat mail naar jou alleen versleuteld wordt afgeleverd.").met(gezien).metDetail(beleid...)
	case mode == "testing":
		return punt("mta-sts", "MTA-STS", Matig, "Versleuteling staat nog in de testmodus",
			"De afspraak voor versleutelde mail staat klaar, maar wordt nog niet afgedwongen.").met(gezien).metDetail(beleid...)
	default:
		return nee.met(gezien).metDetail(beleid...)
	}
}

func (k *keurder) tlsRPT(ctx context.Context) Punt {
	for _, t := range k.r.TXT(ctx, "_smtp._tls."+k.domein) {
		if strings.HasPrefix(strings.ToLower(t), "v=tlsrptv1") {
			return punt("tls-rpt", "TLS-RPT", Goed, "Je hoort het als versleuteling misgaat",
				"Mailservers melden je wanneer ze je mail niet versleuteld konden afleveren.").met(kort(t, 140))
		}
	}
	return punt("tls-rpt", "TLS-RPT", Matig, "Je hoort het niet als versleuteling misgaat",
		"Er is geen adres voor meldingen als mail naar jou niet versleuteld kon worden afgeleverd.")
}

func (k *keurder) dane(ctx context.Context, mx []string) Punt {
	met := 0
	var detail []string
	for _, h := range mx {
		rrs, ad, _, _ := k.r.Records(ctx, "_25._tcp."+h, dns.TypeTLSA)
		switch {
		case len(rrs) > 0 && ad:
			met++
			detail = append(detail, h+": TLSA aanwezig en ondertekend")
		case len(rrs) > 0:
			detail = append(detail, h+": TLSA aanwezig, maar niet ondertekend met DNSSEC (telt niet)")
		default:
			detail = append(detail, h+": geen TLSA")
		}
	}
	detail = lijstje(detail, maxDetail)
	gezien := fmt.Sprintf("%d van de %d mailservers", met, len(mx))
	switch {
	case met == len(mx):
		return punt("dane", "DANE", Goed, "Je mailserver is vastgelegd in DNSSEC",
			"Andere mailservers kunnen controleren dat ze echt met jouw mailserver praten, en niet met een nagemaakte.").met(gezien).metDetail(detail...)
	case met > 0:
		return punt("dane", "DANE", Matig, "Een deel van je mailservers is vastgelegd",
			"Niet al je mailservers zijn vastgelegd in DNSSEC.").met(gezien).metDetail(detail...)
	default:
		return punt("dane", "DANE", Matig, "Je mailserver is niet vastgelegd in DNSSEC",
			"Met DANE kunnen andere mailservers controleren dat ze met de echte praten. Veel mailleveranciers ondersteunen het nog niet; vraag het na.").met(gezien).metDetail(detail...)
	}
}

// tagLijst ontleedt "v=DMARC1; p=reject; pct=100" en "v=DKIM1; k=rsa; p=...".
func tagLijst(s string) map[string]string {
	uit := map[string]string{}
	for _, deel := range strings.Split(s, ";") {
		if kv := strings.SplitN(strings.TrimSpace(deel), "=", 2); len(kv) == 2 {
			uit[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.TrimSpace(kv[1])
		}
	}
	return uit
}

func sorteer(s []string) []string {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	return s
}
