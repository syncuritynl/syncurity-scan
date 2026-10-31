package keuring

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

func (k *keurder) domeinnaam(ctx context.Context) Groep {
	sec := k.dnssec(ctx)
	return Groep{ID: "domein", Naam: "Je domeinnaam", Kort: "Domeinnaam", Punten: []Punt{
		sec,
		k.dnssecAlgoritme(ctx, sec.Status == Goed),
		k.caa(ctx),
		k.nameservers(ctx),
		k.txtSchoon(ctx),
	}}
}

func (k *keurder) dnssec(ctx context.Context) Punt {
	rrs, ad, rcode, err := k.r.Records(ctx, k.domein, dns.TypeSOA)
	if err != nil {
		return punt("dnssec", "DNSSEC", Fout, "Beschermd tegen vervalsing", "We kregen geen antwoord van de DNS om dit te meten.")
	}
	ds, _, _, _ := k.r.Records(ctx, k.domein, dns.TypeDS)
	detail := []string{
		fmt.Sprintf("DS-record bij de registry van .%s: %s", tld(k.domein), jaNee(len(ds) > 0)),
		"Antwoorden gevalideerd (AD-vlag): " + jaNee(ad),
	}
	switch {
	case rcode == dns.RcodeServerFailure && len(ds) > 0:
		return punt("dnssec", "DNSSEC", Slecht, "De DNSSEC-ondertekening is kapot",
			"Je domein is ondertekend, maar de handtekening klopt niet. Resolvers die controleren, kunnen je domein dan helemaal niet meer vinden.").
			metDetail(append(detail, "De resolver gaf SERVFAIL: meestal een verlopen handtekening of een DS-record dat niet bij de sleutel past.")...)
	case ad && len(rrs) > 0:
		return punt("dnssec", "DNSSEC", Goed, "Beschermd tegen vervalste antwoorden",
			"Je domeinnaam is ondertekend met DNSSEC. Vervalste antwoorden over je domeinnaam worden herkend en geweigerd.")
	case len(ds) > 0:
		return punt("dnssec", "DNSSEC", Matig, "DNSSEC is half ingesteld",
			"Er staat een DNSSEC-sleutel bij je registratie, maar de antwoorden zijn niet geldig ondertekend.").metDetail(detail...)
	default:
		return punt("dnssec", "DNSSEC", Slecht, "Niet beschermd tegen vervalste antwoorden",
			"Je domein is niet ondertekend met DNSSEC. Een aanvaller die tussen je bezoeker en internet zit, kan bezoekers naar een nepversie van je site sturen.").metDetail(detail...)
	}
}

// algoritmeNaam geeft de leesbare naam van een DNSSEC-algoritme (RFC 8624).
var algoritmeNaam = map[uint8]string{
	5: "RSA/SHA-1", 7: "RSA/SHA-1-NSEC3", 8: "RSA/SHA-256", 10: "RSA/SHA-512",
	13: "ECDSA P-256", 14: "ECDSA P-384", 15: "Ed25519", 16: "Ed448",
}

func (k *keurder) dnssecAlgoritme(ctx context.Context, ondertekend bool) Punt {
	if !ondertekend {
		return punt("dnssec-alg", "DNSKEY", NVT, "Sterke ondertekening",
			"Zonder geldige DNSSEC valt de sterkte niet te meten.")
	}
	ds, _, _, _ := k.r.Records(ctx, k.domein, dns.TypeDS)
	var namen []string
	zwak := false
	gezien := map[uint8]bool{}
	for _, rr := range ds {
		a := rr.(*dns.DS).Algorithm
		if gezien[a] {
			continue
		}
		gezien[a] = true
		naam := algoritmeNaam[a]
		if naam == "" {
			naam = fmt.Sprintf("algoritme %d", a)
		}
		namen = append(namen, naam)
		if a < 8 {
			zwak = true
		}
	}
	tekst := "Algoritme: " + strings.Join(namen, ", ")
	if zwak {
		return punt("dnssec-alg", "DNSKEY", Matig, "De ondertekening is verouderd",
			"Je domein is ondertekend met een verouderde methode (SHA-1). Die wordt uitgefaseerd; vraag je DNS-leverancier om over te stappen.").met(tekst)
	}
	return punt("dnssec-alg", "DNSKEY", Goed, "Sterke ondertekening",
		"Je domein is ondertekend met een moderne, sterke methode.").met(tekst)
}

func (k *keurder) caa(ctx context.Context) Punt {
	rrs, _, _, _ := k.r.Records(ctx, k.domein, dns.TypeCAA)
	var wie, detail []string
	melden := false
	for _, rr := range rrs {
		c := rr.(*dns.CAA)
		detail = append(detail, fmt.Sprintf("%d %s %q", c.Flag, c.Tag, c.Value))
		switch c.Tag {
		case "issue", "issuewild":
			wie = append(wie, c.Tag+" "+leegAls(c.Value, ";"))
		case "iodef":
			melden = true
		}
	}
	if len(wie) == 0 {
		return punt("caa", "CAA", Matig, "Niet vastgelegd wie certificaten mag maken",
			"Elke certificaatleverancier ter wereld mag nu een certificaat voor je domein uitgeven. Met één regel beperk je dat tot je eigen leverancier.")
	}
	uitleg := "Alleen de leverancier die jij hebt gekozen, mag een certificaat voor je domein uitgeven."
	if melden {
		uitleg += " Probeert iemand het toch, dan krijg je een melding."
	}
	return punt("caa", "CAA", Goed, "Vastgelegd wie certificaten mag maken", uitleg).met(strings.Join(wie, ", ")).metDetail(lijstje(detail, maxDetail)...)
}

func (k *keurder) nameservers(ctx context.Context) Punt {
	rrs, _, _, _ := k.r.Records(ctx, k.domein, dns.TypeNS)
	var namen, detail []string
	netten := map[netip.Prefix]bool{}
	for _, rr := range rrs {
		n := strings.TrimSuffix(rr.(*dns.NS).Ns, ".")
		namen = append(namen, n)
		var hier []string
		for _, a := range k.r.Adressen(ctx, n, true) {
			p, _ := a.Prefix(24)
			netten[p] = true
			hier = append(hier, p.String())
		}
		detail = append(detail, n+": "+leegAls(strings.Join(uniek(hier), ", "), "geen IPv4-adres"))
	}
	detail = lijstje(sorteer(detail), maxDetail)
	gezien := strings.Join(sorteer(namen), ", ")
	switch {
	case len(namen) < 2:
		return punt("ns", "NS", Slecht, "Maar één nameserver",
			"Valt die ene uit, dan zijn je website en je mail onbereikbaar.").met(gezien).metDetail(detail...)
	case len(netten) < 2:
		return punt("ns", "NS", Matig, "Nameservers staan op één plek",
			fmt.Sprintf("Je hebt %d nameservers, maar ze staan in hetzelfde netwerk. Valt dat uit, dan valt alles uit.", len(namen))).met(gezien).metDetail(detail...)
	default:
		return punt("ns", "NS", Goed, "Betrouwbare nameservers",
			fmt.Sprintf("%d nameservers, op verschillende plekken. Valt er een uit, dan blijft alles werken.", len(namen))).met(gezien).metDetail(detail...)
	}
}

func jaNee(b bool) string {
	if b {
		return "ja"
	}
	return "nee"
}

func tld(domein string) string {
	return domein[strings.LastIndex(domein, ".")+1:]
}
