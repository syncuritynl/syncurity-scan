package keuring

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// DANE voor de website: een TLSA-record op _443._tcp.<naam> legt in DNS vast
// welk certificaat de website hoort te hebben. Alleen DNS; we vergelijken met
// de keten uit de handdruk die we al deden.

func (k *keurder) daneWeb(ctx context.Context, w *web) Punt {
	rrs, ondertekend, _, _ := k.r.Records(ctx, "_443._tcp."+w.host, dns.TypeTLSA)
	return daneWebOordeel(w.host, rrs, ondertekend, w.staat.PeerCertificates)
}

func daneWebOordeel(host string, rrs []dns.RR, ondertekend bool, keten []*x509.Certificate) Punt {
	const id, tech, titel = "dane-web", "TLSA · 443", "DANE voor de website"
	var tlsa []*dns.TLSA
	for _, rr := range rrs {
		if t, ok := rr.(*dns.TLSA); ok {
			tlsa = append(tlsa, t)
		}
	}
	if len(tlsa) == 0 {
		return punt(id, tech, NVT, titel, "Je website heeft geen DANE-record (TLSA). Dat is optioneel en telt niet mee; ook internet.nl rekent het niet mee voor websites.")
	}
	gezien := fmt.Sprintf("%d TLSA-records op _443._tcp.%s", len(tlsa), host)
	var detail []string
	for _, t := range tlsa {
		detail = append(detail, kort(t.String(), 160))
	}
	if !ondertekend {
		return punt(id, tech, Matig, "DANE-record zonder DNSSEC",
			"Je website heeft een DANE-record, maar je domeinnaam is niet ondertekend met DNSSEC. Dan kan niemand op het record vertrouwen, en doet het niets.").
			met(gezien).metDetail(detail...)
	}
	if len(keten) == 0 {
		return punt(id, tech, Fout, titel, "We kregen geen certificaat om met het DANE-record te vergelijken.").met(gezien)
	}
	blad := false // er staat een record voor het certificaat zelf (gebruik 1 of 3)
	for _, t := range tlsa {
		if t.Usage == 1 || t.Usage == 3 {
			blad = true
		}
		if tlsaPast(t, keten) {
			return punt(id, tech, Goed, titel,
				"Je website heeft een DANE-record dat klopt met het certificaat. Software die DANE controleert, weet zo zeker dat hij met de echte website praat.").met(gezien).metDetail(detail...)
		}
	}
	if !blad {
		// Gebruik 0 of 2 wijst vaak naar het basiscertificaat, en dat stuurt
		// een server meestal niet mee. Dan kunnen we het niet vergelijken.
		return punt(id, tech, Fout, titel, "Je DANE-record wijst naar een certificaat hoger in de keten dat je server niet meestuurt, dus we konden het niet vergelijken.").met(gezien).metDetail(detail...)
	}
	return punt(id, tech, Slecht, "Het DANE-record klopt niet met het certificaat",
		"Je website heeft een DANE-record, maar dat past niet bij het certificaat dat je server laat zien. Software die DANE controleert, weigert dan de verbinding. Dit gebeurt vaak als het certificaat is vernieuwd en het record niet.").
		met(gezien).metDetail(detail...)
}

// tlsaPast: past het record bij het blad (gebruik 1 en 3) of bij een van de
// certificaten erboven (gebruik 0 en 2)?
func tlsaPast(t *dns.TLSA, keten []*x509.Certificate) bool {
	kandidaten := keten[:1]
	if t.Usage == 0 || t.Usage == 2 {
		kandidaten = keten[1:]
	}
	for _, c := range kandidaten {
		if v, err := dns.CertificateToDANE(t.Selector, t.MatchingType, c); err == nil && strings.EqualFold(v, t.Certificate) {
			return true
		}
	}
	return false
}
