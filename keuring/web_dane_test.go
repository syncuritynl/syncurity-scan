package keuring

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDANEWeb(t *testing.T) {
	ca := nieuweCA(t)
	tussen := ca.tussen(t)
	jaar := time.Now().Add(365 * 24 * time.Hour)
	blad, _ := x509.ParseCertificate(tussen.blad(t, jaar, "voorbeeld.nl").Certificate[0])
	ander, _ := x509.ParseCertificate(tussen.blad(t, jaar, "voorbeeld.nl").Certificate[0])
	keten := []*x509.Certificate{blad, tussen.cert}
	record := func(gebruik, selector, soort uint8, c *x509.Certificate) dns.RR {
		r := &dns.TLSA{Hdr: dns.RR_Header{Name: "_443._tcp.voorbeeld.nl.", Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300}}
		if err := r.Sign(int(gebruik), int(selector), int(soort), c); err != nil {
			t.Fatal(err)
		}
		return r
	}
	hoofd := record(3, 1, 1, blad).(*dns.TLSA)
	hoofd.Certificate = strings.ToUpper(hoofd.Certificate)
	for _, tc := range []struct {
		naam        string
		rrs         []dns.RR
		ondertekend bool
		wil         Status
	}{
		{"geen record", nil, true, NVT},
		{"blad, sleutel, sha256", []dns.RR{record(3, 1, 1, blad)}, true, Goed},
		{"hoofdletters", []dns.RR{hoofd}, true, Goed},
		{"blad, heel certificaat, sha512", []dns.RR{record(3, 0, 2, blad)}, true, Goed},
		{"tussencertificaat", []dns.RR{record(2, 0, 1, tussen.cert)}, true, Goed},
		{"oud record naast nieuw", []dns.RR{record(3, 1, 1, ander), record(3, 1, 1, blad)}, true, Goed},
		{"zonder DNSSEC", []dns.RR{record(3, 1, 1, blad)}, false, Matig},
		{"klopt niet", []dns.RR{record(3, 1, 1, ander)}, true, Slecht},
		{"basiscertificaat, niet meegestuurd", []dns.RR{record(2, 0, 1, ca.cert)}, true, Fout},
	} {
		if p := daneWebOordeel("voorbeeld.nl", tc.rrs, tc.ondertekend, keten); p.Status != tc.wil {
			t.Errorf("%s: %s (%s), verwacht %s", tc.naam, p.Status, p.Titel, tc.wil)
		}
	}
}
