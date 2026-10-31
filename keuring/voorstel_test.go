package keuring

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------- voorstellen

func nepKeurder(domein string) *keurder {
	return &keurder{domein: domein, w: &web{host: domein, eind: domein, eerste: &http.Response{Header: http.Header{}}, pagina: &http.Response{Header: http.Header{}}}}
}

func nepU(feiten []Feit, punten ...Punt) *Uitslag {
	return &Uitslag{Feiten: feiten, Groepen: []Groep{{ID: "x", Punten: punten}}}
}

func TestVoorstelDMARC(t *testing.T) {
	k := nepKeurder("voorbeeld.nl")
	u := nepU(nil, Punt{ID: "dkim", Status: Goed}, Punt{ID: "spf-lookups", Status: Goed})
	// SPF en DKIM in orde: quarantine, bestaande rua blijft.
	k.stand = stand{spf: []string{"v=spf1 include:spf.protection.outlook.com -all"}, dmarc: []string{"v=DMARC1; p=none; rua=mailto:x@rapport.nl"},
		dmarcTags: tagLijst("v=DMARC1; p=none; rua=mailto:x@rapport.nl")}
	v := k.voorstelVoor(Punt{ID: "dmarc", Status: Matig}, u, subInfo{})
	if v.tekst != "v=DMARC1; p=quarantine; rua=mailto:x@rapport.nl" || v.naam != "_dmarc.voorbeeld.nl (TXT)" {
		t.Errorf("quarantine: %+v", v)
	}
	// Geen DKIM: p=none als tussenstap, met rua op het eigen domein.
	k.stand = stand{spf: k.stand.spf}
	v = k.voorstelVoor(Punt{ID: "dmarc", Status: Slecht}, nepU(nil, Punt{ID: "dkim", Status: Matig}), subInfo{})
	if v.tekst != "v=DMARC1; p=none; rua=mailto:dmarc@voorbeeld.nl" || !strings.Contains(v.toelichting, "tussenstap") {
		t.Errorf("tussenstap: %+v", v)
	}
	// Nooit zwakker: reject met pct=50 wordt reject zonder pct.
	k.stand = stand{dmarc: []string{"x"}, dmarcTags: tagLijst("v=DMARC1; p=reject; pct=50; rua=mailto:d@voorbeeld.nl; adkim=s")}
	if v = k.voorstelVoor(Punt{ID: "dmarc", Status: Matig}, u, subInfo{}); v.tekst != "v=DMARC1; p=reject; rua=mailto:d@voorbeeld.nl; adkim=s" {
		t.Errorf("reject: %+v", v)
	}
}

func TestVoorstelSPF(t *testing.T) {
	k := nepKeurder("voorbeeld.nl")
	m365 := []Feit{{"E-mail", "Microsoft 365"}}
	for _, g := range []struct {
		spf   []string
		dmarc string
		f     []Feit
		wil   string
	}{
		{nil, "", m365, "v=spf1 include:spf.protection.outlook.com -all"},
		{[]string{"v=spf1 include:_spf.google.com ?all"}, "v=DMARC1; p=reject", m365, "v=spf1 include:_spf.google.com include:spf.protection.outlook.com ~all"},
		{[]string{"v=spf1 a mx ptr ~all", "v=spf1 include:mailchimp.com -all"}, "", nil, "v=spf1 a mx include:mailchimp.com -all"},
		{nil, "", []Feit{{"E-mail", "geen mailserver"}}, "v=spf1 -all"},
		{nil, "", []Feit{{"E-mail", "onbekend.nl"}}, "v=spf1 mx ~all"},
	} {
		k.stand = stand{spf: g.spf}
		if g.dmarc != "" {
			k.stand.dmarc, k.stand.dmarcTags = []string{g.dmarc}, tagLijst(g.dmarc)
		}
		if v := k.voorstelVoor(Punt{ID: "spf", Status: Slecht}, nepU(g.f), subInfo{}); v.tekst != g.wil {
			t.Errorf("%v: %q, wil %q", g.spf, v.tekst, g.wil)
		}
	}
}

func TestVoorstelCAA(t *testing.T) {
	ca := nieuweCA(t)
	blad, _ := x509.ParseCertificate(ca.blad(t, time.Now().Add(time.Hour), "voorbeeld.nl").Certificate[0])
	k := nepKeurder("voorbeeld.nl")
	k.w.staat = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{blad}}
	v := k.voorstelVoor(Punt{ID: "caa", Status: Matig}, nepU(nil), subInfo{uitgevers: []string{"Google Trust Services", "Rare CA BV"}})
	if v.tekst != "0 issue \"letsencrypt.org\"\n0 issue \"pki.goog\"" || !strings.Contains(v.toelichting, "Rare CA BV") {
		t.Errorf("caa: %+v", v)
	}
	k.w.staat = nil
	if v := k.voorstelVoor(Punt{ID: "caa", Status: Matig}, nepU(nil), subInfo{}); v.tekst != "" || v.toelichting == "" {
		t.Errorf("caa zonder certificaat: %+v", v)
	}
}

// Elk punt uit voorstelPunten geeft in een gewone situatie een voorstel.
func TestElkVoorstel(t *testing.T) {
	ca := nieuweCA(t)
	blad, _ := x509.ParseCertificate(ca.blad(t, time.Now().Add(time.Hour), "voorbeeld.nl").Certificate[0])
	k := nepKeurder("voorbeeld.nl")
	k.w.staat = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{blad}}
	k.w.robots = "User-agent: *\nDisallow: /\nDisallow: /beheer/\n"
	k.w.body = []byte(`<script src="https://www.googletagmanager.com/gtag.js"></script><link href="https://fonts.googleapis.com/css2?family=X" rel="stylesheet"><img src="https://cdn.voorbeeld.nl/a.png">`)
	k.w.info.titel = "Bakkerij \u202eDe Vries"
	k.w.info.tekst = "KvK 12345678"
	k.stand = stand{mx: []string{"voorbeeld-nl.mail.protection.outlook.com"}}
	u := nepU([]Feit{{"E-mail", "Microsoft 365"}})
	for id, statussen := range voorstelPunten {
		for _, s := range statussen {
			v := k.voorstelVoor(Punt{ID: id, Status: s}, u, subInfo{})
			if v.tekst == "" || v.naam == "" {
				t.Errorf("%s/%s: geen voorstel (%+v)", id, s, v)
			}
			if strings.ContainsRune(v.tekst, '\u202e') {
				t.Errorf("%s: stuurteken in het voorstel", id)
			}
		}
	}
	if v := k.voorstelVoor(Punt{ID: "geo-crawlers", Status: Slecht}, u, subInfo{}); !strings.Contains(v.tekst, "User-agent: OAI-SearchBot") ||
		strings.Contains(v.tekst, "GPTBot") || !strings.Contains(v.tekst, "Disallow: /beheer/") || strings.Contains(v.tekst, "Disallow: /\n") {
		t.Errorf("robots: %q", v.tekst)
	}
	if v := k.voorstelVoor(Punt{ID: "csp", Status: Matig}, u, subInfo{}); !strings.HasPrefix(v.tekst, "Content-Security-Policy-Report-Only: default-src 'self'") ||
		!strings.Contains(v.tekst, "script-src 'self' https://www.googletagmanager.com") || !strings.Contains(v.tekst, "font-src 'self' https://fonts.gstatic.com") ||
		strings.Contains(v.tekst, "unsafe-inline") || strings.Contains(v.tekst, "cdn.voorbeeld.nl") {
		t.Errorf("csp: %q", v.tekst)
	}
	if v := k.voorstelVoor(Punt{ID: "geo-entiteit", Status: Matig}, u, subInfo{}); !strings.Contains(v.tekst, `"url": "https://voorbeeld.nl/"`) || !strings.Contains(v.tekst, "12345678") {
		t.Errorf("json-ld: %q", v.tekst)
	}
	if v := k.voorstelVoor(Punt{ID: "mta-sts", Status: Matig}, u, subInfo{}); !strings.Contains(v.tekst, "mx: voorbeeld-nl.mail.protection.outlook.com") || !strings.Contains(v.tekst, "mode: testing") {
		t.Errorf("mta-sts: %q", v.tekst)
	}
	if v := k.voorstelVoor(Punt{ID: "mta-sts", Status: Slecht}, u, subInfo{}); v.tekst != "" {
		t.Error("mta-sts/slecht hoort geen voorstel te hebben")
	}
	nu := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	if v := voorstelSecurityTxt(stand{}, "voorbeeld.nl", "www.voorbeeld.nl", nu); !strings.Contains(v.tekst, "Expires: 2027-10-29T00:00:00Z") || !strings.Contains(v.tekst, "Contact: mailto:security@voorbeeld.nl") {
		t.Errorf("security.txt: %q", v.tekst)
	}
}
