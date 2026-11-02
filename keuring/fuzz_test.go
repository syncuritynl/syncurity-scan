package keuring

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

// Normaliseer mag nooit in paniek raken, en wat eruit komt moet er
// onveranderd weer uitkomen: de inlogdienst en de scandienst rekenen erop
// dat een domein één vaste schrijfwijze heeft.
func FuzzNormaliseer(f *testing.F) {
	for _, s := range []string{"syncurity.nl", "https://www.Syncurity.NL/pad?x=1", "münchen.de", "xn--mnchen-3ya.de",
		"[::1]:443", "a@b.nl", "mail.bakkerij.co.uk", "..", "xn--.nl", "1.2.3.4", "*.voorbeeld.nl", "voorbeeld.nl.", "ﬀ.nl"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, invoer string) {
		d, err := Normaliseer(invoer)
		if err != nil {
			return
		}
		d2, err := Normaliseer(d)
		if err != nil || d2 != d {
			t.Errorf("Normaliseer(%q) = %q, maar Normaliseer(%q) = %q, %v", invoer, d, d, d2, err)
		}
		_ = Weergave(d)
	})
}

// ontleed krijgt HTML van wie dan ook: geen paniek, en snel.
func FuzzOntleed(f *testing.F) {
	for _, s := range []string{
		`<!doctype html><html lang="nl"><head><title>x</title><script src="/a.js"></script></head><body><h1>a</h1><img src=x></body></html>`,
		`<script type="application/ld+json">{"@graph":[{"@type":["Organization"]}]}</script>`,
		`<div><div><div><a><table><tr><td><b><i>`, `<svg><style><noscript><template>`, "\x00<\xff>",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		begin := time.Now()
		p := ontleed(body)
		if d := time.Since(begin); d > 2*time.Second {
			t.Errorf("ontleed van %d bytes kostte %s", len(body), d)
		}
		if len(p.zonderAltSrc) > maxDetail || len(p.blokkerend) > maxDetail {
			t.Error("meer details bewaard dan nodig")
		}
	})
}

// Het antwoord op de TLS-proef komt van de server: geen paniek, en nooit
// meer gelezen dan er stond.
func FuzzTLSAntwoord(f *testing.F) {
	f.Add(nepRecord(22, append(append(nepHello(0x009E, 0, nil, heronderExt), nepDHE(priem(1024, false), 0x0401)...), nepKlaar...)))
	f.Add(nepRecord(22, append(append(nepHello(0xC02F, 1, nil, heronderExt), nepECDHE(0x001d, 0x0201)...), nepKlaar...)))
	f.Add(nepRecord(21, []byte{2, 40}))
	f.Add([]byte{22, 3, 3, 0, 4, 2, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		a, err := leesAntwoord(bytes.NewReader(data))
		if err == nil && a.dhBits > 8*len(data) {
			t.Errorf("p van %d bits uit %d bytes", a.dhBits, len(data))
		}
	})
}

// Het antwoord van Team Cymru komt via DNS van buiten: geen paniek, en een
// geaccepteerd prefix bevat altijd het adres.
func FuzzCymru(f *testing.F) {
	for _, s := range []string{"31898 | 92.5.224.0/20 | SE | ripencc | 2007-06-28", "13335 209242 | 92.5.224.0/20 | US |", "| |", "1 | ::/0 |"} {
		f.Add(s)
	}
	a := netip.MustParseAddr("92.5.232.178")
	f.Fuzz(func(t *testing.T, txt string) {
		if r, ok := leesCymru(txt, a); ok && (!r.prefix.Contains(a) || len(r.asns) == 0 || len(r.asns) > 8) {
			t.Errorf("%q gaf %+v", txt, r)
		}
	})
}
