package keuring

import (
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
