package keuring

import (
	"net/http"
	"testing"
)

// kopWeb: een pagina met deze kopregels; cors is wat de server zei op ons
// verzoek met Origin: proefOrigin.
func kopWeb(kop http.Header, corsOrigin string, corsCreds bool) *web {
	return &web{host: "voorbeeld.nl", pagina: &http.Response{StatusCode: 200, Header: kop}, corsOrigin: corsOrigin, corsCreds: corsCreds}
}

func TestCORS(t *testing.T) {
	for _, tc := range []struct {
		naam   string
		kop    http.Header
		origin string
		creds  bool
		wil    Status
	}{
		{"geen", http.Header{}, "", false, Goed},
		{"ster zonder cookies", http.Header{"Access-Control-Allow-Origin": {"*"}}, "*", false, Goed},
		{"ster met cookies", http.Header{"Access-Control-Allow-Origin": {"*"}, "Access-Control-Allow-Credentials": {"true"}}, "*", true, Matig},
		{"zegt elke site terug", http.Header{}, proefOrigin, true, Matig},
		{"zegt elke site terug, zonder cookies", http.Header{}, proefOrigin, false, Matig},
		{"vaste site", http.Header{"Access-Control-Allow-Origin": {"https://app.voorbeeld.nl"}}, "https://app.voorbeeld.nl", true, Goed},
	} {
		if p := cors(kopWeb(tc.kop, tc.origin, tc.creds)); p.Status != tc.wil {
			t.Errorf("%s: %s (%s), verwacht %s", tc.naam, p.Status, p.Titel, tc.wil)
		}
	}
}

func TestCorpCoop(t *testing.T) {
	for _, tc := range []struct {
		coop, corp string
		wil        Status
		gezien     string
	}{
		{"", "", Matig, "Cross-Origin-Opener-Policy: geen"},
		{"same-origin", "", Goed, "Cross-Origin-Opener-Policy: same-origin"},
		{`same-origin-allow-popups; report-to="coop"`, "same-site", Goed, "Cross-Origin-Opener-Policy: same-origin-allow-popups · Cross-Origin-Resource-Policy: same-site"},
		{"unsafe-none", "same-origin", Matig, "Cross-Origin-Opener-Policy: unsafe-none · Cross-Origin-Resource-Policy: same-origin"},
	} {
		kop := http.Header{}
		if tc.coop != "" {
			kop.Set("Cross-Origin-Opener-Policy", tc.coop)
		}
		if tc.corp != "" {
			kop.Set("Cross-Origin-Resource-Policy", tc.corp)
		}
		if p := corpCoop(kopWeb(kop, "", false)); p.Status != tc.wil || p.Gezien != tc.gezien {
			t.Errorf("%q: %s %q, verwacht %s %q", tc.coop, p.Status, p.Gezien, tc.wil, tc.gezien)
		}
	}
}

func TestPermissionsPolicy(t *testing.T) {
	for v, wil := range map[string]Status{
		"": Matig,
		"camera=(), microphone=(), geolocation=()":                                   Goed,
		`geolocation=(self "https://kaart.nl"), camera=(),microphone=()`:             Goed,
		"camera=(), microphone=(), geolocation=(), fullscreen=*, interest-cohort=()": Goed,
		"camera=(), microphone=()":                                                   Matig, // geolocation ontbreekt
		"camera=*, microphone=(), geolocation=()":                                    Matig,
		"camera=(*), microphone=(), geolocation=()":                                  Matig,
		"camera=(, microphone=(), geolocation=()":                                    Matig, // kapot
		"Camera=(), MICROPHONE=(); report-to=x, geolocation=()":                      Goed,
	} {
		kop := http.Header{}
		if v != "" {
			kop.Set("Permissions-Policy", v)
		}
		if p := permissies(kopWeb(kop, "", false)); p.Status != wil {
			t.Errorf("%q: %s (%s), verwacht %s", v, p.Status, p.Titel, wil)
		}
	}
}

// De CSP weegt zoals Mozilla Observatory.
func TestCSP(t *testing.T) {
	for v, wil := range map[string]Status{
		"":                   Matig,
		"default-src 'self'": Goed, // object-src valt terug op default-src
		"default-src 'none'; script-src 'self'; style-src 'self'": Goed,
		"script-src 'self'; object-src 'none'; base-uri 'self'":   Goed,
		"script-src 'self'":                                     Matig, // object-src niet beperkt
		"script-src 'self'; object-src *":                       Matig,
		"default-src 'self'; script-src 'self' 'unsafe-inline'": Matig,
		"default-src 'self'; script-src 'self' 'unsafe-eval'":   Matig,
		"default-src 'self'; script-src 'self' https:":          Matig,
		"default-src 'self'; script-src 'self' data:":           Matig,
		// Een nonce of hash zet 'unsafe-inline' buiten werking (ook sha384 en sha512).
		"default-src 'self'; script-src 'self' 'unsafe-inline' 'nonce-abc'":  Goed,
		"default-src 'self'; script-src 'self' 'unsafe-inline' 'sha384-abc'": Goed,
		// De strikte CSP van Google: met strict-dynamic en een nonce tellen https: en 'unsafe-inline' niet.
		"script-src 'nonce-abc' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'": Goed,
		// Zonder nonce of hash negeert de browser https: niet.
		"script-src 'strict-dynamic' https:; object-src 'none'": Matig,
		"default-src 'self'; style-src 'self' 'unsafe-inline'":  Goed,  // alleen stijlen: geen scripts
		"style-src 'self'; object-src 'none'":                   Matig, // niets voor scripts
	} {
		kop := http.Header{}
		if v != "" {
			kop.Set("Content-Security-Policy", v)
		}
		if p := csp(kopWeb(kop, "", false)); p.Status != wil {
			t.Errorf("%q: %s (%s: %s), verwacht %s", v, p.Status, p.Titel, p.Uitleg, wil)
		}
	}
}
