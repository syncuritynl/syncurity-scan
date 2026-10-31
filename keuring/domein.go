package keuring

import (
	"errors"
	"net"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Foutmeldingen voor de bezoeker. Ze zeggen wat er mis is en wat je kunt doen.
var (
	ErrLeeg        = errors.New("Vul een domeinnaam in, bijvoorbeeld jouwwebsite.nl.")
	ErrOngeldig    = errors.New("Dat lijkt geen domeinnaam. Vul alleen de naam in, bijvoorbeeld jouwwebsite.nl.")
	ErrIPAdres     = errors.New("Vul een domeinnaam in, geen IP-adres.")
	ErrBestaatNiet = errors.New("Deze domeinnaam bestaat niet, of heeft geen DNS. Controleer de spelling.")
)

// Normaliseer maakt van wat iemand intypt een registreerbare domeinnaam:
// zonder schema, pad, poort, www en hoofdletters, in punycode. Een subdomein
// wordt teruggebracht tot het domein zelf, omdat de keuring over het domein gaat.
func Normaliseer(invoer string) (string, error) {
	s := strings.TrimSpace(strings.ToLower(invoer))
	if s == "" {
		return "", ErrLeeg
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.TrimSuffix(strings.Trim(s, "[]"), ".")
	if net.ParseIP(s) != nil {
		return "", ErrIPAdres
	}
	if len(s) > 253 || !strings.Contains(s, ".") {
		return "", ErrOngeldig
	}
	a, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return "", ErrOngeldig
	}
	for _, label := range strings.Split(a, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", ErrOngeldig
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", ErrOngeldig
			}
		}
	}
	// Namen voor bijzonder gebruik: nooit een echte website (RFC 6761, 7686, 8375).
	for _, tld := range []string{".arpa", ".onion", ".local", ".localhost", ".test", ".invalid", ".example", ".internal", ".home.arpa"} {
		if strings.HasSuffix("."+a, tld) {
			return "", ErrOngeldig
		}
	}
	// Alleen echte, publieke achtervoegsels: geen .local, .lan of .internal.
	if _, icann := publicsuffix.PublicSuffix(a); !icann {
		return "", ErrOngeldig
	}
	reg, err := publicsuffix.EffectiveTLDPlusOne(a)
	if err != nil {
		return "", ErrOngeldig
	}
	return reg, nil
}

// Weergave geeft de domeinnaam zoals een mens hem leest (zonder punycode).
// Mengt de naam schriften (een Cyrillische a in "paypal"), dan tonen we de
// punycode, met de leesbare vorm erachter: zo is een lookalike te herkennen.
func Weergave(domein string) string {
	u, err := idna.Display.ToUnicode(domein)
	if err != nil || u == domein {
		return domein
	}
	if gemengd(u) {
		return domein + " (" + u + ")"
	}
	return u
}

func gemengd(s string) bool {
	var schrift *unicode.RangeTable
	for _, r := range s {
		if r == '.' || r == '-' || (r >= '0' && r <= '9') {
			continue
		}
		var hier *unicode.RangeTable
		for _, t := range []*unicode.RangeTable{unicode.Latin, unicode.Cyrillic, unicode.Greek, unicode.Arabic, unicode.Hebrew, unicode.Han, unicode.Hiragana, unicode.Katakana, unicode.Hangul, unicode.Thai, unicode.Armenian, unicode.Georgian} {
			if unicode.Is(t, r) {
				hier = t
				break
			}
		}
		if hier == nil {
			continue
		}
		if schrift != nil && hier != schrift {
			return true
		}
		schrift = hier
	}
	return false
}

// hostnaamRe: een gewone hostnaam in kleine letters, zonder wildcard of _.
var hostnaamRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
