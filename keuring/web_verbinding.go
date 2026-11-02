package keuring

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const geenWebsite = "We vonden geen website op deze domeinnaam, dus dit punt telt niet mee."

func (k *keurder) verbinding(ctx context.Context, w *web) Groep {
	g := Groep{ID: "verbinding", Naam: "Je website: de verbinding", Kort: "Verbinding"}
	if w.host == "" {
		for _, p := range []struct{ id, tech, titel string }{
			{"tls-modern", "TLS 1.3", "Moderne versleuteling"}, {"tls-oud", "TLS 1.0 · 1.1", "Oude versleuteling uit"},
			{"cipher-zwak", "cipher suites", "Sterke versleuteling"}, {"cert", "X.509", "Geldig certificaat"},
			{"cert-sleutel", "RSA · ECDSA", "Sterk certificaat"}, {"https", "301 → https", "Altijd via https"},
			{"hsts", "HSTS", "De browser onthoudt https"},
		} {
			g.Punten = append(g.Punten, punt(p.id, p.tech, NVT, p.titel, geenWebsite))
		}
		g.Punten = append(g.Punten, metStatus("verbinding", NVT, geenWebsite)...)
		return g
	}
	if w.staat == nil {
		reden := "Je website is niet beveiligd bereikbaar via https. Alles wat bezoekers invullen, gaat leesbaar over het internet."
		g.Punten = []Punt{
			punt("tls-modern", "TLS 1.3", Slecht, "Geen versleutelde verbinding", reden, "Handdruk mislukt: "+fmt.Sprint(w.fout)),
			punt("tls-oud", "TLS 1.0 · 1.1", Fout, "Oude versleuteling uit", "Zonder https niet te meten."),
			punt("cipher-zwak", "cipher suites", Fout, "Sterke versleuteling", "Zonder https niet te meten."),
			punt("cert", "X.509", Slecht, "Geen geldig certificaat", "Bezoekers krijgen een waarschuwing dat de verbinding niet veilig is."),
			punt("cert-sleutel", "RSA · ECDSA", Fout, "Sterk certificaat", "Zonder https niet te meten."),
			k.https(w),
			punt("hsts", "HSTS", Fout, "De browser onthoudt https", "Zonder https niet te meten."),
			certWWW(w),
			punt("tls-adressen", "IPv4 · IPv6", Fout, "Elk adres even veilig", "Zonder https niet te meten."),
			punt("dane-web", "TLSA · 443", Fout, "DANE voor de website", "Zonder https niet te meten."),
		}
		return g
	}
	g.Punten = []Punt{
		tlsModern(w), tlsOud(w), suites(w), certificaat(w), certSleutel(w), k.https(w), hsts(w), certWWW(w), tlsAdressen(w), k.daneWeb(ctx, w),
	}
	return g
}

func tlsModern(w *web) Punt {
	gezien := "Beste versie: " + tls.VersionName(w.staat.Version)
	if w.staat.CurveID != 0 {
		gezien += " · sleutel: " + w.staat.CurveID.String()
		if kwantumveilig(w.staat) {
			gezien += " (kwantumveilig)"
		}
	}
	if w.staat.Version >= tls.VersionTLS13 {
		return punt("tls-modern", "TLS 1.3", Goed, "Moderne versleuteling",
			"Je website biedt TLS 1.3 aan, de nieuwste en snelste versie.").met(gezien)
	}
	return punt("tls-modern", "TLS 1.3", Matig, "Niet de nieuwste versleuteling",
		"Je website biedt TLS 1.3 nog niet aan. TLS 1.2 is nog veilig, maar 1.3 is sneller en sluit oude zwakke plekken uit.").met(gezien)
}

func tlsOud(w *web) Punt {
	if len(w.oud) > 0 {
		return punt("tls-oud", "TLS 1.0 · 1.1", Slecht, "Oude, onveilige versleuteling staat aan",
			"Je website accepteert nog versleuteling van vóór 2008. Die is te kraken en browsers weigeren hem al.").met("Aangeboden: "+strings.Join(w.oud, ", ")).
			metDetail("Uit te zetten op "+w.host+": "+strings.Join(w.oud, " en "), "Laat alleen TLS 1.2 en TLS 1.3 aan.")
	}
	return punt("tls-oud", "TLS 1.0 · 1.1", Goed, "Oude versleuteling staat uit",
		"TLS 1.0 en 1.1 worden geweigerd, zoals het hoort.")
}

func suites(w *web) Punt {
	var detail []string
	if len(w.suitesAlle) > 0 {
		detail = append([]string{"Deze suites worden geaccepteerd en moeten uit:"}, w.suitesAlle...)
	}
	switch {
	case w.zwak != "":
		return punt("cipher-zwak", "cipher suites", Slecht, "Zwakke versleuteling wordt geaccepteerd",
			"Je website accepteert nog versleutelmethoden die al jaren als gebroken gelden (RC4 of 3DES).").met("Geaccepteerd: " + w.zwak).metDetail(leegDan(detail, "Geaccepteerd: "+w.zwak)...)
	case w.verouder != "":
		return punt("cipher-zwak", "cipher suites", Matig, "Verouderde versleuteling wordt nog geaccepteerd",
			"Naast moderne methoden accepteert je website ook oudere, zonder forward secrecy of met CBC. Nog niet gekraakt, maar uit te faseren.").met("Geaccepteerd: " + w.verouder).metDetail(leegDan(detail, "Geaccepteerd: "+w.verouder)...)
	default:
		return punt("cipher-zwak", "cipher suites", Goed, "Alleen sterke versleuteling",
			"Je website accepteert alleen moderne versleutelmethoden.").met("Gebruikt: " + tls.CipherSuiteName(w.staat.CipherSuite))
	}
}

func certificaat(w *web) Punt {
	if len(w.staat.PeerCertificates) == 0 {
		return punt("cert", "X.509", Slecht, "Geen geldig certificaat", "Bezoekers krijgen een waarschuwing dat de verbinding niet veilig is.")
	}
	blad := w.staat.PeerCertificates[0]
	err := controleerKeten(w.staat.PeerCertificates, w.host, w.roots)
	dagen := int(time.Until(blad.NotAfter).Hours() / 24)
	gezien := fmt.Sprintf("Uitgegeven door %s, geldig tot %s", uitgever(blad), blad.NotAfter.Format("2-1-2006"))
	var ongeldig x509.CertificateInvalidError
	var naam x509.HostnameError
	var onbekend x509.UnknownAuthorityError
	detail := certDetail(w.staat.PeerCertificates)
	if err != nil {
		detail = append([]string{"Fout bij controleren: " + err.Error()}, detail...)
	}
	switch {
	case errors.As(err, &ongeldig) && ongeldig.Reason == x509.Expired:
		return punt("cert", "X.509", Slecht, "Het certificaat is verlopen",
			"Bezoekers krijgen een rode waarschuwing en veel van hen haken af.").met(gezien).metDetail(detail...)
	case errors.As(err, &naam):
		return punt("cert", "X.509", Slecht, "Het certificaat hoort bij een andere naam",
			"Het certificaat is niet uitgegeven voor "+w.host+". Bezoekers krijgen een waarschuwing.").met(gezien).metDetail(detail...)
	case errors.As(err, &onbekend) && len(w.staat.PeerCertificates) == 1 && !bytes.Equal(blad.RawIssuer, blad.RawSubject):
		// Alleen het blad, door een ander uitgegeven: het tussencertificaat
		// ontbreekt. We halen het niet zelf op (AIA): dat zou een verbinding
		// buiten het domein zijn.
		return punt("cert", "X.509", Slecht, "De keten van het certificaat is niet compleet",
			"Je server stuurt het tussencertificaat niet mee. Chrome vult dat vaak zelf aan, maar Firefox, Android-telefoons, apps en andere servers geven een waarschuwing of weigeren de verbinding.").met(gezien).metDetail(detail...)
	case err != nil:
		return punt("cert", "X.509", Slecht, "Het certificaat wordt niet vertrouwd",
			"Browsers vertrouwen dit certificaat niet, bijvoorbeeld omdat het zelf ondertekend is of de keten niet compleet is.").met(gezien).metDetail(detail...)
	case dagen < 14:
		return punt("cert", "X.509", Matig, "Het certificaat verloopt binnenkort",
			fmt.Sprintf("Nog %d dagen geldig. Wordt het niet op tijd vernieuwd, dan krijgen bezoekers een waarschuwing.", dagen)).met(gezien).metDetail(detail...)
	default:
		return punt("cert", "X.509", Goed, "Geldig certificaat",
			fmt.Sprintf("Vertrouwd door alle browsers en nog %d dagen geldig.", dagen)).met(gezien).metDetail(detail...)
	}
}

// controleerKeten controleert het certificaat voor host zoals een browser dat
// doet, met alleen de tussencertificaten die de server zelf meestuurde.
// roots nil: de vertrouwde basiscertificaten van het systeem.
func controleerKeten(keten []*x509.Certificate, host string, roots *x509.CertPool) error {
	tussen := x509.NewCertPool()
	for _, c := range keten[1:] {
		tussen.AddCert(c)
	}
	_, err := keten[0].Verify(x509.VerifyOptions{DNSName: host, Intermediates: tussen, Roots: roots})
	return err
}

// certDetail: voor welke namen het certificaat geldt, en de keten. Handig om
// te zien of een vergeten naam erin staat, of een tussencertificaat ontbreekt.
func certDetail(keten []*x509.Certificate) []string {
	blad := keten[0]
	namen := blad.DNSNames
	if len(namen) == 0 && blad.Subject.CommonName != "" {
		namen = []string{blad.Subject.CommonName}
	}
	uit := []string{"Geldig voor: " + strings.Join(lijstje(namen, 8), ", "),
		fmt.Sprintf("Geldig van %s tot %s", blad.NotBefore.Format("2-1-2006"), blad.NotAfter.Format("2-1-2006"))}
	if len(keten) == 1 {
		uit = append(uit, "De server stuurt geen tussencertificaat mee.")
	}
	for i, c := range keten[1:] {
		if i == 3 {
			break
		}
		uit = append(uit, "Keten: "+leegAls(c.Subject.CommonName, uitgever(c)))
	}
	return uit
}

// leegDan geeft s, of alleen anders als s leeg is.
func leegDan(s []string, anders ...string) []string {
	if len(s) == 0 {
		return anders
	}
	return s
}

func uitgever(c *x509.Certificate) string {
	if len(c.Issuer.Organization) > 0 {
		return c.Issuer.Organization[0]
	}
	return leegAls(c.Issuer.CommonName, "onbekend")
}

func certSleutel(w *web) Punt {
	if len(w.staat.PeerCertificates) == 0 {
		return punt("cert-sleutel", "RSA · ECDSA", Fout, "Sterk certificaat", "Geen certificaat om te meten.")
	}
	c := w.staat.PeerCertificates[0]
	var soort string
	sterk := true
	switch s := c.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := s.N.BitLen()
		soort = fmt.Sprintf("RSA %d bits", bits)
		sterk = bits >= 2048
	case *ecdsa.PublicKey:
		soort = fmt.Sprintf("ECDSA %d bits", s.Curve.Params().BitSize)
		sterk = s.Curve.Params().BitSize >= 256
	case ed25519.PublicKey:
		soort = "Ed25519"
	default:
		soort = "onbekend type"
	}
	alg := c.SignatureAlgorithm.String()
	if strings.Contains(alg, "SHA1") || strings.Contains(alg, "MD5") {
		return punt("cert-sleutel", "RSA · ECDSA", Slecht, "Het certificaat is zwak ondertekend",
			"Het certificaat is ondertekend met een verouderde methode ("+alg+") die te vervalsen is.").met("Sleutel: " + soort + ", handtekening: " + alg)
	}
	if !sterk {
		return punt("cert-sleutel", "RSA · ECDSA", Slecht, "De sleutel van het certificaat is te kort",
			"Een kortere sleutel dan 2048 bits (RSA) of 256 bits (ECDSA) is met genoeg rekenkracht te kraken.").met("Sleutel: " + soort)
	}
	return punt("cert-sleutel", "RSA · ECDSA", Goed, "Sterk certificaat",
		"De sleutel is lang genoeg en het certificaat is modern ondertekend.").met("Sleutel: " + soort + ", handtekening: " + alg)
}

func (k *keurder) https(w *web) Punt {
	gezien := "http:// stuurt door naar: " + leegAls(w.httpLoc, "nergens heen")
	detail := []string{fmt.Sprintf("http://%s/ geeft HTTP %d", w.host, w.httpCode)}
	if w.httpLoc != "" {
		detail = append(detail, "Location: "+w.httpLoc, "Hoort te zijn: https://"+w.host+"/ met een 301")
	}
	if w.httpCode == 0 {
		return punt("https", "301 → https", Goed, "Altijd via https",
			"Je website is niet onbeveiligd bereikbaar: http:// staat dicht.")
	}
	switch {
	case zelfdeAdres(w.httpLoc, w.host):
		return punt("https", "301 → https", Goed, "Altijd via https",
			"Wie http:// typt of op een oude link klikt, komt meteen op de beveiligde versie.").met(gezien)
	case strings.HasPrefix(w.httpLoc, "https://"):
		return punt("https", "301 → https", Matig, "Via https, maar met een omweg",
			"Bezoekers worden naar https gestuurd, maar meteen ook naar een andere naam. Dan geldt de beveiliging van je eigen naam niet.").met(gezien).metDetail(detail...)
	default:
		return punt("https", "301 → https", Slecht, "Niet altijd via https",
			"Wie http:// typt of op een oude link klikt, blijft op de onbeveiligde versie van je site.").met(gezien).metDetail(detail...)
	}
}

// hsts kijkt naar het antwoord van de naam zelf, niet naar de pagina na een
// doorverwijzing: HSTS geldt per naam.
func hsts(w *web) Punt {
	v := ""
	if w.eerste != nil {
		v = w.eerste.Header.Get("Strict-Transport-Security")
	}
	maxAge := 0
	for _, deel := range strings.Split(v, ";") {
		if kv := strings.SplitN(strings.TrimSpace(deel), "=", 2); len(kv) == 2 && strings.EqualFold(kv[0], "max-age") {
			maxAge, _ = strconv.Atoi(strings.Trim(kv[1], `"`))
		}
	}
	var detail []string
	if v != "" {
		l := strings.ToLower(v)
		detail = append(detail, "Gemeten op https://"+w.host+"/: "+v)
		if !strings.Contains(l, "includesubdomains") {
			detail = append(detail, "Zonder includeSubDomains: geldt niet voor je subdomeinen.")
		}
	} else {
		detail = append(detail, "https://"+w.host+"/ stuurt geen Strict-Transport-Security mee.")
	}
	switch {
	case maxAge >= 31536000:
		return punt("hsts", "HSTS", Goed, "De browser onthoudt https",
			"Na het eerste bezoek gaat de browser altijd meteen naar de beveiligde versie, ook als iemand http:// typt.").met("Strict-Transport-Security: " + v)
	case maxAge > 0:
		return punt("hsts", "HSTS", Matig, "De browser onthoudt https maar kort",
			fmt.Sprintf("De browser onthoudt de beveiligde versie maar %d dagen; een jaar is de norm.", maxAge/86400)).met("Strict-Transport-Security: " + v).metDetail(detail...)
	default:
		return punt("hsts", "HSTS", Slecht, "De browser onthoudt https niet",
			"Bij elk nieuw bezoek begint de verbinding onbeveiligd, en daar kan iemand op een openbaar wifi-netwerk tussen gaan zitten.").metDetail(detail...)
	}
}
