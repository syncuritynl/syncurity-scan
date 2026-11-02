package keuring

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"syscall"
)

// De punten uit de STARTTLS-meting (mailtls.go).

// mailNietTeMeten: de gezamenlijke uitkomst als er niets te meten viel.
// ok is false als het punt zelf moet oordelen; gemeten zijn dan de
// mailservers waarmee een gesprek lukte.
func mailNietTeMeten(id, tech, titel string, ms []mxMeting, err error) (Punt, []mxMeting, bool) {
	if err != nil {
		return punt(id, tech, Fout, titel, "Niet gemeten: de controle van mailservers staat uit."), nil, true
	}
	var gemeten []mxMeting
	var detail []string
	geweigerd, alleenV4 := false, true
	for _, m := range ms {
		if m.fout != nil {
			if m.adres.IsValid() {
				detail = append(detail, fmt.Sprintf("%s (%s): %v", m.naam, m.adres, m.fout))
			} else {
				detail = append(detail, fmt.Sprintf("%s: %v", m.naam, m.fout))
			}
			geweigerd = geweigerd || weigering(m.fout)
			alleenV4 = alleenV4 && m.alleenV4
			continue
		}
		gemeten = append(gemeten, m)
	}
	switch {
	case len(gemeten) > 0:
	case geweigerd:
		return punt(id, tech, Fout, titel,
			"Niet te meten vanaf onze server: je mailserver weigerde onze verbinding. Veel providers weigeren verbindingen vanuit datacenters; dat zegt niets over je mail.").metDetail(detail...), nil, true
	case alleenV4:
		return punt(id, tech, Fout, titel,
			"We konden je mailserver vanaf onze scanserver niet bereiken (alleen via IPv4), dus dit is niet gemeten. Dat zegt niets over je mail.").metDetail(detail...), nil, true
	default:
		return punt(id, tech, Fout, titel,
			"We konden je mailserver vanaf onze scanserver niet bereiken, dus dit is niet gemeten. Dat zegt niets over je mail.").metDetail(detail...), nil, true
	}
	return Punt{}, gemeten, false
}

// weigering: de mailserver zelf zei nee (verbinding geweigerd, of een
// foutcode of onzin in plaats van de begroeting). Een time-out of geen
// route is geen weigering: dan kwamen we er niet bij.
func weigering(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, errSMTP)
}

func starttlsPunt(ms []mxMeting, err error, leverancier string) Punt {
	const id, tech, titel = "starttls", "STARTTLS", "Mail versleuteld afgeleverd"
	p, gemeten, klaar := mailNietTeMeten(id, tech, titel, ms, err)
	if klaar {
		return p
	}
	var geen, kapot, zwak, detail []string
	versies := map[string]bool{}
	for _, m := range gemeten {
		switch {
		case m.geenTLS:
			geen = append(geen, m.naam)
			detail = append(detail, m.naam+": geen STARTTLS")
			continue
		case m.tlsFout != nil:
			kapot = append(kapot, m.naam)
			detail = append(detail, fmt.Sprintf("%s: versleuteling mislukt (%v)", m.naam, m.tlsFout))
			continue
		}
		versies[tls.VersionName(m.versie)] = true
		regel := fmt.Sprintf("%s: %s, %s", m.naam, tls.VersionName(m.versie), tls.CipherSuiteName(m.suite))
		if m.oud != "" {
			zwak = append(zwak, m.naam+" accepteert "+m.oud)
		}
		if m.zwak != "" {
			z := m.naam + " accepteert " + m.zwak
			if m.dhBits > 0 {
				z += fmt.Sprintf(" (DH van %d bits)", m.dhBits)
			}
			zwak = append(zwak, z)
		}
		detail = append(detail, regel)
	}
	detail = append(detail, zwak...)
	switch {
	case len(geen) > 0:
		return punt(id, tech, Slecht, "Mail aan jou gaat onversleuteld",
			"Je mailserver biedt geen versleuteling (STARTTLS) aan. Mail aan jou gaat dan leesbaar over het internet, en iedereen onderweg kan meelezen.").
			met("Geen STARTTLS: " + strings.Join(geen, ", ")).metDetail(detail...)
	case len(kapot) > 0:
		return punt(id, tech, Slecht, "Versleutelen naar je mailserver mislukt",
			"Je mailserver biedt versleuteling aan, maar die mislukt. Andere mailservers sturen je mail dan meestal onversleuteld, of helemaal niet.").
			met("Mislukt: " + strings.Join(kapot, ", ")).metDetail(detail...)
	case len(zwak) > 0:
		uitleg := "Je mailserver versleutelt, maar accepteert ook nog oude versies of zwakke versleuteling. internet.nl noemt dat onvoldoende: een afzender met oude software kan zo een zwakke verbinding krijgen."
		if leverancier == "Microsoft 365" || leverancier == "Google Workspace" {
			uitleg += " Je mail loopt via " + leverancier + ". Dit stelt " + leverancier + " zelf in; je kunt het niet aanpassen. internet.nl noemt dit bij deze diensten het hoogst haalbare."
		}
		return punt(id, tech, Matig, "Mail versleuteld, maar ook nog zwak", uitleg).met(kort(strings.Join(zwak, "; "), 200)).metDetail(detail...)
	}
	return punt(id, tech, Goed, titel,
		"Je mailserver versleutelt de verbinding met moderne TLS. Mail aan jou gaat versleuteld over het internet.").
		met(fmt.Sprintf("%d %s: STARTTLS met %s", len(gemeten), map[bool]string{true: "mailserver", false: "mailservers"}[len(gemeten) == 1], strings.Join(sleutels(versies), ", "))).metDetail(detail...)
}

func mxCert(ms []mxMeting, err error, roots *x509.CertPool) Punt {
	const id, tech, titel = "mx-cert", "X.509 · MX", "Certificaat van de mailserver klopt"
	p, gemeten, klaar := mailNietTeMeten(id, tech, titel, ms, err)
	if klaar {
		return p
	}
	var fout, detail []string
	n := 0
	for _, m := range gemeten {
		if len(m.keten) == 0 {
			continue
		}
		n++
		blad := m.keten[0]
		regel := fmt.Sprintf("%s: uitgegeven door %s, geldig tot %s", m.naam, uitgever(blad), blad.NotAfter.Format("2-1-2006"))
		if e := controleerKeten(m.keten, m.naam, roots); e != nil {
			fout = append(fout, m.naam)
			var naamFout x509.HostnameError
			if errors.As(e, &naamFout) {
				regel += ", maar voor een andere naam"
			} else {
				regel += ", maar niet vertrouwd (" + kort(e.Error(), 80) + ")"
			}
		}
		detail = append(detail, regel)
	}
	switch {
	case n == 0:
		return punt(id, tech, NVT, titel, "Je mailserver biedt geen versleuteling aan, dus er is geen certificaat om te controleren.")
	case len(fout) > 0:
		return punt(id, tech, Matig, "Certificaat van de mailserver klopt niet",
			"Het certificaat van je mailserver is niet geldig voor zijn naam, of wordt niet vertrouwd. De meeste mailservers leveren nog wel af, maar DANE en MTA-STS werken alleen met een geldig certificaat.").
			met("Klopt niet: " + strings.Join(fout, ", ")).metDetail(detail...)
	}
	return punt(id, tech, Goed, titel, "Het certificaat van je mailserver is geldig voor zijn naam en wordt vertrouwd.").met(detail[0]).metDetail(detail...)
}
