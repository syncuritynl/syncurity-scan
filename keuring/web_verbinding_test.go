package keuring

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

// De sleuteluitwisseling staat in wat we zagen; aan de status verandert niets.
func TestTLSModernSleutel(t *testing.T) {
	for _, tc := range []struct {
		staat  tls.ConnectionState
		gezien string
		status Status
	}{
		{tls.ConnectionState{Version: tls.VersionTLS13, CurveID: tls.X25519MLKEM768}, "Beste versie: TLS 1.3 · sleutel: X25519MLKEM768 (kwantumveilig)", Goed},
		{tls.ConnectionState{Version: tls.VersionTLS13, CurveID: tls.X25519}, "Beste versie: TLS 1.3 · sleutel: X25519", Goed},
		{tls.ConnectionState{Version: tls.VersionTLS12}, "Beste versie: TLS 1.2", Matig},
	} {
		p := tlsModern(&web{host: "voorbeeld.nl", staat: &tc.staat})
		if p.Gezien != tc.gezien || p.Status != tc.status {
			t.Errorf("%q (%s), verwacht %q (%s)", p.Gezien, p.Status, tc.gezien, tc.status)
		}
	}
}

// Een server die alleen het blad stuurt, zonder tussencertificaat.
func TestCertificaatKeten(t *testing.T) {
	ca := nieuweCA(t)
	tussen := ca.tussen(t)
	jaar := time.Now().Add(365 * 24 * time.Hour)
	alleenBlad := tussen.blad(t, jaar, "voorbeeld.nl")
	compleet := alleenBlad
	compleet.Certificate = append(compleet.Certificate, tussen.cert.Raw)
	for _, tc := range []struct {
		naam  string
		cert  tls.Certificate
		titel string
		wil   Status
	}{
		{"compleet", compleet, "Geldig certificaat", Goed},
		{"alleen het blad", alleenBlad, "De keten van het certificaat is niet compleet", Slecht},
		{"zelf ondertekend", zelfOndertekend(t, "voorbeeld.nl"), "Het certificaat wordt niet vertrouwd", Slecht},
		{"andere naam", tussen.blad(t, jaar, "ander.nl"), "Het certificaat hoort bij een andere naam", Slecht},
	} {
		w := &web{host: "voorbeeld.nl", staat: staatVan(t, tlsServer(t, tc.cert, ""), "voorbeeld.nl"), roots: ca.pool}
		p := certificaat(w)
		if p.Status != tc.wil || p.Titel != tc.titel {
			t.Errorf("%s: %s (%s), verwacht %s (%s)", tc.naam, p.Status, p.Titel, tc.wil, tc.titel)
		}
		if tc.naam == "alleen het blad" && !strings.Contains(strings.Join(p.Detail, " "), "geen tussencertificaat") {
			t.Errorf("%s: detail %v", tc.naam, p.Detail)
		}
	}
}

// zelfOndertekend: een certificaat voor naam zonder uitgever boven zich.
func zelfOndertekend(t *testing.T, naam string) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: naam}, DNSNames: []string{naam},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
