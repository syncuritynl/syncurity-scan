package keuring

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ---------------------------------------------------------------- nep-DNS

// nepDNS beantwoordt vragen uit een lijst records, zonder netwerk. Namen in
// nx geven NXDOMAIN (met de CNAME-keten ervoor, zoals een echte resolver).
type nepDNS struct {
	rr   []dns.RR
	nx   map[string]bool
	fout map[string]bool // SERVFAIL
}

func nieuwNepDNS(t *testing.T, records ...string) *nepDNS {
	n := &nepDNS{nx: map[string]bool{}, fout: map[string]bool{}}
	for _, r := range records {
		rr, err := dns.NewRR(r)
		if err != nil {
			t.Fatalf("%s: %v", r, err)
		}
		n.rr = append(n.rr, rr)
	}
	return n
}

func (n *nepDNS) Vraag(_ context.Context, naam string, soort uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(naam), soort)
	huidig := dns.Fqdn(strings.ToLower(naam))
	for i := 0; i < 8; i++ {
		if n.fout[huidig] {
			m.Rcode = dns.RcodeServerFailure
			return m, nil
		}
		if n.nx[huidig] {
			m.Rcode = dns.RcodeNameError
			return m, nil
		}
		volgende := ""
		gevonden := false
		for _, rr := range n.rr {
			if !strings.EqualFold(rr.Header().Name, huidig) {
				continue
			}
			gevonden = true
			if c, ok := rr.(*dns.CNAME); ok && soort != dns.TypeCNAME {
				m.Answer = append(m.Answer, rr)
				volgende = c.Target
			} else if rr.Header().Rrtype == soort {
				m.Answer = append(m.Answer, rr)
			}
		}
		if volgende == "" {
			if !gevonden {
				m.Rcode = dns.RcodeNameError
			}
			return m, nil
		}
		huidig = strings.ToLower(volgende)
	}
	return m, nil
}

// ---------------------------------------------------------------- certificaten

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func nieuweCA(t *testing.T) *testCA {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA", Organization: []string{"Let's Encrypt"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour * 365), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return &testCA{c, key, pool}
}

func (ca *testCA) blad(t *testing.T, tot time.Time, namen ...string) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: namen[0]},
		DNSNames: namen, NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: tot,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tussen maakt een tussencertificaat onder deze CA. Bladen van het
// tussencertificaat zijn alleen te controleren als de server het meestuurt.
func (ca *testCA) tussen(t *testing.T) *testCA {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "Test tussen-CA", Organization: []string{"Let's Encrypt"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour * 365), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{c, key, ca.pool}
}

// staatVan doet een handdruk met een testserver, zonder het certificaat te
// controleren, zoals handdruk() dat ook doet.
func staatVan(t *testing.T, adres, naam string) *tls.ConnectionState {
	t.Helper()
	c, err := tls.Dial("tcp", adres, &tls.Config{ServerName: naam, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s := c.ConnectionState()
	return &s
}

// tlsServer start een https-server met dit certificaat en deze pagina.
func tlsServer(t *testing.T, cert tls.Certificate, pagina string) string {
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			t.Errorf("de proef vroeg %s op; alleen / mag", r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(pagina))
	}))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s.Listener.Addr().String()
}
