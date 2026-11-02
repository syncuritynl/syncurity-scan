package keuring

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------- nep-antwoorden

func nepRecord(soort byte, data []byte) []byte {
	return append([]byte{soort, 3, 3, byte(len(data) >> 8), byte(len(data))}, data...)
}

func nepBericht(soort byte, body []byte) []byte {
	return append([]byte{soort, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

// nepHello: een ServerHello met deze suite en compressie; ext is het blok
// extensies (nil: geen).
func nepHello(suite uint16, comp byte, random []byte, ext []byte) []byte {
	if random == nil {
		random = make([]byte, 32)
	}
	b := append([]byte{3, 3}, random...)
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, suite)
	b = append(b, comp)
	if ext != nil {
		b = binary.BigEndian.AppendUint16(b, uint16(len(ext)))
		b = append(b, ext...)
	}
	return nepBericht(2, b)
}

var heronderExt = []byte{0xff, 0x01, 0, 1, 0}

func nepDHE(p []byte, handtekening uint16) []byte {
	var b []byte
	for _, v := range [][]byte{p, {2}, bytes.Repeat([]byte{7}, len(p))} {
		b = binary.BigEndian.AppendUint16(b, uint16(len(v)))
		b = append(b, v...)
	}
	b = binary.BigEndian.AppendUint16(b, handtekening)
	b = binary.BigEndian.AppendUint16(b, 4)
	return nepBericht(12, append(b, 1, 2, 3, 4))
}

func nepECDHE(curve, handtekening uint16) []byte {
	b := []byte{3, byte(curve >> 8), byte(curve), 32}
	b = append(b, bytes.Repeat([]byte{9}, 32)...)
	b = binary.BigEndian.AppendUint16(b, handtekening)
	b = binary.BigEndian.AppendUint16(b, 2)
	return nepBericht(12, append(b, 5, 6))
}

var (
	nepCert  = nepBericht(11, []byte{0, 0, 3, 0, 0, 0}) // lege keten, genoeg om over te slaan
	nepKlaar = nepBericht(14, nil)
)

// priem: p zoals een groep uit RFC 7919 (begin en eind kloppen), of een
// willekeurig getal van zoveel bits.
func priem(bits int, ffdhe bool) []byte {
	p := bytes.Repeat([]byte{0x5A}, bits/8)
	p[0] = 0xC0
	if ffdhe {
		copy(p, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xAD, 0xF8, 0x54, 0x58, 0xA2, 0xBB, 0x4A, 0x9A})
		copy(p[len(p)-8:], bytes.Repeat([]byte{0xFF}, 8))
	}
	return p
}

func TestLeesAntwoord(t *testing.T) {
	// Eén handshake verdeeld over twee records, zoals servers met een grote keten doen.
	dhe := append(append(nepHello(0x009E, 0, nil, heronderExt), nepCert...), nepDHE(priem(1024, false), 0x0401)...)
	dhe = append(dhe, nepKlaar...)
	gedeeld := append(nepRecord(22, dhe[:50]), nepRecord(22, dhe[50:])...)

	hrr := append([]byte(nil), helloRetry...)
	for _, tc := range []struct {
		naam  string
		data  []byte
		fout  bool
		check func(a proefAntwoord) bool
	}{
		{"DHE 1024 over twee records", gedeeld, false, func(a proefAntwoord) bool {
			return a.sleutel && a.dhBits == 1024 && a.dhGroep == "" && a.handtekening == 0x0401 && a.heronder && a.compressie == 0
		}},
		{"ffdhe2048", nepRecord(22, append(append(nepHello(0x009F, 0, nil, heronderExt), nepDHE(priem(2048, true), 0x0804)...), nepKlaar...)), false,
			func(a proefAntwoord) bool { return a.dhBits == 2048 && a.dhGroep == "ffdhe2048" }},
		{"ECDHE met SHA-1", nepRecord(22, append(append(nepHello(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0, nil, heronderExt), nepECDHE(0x001d, 0x0201)...), nepKlaar...)), false,
			func(a proefAntwoord) bool { return a.curve == 0x001d && sha1Handtekening(a.handtekening) }},
		{"compressie, geen heronderhandeling", nepRecord(22, append(nepHello(tls.TLS_RSA_WITH_AES_128_GCM_SHA256, 1, nil, nil), nepKlaar...)), false,
			func(a proefAntwoord) bool { return a.compressie == 1 && !a.heronder && !a.sleutel }},
		{"geweigerd", nepRecord(21, []byte{2, alertHandshake}), false, func(a proefAntwoord) bool { return a.geweigerd && a.alert == alertHandshake }},
		{"HelloRetryRequest", nepRecord(22, nepHello(0x1301, 0, hrr, []byte{0, 43, 0, 2, 3, 4})), false, func(a proefAntwoord) bool { return a.tls13 }},
		{"geweigerd na het certificaat", append(nepRecord(22, append(nepHello(0xC02B, 0, nil, heronderExt), nepCert...)), nepRecord(21, []byte{2, alertHandshake})...), false,
			func(a proefAntwoord) bool { return a.geweigerd && a.versie == 0x0303 && a.suite == 0xC02B }},
		{"leeg", nil, true, nil},
		{"afgekapt", gedeeld[:len(gedeeld)-3], true, nil},
		{"kapotte sleutel", nepRecord(22, append(nepHello(0x009E, 0, nil, nil), nepBericht(12, []byte{0x10, 0})...)), true, nil},
		{"certificaat voor de hello", nepRecord(22, append(nepCert, nepKlaar...)), true, nil},
		{"geen TLS", []byte("HTTP/1.1 400 Bad Request\r\n\r\n"), true, nil},
	} {
		a, err := leesAntwoord(bytes.NewReader(tc.data))
		if (err != nil) != tc.fout || (tc.check != nil && !tc.check(a)) {
			t.Errorf("%s: %+v, %v", tc.naam, a, err)
		}
	}
}

// De ClientHello zet de suites in onze volgorde en biedt de compressie aan.
func TestClientHello(t *testing.T) {
	b := clientHello(proefHello{naam: "voorbeeld.nl", suites: []uint16{0x009C, 0xC02F}, compressie: []byte{1, 0}})
	if b[0] != 22 || int(binary.BigEndian.Uint16(b[3:])) != len(b)-5 || b[5] != 1 {
		t.Fatalf("geen geldig record: % x", b[:10])
	}
	if !bytes.Equal(b[44:50], []byte{0, 4, 0x00, 0x9C, 0xC0, 0x2F}) || !bytes.Equal(b[50:53], []byte{2, 1, 0}) {
		t.Errorf("suites of compressie: % x", b[44:53])
	}
	if !bytes.Contains(b, []byte("voorbeeld.nl")) || !bytes.Contains(b, []byte{0xff, 0x01, 0, 1, 0}) {
		t.Error("SNI of renegotiation_info ontbreekt")
	}
	if bytes.Contains(clientHello(proefHello{naam: "192.0.2.1", suites: []uint16{1}}), []byte("192.0.2.1")) {
		t.Error("SNI met een IP-adres")
	}
}

// goServer: een echte TLS-server van Go, als tegenpartij voor de proef.
func goServer(t *testing.T, minVersie uint16) func() (net.Conn, error) {
	ca := nieuweCA(t)
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{ca.blad(t, time.Now().Add(time.Hour), "voorbeeld.nl")}, MinVersion: minVersie})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _ = c.(*tls.Conn).Handshake() }()
		}
	}()
	return func() (net.Conn, error) { return net.Dial("tcp", l.Addr().String()) }
}

func TestProefTegenGo(t *testing.T) {
	zwak := tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
	o := meetOudeTLS(goServer(t, tls.VersionTLS12), "voorbeeld.nl", tls.VersionTLS13, zwak, 2*time.Second)
	if o.fout != nil || o.alleen13 || o.opties.versie != 0x0303 || !o.opties.heronder || o.opties.compressie != 0 || !o.opties.sleutel || o.opties.curve == 0 {
		t.Fatalf("eerste proef: %+v %v", o.opties, o.fout)
	}
	if o.dhFout != nil || !o.dh.geweigerd {
		t.Errorf("Go kent geen DHE en hoort te weigeren: %+v %v", o.dh, o.dhFout)
	}
	for _, p := range []Punt{tlsDH(o), tlsVolgorde(o), tlsOpties(o), tlsHash(o)} {
		if p.Status != Goed {
			t.Errorf("%s: %s (%s) %v", p.ID, p.Status, p.Titel, p.Detail)
		}
	}
	o = meetOudeTLS(goServer(t, tls.VersionTLS13), "voorbeeld.nl", tls.VersionTLS13, 0, 2*time.Second)
	if !o.alleen13 || tlsDH(o).Uitleg != alleen13Tekst {
		t.Errorf("alleen TLS 1.3: %+v", o)
	}
	o = meetOudeTLS(func() (net.Conn, error) { return nil, errors.New("verbinding geweigerd") }, "voorbeeld.nl", tls.VersionTLS12, 0, time.Second)
	if p := tlsOpties(o); p.Status != Fout {
		t.Errorf("zonder verbinding: %s", p.Status)
	}
}

// Over een net.Conn: de proef schrijft één hello en leest het antwoord.
func TestProefOverPijp(t *testing.T) {
	klant, server := net.Pipe()
	go func() {
		defer server.Close()
		kop := make([]byte, 5)
		if _, err := server.Read(kop); err != nil {
			return
		}
		rest := make([]byte, binary.BigEndian.Uint16(kop[3:]))
		for n := 0; n < len(rest); {
			m, err := server.Read(rest[n:])
			if err != nil {
				return
			}
			n += m
		}
		if !bytes.Contains(rest, []byte{0x00, 0x9E}) {
			t.Error("de hello biedt geen DHE aan")
		}
		_, _ = server.Write(nepRecord(22, append(append(nepHello(0x009E, 0, nil, heronderExt), nepDHE(priem(1024, false), 0x0401)...), nepKlaar...)))
	}()
	a, err := tlsProef(klant, proefHello{naam: "voorbeeld.nl", suites: dheSuites}, 2*time.Second)
	if err != nil || a.dhBits != 1024 {
		t.Errorf("%+v %v", a, err)
	}
}

func TestOudeTLSPunten(t *testing.T) {
	dh := func(bits int, groep string) proefAntwoord {
		return proefAntwoord{suite: 0x009E, sleutel: true, dhBits: bits, dhGroep: groep, handtekening: 0x0401}
	}
	goed := proefAntwoord{versie: 0x0303, suite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, heronder: true, sleutel: true}
	weg := proefAntwoord{geweigerd: true, alert: alertHandshake}
	for _, tc := range []struct {
		naam string
		o    oudeTLS
		f    func(oudeTLS) Punt
		wil  Status
	}{
		{"DH geweigerd", oudeTLS{opties: goed, dh: weg}, tlsDH, Goed},
		{"DH 1024", oudeTLS{opties: goed, dh: dh(1024, "")}, tlsDH, Slecht},
		{"DH 2048", oudeTLS{opties: goed, dh: dh(2048, "ffdhe2048")}, tlsDH, Matig},
		{"DH 4096", oudeTLS{opties: goed, dh: dh(4096, "")}, tlsDH, Matig},
		{"DH zonder antwoord", oudeTLS{opties: goed, dhFout: errProef}, tlsDH, Fout},
		{"DH gekozen, toen gestopt", oudeTLS{opties: goed, dh: proefAntwoord{geweigerd: true, versie: 0x0303, suite: 0x009E}}, tlsDH, Fout},
		{"alleen TLS 1.3", oudeTLS{alleen13: true}, tlsDH, Goed},
		{"niet te meten", oudeTLS{fout: errProef}, tlsHash, Fout},
		{"niets te kiezen", oudeTLS{opties: goed}, tlsVolgorde, Goed},
		{"server kiest sterk", oudeTLS{opties: goed, zwakVoor: tls.TLS_RSA_WITH_AES_128_CBC_SHA}, tlsVolgorde, Goed},
		{"bezoeker kiest", oudeTLS{opties: proefAntwoord{suite: tls.TLS_RSA_WITH_AES_128_CBC_SHA, heronder: true}, zwakVoor: tls.TLS_RSA_WITH_AES_128_CBC_SHA}, tlsVolgorde, Matig},
		{"opties in orde", oudeTLS{opties: goed}, tlsOpties, Goed},
		{"compressie", oudeTLS{opties: proefAntwoord{compressie: 1, heronder: true}}, tlsOpties, Slecht},
		{"geen heronderhandeling", oudeTLS{opties: proefAntwoord{}}, tlsOpties, Slecht},
		{"SHA-1 geweigerd", oudeTLS{opties: goed, hash: weg}, tlsHash, Goed},
		{"SHA-1 gebruikt", oudeTLS{opties: goed, hash: proefAntwoord{sleutel: true, handtekening: 0x0203}}, tlsHash, Matig},
		{"SHA-256 ondanks de vraag", oudeTLS{opties: goed, hash: proefAntwoord{sleutel: true, handtekening: 0x0403}}, tlsHash, Goed},
	} {
		if p := tc.f(tc.o); p.Status != tc.wil {
			t.Errorf("%s: %s (%s), verwacht %s", tc.naam, p.Status, p.Titel, tc.wil)
		}
	}
	if p := tlsDH(oudeTLS{opties: goed, dh: dh(2048, "ffdhe2048")}); p.Gezien != "DHE met 2048 bits (ffdhe2048)" || !strings.Contains(strings.Join(p.Detail, " "), "2048 bits") {
		t.Errorf("gezien %q, detail %v", p.Gezien, p.Detail)
	}
}
