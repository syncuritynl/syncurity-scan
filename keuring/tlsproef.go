package keuring

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"time"
)

// Een eigen, kleine TLS 1.2-proef voor wat crypto/tls niet kan laten zien:
// de sterkte van DH, de volgorde van de suites, compressie, veilige
// heronderhandeling en de hashfunctie bij de sleuteluitwisseling. We sturen
// één gewone ClientHello, zoals elke browser, lezen het antwoord tot en met
// ServerHelloDone en sluiten dan de verbinding. Geen sleuteluitwisseling,
// geen Finished, geen heronderhandeling: alleen kijken wat de server aanbiedt.
// Werkt over elke net.Conn, dus ook na STARTTLS.

// proefHello is wat we aanbieden, in onze volgorde.
type proefHello struct {
	naam         string   // voor SNI; leeg of een IP-adres: geen SNI
	suites       []uint16 // in deze volgorde
	compressie   []byte   // nil: alleen null (0)
	handtekening []uint16 // signature_algorithms; nil: de gangbare
}

// proefAntwoord is wat de server terugzei.
type proefAntwoord struct {
	geweigerd    bool   // de server stuurde een alert, voor of na de ServerHello (dan is versie gezet)
	alert        byte   // de reden (description) van die alert
	tls13        bool   // de server antwoordde met TLS 1.3 of een HelloRetryRequest
	versie       uint16 // server_version uit de ServerHello
	suite        uint16
	compressie   byte
	heronder     bool   // renegotiation_info in de ServerHello
	sleutel      bool   // er kwam een ServerKeyExchange
	dhBits       int    // DHE: lengte van p in bits
	dhGroep      string // DHE: "ffdhe2048" enz. als p op een groep uit RFC 7919 lijkt
	curve        uint16 // ECDHE: de gekozen named curve
	handtekening uint16 // SignatureAndHashAlgorithm van de ServerKeyExchange
}

const (
	maxProef = 64 << 10 // zoveel lezen we hooguit van de server

	alertHandshake = 40
)

// dheSuites: DHE met RSA (GCM en CBC). crypto/tls kent ze niet.
var dheSuites = []uint16{0x009E, 0x009F, 0x0033, 0x0039, 0x0067, 0x006B}

// Standaardlijsten voor de proef.
var (
	proefGroepen        = []uint16{0x001d, 0x0017, 0x0018} // x25519, secp256r1, secp384r1
	proefHandtekeningen = []uint16{0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0403, 0x0503, 0x0603, 0x0201, 0x0203}
	sha1Handtekeningen  = []uint16{0x0201, 0x0203} // rsa_pkcs1_sha1, ecdsa_sha1
)

// helloRetry is de vaste "random" van een HelloRetryRequest (RFC 8446).
var helloRetry = []byte{0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C}

var errProef = errors.New("onverwacht antwoord op de TLS-proef")

// tlsProef stuurt de ClientHello over c en leest het antwoord, hooguit
// timeout lang.
func tlsProef(c net.Conn, h proefHello, timeout time.Duration) (proefAntwoord, error) {
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write(clientHello(h)); err != nil {
		return proefAntwoord{}, err
	}
	return leesAntwoord(io.LimitReader(c, maxProef))
}

// clientHello bouwt het record met de ClientHello.
func clientHello(h proefHello) []byte {
	var b []byte
	b = append(b, 0x03, 0x03) // TLS 1.2
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	b = append(b, random...)
	b = append(b, 0) // geen sessie-id
	b = binary.BigEndian.AppendUint16(b, uint16(2*len(h.suites)))
	for _, s := range h.suites {
		b = binary.BigEndian.AppendUint16(b, s)
	}
	comp := h.compressie
	if len(comp) == 0 {
		comp = []byte{0}
	}
	b = append(b, byte(len(comp)))
	b = append(b, comp...)

	var ext []byte
	voeg := func(soort uint16, data []byte) {
		ext = binary.BigEndian.AppendUint16(ext, soort)
		ext = binary.BigEndian.AppendUint16(ext, uint16(len(data)))
		ext = append(ext, data...)
	}
	if h.naam != "" && net.ParseIP(h.naam) == nil {
		naam := []byte(strings.TrimSuffix(h.naam, "."))
		var sni []byte
		sni = binary.BigEndian.AppendUint16(sni, uint16(len(naam)+3))
		sni = append(sni, 0) // host_name
		sni = binary.BigEndian.AppendUint16(sni, uint16(len(naam)))
		voeg(0, append(sni, naam...))
	}
	voeg(10, lijst16(proefGroepen))
	voeg(11, []byte{1, 0}) // ec_point_formats: uncompressed
	voeg(13, lijst16(leegDan16(h.handtekening, proefHandtekeningen)))
	voeg(0xff01, []byte{0}) // renegotiation_info, leeg
	b = binary.BigEndian.AppendUint16(b, uint16(len(ext)))
	b = append(b, ext...)

	hs := append([]byte{1, byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}, b...)
	rec := []byte{22, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func lijst16(l []uint16) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(2*len(l)))
	for _, v := range l {
		b = binary.BigEndian.AppendUint16(b, v)
	}
	return b
}

func leegDan16(l, anders []uint16) []uint16 {
	if len(l) == 0 {
		return anders
	}
	return l
}

// leesAntwoord leest records tot ServerHelloDone, een alert of TLS 1.3. Wat
// de server stuurt, is onbetrouwbaar: elke lengte wordt nagerekend.
func leesAntwoord(r io.Reader) (proefAntwoord, error) {
	var a proefAntwoord
	var hs []byte // handshake-berichten, over records heen
	hello := false
	for {
		kop := make([]byte, 5)
		if _, err := io.ReadFull(r, kop); err != nil {
			return a, fmt.Errorf("%w: %v", errProef, err)
		}
		n := int(binary.BigEndian.Uint16(kop[3:]))
		if n == 0 || n > 16384+2048 {
			return a, errProef
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(r, data); err != nil {
			return a, fmt.Errorf("%w: %v", errProef, err)
		}
		switch kop[0] {
		case 21: // alert
			if len(data) < 2 {
				return a, errProef
			}
			// Ook na de ServerHello: een server die geen handtekening kan
			// zetten met wat wij aanbieden, stopt na zijn certificaat.
			a.geweigerd, a.alert = true, data[1]
			return a, nil
		case 22: // handshake
			hs = append(hs, data...)
		default:
			return a, errProef
		}
		for len(hs) >= 4 {
			lengte := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
			if lengte > maxProef {
				return a, errProef
			}
			if len(hs) < 4+lengte {
				break // het bericht loopt door in het volgende record
			}
			soort, body := hs[0], hs[4:4+lengte]
			hs = hs[4+lengte:]
			switch {
			case soort == 2 && !hello:
				if err := a.serverHello(body); err != nil {
					return a, err
				}
				if a.tls13 {
					return a, nil
				}
				hello = true
			case !hello:
				return a, errProef
			case soort == 12:
				if err := a.sleutelUitwisseling(body); err != nil {
					return a, err
				}
			case soort == 14: // ServerHelloDone
				return a, nil
			}
		}
	}
}

// lezer leest velden uit een bericht en onthoudt of er iets te kort was.
type lezer struct {
	b    []byte
	fout bool
}

func (l *lezer) pak(n int) []byte {
	if n < 0 || len(l.b) < n {
		l.fout = true
		l.b = nil
		return nil
	}
	v := l.b[:n]
	l.b = l.b[n:]
	return v
}

func (l *lezer) u8() int {
	if v := l.pak(1); v != nil {
		return int(v[0])
	}
	return 0
}

func (l *lezer) u16() int {
	if v := l.pak(2); v != nil {
		return int(binary.BigEndian.Uint16(v))
	}
	return 0
}

func (a *proefAntwoord) serverHello(body []byte) error {
	l := &lezer{b: body}
	a.versie = uint16(l.u16())
	random := l.pak(32)
	l.pak(l.u8()) // sessie-id
	a.suite = uint16(l.u16())
	a.compressie = byte(l.u8())
	if l.fout {
		return errProef
	}
	if bytes.Equal(random, helloRetry) || a.versie > 0x0303 {
		a.tls13 = true
		return nil
	}
	if len(l.b) == 0 {
		return nil // geen extensies
	}
	ext := &lezer{b: l.pak(l.u16())}
	for len(ext.b) > 0 && !ext.fout {
		soort := ext.u16()
		data := ext.pak(ext.u16())
		switch soort {
		case 0xff01:
			a.heronder = true
		case 43: // supported_versions: alleen bij TLS 1.3
			if len(data) == 2 && binary.BigEndian.Uint16(data) >= 0x0304 {
				a.tls13 = true
			}
		}
	}
	if l.fout || ext.fout {
		return errProef
	}
	return nil
}

func (a *proefAntwoord) sleutelUitwisseling(body []byte) error {
	l := &lezer{b: body}
	switch {
	case isDHE(a.suite):
		p := l.pak(l.u16())
		l.pak(l.u16()) // g
		l.pak(l.u16()) // Ys
		if l.fout || len(p) == 0 {
			return errProef
		}
		a.dhBits = new(big.Int).SetBytes(p).BitLen()
		a.dhGroep = ffdheGroep(p, a.dhBits)
	case strings.Contains(suiteNaam(a.suite), "ECDHE"):
		if l.u8() != 3 { // alleen named_curve
			return errProef
		}
		a.curve = uint16(l.u16())
		l.pak(l.u8()) // publieke sleutel
	default:
		return errProef
	}
	if a.versie >= 0x0303 { // vóór TLS 1.2 staat er geen algoritme bij de handtekening
		a.handtekening = uint16(l.u16())
	}
	l.pak(l.u16())
	if l.fout {
		return errProef
	}
	a.sleutel = true
	return nil
}

func isDHE(s uint16) bool {
	for _, d := range dheSuites {
		if s == d {
			return true
		}
	}
	return false
}

// ffdheGroep: de groepen uit RFC 7919 beginnen allemaal met dezelfde cijfers
// van e en eindigen op 64 enen. Dat is genoeg om ze te herkennen; een eigen
// priem die er toevallig zo uitziet, bestaat in de praktijk niet.
func ffdheGroep(p []byte, bits int) string {
	begin := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xAD, 0xF8, 0x54, 0x58, 0xA2, 0xBB, 0x4A, 0x9A}
	eind := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	switch bits {
	case 2048, 3072, 4096, 6144, 8192:
		if bytes.HasPrefix(p, begin) && bytes.HasSuffix(p, eind) {
			return fmt.Sprintf("ffdhe%d", bits)
		}
	}
	return ""
}

// suiteNaam: de naam van een suite, ook voor DHE (die kent crypto/tls niet).
func suiteNaam(s uint16) string {
	if n, ok := dheNamen[s]; ok {
		return n
	}
	return tls.CipherSuiteName(s)
}

var dheNamen = map[uint16]string{
	0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", 0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
}

// handtekeningNaam: de SignatureAndHashAlgorithm in woorden.
func handtekeningNaam(v uint16) string {
	if n, ok := map[uint16]string{
		0x0201: "RSA met SHA-1", 0x0203: "ECDSA met SHA-1", 0x0202: "DSA met SHA-1",
		0x0401: "RSA met SHA-256", 0x0501: "RSA met SHA-384", 0x0601: "RSA met SHA-512",
		0x0403: "ECDSA met SHA-256", 0x0503: "ECDSA met SHA-384", 0x0603: "ECDSA met SHA-512",
		0x0804: "RSA-PSS met SHA-256", 0x0805: "RSA-PSS met SHA-384", 0x0806: "RSA-PSS met SHA-512",
		0x0807: "Ed25519", 0x0808: "Ed448",
	}[v]; ok {
		return n
	}
	return fmt.Sprintf("0x%04X", v)
}

// sha1Handtekening: de hash van een SignatureAndHashAlgorithm is SHA-1 of
// MD5 (het eerste byte is 2 of 1).
func sha1Handtekening(v uint16) bool {
	return v>>8 == 1 || v>>8 == 2
}
