package keuring

import (
	"bufio"
	"cmp"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Lijsten zijn de gegevens van schijf die de keuring gebruikt: de routes
// uit RPKI (rpki.txt.gz) en de HSTS-preloadlijst (hsts.txt.gz). Een proces
// buiten de dienst zet ze klaar; de dienst leest ze alleen. Een nieuwe
// versie (andere wijzigingstijd) wordt hooguit elke tien minuten opgepikt;
// lukt het lezen niet, dan blijft de oude staan en melden we het één keer.
//
// Formaat, als gzip:
//
//	# rpki 2026-11-01 1034567        # hsts 2026-11-01 95123
//	1.0.0.0/24 24 13335               voorbeeld.nl 1
//	2001:db8::/32 48 64496            ander.nl 0
//
// rpki: prefix, maximale lengte, ASN. hsts: naam, 1 als subdomeinen meedoen.
type Lijsten struct {
	map_ string
	nu   func() time.Time

	mu            sync.Mutex
	gecontroleerd time.Time
	rpki          atomic.Pointer[rpkiLijst]
	hsts          atomic.Pointer[hstsLijst]
	tijden        map[string]time.Time // wijzigingstijd van wat er geladen is
	gemeld        map[string]time.Time // wijzigingstijd waarvan de fout al gemeld is
}

const (
	lijstControle = 10 * time.Minute
	lijstMaxOud   = 3 * 24 * time.Hour

	maxRPKIRegels = 5_000_000
	maxHSTSRegels = 1_000_000
	maxLijstBytes = 256 << 20 // uitgepakt
	maxLijstRegel = 200
)

var (
	errGeenLijst = errors.New("de lijst is er niet")
	errLijstOud  = errors.New("de lijst is te oud")
)

// NieuweLijsten leest de lijsten uit map_ (en daarna steeds als ze
// veranderen). Ontbreken ze, dan zijn de punten die ze nodig hebben niet te meten.
func NieuweLijsten(map_ string) *Lijsten {
	l := &Lijsten{map_: map_, nu: time.Now, tijden: map[string]time.Time{}, gemeld: map[string]time.Time{}}
	l.mu.Lock()
	l.laad()
	l.mu.Unlock()
	return l
}

// bij laadt nieuwe versies als de laatste controle lang genoeg geleden is.
// Is een andere scan al aan het laden, dan gebruiken we zolang de oude.
func (l *Lijsten) bij() {
	if !l.mu.TryLock() {
		return
	}
	defer l.mu.Unlock()
	if l.nu().Sub(l.gecontroleerd) >= lijstControle {
		l.laad()
	}
}

func (l *Lijsten) laad() {
	l.gecontroleerd = l.nu()
	if r, ok := laadLijst(l, "rpki.txt.gz", leesRPKI); ok {
		l.rpki.Store(r)
	}
	if h, ok := laadLijst(l, "hsts.txt.gz", leesHSTS); ok {
		l.hsts.Store(h)
	}
}

// laadLijst leest één bestand als het veranderd is. ok: er is een nieuwe versie.
func laadLijst[T any](l *Lijsten, naam string, lees func(io.Reader) (*T, error)) (*T, bool) {
	pad := filepath.Join(l.map_, naam)
	st, err := os.Stat(pad)
	if err != nil || st.ModTime().Equal(l.tijden[naam]) {
		return nil, false
	}
	v, err := leesGzip(pad, lees)
	if err != nil {
		if !l.gemeld[naam].Equal(st.ModTime()) {
			log.Printf("lijst %s niet geladen, de oude blijft staan: %v", pad, err)
			l.gemeld[naam] = st.ModTime()
		}
		return nil, false
	}
	l.tijden[naam] = st.ModTime()
	return v, true
}

func leesGzip[T any](pad string, lees func(io.Reader) (*T, error)) (*T, error) {
	f, err := os.Open(pad)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer z.Close()
	return lees(io.LimitReader(z, maxLijstBytes))
}

// geldig: de lijst is er en is niet te oud.
func lijstGeldig(datum time.Time, nu time.Time) error {
	if nu.Sub(datum) > lijstMaxOud {
		return fmt.Errorf("%w (%s)", errLijstOud, datum.Format("2-1-2006"))
	}
	return nil
}

// RPKI geeft de routes, of waarom die er niet zijn.
func (l *Lijsten) RPKI() (*rpkiLijst, error) {
	if l == nil {
		return nil, errGeenLijst
	}
	l.bij()
	r := l.rpki.Load()
	if r == nil {
		return nil, errGeenLijst
	}
	return r, lijstGeldig(r.datum, l.nu())
}

// HSTS geeft de preloadlijst, of waarom die er niet is.
func (l *Lijsten) HSTS() (*hstsLijst, error) {
	if l == nil {
		return nil, errGeenLijst
	}
	l.bij()
	h := l.hsts.Load()
	if h == nil {
		return nil, errGeenLijst
	}
	return h, lijstGeldig(h.datum, l.nu())
}

// regels leest de kopregel "# soort JJJJ-MM-DD N" en geeft dan elke regel
// aan f. Het aantal regels moet precies N zijn.
func regels(r io.Reader, soort string, max int, f func(regel string) error) (time.Time, error) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, maxLijstRegel), maxLijstRegel)
	if !s.Scan() {
		return time.Time{}, fmt.Errorf("geen kopregel: %v", s.Err())
	}
	kop := strings.Split(s.Text(), " ")
	if len(kop) != 4 || kop[0] != "#" || kop[1] != soort {
		return time.Time{}, fmt.Errorf("kopregel %q is niet \"# %s JJJJ-MM-DD N\"", kort(s.Text(), 60), soort)
	}
	datum, err := time.Parse("2006-01-02", kop[2])
	if err != nil {
		return time.Time{}, fmt.Errorf("datum in de kopregel: %v", err)
	}
	n, err := strconv.Atoi(kop[3])
	if err != nil || n < 1 || n > max {
		return time.Time{}, fmt.Errorf("aantal in de kopregel: %q", kop[3])
	}
	gelezen := 0
	for s.Scan() {
		gelezen++
		if gelezen > n {
			return time.Time{}, fmt.Errorf("meer regels dan de %d uit de kopregel", n)
		}
		if err := f(s.Text()); err != nil {
			return time.Time{}, fmt.Errorf("regel %d: %v", gelezen+1, err)
		}
	}
	if err := s.Err(); err != nil {
		return time.Time{}, err
	}
	if gelezen != n {
		return time.Time{}, fmt.Errorf("%d regels, de kopregel zegt %d", gelezen, n)
	}
	return datum, nil
}

// ---------------------------------------------------------------- RPKI

// vrp4 en vrp6: een route die in RPKI is vastgelegd (Validated ROA Payload).
// Vaste, kleine structs in gesorteerde slices: ruim een miljoen regels
// passen zo in ongeveer 15 MiB.
type vrp4 struct {
	net      uint32
	asn      uint32
	len, max uint8
}

type vrp6 struct {
	hi, lo   uint64
	asn      uint32
	len, max uint8
}

type rpkiLijst struct {
	datum time.Time
	v4    []vrp4
	v6    []vrp6
}

func leesRPKI(r io.Reader) (*rpkiLijst, error) {
	l := &rpkiLijst{}
	datum, err := regels(r, "rpki", maxRPKIRegels, func(regel string) error {
		f := strings.Split(regel, " ")
		if len(f) != 3 {
			return errors.New("niet \"prefix maxlen asn\"")
		}
		p, err := netip.ParsePrefix(f[0])
		if err != nil || p != p.Masked() || p.Addr().Is4In6() || p.Addr().Zone() != "" {
			return fmt.Errorf("prefix %q", kort(f[0], 50))
		}
		max, err := strconv.Atoi(f[1])
		if err != nil || max < p.Bits() || max > p.Addr().BitLen() {
			return fmt.Errorf("maxlen %q", kort(f[1], 10))
		}
		asn, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil {
			return fmt.Errorf("asn %q", kort(f[2], 12))
		}
		if p.Addr().Is4() {
			l.v4 = append(l.v4, vrp4{net: v4getal(p.Addr()), asn: uint32(asn), len: uint8(p.Bits()), max: uint8(max)})
		} else {
			hi, lo := v6getal(p.Addr())
			l.v6 = append(l.v6, vrp6{hi: hi, lo: lo, asn: uint32(asn), len: uint8(p.Bits()), max: uint8(max)})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	l.datum = datum
	// Precies zo groot als nodig: append laat tot de helft ongebruikt.
	l.v4, l.v6 = slices.Clone(l.v4), slices.Clone(l.v6)
	slices.SortFunc(l.v4, func(a, b vrp4) int {
		return cmp.Or(cmp.Compare(a.net, b.net), cmp.Compare(a.len, b.len))
	})
	slices.SortFunc(l.v6, func(a, b vrp6) int {
		return cmp.Or(cmp.Compare(a.hi, b.hi), cmp.Compare(a.lo, b.lo), cmp.Compare(a.len, b.len))
	})
	return l, nil
}

func v4getal(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func v6getal(a netip.Addr) (hi, lo uint64) {
	b := a.As16()
	for i := 0; i < 8; i++ {
		hi = hi<<8 | uint64(b[i])
		lo = lo<<8 | uint64(b[i+8])
	}
	return
}

// rpkiStatus is de uitkomst van RFC 6811 voor één route.
type rpkiStatus int

const (
	rpkiOnbekend rpkiStatus = iota // geen vastgelegde route dekt deze (NotFound)
	rpkiGeldig                     // Valid
	rpkiOngeldig                   // Invalid: wel gedekt, maar niet door dit AS of te specifiek
)

// erger: ongeldig is erger dan niet vastgelegd, en dat is erger dan geldig.
func (s rpkiStatus) erger(t rpkiStatus) bool {
	rang := [...]int{rpkiOnbekend: 1, rpkiGeldig: 0, rpkiOngeldig: 2}
	return rang[s] > rang[t]
}

func (s rpkiStatus) String() string {
	return [...]string{"niet vastgelegd", "geldig", "ongeldig"}[s]
}

// valideer volgt RFC 6811: alle vastgelegde routes die p dekken (zelfde
// begin, even lang of korter); geldig als er een is met dit AS en een
// maximale lengte van minstens die van p.
func (r *rpkiLijst) valideer(p netip.Prefix, asn uint32) rpkiStatus {
	p = p.Masked()
	gedekt, geldig := false, false
	past := func(vAsn uint32, vMax uint8) {
		gedekt = true
		if vAsn == asn && asn != 0 && p.Bits() <= int(vMax) {
			geldig = true
		}
	}
	if p.Addr().Is4() {
		a := v4getal(p.Addr())
		for l := 0; l <= p.Bits(); l++ {
			sleutel := a &^ (1<<(32-l) - 1)
			if l == 0 {
				sleutel = 0
			}
			i, _ := slices.BinarySearchFunc(r.v4, vrp4{net: sleutel, len: uint8(l)}, func(v, d vrp4) int {
				return cmp.Or(cmp.Compare(v.net, d.net), cmp.Compare(v.len, d.len))
			})
			for ; i < len(r.v4) && r.v4[i].net == sleutel && int(r.v4[i].len) == l; i++ {
				past(r.v4[i].asn, r.v4[i].max)
			}
		}
	} else {
		hi, lo := v6getal(p.Addr())
		for l := 0; l <= p.Bits(); l++ {
			mh, ml := hi, lo
			switch {
			case l == 0:
				mh, ml = 0, 0
			case l < 64:
				mh, ml = hi&^(1<<(64-l)-1), 0
			case l == 64:
				ml = 0
			case l < 128:
				ml = lo &^ (1<<(128-l) - 1)
			}
			i, _ := slices.BinarySearchFunc(r.v6, vrp6{hi: mh, lo: ml, len: uint8(l)}, func(v, d vrp6) int {
				return cmp.Or(cmp.Compare(v.hi, d.hi), cmp.Compare(v.lo, d.lo), cmp.Compare(v.len, d.len))
			})
			for ; i < len(r.v6) && r.v6[i].hi == mh && r.v6[i].lo == ml && int(r.v6[i].len) == l; i++ {
				past(r.v6[i].asn, r.v6[i].max)
			}
		}
	}
	switch {
	case geldig:
		return rpkiGeldig
	case gedekt:
		return rpkiOngeldig
	default:
		return rpkiOnbekend
	}
}

// ---------------------------------------------------------------- HSTS

type hstsLijst struct {
	datum time.Time
	namen map[string]bool // naam → subdomeinen doen mee
}

func leesHSTS(r io.Reader) (*hstsLijst, error) {
	h := &hstsLijst{namen: map[string]bool{}}
	datum, err := regels(r, "hsts", maxHSTSRegels, func(regel string) error {
		naam, vlag, ok := strings.Cut(regel, " ")
		if !ok || (vlag != "0" && vlag != "1") || !hstsNaam(naam) {
			return errors.New("niet \"naam 1|0\"")
		}
		h.namen[naam] = vlag == "1"
		return nil
	})
	if err != nil {
		return nil, err
	}
	h.datum = datum
	return h, nil
}

// hstsNaam: kleine letters, cijfers, streepjes en punten, geen lege delen.
func hstsNaam(n string) bool {
	if n == "" || len(n) > 253 {
		return false
	}
	for _, deel := range strings.Split(n, ".") {
		if deel == "" || len(deel) > 63 {
			return false
		}
		for _, c := range deel {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// preload: "ja" als de naam zelf op de lijst staat, "ja, via x" als een
// bovenliggende naam er met subdomeinen op staat, anders "nee".
func (h *hstsLijst) preload(naam string) string {
	if _, ok := h.namen[naam]; ok {
		return "ja"
	}
	for d := naam; strings.Contains(d, "."); {
		d = d[strings.Index(d, ".")+1:]
		if h.namen[d] {
			return "ja, via " + d
		}
	}
	return "nee"
}
