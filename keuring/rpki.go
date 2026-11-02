package keuring

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// RPKI: is de route naar een adres vastgelegd, en klopt hij? Welk netwerk
// (AS) een adres aankondigt en met welk prefix, vragen we via de gewone
// resolver op bij Team Cymru; de vastgelegde routes komen uit de lijst op
// schijf (lijsten.go). Geen verbinding met de servers zelf.

// route is wat Team Cymru over een adres zegt.
type route struct {
	asns   []uint32
	prefix netip.Prefix
}

// cymruNaam: 4.3.2.1.origin.asn.cymru.com, of de omgekeerde nibbles van een
// IPv6-adres onder origin6.asn.cymru.com.
func cymruNaam(a netip.Addr) string {
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", b[3], b[2], b[1], b[0])
	}
	b := a.As16()
	var s strings.Builder
	for i := 15; i >= 0; i-- {
		fmt.Fprintf(&s, "%x.%x.", b[i]&0xf, b[i]>>4)
	}
	return s.String() + "origin6.asn.cymru.com"
}

// leesCymru ontleedt "31898 | 92.5.224.0/20 | SE | ripencc | 2007-06-28".
// Het antwoord is onbetrouwbaar: het prefix moet geldig zijn en het adres
// bevatten, en het ASN een getal. Er kunnen meer ASN's staan (gescheiden
// door spaties); meer dan acht is onzin.
func leesCymru(txt string, a netip.Addr) (route, bool) {
	if len(txt) > 512 {
		return route{}, false
	}
	velden := strings.Split(txt, "|")
	if len(velden) < 2 {
		return route{}, false
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(velden[1]))
	a = a.Unmap()
	if err != nil || p != p.Masked() || !p.Contains(a) || p.Addr().Is4() != a.Is4() {
		return route{}, false
	}
	r := route{prefix: p}
	for _, s := range strings.Fields(velden[0]) {
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil || n == 0 || len(r.asns) == 8 {
			return route{}, false
		}
		r.asns = append(r.asns, uint32(n))
	}
	return r, len(r.asns) > 0
}

var errGeenRoute = errors.New("geen aangekondigde route gevonden")

// zoekRoute vraagt de route van een adres op. Bij meer antwoorden telt het
// meest specifieke prefix: dat volgt het verkeer.
func zoekRoute(ctx context.Context, v vrager, a netip.Addr) (route, error) {
	m, err := v.Vraag(ctx, cymruNaam(a), dns.TypeTXT)
	if err != nil {
		return route{}, err
	}
	var beste route
	for i, rr := range m.Answer {
		if i == 8 {
			break
		}
		t, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		if r, ok := leesCymru(strings.Join(t.Txt, ""), a); ok && (!beste.prefix.IsValid() || r.prefix.Bits() > beste.prefix.Bits()) {
			beste = r
		}
	}
	if !beste.prefix.IsValid() {
		return route{}, errGeenRoute
	}
	return beste, nil
}

// rpkiAdres: de uitkomst voor één adres van een server.
type rpkiAdres struct {
	host   string
	adres  netip.Addr
	route  route
	status rpkiStatus // het slechtste over de ASN's van de route
	fout   error
}

type hostAdres struct {
	host  string
	adres netip.Addr
}

// meetRPKI zoekt de routes op, hooguit vier tegelijk.
func meetRPKI(ctx context.Context, v vrager, lijst *rpkiLijst, adressen []hostAdres) []rpkiAdres {
	uit := make([]rpkiAdres, len(adressen))
	rem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, ha := range adressen {
		wg.Go(func() {
			rem <- struct{}{}
			defer func() { <-rem }()
			m := rpkiAdres{host: ha.host, adres: ha.adres}
			m.route, m.fout = zoekRoute(ctx, v, ha.adres)
			if m.fout == nil {
				// Kondigen meer netwerken hetzelfde prefix aan, dan telt het
				// slechtste: een ongeldige aankondiging is een kaping of een fout.
				for j, asn := range m.route.asns {
					s := lijst.valideer(m.route.prefix, asn)
					if j == 0 || s.erger(m.status) {
						m.status = s
					}
				}
			}
			uit[i] = m
		})
	}
	wg.Wait()
	return uit
}

// rpkiAdressen: hooguit maxPerFamilie adressen per soort, per naam.
func (k *keurder) rpkiAdressen(ctx context.Context, hosts []string) []hostAdres {
	var uit []hostAdres
	for _, h := range hosts {
		v4, v6 := k.kiezer.Adressen(ctx, h)
		for _, a := range slices.Concat(v4[:min(len(v4), maxPerFamilie)], v6[:min(len(v6), maxPerFamilie)]) {
			uit = append(uit, hostAdres{h, a})
		}
	}
	return uit
}

// rpkiPunt meet en oordeelt. wat: "je website", "je mailservers", "je nameservers".
func (k *keurder) rpkiPunt(ctx context.Context, id, tech, titel, wat string, hosts []string) Punt {
	lijst, err := k.lijsten.RPKI()
	if err != nil {
		return rpkiOordeel(id, tech, titel, wat, err, nil)
	}
	return rpkiOordeel(id, tech, titel, wat, nil, meetRPKI(ctx, k.r, lijst, k.rpkiAdressen(ctx, hosts)))
}

func rpkiOordeel(id, tech, titel, wat string, lijstFout error, ms []rpkiAdres) Punt {
	if lijstFout != nil {
		reden := "We konden dit nu niet meten: de lijst met vastgelegde routes ontbreekt."
		if errors.Is(lijstFout, errLijstOud) {
			reden = "We konden dit nu niet meten: onze lijst met vastgelegde routes is te oud."
		}
		return punt(id, tech, Fout, titel, reden)
	}
	if len(ms) == 0 {
		return punt(id, tech, NVT, titel, "We vonden geen adressen om te controleren.")
	}
	var detail, gezien []string
	aantal := map[rpkiStatus]int{}
	gemeten := 0
	dubbel := map[string]bool{}
	for _, m := range ms {
		if m.fout != nil {
			detail = append(detail, fmt.Sprintf("%s (%s): geen route gevonden", m.adres, m.host))
			continue
		}
		gemeten++
		aantal[m.status]++
		asns := make([]string, len(m.route.asns))
		for i, a := range m.route.asns {
			asns[i] = fmt.Sprintf("AS%d", a)
		}
		regel := fmt.Sprintf("%s via %s: %s", m.route.prefix, strings.Join(asns, " "), m.status)
		if !dubbel[regel] {
			dubbel[regel] = true
			gezien = append(gezien, regel)
		}
		detail = append(detail, fmt.Sprintf("%s (%s): %s", m.adres, m.host, regel))
	}
	if gemeten == 0 {
		return punt(id, tech, Fout, titel, "We vonden de route naar "+wat+" niet in de openbare routetabel.").metDetail(detail...)
	}
	sort.Strings(gezien)
	g := strings.Join(lijstje(gezien, 4), ", ")
	switch {
	case aantal[rpkiOngeldig] > 0:
		return punt(id, tech, Slecht, "Route naar "+wat+" klopt niet met RPKI",
			"De route naar "+wat+" wordt aangekondigd door een netwerk dat er volgens de vastgelegde gegevens (RPKI) niet bij hoort. Netwerken die RPKI controleren, kunnen het verkeer weigeren, of het is een teken dat iemand de route probeert te kapen.").met(g).metDetail(detail...)
	case aantal[rpkiOnbekend] > 0:
		return punt(id, tech, Matig, "Route naar "+wat+" niet vastgelegd",
			"De route naar "+wat+" is niet vastgelegd in RPKI. Dan kan een ander netwerk zich makkelijker voordoen als de jouwe en het verkeer omleiden. Dit regel je niet zelf: vraag het je hostingpartij of provider.").met(g).metDetail(detail...)
	default:
		return punt(id, tech, Goed, titel,
			"De route naar "+wat+" is vastgelegd in RPKI en klopt. Netwerken die dat controleren, trappen niet in een omgeleide route.").met(g).metDetail(detail...)
	}
}

// mxOpVoorkeur: de mailservers, laagste voorkeur (= eerst gebruikt) eerst.
func (k *keurder) mxOpVoorkeur(ctx context.Context) []string {
	rrs, _, _, _ := k.r.Records(ctx, k.domein, dns.TypeMX)
	type mx struct {
		naam string
		pref uint16
	}
	var l []mx
	for _, rr := range rrs {
		m := rr.(*dns.MX)
		if n := strings.ToLower(strings.TrimSuffix(m.Mx, ".")); n != "" {
			l = append(l, mx{n, m.Preference})
		}
	}
	sort.SliceStable(l, func(i, j int) bool { return l[i].pref < l[j].pref || l[i].pref == l[j].pref && l[i].naam < l[j].naam })
	var uit []string
	for _, m := range l {
		uit = append(uit, m.naam)
	}
	return uit
}

// eerste: hooguit n.
func eerste(s []string, n int) []string {
	return s[:min(len(s), n)]
}

// nsNamen: de nameservers van het domein, op naam.
func (k *keurder) nsNamen(ctx context.Context) []string {
	rrs, _, _, _ := k.r.Records(ctx, k.domein, dns.TypeNS)
	var uit []string
	for _, rr := range rrs {
		uit = append(uit, strings.ToLower(strings.TrimSuffix(rr.(*dns.NS).Ns, ".")))
	}
	sort.Strings(uit)
	return uit
}
