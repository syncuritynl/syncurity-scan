package keuring

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"
)

// ErrBudget betekent dat een scan zijn verbindingen op heeft. Zo kan niemand
// de scan gebruiken om veel verkeer naar een ander te sturen.
var ErrBudget = errors.New("te veel verbindingen voor één scan")

// maxPerFamilie: zoals een browser proberen we hooguit twee adressen per
// soort (IPv4, IPv6). Met 1000 A-records kost een verbinding er dus geen 1000.
const maxPerFamilie = 2

// ErrNietPubliek betekent dat een naam naar een adres wijst dat we nooit
// benaderen: privé, loopback, link-local, de metadata-dienst van de cloud, enz.
// Zonder deze rem kan iemand de keuring gebruiken om binnen te kijken (SSRF).
var ErrNietPubliek = errors.New("adres is niet publiek")

// verboden zijn netwerken die niet onder IsGlobalUnicast/IsPrivate vallen
// maar die we toch nooit willen benaderen.
var verboden = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fd00:c1::/32"), // metadata-dienst van Oracle over IPv6
	// IPv4 verpakt in IPv6, tunnels en speciale reeksen (RFC 6890 en opvolgers).
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("::ffff:0:0:0/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001::/32"), // Teredo
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:10::/28"),
	netip.MustParsePrefix("2001:20::/28"),
	netip.MustParsePrefix("2002::/16"), // 6to4
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("192.88.99.0/24"),
}

// Publiek zegt of we een adres mogen benaderen.
func Publiek(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() {
		return false
	}
	for _, p := range verboden {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// controle draait vlak voor connect(), op het echte adres. Ook als iets anders
// dan onze eigen resolver een naam omzet, kan er zo nooit iets intern bereikt worden.
func controle(_, adres string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(adres)
	if err != nil || !Publiek(ap.Addr()) {
		return ErrNietPubliek
	}
	if p := ap.Port(); p != 80 && p != 443 {
		return fmt.Errorf("poort %d: %w", p, ErrNietPubliek)
	}
	return nil
}

// Kiezer opent TCP-verbindingen, alleen naar publieke adressen en alleen naar
// de poorten 80 en 443, en zet namen om via de eigen Resolver. Mailservers
// worden nooit benaderd: de e-mailpunten komen uit DNS.
type Kiezer struct {
	R        *Resolver
	Timeout  time.Duration
	Max      int32 // hooguit zoveel verbindingspogingen; 0 is onbeperkt
	pogingen atomic.Int32
}

func (k *Kiezer) mag() error {
	if k.Max > 0 && k.pogingen.Add(1) > k.Max {
		return ErrBudget
	}
	return nil
}

func (k *Kiezer) dialer() *net.Dialer {
	return &net.Dialer{Timeout: k.Timeout, Control: controle}
}

// Adressen geeft de publieke A- en AAAA-adressen van een naam.
func (k *Kiezer) Adressen(ctx context.Context, naam string) (v4, v6 []netip.Addr) {
	for _, a := range k.R.Adressen(ctx, naam, true) {
		if Publiek(a) {
			v4 = append(v4, a)
		}
	}
	for _, a := range k.R.Adressen(ctx, naam, false) {
		if Publiek(a) {
			v6 = append(v6, a)
		}
	}
	return
}

// DialContext is te gebruiken in een http.Transport.
func (k *Kiezer) DialContext(ctx context.Context, netw, adres string) (net.Conn, error) {
	host, poort, err := net.SplitHostPort(adres)
	if err != nil {
		return nil, err
	}
	var kandidaten []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		kandidaten = []netip.Addr{a}
	} else {
		v4, v6 := k.Adressen(ctx, host)
		kandidaten = append(v4[:min(len(v4), maxPerFamilie)], v6[:min(len(v6), maxPerFamilie)]...)
	}
	if len(kandidaten) == 0 {
		return nil, fmt.Errorf("%s: geen publiek adres", host)
	}
	var laatste error
	for _, a := range kandidaten {
		if err := k.mag(); err != nil {
			return nil, err
		}
		c, err := k.dialer().DialContext(ctx, "tcp", net.JoinHostPort(a.String(), poort))
		if err == nil {
			return c, nil
		}
		laatste = err
	}
	return nil, laatste
}

// DialAdres verbindt met één bepaald adres (om IPv6 apart te kunnen meten).
func (k *Kiezer) DialAdres(ctx context.Context, a netip.Addr, poort string) (net.Conn, error) {
	if err := k.mag(); err != nil {
		return nil, err
	}
	return k.dialer().DialContext(ctx, "tcp", net.JoinHostPort(a.String(), poort))
}
