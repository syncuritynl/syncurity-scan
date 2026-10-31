package keuring

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Resolver stelt DNS-vragen aan een validerende resolver. Op de server is dat
// een eigen unbound op 127.0.0.1; bij het ontwikkelen kan het een publieke zijn.
// Een validerende resolver is nodig voor DNSSEC: alleen die zet de AD-vlag.
type Resolver struct {
	Servers []string // host:poort
	Timeout time.Duration
}

var errGeenAntwoord = errors.New("geen antwoord van de resolver")

// Vraag stuurt één vraag, met DNSSEC-OK, en valt bij afkappen terug op TCP.
func (r *Resolver) Vraag(ctx context.Context, naam string, soort uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(naam), soort)
	m.SetEdns0(1232, true)
	m.RecursionDesired = true
	m.AuthenticatedData = true

	var laatste error = errGeenAntwoord
	for _, s := range r.Servers {
		for _, netw := range []string{"udp", "tcp"} {
			c := &dns.Client{Net: netw, Timeout: r.Timeout}
			in, _, err := c.ExchangeContext(ctx, m, s)
			if err != nil {
				laatste = err
				break // volgende server
			}
			if in.Truncated && netw == "udp" {
				continue
			}
			return in, nil
		}
	}
	return nil, laatste
}

// Records geeft de antwoorden van een bepaald type, plus of ze gevalideerd zijn.
func (r *Resolver) Records(ctx context.Context, naam string, soort uint16) ([]dns.RR, bool, int, error) {
	in, err := r.Vraag(ctx, naam, soort)
	if err != nil {
		return nil, false, dns.RcodeServerFailure, err
	}
	var uit []dns.RR
	for _, rr := range in.Answer {
		if rr.Header().Rrtype == soort {
			uit = append(uit, rr)
		}
	}
	return uit, in.AuthenticatedData, in.Rcode, nil
}

// TXT geeft alle TXT-records van een naam, elk als één tekst.
func (r *Resolver) TXT(ctx context.Context, naam string) []string {
	rrs, _, _, _ := r.Records(ctx, naam, dns.TypeTXT)
	var uit []string
	for _, rr := range rrs {
		uit = append(uit, strings.Join(rr.(*dns.TXT).Txt, ""))
	}
	return uit
}

// Adressen geeft de A- (v4) of AAAA-adressen van een naam.
func (r *Resolver) Adressen(ctx context.Context, naam string, v4 bool) []netip.Addr {
	soort := dns.TypeAAAA
	if v4 {
		soort = dns.TypeA
	}
	rrs, _, _, _ := r.Records(ctx, naam, soort)
	var uit []netip.Addr
	for _, rr := range rrs {
		var a netip.Addr
		switch v := rr.(type) {
		case *dns.A:
			a, _ = netip.AddrFromSlice(v.A.To4())
		case *dns.AAAA:
			a, _ = netip.AddrFromSlice(v.AAAA)
		}
		if a.IsValid() {
			uit = append(uit, a)
		}
	}
	return uit
}

// MX geeft de mailservers, zonder punt aan het eind. Een null-MX ("0 .")
// betekent: dit domein ontvangt geen mail; dan is nullMX waar.
func (r *Resolver) MX(ctx context.Context, naam string) (hosts []string, nullMX bool) {
	rrs, _, _, _ := r.Records(ctx, naam, dns.TypeMX)
	for _, rr := range rrs {
		h := strings.TrimSuffix(rr.(*dns.MX).Mx, ".")
		if h == "" {
			nullMX = true
			continue
		}
		hosts = append(hosts, strings.ToLower(h))
	}
	return
}
