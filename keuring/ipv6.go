package keuring

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"syscall"

	"github.com/miekg/dns"
)

func (k *keurder) modern(ctx context.Context, w *web) Groep {
	return Groep{ID: "modern", Naam: "Modern internet", Kort: "Modern internet", Punten: []Punt{
		k.webIPv6(ctx, w.host),
		k.mailIPv6(ctx),
		k.nsIPv6(ctx),
		http2(w),
	}}
}

func (k *keurder) webIPv6(ctx context.Context, host string) Punt {
	if host == "" {
		return punt("ipv6-web", "AAAA", NVT, "Website bereikbaar via IPv6", geenWebsite)
	}
	_, v6 := k.kiezer.Adressen(ctx, host)
	if len(v6) == 0 {
		return punt("ipv6-web", "AAAA", Matig, "Website niet bereikbaar via IPv6",
			"Je website heeft geen IPv6-adres, het nieuwe soort internetadres. Bezoekers met IPv6 komen er via een omweg van hun provider, wat iets trager kan zijn.")
	}
	gezien := adressen(v6)
	// Echt verbinden waar dat kan. Heeft de scanserver zelf geen IPv6, dan
	// blijft het bij het DNS-record; dat is eerlijk genoeg.
	for _, a := range v6 {
		c, err := k.kiezer.DialAdres(ctx, a, "443")
		if err == nil {
			c.Close()
			return punt("ipv6-web", "AAAA", Goed, "Website bereikbaar via IPv6",
				"Ook bezoekers met het nieuwe internetadres komen rechtstreeks binnen.").met(gezien)
		}
		if errors.Is(err, syscall.ENETUNREACH) || strings.Contains(err.Error(), "network is unreachable") {
			return punt("ipv6-web", "AAAA", Goed, "Website bereikbaar via IPv6",
				"Je website heeft een IPv6-adres.").met(gezien)
		}
	}
	return punt("ipv6-web", "AAAA", Slecht, "Website niet bereikbaar via IPv6",
		"Je website heeft een IPv6-adres, maar daarop antwoordt niets. Bezoekers met IPv6 kunnen tegen een trage of lege pagina aanlopen.").met(gezien).
		metDetail("Geen verbinding op poort 443 met: "+gezien, "Controleer of de webserver ook op IPv6 luistert en of de firewall IPv6 doorlaat.")
}

func (k *keurder) mailIPv6(ctx context.Context) Punt {
	mx, _ := k.r.MX(ctx, k.domein)
	if len(mx) == 0 {
		return punt("ipv6-mail", "MX · AAAA", NVT, "Mail bereikbaar via IPv6",
			"Deze domeinnaam ontvangt geen mail, dus dit punt telt niet mee.")
	}
	met := 0
	var zonder []string
	for _, h := range mx {
		if len(k.r.Adressen(ctx, h, false)) > 0 {
			met++
		} else {
			zonder = append(zonder, h)
		}
	}
	gezien := fmt.Sprintf("%d van de %d mailservers", met, len(mx))
	var detail []string
	if len(zonder) > 0 {
		detail = append([]string{"Zonder IPv6-adres (AAAA):"}, lijstje(sorteer(zonder), maxDetail-1)...)
	}
	switch {
	case met == len(mx):
		return punt("ipv6-mail", "MX · AAAA", Goed, "Mail bereikbaar via IPv6",
			"Je mailserver ontvangt ook via IPv6.").met(gezien)
	case met > 0:
		return punt("ipv6-mail", "MX · AAAA", Matig, "Mail deels bereikbaar via IPv6",
			"Niet al je mailservers zijn via IPv6 bereikbaar.").met(gezien).metDetail(detail...)
	default:
		return punt("ipv6-mail", "MX · AAAA", Matig, "Mail niet bereikbaar via IPv6",
			"Je mailserver heeft geen IPv6-adres. Mail komt nu nog gewoon aan, maar IPv6 wordt steeds vaker gebruikt.").met(gezien).metDetail(detail...)
	}
}

func (k *keurder) nsIPv6(ctx context.Context) Punt {
	rrs, _, _, _ := k.r.Records(ctx, k.domein, dns.TypeNS)
	if len(rrs) == 0 {
		return punt("ipv6-ns", "NS · AAAA", Fout, "Nameservers bereikbaar via IPv6", "We vonden geen nameservers om te meten.")
	}
	met := 0
	var zonder []string
	for _, rr := range rrs {
		n := strings.TrimSuffix(rr.(*dns.NS).Ns, ".")
		if len(k.r.Adressen(ctx, n, false)) > 0 {
			met++
		} else {
			zonder = append(zonder, n)
		}
	}
	gezien := fmt.Sprintf("%d van de %d nameservers", met, len(rrs))
	var detail []string
	if len(zonder) > 0 {
		detail = append([]string{"Zonder IPv6-adres (AAAA):"}, lijstje(sorteer(zonder), maxDetail-1)...)
	}
	switch {
	case met >= 2:
		return punt("ipv6-ns", "NS · AAAA", Goed, "Nameservers bereikbaar via IPv6",
			"Je domein is ook te vinden voor wie alleen IPv6 heeft.").met(gezien)
	case met == 1:
		return punt("ipv6-ns", "NS · AAAA", Matig, "Maar één nameserver via IPv6",
			"Voor bezoekers met alleen IPv6 hangt je hele domein aan die ene nameserver.").met(gezien).metDetail(detail...)
	default:
		return punt("ipv6-ns", "NS · AAAA", Matig, "Nameservers niet bereikbaar via IPv6",
			"Je nameservers hebben geen IPv6-adres. Dat gaat nu nog goed, omdat de DNS-servers van providers ook IPv4 hebben, maar het is niet meer van deze tijd.").met(gezien).metDetail(detail...)
	}
}

func http2(w *web) Punt {
	if w.host == "" {
		return punt("http2", "HTTP/2 · HTTP/3", NVT, "Snel protocol", geenWebsite)
	}
	if w.staat == nil {
		return punt("http2", "HTTP/2 · HTTP/3", Fout, "Snel protocol", "Zonder https niet te meten.")
	}
	h3 := strings.Contains(w.kop("Alt-Svc"), "h3")
	if w.staat.NegotiatedProtocol == "h2" {
		gezien := "HTTP/2"
		uitleg := "Je website gebruikt HTTP/2: alle onderdelen van een pagina komen tegelijk binnen."
		if h3 {
			gezien += " en HTTP/3"
			uitleg = "Je website gebruikt HTTP/2 en HTTP/3, de snelste manier om een pagina te laden, ook op een wankele mobiele verbinding."
		}
		return punt("http2", "HTTP/2 · HTTP/3", Goed, "Snel protocol", uitleg).met(gezien)
	}
	return punt("http2", "HTTP/2 · HTTP/3", Matig, "Verouderd protocol",
		"Je website gebruikt nog HTTP/1.1. Met HTTP/2 laden pagina's merkbaar sneller, zonder dat je iets aan de site zelf hoeft te doen.").met("HTTP/1.1")
}

func adressen(a []netip.Addr) string {
	meer := len(a) - 3
	a = a[:min(len(a), 3)]
	s := make([]string, len(a))
	for i, x := range a {
		s[i] = x.String()
	}
	if meer > 0 {
		s = append(s, fmt.Sprintf("en nog %d", meer))
	}
	return strings.Join(s, ", ")
}
