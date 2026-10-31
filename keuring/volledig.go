package keuring

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Volledig is het volledige rapport, alleen voor de eigenaar na domeinbewijs.
// Het verlaat de scandienst alleen via de interne socket.
type Volledig struct {
	Uitslag                 // alles van de gratis scan, mét Detail en Oplossing per punt
	Subdomeinen []Subdomein `json:"subdomeinen"`
	SubBron     string      `json:"sub_bron"` // "crt.sh", "certspotter" of "" als beide faalden
	SubMelding  string      `json:"sub_melding,omitempty"`
}

// VolledigTotaal is de tijd voor het hele volledige rapport.
const VolledigTotaal = 90 * time.Second

// KeurVolledig doet de gewone keuring met de details en oplossingen erbij,
// en zoekt tegelijk de subdomeinen op. Hooguit 90 seconden.
//
// Alleen aanroepen na domeinbewijs (ControleerTXT): het rapport laat precies
// zien waar iemand moet zoeken.
func KeurVolledig(ctx context.Context, invoer string, in Instellingen) (*Volledig, error) {
	domein, err := Normaliseer(invoer)
	if err != nil {
		return nil, err
	}
	ctx, stop := context.WithTimeout(ctx, VolledigTotaal)
	defer stop()
	r := &Resolver{Servers: in.Resolvers, Timeout: in.Timeout}
	if err := bestaat(ctx, r, domein); err != nil {
		return nil, err
	}

	subKlaar := make(chan subUitslag, 1)
	go func() { subKlaar <- nieuweSubZoeker(domein, r, in).zoek(ctx) }()

	// De gewone keuring houdt zijn eigen tijd (in.Totaal), zoals op /scan.
	kctx, kstop := context.WithTimeout(ctx, in.Totaal)
	u, k := keur(kctx, domein, r, in, true)
	kstop()
	sub := <-subKlaar

	vulOplossingen(u, k, teksten(), sub.info())
	return &Volledig{Uitslag: *u, Subdomeinen: leegNiet(sub.lijst), SubBron: sub.bron, SubMelding: sub.melding}, nil
}

func leegNiet(s []Subdomein) []Subdomein {
	if s == nil {
		return []Subdomein{}
	}
	return s
}

// vulOplossingen zet bij elk punt dat Matig of Slecht is de tekst uit
// oplossingen.json en het berekende voorstel. Daarna opnieuw tellen, zodat
// Eerst ook de oplossingen heeft.
func vulOplossingen(u *Uitslag, k *keurder, b oplossingenBestand, sub subInfo) {
	for i := range u.Groepen {
		for j := range u.Groepen[i].Punten {
			p := &u.Groepen[i].Punten[j]
			if p.Status != Matig && p.Status != Slecht {
				continue
			}
			o := oplossingVoor(b, *p, u.Feiten)
			v := k.voorstelVoor(*p, u, sub)
			if v.tekst != "" || v.toelichting != "" {
				if o == nil {
					_, wie := soortPunt(p.ID)
					o = &Oplossing{Wie: wie, Stappen: []string{}}
				}
				o.Voorstel, o.Naam, o.Toelichting = v.tekst, v.naam, v.toelichting
			}
			p.Oplossing = o
		}
	}
	u.tel()
}

// ---------------------------------------------------------------- domeinbewijs

// TokenRe is de vorm van een verificatietoken: 22 tekens base64url (128 bits).
var TokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

// ErrToken: het token heeft niet de goede vorm.
var ErrToken = errors.New("ongeldig token")

const (
	maxGezien     = 10
	maxGezienLang = 200
)

// ControleerTXT zoekt het TXT-record "syncurity-verificatie=<token>" op het
// domein zelf en op _syncurity.<domein>. waar is de naam waar het stond;
// gezien zijn de TXT-waarden die er wel staan (hooguit 10, elk hooguit 200
// tekens), zodat de klant ziet wat er mis is. err alleen als de DNS geen
// antwoord gaf (bijv. SERVFAIL) en het record nergens gevonden is.
func ControleerTXT(ctx context.Context, invoer, token string, in Instellingen) (gevonden bool, waar string, gezien []string, err error) {
	domein, err := Normaliseer(invoer)
	if err != nil {
		return false, "", nil, err
	}
	if !TokenRe.MatchString(token) {
		return false, "", nil, ErrToken
	}
	r := &Resolver{Servers: in.Resolvers, Timeout: in.Timeout}
	return controleerTXT(ctx, r, domein, token)
}

func controleerTXT(ctx context.Context, r vrager, domein, token string) (bool, string, []string, error) {
	zoek := "syncurity-verificatie=" + token
	var gezien []string
	var fout error
	for _, naam := range []string{domein, "_syncurity." + domein} {
		m, err := r.Vraag(ctx, naam, dns.TypeTXT)
		if err != nil {
			fout = err
			continue
		}
		if m.Rcode == dns.RcodeServerFailure || m.Rcode == dns.RcodeRefused {
			fout = errors.New("de DNS gaf " + dns.RcodeToString[m.Rcode])
			continue
		}
		for _, rr := range m.Answer {
			t, ok := rr.(*dns.TXT)
			if !ok || !strings.EqualFold(strings.TrimSuffix(t.Hdr.Name, "."), naam) {
				continue
			}
			waarde := strings.Join(t.Txt, "")
			if waarde == zoek {
				return true, naam, nil, nil
			}
			if len(gezien) < maxGezien {
				gezien = append(gezien, kort(schoon(waarde), maxGezienLang))
			}
		}
	}
	if fout != nil {
		return false, "", gezien, fout
	}
	return false, "", gezien, nil
}
