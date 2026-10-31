package keuring

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// De vaste teksten van de oplossingen: per punt en status wie het moet doen
// en in welke stappen. Ze staan los van de code, zodat ze zonder
// programmeerwerk bij te werken zijn. Formaat:
//
//	{ "<punt-id>": { "matig"|"slecht"|"alle": {
//	    "wie": "...", "stappen": ["..."], "varianten": { "<feitwaarde>": ["..."] } } } }
//
// "alle" geldt voor matig en slecht als er geen eigen tekst is.
//
//go:embed oplossingen.json
var oplossingenJSON []byte

type oplossingTekst struct {
	Wie       string              `json:"wie"`
	Stappen   []string            `json:"stappen"`
	Varianten map[string][]string `json:"varianten,omitempty"`
}

type oplossingenBestand map[string]map[string]oplossingTekst

var oplossingStatussen = map[string]bool{"matig": true, "slecht": true, "alle": true}

// leesOplossingen ontleedt en controleert het bestand: geldige JSON, geen
// onbekende velden, alleen bekende punt-ids en statussen, en altijd stappen.
func leesOplossingen(data []byte) (oplossingenBestand, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var b oplossingenBestand
	if err := dec.Decode(&b); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("na het JSON-object staat nog iets")
	}
	for id, per := range b {
		if _, ok := uitleg[id]; !ok {
			return nil, fmt.Errorf("onbekend punt-id %q", id)
		}
		for st, t := range per {
			if !oplossingStatussen[st] {
				return nil, fmt.Errorf("%s: onbekende status %q (matig, slecht of alle)", id, st)
			}
			if len(t.Stappen) == 0 {
				return nil, fmt.Errorf("%s/%s: geen stappen", id, st)
			}
			for v, stappen := range t.Varianten {
				if len(stappen) == 0 {
					return nil, fmt.Errorf("%s/%s: variant %q zonder stappen", id, st, v)
				}
			}
		}
	}
	return b, nil
}

var (
	oplossingenEens sync.Once
	oplossingen     oplossingenBestand
)

// teksten geeft de ingelezen oplossingen. Is het bestand ongeldig, dan
// zijn er geen teksten (de test TestOplossingenGeldig houdt dat tegen
// voordat er iets gebouwd wordt); de dienst valt er niet door om.
func teksten() oplossingenBestand {
	oplossingenEens.Do(func() {
		b, err := leesOplossingen(oplossingenJSON)
		if err == nil {
			oplossingen = b
		}
	})
	return oplossingen
}

// soortPunt zegt in welke feiten we een variant zoeken, in volgorde:
//   - mailpunten: eerst de mailleverancier (Microsoft 365 heeft eigen
//     stappen), dan de DNS-leverancier (daar zet je het record);
//   - DNS-punten: de DNS-leverancier;
//   - webpunten: het systeem (WordPress, Shopify, ...), dan de webserver.
//
// Ook de standaard voor "wie" hangt ervan af.
func soortPunt(id string) (feiten []string, wie string) {
	switch id {
	case "dmarc", "dmarc-rua", "spf", "spf-lookups", "dkim", "mta-sts", "tls-rpt", "dane", "ipv6-mail":
		return []string{"E-mail", "DNS"}, "wie je e-mail beheert"
	case "dnssec", "dnssec-alg", "caa", "ns", "ipv6-ns":
		return []string{"DNS"}, "wie je domeinnaam beheert"
	default:
		return []string{"Gemaakt met", "Webserver"}, "je webbouwer"
	}
}

// waarden splitst een feit als "Microsoft 365 en Mimecast" in zijn delen.
func waarden(feiten []Feit, naam string) []string {
	for _, f := range feiten {
		if f.Naam == naam {
			return strings.Split(f.Waarde, " en ")
		}
	}
	return nil
}

// oplossingVoor zoekt de tekst bij een punt. De eerste variant die past
// (in de volgorde van soortPunt, en binnen een feit in de volgorde waarin de
// leveranciers genoemd worden) vervangt de algemene stappen. nil als er
// voor dit punt en deze status niets staat.
func oplossingVoor(b oplossingenBestand, p Punt, feiten []Feit) *Oplossing {
	per := b[p.ID]
	t, ok := per[string(p.Status)]
	if !ok {
		t, ok = per["alle"]
	}
	soorten, wie := soortPunt(p.ID)
	if !ok {
		return nil
	}
	o := &Oplossing{Wie: leegAls(t.Wie, wie), Stappen: append([]string(nil), t.Stappen...)}
	for _, soort := range soorten {
		for _, w := range waarden(feiten, soort) {
			for sleutel, stappen := range t.Varianten {
				if strings.EqualFold(strings.TrimSpace(w), sleutel) {
					o.Stappen = append([]string(nil), stappen...)
					return o
				}
			}
		}
	}
	return o
}
