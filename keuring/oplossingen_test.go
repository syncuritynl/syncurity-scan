package keuring

import (
	"sort"
	"strings"
	"testing"
)

// Het bestand moet geldig zijn: anders zijn er in productie geen teksten.
// Slaagt ook met {}.
func TestOplossingenGeldig(t *testing.T) {
	b, err := leesOplossingen(oplossingenJSON)
	if err != nil {
		t.Fatalf("oplossingen.json: %v", err)
	}
	// Een variant die nooit kan passen is waarschijnlijk een tikfout.
	bekend := map[string]bool{}
	for _, l := range mailLeveranciers {
		bekend[l.naam] = true
	}
	for _, l := range dnsLeveranciers {
		bekend[l.naam] = true
	}
	for _, s := range systemen {
		bekend[s.naam] = true
	}
	for id, per := range b {
		for st, tekst := range per {
			for v := range tekst.Varianten {
				if !bekend[v] {
					t.Logf("%s/%s: variant %q komt niet voor in feiten.go en past dus nooit", id, st, v)
				}
			}
			if n := len(tekst.Stappen); n > 5 {
				t.Logf("%s/%s: %d stappen, de afspraak is 2 tot 5", id, st, n)
			}
		}
	}
}

func TestLeesOplossingenWeigert(t *testing.T) {
	for naam, data := range map[string]string{
		"geen json":        `{`,
		"onbekend id":      `{"bestaat-niet":{"matig":{"wie":"x","stappen":["a"]}}}`,
		"onbekende status": `{"dmarc":{"goed":{"wie":"x","stappen":["a"]}}}`,
		"onbekend veld":    `{"dmarc":{"matig":{"wie":"x","stappen":["a"],"extra":1}}}`,
		"geen stappen":     `{"dmarc":{"matig":{"wie":"x","stappen":[]}}}`,
		"na het object":    `{} {}`,
	} {
		if _, err := leesOplossingen([]byte(data)); err == nil {
			t.Errorf("%s: geen fout", naam)
		}
	}
	if _, err := leesOplossingen([]byte(`{}`)); err != nil {
		t.Errorf("{}: %v", err)
	}
}

// Meldt (zonder te falen) welke punten nog geen tekst hebben.
func TestOplossingenCompleet(t *testing.T) {
	b, _ := leesOplossingen(oplossingenJSON)
	var zonder []string
	for id := range uitleg {
		if len(b[id]) == 0 {
			zonder = append(zonder, id)
		}
	}
	sort.Strings(zonder)
	if len(zonder) > 0 {
		t.Logf("%d punten zonder oplossingstekst: %s", len(zonder), strings.Join(zonder, ", "))
	}
}

// Een tekst die naar "het voorstel hieronder" verwijst, moet een punt en
// status hebben waarvoor de code een voorstel maakt.
func TestVoorstelBijTekst(t *testing.T) {
	b, err := leesOplossingen(oplossingenJSON)
	if err != nil {
		t.Fatal(err)
	}
	for id, per := range b {
		for st, tekst := range per {
			alles := strings.Join(tekst.Stappen, " ")
			for _, v := range tekst.Varianten {
				alles += " " + strings.Join(v, " ")
			}
			if !strings.Contains(strings.ToLower(alles), "voorstel") {
				continue
			}
			statussen := []Status{Status(st)}
			if st == "alle" {
				statussen = []Status{Matig, Slecht}
			}
			for _, s := range statussen {
				// "alle" geldt alleen waar er geen eigen tekst is.
				if st == "alle" && per[string(s)].Stappen != nil {
					continue
				}
				if !heeftVoorstel(id, s) {
					t.Errorf("%s/%s verwijst naar het voorstel, maar de code maakt er geen", id, s)
				}
			}
		}
	}
}

func TestOplossingVariant(t *testing.T) {
	b := oplossingenBestand{
		"dmarc": {"alle": {Wie: "x", Stappen: []string{"algemeen"}, Varianten: map[string][]string{
			"TransIP": {"transip"}, "Mimecast": {"mimecast"}}}},
		"csp": {"matig": {Stappen: []string{"algemeen"}, Varianten: map[string][]string{"WordPress": {"wp"}}}},
	}
	feiten := []Feit{{"E-mail", "Microsoft 365 en Mimecast"}, {"DNS", "TransIP"}, {"Gemaakt met", "WordPress"}}
	// Mailpunt: eerst de mailleverancier (Mimecast, als deel van "... en Mimecast"), dan DNS.
	if o := oplossingVoor(b, Punt{ID: "dmarc", Status: Slecht}, feiten); o == nil || o.Stappen[0] != "mimecast" {
		t.Errorf("dmarc: %+v", o)
	}
	if o := oplossingVoor(b, Punt{ID: "dmarc", Status: Matig}, feiten[1:]); o == nil || o.Stappen[0] != "transip" {
		t.Errorf("dmarc via DNS: %+v", o)
	}
	o := oplossingVoor(b, Punt{ID: "csp", Status: Matig}, feiten)
	if o == nil || o.Stappen[0] != "wp" || o.Wie != "je webbouwer" {
		t.Errorf("csp: %+v", o)
	}
	o.Stappen[0] = "veranderd"
	if b["csp"]["matig"].Varianten["WordPress"][0] != "wp" {
		t.Error("de oplossing deelt zijn stappen met het bestand")
	}
	if oplossingVoor(b, Punt{ID: "csp", Status: Slecht}, feiten) != nil {
		t.Error("csp/slecht heeft geen tekst en hoort nil te geven")
	}
}
