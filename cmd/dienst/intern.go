package main

// De interne API voor de inlogdienst (syncurity-auth), op een eigen socket
// in /run/syncurity-keuring-intern/ met groep syncurity-intern. nginx kent
// die socket niet en kan er niet bij: een fout in nginx maakt zo nooit een
// volledig rapport van een willekeurig domein publiek. Geen remmen per
// adres (dat doet de inlogdienst), wel hooguit 2 volledige rapporten
// tegelijk. Zie ontwerp/volledig-rapport.md.

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"syncurity.nl/keuring/keuring"
)

const (
	maxIntern        = 4 << 10
	volledigTegelijk = 2
	txtTijd          = 15 * time.Second
)

type (
	txtFunctie      func(ctx context.Context, domein, token string, in keuring.Instellingen) (bool, string, []string, error)
	volledigFunctie func(ctx context.Context, domein string, in keuring.Instellingen) (*keuring.Volledig, error)
)

type internVraag struct {
	Domein string `json:"domein"`
	Token  string `json:"token"`
}

type txtAntwoord struct {
	Gevonden bool     `json:"gevonden"`
	Waar     string   `json:"waar,omitempty"`
	Gezien   []string `json:"gezien,omitempty"`
	Fout     string   `json:"fout,omitempty"`
}

type foutAntwoord struct {
	Fout string `json:"fout"`
}

// intern is de handler van de interne socket. Alleen deze twee paden.
func (d *dienst) intern() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/intern/txt", d.internTXT)
	mux.HandleFunc("/intern/volledig", d.internVolledig)
	return mux
}

func stuurJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// leesVraag controleert methode, type, grootte en inhoud. ok is onwaar als
// er al een fout is gestuurd. Het domein komt genormaliseerd terug.
func leesVraag(w http.ResponseWriter, r *http.Request) (internVraag, bool) {
	var v internVraag
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		stuurJSON(w, http.StatusMethodNotAllowed, foutAntwoord{"alleen POST"})
		return v, false
	}
	if t := strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]); !strings.EqualFold(t, "application/json") {
		stuurJSON(w, http.StatusUnsupportedMediaType, foutAntwoord{"alleen application/json"})
		return v, false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxIntern))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		var te *http.MaxBytesError
		if errors.As(err, &te) {
			stuurJSON(w, http.StatusRequestEntityTooLarge, foutAntwoord{"te groot"})
		} else {
			stuurJSON(w, http.StatusBadRequest, foutAntwoord{"ongeldige JSON"})
		}
		return v, false
	}
	if dec.More() {
		stuurJSON(w, http.StatusBadRequest, foutAntwoord{"ongeldige JSON"})
		return v, false
	}
	if !keuring.TokenRe.MatchString(v.Token) {
		stuurJSON(w, http.StatusBadRequest, foutAntwoord{"ongeldig token"})
		return v, false
	}
	domein, err := keuring.Normaliseer(v.Domein)
	if err != nil {
		stuurJSON(w, http.StatusBadRequest, foutAntwoord{err.Error()})
		return v, false
	}
	v.Domein = domein
	return v, true
}

const foutDNS = "De DNS gaf geen antwoord. Probeer het over een paar minuten nog eens."

func (d *dienst) internTXT(w http.ResponseWriter, r *http.Request) {
	v, ok := leesVraag(w, r)
	if !ok {
		return
	}
	begin := time.Now()
	ctx, stop := context.WithTimeout(r.Context(), txtTijd)
	defer stop()
	gevonden, waar, gezien, err := d.txt(ctx, v.Domein, v.Token, d.in)
	a := txtAntwoord{Gevonden: gevonden, Waar: waar, Gezien: gezien}
	if err != nil && !gevonden {
		a.Fout = foutDNS
		log.Printf("intern txt fout (%s) %.1fs", soortFout(err), time.Since(begin).Seconds())
	} else {
		log.Printf("intern txt %.1fs", time.Since(begin).Seconds())
	}
	stuurJSON(w, http.StatusOK, a)
}

func (d *dienst) internVolledig(w http.ResponseWriter, r *http.Request) {
	v, ok := leesVraag(w, r)
	if !ok {
		return
	}
	select {
	case d.volPlekken <- struct{}{}:
		defer func() { <-d.volPlekken }()
	default:
		stuurJSON(w, http.StatusServiceUnavailable, foutAntwoord{"druk"})
		return
	}
	begin := time.Now()
	ctx, stop := context.WithTimeout(r.Context(), txtTijd)
	gevonden, _, _, err := d.txt(ctx, v.Domein, v.Token, d.in)
	stop()
	switch {
	case gevonden:
	case err != nil:
		log.Printf("intern volledig: txt-fout (%s)", soortFout(err))
		stuurJSON(w, http.StatusBadGateway, foutAntwoord{foutDNS})
		return
	default:
		// Het record is weg: de inlogdienst laat de verificatie vervallen.
		log.Printf("intern volledig: verificatie ontbreekt")
		stuurJSON(w, http.StatusForbidden, foutAntwoord{"verificatie"})
		return
	}
	ctx, stop = context.WithTimeout(r.Context(), keuring.VolledigTotaal)
	defer stop()
	vol, err := d.volledig(ctx, v.Domein, d.in)
	if err != nil {
		if errors.Is(err, keuring.ErrBestaatNiet) {
			stuurJSON(w, http.StatusNotFound, foutAntwoord{err.Error()})
			return
		}
		log.Printf("intern volledig mislukt (%s) %.1fs", soortFout(err), time.Since(begin).Seconds())
		stuurJSON(w, http.StatusBadGateway, foutAntwoord{"De scan lukte niet. Probeer het over een minuut nog eens."})
		return
	}
	// Geen domeinnaam in het logboek, zoals bij /scan.
	log.Printf("intern volledig klaar %d/%d, %d subdomeinen %.1fs", vol.InOrde, vol.Totaal, len(vol.Subdomeinen), time.Since(begin).Seconds())
	stuurJSON(w, http.StatusOK, vol)
}
