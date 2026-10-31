package keuring

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// ---------------------------------------------------------------- TXT

func TestControleerTXT(t *testing.T) {
	token := "abcdefghijklmnopqrstuv"
	r := nieuwNepDNS(t,
		`voorbeeld.nl. 300 IN TXT "v=spf1 -all"`,
		`voorbeeld.nl. 300 IN TXT "syncurity-verificatie=" "`+token+`"`,
		`_syncurity.ander.nl. 300 IN TXT "syncurity-verificatie=`+token+`"`,
		`fout.nl. 300 IN TXT "syncurity-verificatie=`+token+`x"`,
		`fout.nl. 300 IN TXT "syncurity-verificatie=`+strings.ToUpper(token)+`"`,
	)
	r.fout["kapot.nl."] = true
	r.fout["_syncurity.kapot.nl."] = true
	if ok, waar, _, err := controleerTXT(context.Background(), r, "voorbeeld.nl", token); !ok || waar != "voorbeeld.nl" || err != nil {
		t.Errorf("op het domein: %v %q %v", ok, waar, err)
	}
	if ok, waar, _, _ := controleerTXT(context.Background(), r, "ander.nl", token); !ok || waar != "_syncurity.ander.nl" {
		t.Errorf("op _syncurity: %v %q", ok, waar)
	}
	ok, _, gezien, err := controleerTXT(context.Background(), r, "fout.nl", token)
	if ok || err != nil || len(gezien) != 2 {
		t.Errorf("bijna goed telt niet: %v %v %v", ok, gezien, err)
	}
	if ok, _, _, err := controleerTXT(context.Background(), r, "kapot.nl", token); ok || err == nil {
		t.Errorf("SERVFAIL: %v %v", ok, err)
	}
	if _, _, _, err := ControleerTXT(context.Background(), "voorbeeld.nl", "te-kort", Standaard); !errors.Is(err, ErrToken) {
		t.Errorf("kort token: %v", err)
	}
	if _, _, _, err := ControleerTXT(context.Background(), "192.168.1.1", token, Standaard); err == nil {
		t.Error("IP-adres als domein geaccepteerd")
	}
}

func TestVulOplossingen(t *testing.T) {
	k := nepKeurder("voorbeeld.nl")
	b := oplossingenBestand{"nosniff": {"alle": {Wie: "je webbouwer", Stappen: []string{"Zet het voorstel hieronder erin."}}}}
	u := nepU(nil, Punt{ID: "nosniff", Status: Matig}, Punt{ID: "hsts", Status: Goed}, Punt{ID: "seo-titel", Status: Slecht})
	vulOplossingen(u, k, b, subInfo{})
	p := u.Groepen[0].Punten
	if p[0].Oplossing == nil || p[0].Oplossing.Voorstel != "X-Content-Type-Options: nosniff" || p[0].Oplossing.Stappen[0] == "" {
		t.Errorf("nosniff: %+v", p[0].Oplossing)
	}
	if p[1].Oplossing != nil || p[2].Oplossing != nil {
		t.Error("een punt dat goed is, of zonder tekst en voorstel, kreeg een oplossing")
	}
	if len(u.Eerst) == 0 || u.Eerst[0].ID != "seo-titel" {
		t.Errorf("Eerst: %+v", u.Eerst)
	}
}
