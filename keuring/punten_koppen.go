package keuring

import (
	"fmt"
	"strings"
)

// Drie kopregels die Mozilla Observatory en securityheaders.com ook bekijken.
// Alleen uit de antwoorden die de scan toch al krijgt.

// proefOrigin: de site waarvoor we ons uitgeven bij de cors-meting. .invalid
// bestaat nooit (RFC 2606), dus een server die dit terugzegt, zegt elke site terug.
const proefOrigin = "https://voorbeeld.invalid"

// cors: mag een andere site je pagina lezen? Access-Control-Allow-Origin: *
// zonder cookies is op een openbare pagina geen probleem (Observatory geeft
// er ook geen aftrek voor): die pagina kan iedereen toch al lezen. Kan beter
// is het pas als de server elke site terugzegt (dan geeft hij ook toegang
// zodra er wel cookies meegaan), of * combineert met cookies.
func cors(w *web) Punt {
	const id, tech, titel = "cors", "Access-Control-Allow-Origin", "Pagina niet voor elke site leesbaar"
	ster := strings.TrimSpace(w.kop("Access-Control-Allow-Origin")) == "*" || strings.TrimSpace(w.corsOrigin) == "*"
	creds := w.corsCreds || strings.EqualFold(strings.TrimSpace(w.kop("Access-Control-Allow-Credentials")), "true")
	switch {
	case strings.EqualFold(strings.TrimSpace(w.corsOrigin), proefOrigin):
		gezien := "Access-Control-Allow-Origin zegt elke site terug"
		if creds {
			gezien += ", met Access-Control-Allow-Credentials: true"
		}
		return punt(id, tech, Matig, "Elke site mag je pagina lezen",
			"Je server geeft elke andere site die erom vraagt toegang tot je pagina's. Gaan er inlogcookies mee, dan kan een kwaadaardige site gegevens van ingelogde bezoekers uitlezen.").
			met(gezien).metDetail("Op een verzoek met Origin: "+proefOrigin+" antwoordde de server met dezelfde Origin.", "Noem alleen de sites die echt toegang nodig hebben.")
	case ster && creds:
		return punt(id, tech, Matig, "Elke site mag je pagina lezen, met cookies",
			"Je server zegt dat elke site je pagina mag lezen, en ook met cookies. Browsers weigeren die combinatie, maar het wijst op een instelling die te ruim staat.").
			met("Access-Control-Allow-Origin: * met Access-Control-Allow-Credentials: true")
	case ster:
		return punt(id, tech, Goed, titel,
			"Je pagina mag door elke site gelezen worden (Access-Control-Allow-Origin: *), maar zonder cookies. Voor een openbare pagina is dat geen probleem.").
			met("Access-Control-Allow-Origin: *")
	default:
		return punt(id, tech, Goed, titel, "Andere sites kunnen je pagina niet uitlezen in de browser van je bezoekers.")
	}
}

// eersteWaarde: de waarde van een kopregel zonder parameters (; report-to=...).
func eersteWaarde(v string) string {
	if i := strings.IndexAny(v, ";,"); i >= 0 {
		v = v[:i]
	}
	return strings.ToLower(strings.Trim(strings.TrimSpace(v), `"`))
}

func corpCoop(w *web) Punt {
	const id, tech, titel = "corp-coop", "COOP · CORP", "Pagina afgeschermd van andere sites"
	coop := eersteWaarde(w.kop("Cross-Origin-Opener-Policy"))
	corp := eersteWaarde(w.kop("Cross-Origin-Resource-Policy"))
	gezien := "Cross-Origin-Opener-Policy: " + leegAls(coop, "geen")
	if corp != "" {
		gezien += " · Cross-Origin-Resource-Policy: " + corp
	}
	if coop == "same-origin" || coop == "same-origin-allow-popups" {
		return punt(id, tech, Goed, titel,
			"Opent een andere site jouw pagina in een nieuw venster, dan kan die er niet bij. Dat beschermt tegen aanvallen via geopende vensters en lekken tussen tabbladen.").met(gezien)
	}
	return punt(id, tech, Matig, "Pagina niet afgeschermd van andere sites",
		"Een andere site die jouw pagina opent, houdt een lijntje naar dat venster. Daarmee kan hij bijvoorbeeld je bezoeker ongemerkt doorsturen naar een nagemaakte pagina. Cross-Origin-Opener-Policy knipt dat lijntje door.").
		met(gezien).metDetail(ontbreektOp(w, "Cross-Origin-Opener-Policy: same-origin")...)
}

// gevoelig: wat een Permissions-Policy minstens dicht hoort te zetten.
var gevoelig = []string{"camera", "microphone", "geolocation"}

// toestemmingen ontleedt een Permissions-Policy (een structured-field
// dictionary): camera=(), geolocation=(self "https://kaart.nl"), fullscreen=*.
// Per functie: true als hij dicht staat of alleen voor genoemde herkomsten
// open, false als elke site hem mag gebruiken (*).
func toestemmingen(v string) map[string]bool {
	uit := map[string]bool{}
	for _, item := range strings.Split(v, ",") {
		naam, waarde, ok := strings.Cut(strings.TrimSpace(item), "=")
		naam = strings.ToLower(strings.TrimSpace(naam))
		if !ok || naam == "" {
			continue
		}
		waarde = strings.TrimSpace(waarde)
		if strings.HasPrefix(waarde, "(") {
			if eind := strings.Index(waarde, ")"); eind > 0 {
				waarde = waarde[1:eind]
			} else {
				continue // kapot: telt niet
			}
		} else if i := strings.Index(waarde, ";"); i >= 0 {
			waarde = waarde[:i]
		}
		dicht := true
		for _, f := range strings.Fields(waarde) {
			if f == "*" {
				dicht = false
			}
		}
		uit[naam] = dicht
	}
	return uit
}

func permissies(w *web) Punt {
	const id, tech, titel = "permissions", "Permissions-Policy", "Camera en microfoon dicht"
	v := w.kop("Permissions-Policy")
	if strings.TrimSpace(v) == "" {
		return punt(id, tech, Matig, "Camera en microfoon niet dichtgezet",
			"Je site zegt niet welke functies van de browser hij gebruikt. Komt er ooit kwaadaardige code op je site, bijvoorbeeld via een plug-in, dan kan die om de camera, microfoon of locatie van je bezoekers vragen onder jouw naam.").
			metDetail(ontbreektOp(w, "Permissions-Policy")...)
	}
	t := toestemmingen(v)
	var open []string
	for _, f := range gevoelig {
		if dicht, ok := t[f]; !ok || !dicht {
			open = append(open, f)
		}
	}
	gezien := "Permissions-Policy: " + kort(v, 160)
	if len(open) > 0 {
		return punt(id, tech, Matig, "Niet alles dichtgezet",
			fmt.Sprintf("Je site heeft een Permissions-Policy, maar zet niet alles dicht wat hij niet gebruikt: %s. Kwaadaardige code op je site zou daar nog om kunnen vragen.", enLijst(open))).
			met(gezien).metDetail("Nog open: "+strings.Join(open, ", "), "Bijvoorbeeld: camera=(), microphone=(), geolocation=()")
	}
	return punt(id, tech, Goed, titel,
		"Je site zet camera, microfoon en locatie dicht. Ook kwaadaardige code kan daar dan niet om vragen.").met(gezien)
}
