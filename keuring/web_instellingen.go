package keuring

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

func (k *keurder) instellingen(ctx context.Context, w *web) Groep {
	g := Groep{ID: "instellingen", Naam: "Je website: beveiliging en privacy", Kort: "Beveiliging en privacy"}
	if w.host == "" || w.pagina == nil || w.geweigerd != 0 {
		s, reden := geenPagina(w)
		for _, p := range []struct{ id, tech, titel string }{
			{"csp", "CSP", "Beleid voor scripts"}, {"nosniff", "nosniff", "Bestandstype ligt vast"},
			{"frame", "frame-ancestors", "Niet in te bedden"}, {"referrer", "Referrer-Policy", "Niet doorgeven waar bezoekers vandaan komen"},
			{"cookies", "Secure · SameSite", "Veilige cookies"}, {"versie", "Server", "Softwareversie verborgen"},
			{"mixed", "mixed content", "Alles via https geladen"}, {"trackers", "externe scripts", "Geen trackers zonder toestemming"},
		} {
			g.Punten = append(g.Punten, punt(p.id, p.tech, s, p.titel, reden))
		}
		g.Punten = append(g.Punten, k.securityTxt(ctx, w.host))
		g.Punten = append(g.Punten, metStatus("instellingen", s, reden)...)
		return g
	}
	g.Punten = []Punt{csp(w), nosniff(w), frame(w), referrer(w), cookies(w), versie(w), mixed(w), trackers(k.domein, w), k.securityTxt(ctx, w.host),
		software(w), bibliotheken(w), php(w), sri(k.domein, w), formulieren(w)}
	return g
}

func csp(w *web) Punt {
	v := w.kop("Content-Security-Policy")
	if v == "" {
		return punt("csp", "CSP", Matig, "Geen beleid voor scripts",
			"Er staat geen Content-Security-Policy. Die bepaalt welke scripts je site mag uitvoeren, en maakt het veel moeilijker om via je site kwaadaardige code bij bezoekers te krijgen.").
			metDetail(ontbreektOp(w, "Content-Security-Policy")...)
	}
	l := strings.ToLower(v)
	scripts := richtlijn(l, "script-src")
	if scripts == "" {
		scripts = richtlijn(l, "default-src")
	}
	var zwak []string
	if strings.Contains(scripts, "'unsafe-inline'") && !strings.Contains(scripts, "'nonce-") && !strings.Contains(scripts, "'sha256-") && !strings.Contains(scripts, "'strict-dynamic'") {
		zwak = append(zwak, "'unsafe-inline'")
	}
	if strings.Contains(scripts, "'unsafe-eval'") {
		zwak = append(zwak, "'unsafe-eval'")
	}
	for _, d := range strings.Fields(scripts) {
		if d == "*" || d == "https:" || d == "http:" || d == "data:" {
			zwak = append(zwak, d)
		}
	}
	gezien := "Content-Security-Policy: " + kort(v, 160)
	if scripts == "" || len(zwak) > 0 {
		reden := "Er staat een beleid, maar het laat nog onveilige scripts toe"
		if len(zwak) > 0 {
			reden += " (" + strings.Join(zwak, ", ") + ")"
		}
		return punt("csp", "CSP", Matig, "Het beleid voor scripts is ruim", reden+". Daarmee beschermt het weinig.").met(gezien).metDetail(cspDetail(l, zwak)...)
	}
	return punt("csp", "CSP", Goed, "Streng beleid voor scripts",
		"Alleen scripts die je site zelf aanwijst, mogen draaien.").met(gezien).metDetail(cspDetail(l, nil)...)
}

// cspDetail noemt per richtlijn wat er zwak is of ontbreekt.
func cspDetail(l string, zwak []string) []string {
	var uit []string
	if len(zwak) > 0 {
		bron := "script-src"
		if richtlijn(l, "script-src") == "" {
			bron = "default-src"
		}
		uit = append(uit, bron+" laat toe: "+strings.Join(zwak, " "))
	}
	if richtlijn(l, "script-src") == "" && richtlijn(l, "default-src") == "" {
		uit = append(uit, "Ontbreekt: script-src of default-src (dan geldt er niets voor scripts)")
	}
	var mist []string
	for _, r := range []string{"object-src", "base-uri", "frame-ancestors", "form-action"} {
		if !strings.Contains(" "+strings.ReplaceAll(l, ";", " ; ")+" ", " "+r+" ") {
			mist = append(mist, r)
		}
	}
	if len(mist) > 0 {
		uit = append(uit, "Ontbreekt ook: "+strings.Join(mist, ", "))
	}
	if strings.Contains(l, "report-uri") || strings.Contains(l, "report-to") {
		uit = append(uit, "Er staat een adres voor meldingen (report-uri/report-to).")
	}
	return uit
}

func richtlijn(csp, naam string) string {
	for _, deel := range strings.Split(csp, ";") {
		f := strings.Fields(deel)
		if len(f) > 0 && f[0] == naam {
			return strings.Join(f[1:], " ")
		}
	}
	return ""
}

func nosniff(w *web) Punt {
	if strings.EqualFold(strings.TrimSpace(w.kop("X-Content-Type-Options")), "nosniff") {
		return punt("nosniff", "nosniff", Goed, "Bestandstype ligt vast",
			"De browser voert een plaatje of tekstbestand nooit uit als script.").met("X-Content-Type-Options: nosniff")
	}
	d := ontbreektOp(w, "X-Content-Type-Options")
	if v := w.kop("X-Content-Type-Options"); v != "" {
		d = []string{"X-Content-Type-Options staat op \"" + v + "\"; de enige geldige waarde is nosniff."}
	}
	return punt("nosniff", "nosniff", Matig, "Bestandstype ligt niet vast",
		"Zonder deze instelling kan een browser een geüpload bestand als script uitvoeren.").metDetail(d...)
}

func frame(w *web) Punt {
	xfo := w.kop("X-Frame-Options")
	fa := richtlijn(strings.ToLower(w.kop("Content-Security-Policy")), "frame-ancestors")
	switch {
	case fa != "":
		return punt("frame", "frame-ancestors", Goed, "Je site is niet in te bedden",
			"Een andere site kan jouw pagina niet onzichtbaar in de zijne laden om bezoekers te laten klikken waar ze niet willen.").met("frame-ancestors " + fa)
	case xfo != "":
		return punt("frame", "frame-ancestors", Goed, "Je site is niet in te bedden",
			"Een andere site kan jouw pagina niet onzichtbaar in de zijne laden.").met("X-Frame-Options: " + xfo)
	default:
		return punt("frame", "frame-ancestors", Matig, "Je site is in te bedden",
			"Een andere site kan jouw pagina onzichtbaar in de zijne laden en bezoekers zo laten klikken op iets wat ze niet zien (clickjacking).").
			metDetail(ontbreektOp(w, "X-Frame-Options en frame-ancestors in de Content-Security-Policy")...)
	}
}

func referrer(w *web) Punt {
	v := strings.ToLower(strings.TrimSpace(w.kop("Referrer-Policy")))
	laatste := v
	if i := strings.LastIndex(v, ","); i >= 0 {
		laatste = strings.TrimSpace(v[i+1:])
	}
	switch laatste {
	case "":
		return punt("referrer", "Referrer-Policy", Matig, "Andere sites kunnen zien waar bezoekers vandaan komen",
			"Er staat geen Referrer-Policy. Moderne browsers geven andere sites dan alleen je domeinnaam door; met een eigen instelling leg je dat vast, ook voor oudere browsers.").
			metDetail(ontbreektOp(w, "Referrer-Policy")...)
	case "unsafe-url", "no-referrer-when-downgrade":
		return punt("referrer", "Referrer-Policy", Matig, "Andere sites zien waar bezoekers vandaan komen",
			"Je site geeft het volledige adres van de pagina door aan andere sites waar een bezoeker op klikt.").met("Referrer-Policy: " + v).
			metDetail("De laatste waarde telt: " + laatste + ". Kies strict-origin-when-cross-origin of strenger.")
	default:
		return punt("referrer", "Referrer-Policy", Goed, "Niet doorgeven waar bezoekers vandaan komen",
			"Andere sites krijgen niet te zien vanaf welke pagina een bezoeker kwam.").met("Referrer-Policy: " + v)
	}
}

// ontbreektOp zegt welke kopregel ontbreekt, en op welk adres we keken.
func ontbreektOp(w *web, kop string) []string {
	adres := "https://" + w.host + "/"
	if w.pagina != nil && w.pagina.Request != nil && w.pagina.Request.URL != nil {
		adres = w.pagina.Request.URL.String()
	}
	return []string{"Ontbreekt: " + kop, "Gemeten op " + adres}
}

func cookies(w *web) Punt {
	var alle []*http.Cookie
	for _, r := range []*http.Response{w.eerste, w.pagina} {
		if r != nil {
			alle = append(alle, r.Cookies()...)
		}
	}
	if len(alle) == 0 {
		return punt("cookies", "Secure · SameSite", Goed, "Geen cookies bij een eerste bezoek",
			"Je site zet niets in de browser van een bezoeker die alleen kijkt.")
	}
	var onveilig, zonderSameSite, namen, detail []string
	gezien := map[string]bool{}
	for _, c := range alle {
		if gezien[c.Name] {
			continue
		}
		gezien[c.Name] = true
		namen = append(namen, c.Name)
		var mist []string
		if !c.Secure {
			onveilig = append(onveilig, c.Name)
			mist = append(mist, "Secure")
		}
		if !c.HttpOnly {
			mist = append(mist, "HttpOnly")
		}
		if c.SameSite == http.SameSiteDefaultMode {
			zonderSameSite = append(zonderSameSite, c.Name)
			mist = append(mist, "SameSite")
		}
		if len(mist) > 0 {
			detail = append(detail, kort(c.Name, 60)+": zonder "+strings.Join(mist, ", "))
		}
	}
	detail = lijstje(detail, maxDetail)
	if len(detail) > 0 {
		detail = append(detail, "HttpOnly mag ontbreken als een script op je site de cookie echt nodig heeft.")
	}
	lijst := fmt.Sprintf("%d cookies: %s", len(namen), kort(strings.Join(namen, ", "), 120))
	switch {
	case len(onveilig) > 0:
		return punt("cookies", "Secure · SameSite", Slecht, "Cookies kunnen onbeveiligd meereizen",
			"Niet al je cookies hebben het Secure-kenmerk. Op een onbeveiligde verbinding kan iemand ze dan onderscheppen.").met(lijst + "; zonder Secure: " + strings.Join(onveilig, ", ")).metDetail(detail...)
	case len(zonderSameSite) > 0:
		return punt("cookies", "Secure · SameSite", Matig, "Cookies zonder SameSite",
			"Sommige cookies hebben geen SameSite-kenmerk, waardoor een andere site er in jouw naam mee kan werken.").met(lijst + "; zonder SameSite: " + strings.Join(zonderSameSite, ", ")).metDetail(detail...)
	default:
		return punt("cookies", "Secure · SameSite", Goed, "Veilige cookies",
			"Alle cookies reizen alleen versleuteld mee en zijn afgeschermd voor andere sites.").met(lijst).metDetail(detail...)
	}
}

var cijfers = regexp.MustCompile(`\d+\.\d+`)
var generator = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)

func versie(w *web) Punt {
	var lekt []string
	if s := w.kop("Server"); cijfers.MatchString(s) {
		lekt = append(lekt, "Server: "+s)
	}
	for _, h := range []string{"X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"} {
		if v := w.kop(h); v != "" {
			lekt = append(lekt, h+": "+v)
		}
	}
	if m := generator.FindSubmatch(w.body); m != nil && cijfers.Match(m[1]) {
		lekt = append(lekt, "generator: "+string(m[1]))
	}
	if len(lekt) > 0 {
		return punt("versie", "Server · X-Powered-By", Matig, "Je site laat zien welke softwareversie erop draait",
			"Een aanvaller ziet zo meteen of er een bekende kwetsbaarheid in je versie zit. Die informatie hoeft niet openbaar te zijn.").met(kort(strings.Join(lekt, "; "), 160)).metDetail(lekt...)
	}
	return punt("versie", "Server · X-Powered-By", Goed, "Softwareversie blijft verborgen",
		"Je site laat niet zien welke softwareversie erop draait.")
}

var bron = regexp.MustCompile(`(?is)<(script|link|img|iframe|source|video|audio|embed)\b[^>]*?\b(?:src|href)\s*=\s*["']([^"']+)["']`)

func mixed(w *web) Punt {
	var http1 []string
	for _, m := range bron.FindAllSubmatch(w.body, -1) {
		if u := string(m[2]); strings.HasPrefix(strings.ToLower(u), "http://") {
			http1 = append(http1, u)
		}
	}
	if len(http1) > 0 {
		var detail []string
		for _, u := range uniek(http1) {
			detail = append(detail, kort(u, 160))
		}
		return punt("mixed", "mixed content", Slecht, "Je pagina laadt onderdelen onbeveiligd",
			fmt.Sprintf("Je pagina haalt %d onderdelen op via http://. Die kunnen onderweg worden vervangen, en browsers blokkeren ze vaak.", len(http1))).met("Bijvoorbeeld: " + kort(http1[0], 100)).
			metDetail(lijstje(detail, maxDetail)...)
	}
	return punt("mixed", "mixed content", Goed, "Alles wordt via https geladen",
		"Alle scripts, stijlen en afbeeldingen op je homepage komen beveiligd binnen.")
}

// bekendeTrackers zijn diensten die bezoekers volgen. Daarvoor is volgens de
// AVG en de Telecommunicatiewet meestal toestemming nodig.
var bekendeTrackers = map[string]string{
	"google-analytics.com": "Google Analytics", "googletagmanager.com": "Google Tag Manager",
	"doubleclick.net": "Google Ads", "googleadservices.com": "Google Ads",
	"connect.facebook.net": "Meta Pixel", "facebook.com": "Meta", "hotjar.com": "Hotjar",
	"clarity.ms": "Microsoft Clarity", "bat.bing.com": "Microsoft Ads", "snap.licdn.com": "LinkedIn Insight",
	"analytics.tiktok.com": "TikTok Pixel", "matomo.cloud": "Matomo Cloud", "leadinfo.net": "Leadinfo",
	"hubspot.com": "HubSpot", "hs-scripts.com": "HubSpot", "plausible.io": "Plausible",
}

func trackers(domein string, w *web) Punt {
	extern := map[string]bool{}
	gevonden := map[string]bool{}
	waar := map[string]bool{} // "Google Analytics: www.googletagmanager.com"
	for _, m := range bron.FindAllSubmatch(w.body, -1) {
		u, err := url.Parse(strings.TrimSpace(string(m[2])))
		if err != nil || u.Host == "" {
			continue
		}
		h := strings.ToLower(u.Hostname())
		if h == domein || strings.HasSuffix(h, "."+domein) {
			continue
		}
		extern[h] = true
		for t, naam := range bekendeTrackers {
			if h == t || strings.HasSuffix(h, "."+t) {
				gevonden[naam] = true
				waar[naam+": "+h] = true
			}
		}
	}
	diensten := sleutels(extern)
	var detail []string
	for _, x := range sleutels(waar) {
		detail = append(detail, "Tracker "+x)
	}
	var overig []string
	for _, h := range diensten {
		if !trackerHost(h) {
			overig = append(overig, h)
		}
	}
	if len(overig) > 0 {
		detail = append(detail, "Andere externe partijen: "+strings.Join(lijstje(overig, 12), ", "))
	}
	if len(gevonden) > 0 {
		return punt("trackers", "externe scripts", Matig, "Je site laadt trackers",
			"Je homepage laadt diensten die bezoekers volgen. Daarvoor heb je meestal vooraf toestemming nodig (AVG), en de gegevens gaan naar die partijen.").met("Gevonden: " + strings.Join(sleutels(gevonden), ", ")).metDetail(detail...)
	}
	if len(diensten) > 0 {
		return punt("trackers", "externe scripts", Goed, "Geen trackers gevonden",
			fmt.Sprintf("We vonden geen bekende trackers. Je homepage laadt wel onderdelen van %d andere partijen.", len(diensten))).met("Externe partijen: " + kort(strings.Join(diensten, ", "), 140)).metDetail(detail...)
	}
	return punt("trackers", "externe scripts", Goed, "Geen trackers, geen externe partijen",
		"Je homepage laadt niets van andere partijen. Bezoekers worden door niemand anders gevolgd.")
}

func trackerHost(h string) bool {
	for t := range bekendeTrackers {
		if h == t || strings.HasSuffix(h, "."+t) {
			return true
		}
	}
	return false
}

func sleutels(m map[string]bool) []string {
	s := make([]string, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	sort.Strings(s)
	return s
}

func kort(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func (k *keurder) securityTxt(ctx context.Context, host string) Punt {
	if host == "" {
		return punt("securitytxt", "security.txt", NVT, "Contactpunt voor beveiligingsmeldingen", geenWebsite)
	}
	adres := "https://" + host + "/.well-known/security.txt"
	resp, body := k.haal(ctx, k.vrij, adres)
	ontbreekt := punt("securitytxt", "security.txt", Matig, "Geen contactpunt voor beveiligingsmeldingen",
		"Er is geen security.txt. Wie een lek in je site vindt, weet niet waar dat gemeld kan worden.")
	switch {
	case resp == nil:
		return ontbreekt.metDetail(adres + " gaf geen antwoord")
	case resp.StatusCode != http.StatusOK:
		return ontbreekt.metDetail(fmt.Sprintf("%s geeft HTTP %d", adres, resp.StatusCode))
	case !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain"):
		return ontbreekt.metDetail(adres+" is er, maar als "+leegAls(resp.Header.Get("Content-Type"), "onbekend type"),
			"Het hoort een tekstbestand te zijn (Content-Type: text/plain).")
	}
	var contact []string
	verloopt := time.Time{}
	for _, r := range strings.Split(string(body), "\n") {
		kv := strings.SplitN(strings.TrimSpace(r), ":", 2)
		if len(kv) != 2 {
			continue
		}
		switch strings.ToLower(kv[0]) {
		case "contact":
			contact = append(contact, strings.TrimSpace(kv[1]))
		case "expires":
			verloopt, _ = time.Parse(time.RFC3339, strings.TrimSpace(kv[1]))
		}
	}
	if len(contact) == 0 {
		return ontbreekt.metDetail(adres+" heeft geen regel Contact:", "Zonder Contact weet een melder nog niet waar hij terechtkan.")
	}
	k.leg(func(s *stand) { s.secContact = contact })
	if !verloopt.IsZero() && verloopt.Before(time.Now()) {
		return punt("securitytxt", "security.txt", Matig, "Het contactpunt is verlopen",
			"Je security.txt heeft een vervaldatum die al voorbij is. Werk hem bij, anders vertrouwen melders hem niet.").met("Verlopen op "+verloopt.Format("2-1-2006")).
			metDetail("Contact: "+strings.Join(contact, ", "), "Expires: "+verloopt.Format(time.RFC3339))
	}
	if verloopt.IsZero() {
		return punt("securitytxt", "security.txt", Goed, "Contactpunt voor beveiligingsmeldingen",
			"Wie een lek vindt, weet waar dat gemeld kan worden.").met("Contact: " + strings.Join(contact, ", ")).
			metDetail("Er staat geen geldige Expires-regel; die is verplicht (RFC 9116).")
	}
	return punt("securitytxt", "security.txt", Goed, "Contactpunt voor beveiligingsmeldingen",
		"Wie een lek vindt, weet waar dat gemeld kan worden.").met("Contact: " + strings.Join(contact, ", "))
}
