package main

import (
	"fmt"
	"net/url"

	"syncurity.nl/keuring/keuring"
	"syncurity.nl/keuring/pdf"
)

// Het rapport als pdf, in dezelfde opbouw als de rapportpagina: op elke
// pagina linksboven het logo en rechts syncurity.nl; pagina 1
// het bovenste deel tot en met "Eerst aanpakken", daarna de onderdelen.
// Alleen de gratis uitslag (Openbaar), net als op de pagina.

// Kleuren uit het tokenblok van stijl.css.
var (
	kInk     = pdf.Hex("#0c1222")
	kGedempt = pdf.Hex("#646a78")
	kAccent  = pdf.Hex("#1e3a8a")
	kPapier  = pdf.Hex("#f7f7f3")
	kLijn    = pdf.Hex("#e6e5de")
	kSterk   = pdf.Hex("#d9d9d1")
	kWit     = pdf.Hex("#ffffff")
	kGoed    = pdf.Hex("#1f7a4a")
	kMatig   = pdf.Hex("#b25e00")
	kSlecht  = pdf.Hex("#b3261e")
)

func statusKleur(s keuring.Status) pdf.Kleur {
	switch s {
	case keuring.Goed:
		return kGoed
	case keuring.Matig:
		return kMatig
	case keuring.Slecht:
		return kSlecht
	}
	return kSterk
}

// Het logo uit /assets/icoon.svg: viewBox 27 16 46 68 met deze transformaties.
const logoPad = `M 1256.785156 1755.425781 C 1166.535156 1858.023438 1082.964844 1960.808594 1047.777344 2011.34375 C 1038.609375 2024.523438 1022.691406 2048.109375 1008.613281 2073.21875 C 1104.382812 1999.515625 1226.277344 1857.332031 1256.785156 1755.425781 Z M 1536.191406 1476.316406 L 1535.523438 1473.515625 L 1535.082031 1473.296875 C 1534.421875 1474.425781 1535.292969 1475.449219 1536.191406 1476.316406 Z M 1540.511719 1496.175781 C 1537.390625 1481.464844 1537.929688 1483.554688 1536.742188 1478.585938 C 1506.574219 1496.554688 1459.039062 1539.851562 1404.9375 1594.921875 C 1485.859375 1705.621094 1419.84375 1850.554688 1347.164062 1951.382812 C 1278.292969 2046.929688 993.792969 2351.636719 871.0625 2229.609375 C 760.886719 2120.070312 986.398438 1890.007812 1064.597656 1810.347656 C 1082.976562 1791.621094 1144.328125 1731.996094 1217.898438 1666.523438 C 1158.117188 1648.945312 1057.648438 1651.675781 1029.300781 1652.964844 C 933.3125 1657.324219 782.21875 1649.90625 773.574219 1523.8125 C 758 1296.378906 1372.0625 995.554688 1563.359375 1214.566406 C 1595.65625 1251.554688 1559.5 1268.640625 1530.640625 1250.144531 C 1399.628906 1166.144531 1168.605469 1254.492188 1062.066406 1345.453125 C 822.429688 1550.027344 1170.84375 1406.855469 1358.832031 1548.410156 C 1447.621094 1479.707031 1527.792969 1431.5625 1552.238281 1457.648438 C 1566.238281 1472.585938 1550.238281 1487.257812 1540.519531 1496.164062 L 1540.511719 1496.175781`

var logoTrans = [][6]float64{
	{1, 0, 0, 1, -27, -16},    // viewBox begint bij 27,16
	{-1, 0, 0, -1, 100, 100},  // rotate(180 50 50)
	{1, 0, 0, 1, 30.8512, 19}, // translate
	{0.04571995, 0, 0, 0.04571995, 0, 0},
	{1, 0, 0, 1, -758, -995.5547},
}

const (
	rand   = 50.0
	breed  = pdf.A4Breed - 2*rand
	boven  = 104.0 // hier begint de inhoud, onder de kop
	onder  = pdf.A4Hoog - 64
	site   = "https://syncurity.nl"
	logoH  = 30.0
	midden = pdf.A4Breed / 2
	regelU = 1.45 // regelafstand als factor van de lettermaat
)

type pdfRapport struct {
	d       *pdf.Document
	y       float64
	u       *keuring.Uitslag
	domein  string
	wanneer string
}

func (r *pdfRapport) kop() {
	d := r.d
	d.Pad(rand, 34, logoH/68, logoTrans, logoPad, kAccent)
	d.Link(rand, 34, logoH*46/68, logoH, site+"/")
	d.TekstRechts(pdf.A4Breed-rand, 54, pdf.Gewoon, 11, kGedempt, "syncurity.nl")
	w := pdf.Breedte(pdf.Gewoon, 11, "syncurity.nl")
	d.Link(pdf.A4Breed-rand-w, 42, w, 16, site+"/")
	r.y = boven
}

func (r *pdfRapport) nieuwePagina() {
	r.d.NieuwePagina()
	r.kop()
}

// past zorgt dat er nog h punten ruimte is, anders een nieuwe pagina.
func (r *pdfRapport) past(h float64) {
	if r.y+h > onder {
		r.nieuwePagina()
	}
}

// alinea schrijft tekst over regels en geeft de hoogte; teken=false meet alleen.
func (r *pdfRapport) alinea(x, w float64, l pdf.Letter, maat float64, k pdf.Kleur, s string, teken bool) float64 {
	regels := pdf.Afbreken(l, maat, w, s)
	h := maat * regelU
	if teken {
		for i, regel := range regels {
			r.d.Tekst(x, r.y+maat+float64(i)*h, l, maat, k, regel)
		}
	}
	return float64(len(regels)) * h
}

func maakPDF(u *keuring.Uitslag, sub string) []byte {
	r := &pdfRapport{
		d:       &pdf.Document{Titel: "Scan " + keuring.Weergave(u.Domein) + " · Syncurity", Maker: "Syncurity", Tijd: u.Tijd},
		u:       u,
		domein:  keuring.Weergave(u.Domein),
		wanneer: wanneer(u.Tijd),
	}
	r.nieuwePagina()
	r.voorblad(sub)
	r.nieuwePagina()
	for _, g := range u.Groepen {
		r.groep(g)
	}
	r.ontgrendel()

	// Onderaan elke pagina: waar het over gaat en het paginanummer.
	n := r.d.Paginas()
	for i := range n {
		r.d.OpPagina(i)
		r.d.Lijn(rand, pdf.A4Hoog-44, pdf.A4Breed-rand, pdf.A4Hoog-44, 0.5, kLijn)
		voet := "Scan van " + r.domein + " · " + r.wanneer
		if v := openbareVersie(); v != "" {
			voet += " · versie " + v
		}
		r.d.Tekst(rand, pdf.A4Hoog-30, pdf.Gewoon, 8, kGedempt, voet)
		r.d.TekstRechts(pdf.A4Breed-rand, pdf.A4Hoog-30, pdf.Gewoon, 8, kGedempt, fmt.Sprintf("Pagina %d van %d", i+1, n))
	}
	return r.d.Bytes()
}

// voorblad: datum, domein, scorering, de onderdelen, feiten en eerst aanpakken.
func (r *pdfRapport) voorblad(sub string) {
	d, u := r.d, r.u
	r.y = 128
	d.TekstMidden(midden, r.y, pdf.Gewoon, 10, kGedempt, "Scan van "+r.wanneer)
	maat := 30.0
	for maat > 14 && pdf.Breedte(pdf.Vet, maat, r.domein) > breed {
		maat--
	}
	r.y += 14
	for _, regel := range pdf.Afbreken(pdf.Vet, maat, breed, r.domein) {
		r.y += maat * 1.1
		d.TekstMidden(midden, r.y, pdf.Vet, maat, kInk, regel)
	}

	// Scorering zoals op de site: grijze baan, blauwe stand vanaf 12 uur.
	r.y += 26
	straal, dik := 46.0, 9.0
	cy := r.y + straal + dik/2
	d.Boog(midden, cy, straal, 0, 360, dik, kLijn)
	if u.Totaal > 0 && u.InOrde > 0 {
		d.Boog(midden, cy, straal, 0, 360*float64(u.InOrde)/float64(u.Totaal), dik, kAccent)
	}
	d.TekstMidden(midden, cy+5, pdf.Vet, 22, kInk, fmt.Sprintf("%d/%d", u.InOrde, u.Totaal))
	d.TekstMidden(midden, cy+19, pdf.Gewoon, 8.5, kGedempt, "in orde")
	r.y = cy + straal + dik/2 + 26

	// De onderdelen in twee kolommen, zoals op een groot scherm.
	kol, tussen, rij := 205.0, 30.0, 23.0
	x0 := midden - kol - tussen/2
	helft := (len(u.Groepen) + 1) / 2
	for i, g := range u.Groepen {
		x := x0
		y := r.y + float64(i)*rij
		if i >= helft {
			x, y = x0+kol+tussen, r.y+float64(i-helft)*rij
		}
		d.Tekst(x, y+15, pdf.Gewoon, 10.5, kInk, g.Kort)
		d.TekstRechts(x+kol, y+15, pdf.Gewoon, 10.5, kInk, fmt.Sprintf("%d / %d", g.InOrde, g.Totaal))
		d.Lijn(x, y+rij, x+kol, y+rij, 0.6, kLijn)
	}
	r.y += float64(helft)*rij + 22

	if sub != "" {
		r.y += r.alineaMidden(8.5, kGedempt, "Je vulde "+sub+" in. De scan gaat over de hele domeinnaam "+r.domein+".") + 4
	}
	if u.Melding != "" {
		h := r.alinea(rand+12, breed-24, pdf.Gewoon, 9.5, kInk, u.Melding, false) + 16
		d.Vlak(rand, r.y, breed, h, 6, kPapier)
		r.y += 8
		r.alinea(rand+12, breed-24, pdf.Gewoon, 9.5, kInk, u.Melding, true)
		r.y += h - 8 + 12
	}

	// Feiten als labels naast elkaar, gecentreerd per regel.
	if len(u.Feiten) > 0 {
		type label struct {
			naam, waarde string
			w            float64
		}
		var regels [][]label
		var regelW []float64
		var huidig []label
		var hw float64
		for _, f := range u.Feiten {
			w := pdf.Breedte(pdf.Gewoon, 8.5, f.Naam) + 5 + pdf.Breedte(pdf.Vet, 8.5, f.Waarde) + 20
			if hw+w > breed && len(huidig) > 0 {
				regels, regelW = append(regels, huidig), append(regelW, hw-8)
				huidig, hw = nil, 0
			}
			huidig = append(huidig, label{f.Naam, f.Waarde, w})
			hw += w + 8
		}
		regels, regelW = append(regels, huidig), append(regelW, hw-8)
		for i, regel := range regels {
			x := midden - regelW[i]/2
			for _, l := range regel {
				d.Kader(x, r.y, l.w, 20, 10, 0.6, kLijn)
				d.Tekst(x+10, r.y+13.5, pdf.Gewoon, 8.5, kGedempt, l.naam)
				d.Tekst(x+10+pdf.Breedte(pdf.Gewoon, 8.5, l.naam)+5, r.y+13.5, pdf.Vet, 8.5, kInk, l.waarde)
				x += l.w + 8
			}
			r.y += 28
		}
		r.y += 10
	}

	if len(u.Eerst) > 0 {
		r.past(60)
		d.Tekst(rand, r.y+16, pdf.Vet, 16, kInk, "Eerst aanpakken")
		r.y += 32
		for _, p := range u.Eerst {
			h := 11*regelU + r.alinea(rand+18, breed-18, pdf.Gewoon, 9.5, kGedempt, p.Uitleg, false) + 14
			r.past(h)
			d.Lijn(rand, r.y, rand+breed, r.y, 0.6, kLijn)
			r.y += 10
			d.Stip(rand+4, r.y+7, 3.5, statusKleur(p.Status))
			d.Tekst(rand+18, r.y+11, pdf.Vet, 11, kInk, p.Titel)
			r.y += 11 * regelU
			r.y += r.alinea(rand+18, breed-18, pdf.Gewoon, 9.5, kGedempt, p.Uitleg, true) + 4
		}
	}
}

func (r *pdfRapport) alineaMidden(maat float64, k pdf.Kleur, s string) float64 {
	regels := pdf.Afbreken(pdf.Gewoon, maat, breed, s)
	for i, regel := range regels {
		r.d.TekstMidden(midden, r.y+maat+float64(i)*maat*regelU, pdf.Gewoon, maat, k, regel)
	}
	return float64(len(regels)) * maat * regelU
}

// punt meet (teken=false) of tekent een punt en geeft de hoogte.
func (r *pdfRapport) punt(p keuring.Punt, teken bool) float64 {
	d := r.d
	start := r.y
	tx := rand + 18
	tw := breed - 18
	oordeelW := pdf.Breedte(pdf.Vet, 8.5, p.Oordeel)
	titelW := tw - oordeelW - 16
	y := r.y + 8

	titel := pdf.Afbreken(pdf.Vet, 11, titelW, p.Titel)
	if teken {
		d.Stip(rand+4, y+7, 3.5, statusKleur(p.Status))
		for i, t := range titel {
			d.Tekst(tx, y+11+float64(i)*11*1.3, pdf.Vet, 11, kInk, t)
		}
		ok := statusKleur(p.Status)
		if p.Status == keuring.NVT || p.Status == keuring.Fout {
			ok = kGedempt
		}
		d.TekstRechts(rand+breed, y+11, pdf.Vet, 8.5, ok, p.Oordeel)
	}
	y += float64(len(titel))*11*1.3 + 1

	r.y = y
	y += r.alinea(tx, tw, pdf.Gewoon, 9.5, kGedempt, p.Uitleg, teken)

	if p.Gezien != "" {
		y += 4
		regels := pdf.Afbreken(pdf.Mono, 8, tw-16, p.Gezien)
		h := float64(len(regels))*8*regelU + 7
		if teken {
			d.Vlak(tx, y, tw, h, 4, kPapier)
			for i, regel := range regels {
				d.Tekst(tx+8, y+3.5+8+float64(i)*8*regelU, pdf.Mono, 8, kInk, regel)
			}
		}
		y += h
	}

	// Techniek en de uitleg op de site, als link.
	y += 4
	if teken {
		d.Tekst(tx, y+8, pdf.Mono, 8, kGedempt, p.Techniek)
		if p.Meer != "" {
			x := tx + pdf.Breedte(pdf.Mono, 8, p.Techniek+" · ")
			d.Tekst(tx+pdf.Breedte(pdf.Mono, 8, p.Techniek), y+8, pdf.Mono, 8, kGedempt, " · ")
			w := pdf.Breedte(pdf.Mono, 8, "Lees de uitleg")
			d.Tekst(x, y+8, pdf.Mono, 8, kAccent, "Lees de uitleg")
			d.Lijn(x, y+9.5, x+w, y+9.5, 0.5, kAccent)
			d.Link(x, y, w, 11, site+p.Meer)
		}
	}
	y += 11 + 8
	if teken {
		d.Lijn(rand, y, rand+breed, y, 0.6, kLijn)
	}
	r.y = start
	return y - start
}

func (r *pdfRapport) groep(g keuring.Groep) {
	d := r.d
	samen := pdf.Afbreken(pdf.Gewoon, 10, breed, g.Samen)
	kopH := 20 + float64(len(samen))*10*regelU + 18
	eerste := 0.0
	if len(g.Punten) > 0 {
		eerste = r.punt(g.Punten[0], false)
	}
	// De kop van een onderdeel nooit los onderaan een pagina.
	r.past(kopH + eerste)
	if r.y > boven {
		r.y += 18
	}
	d.Tekst(rand, r.y+16, pdf.Vet, 16, kInk, g.Naam)
	r.y += 22
	for i, s := range samen {
		d.Tekst(rand, r.y+10+float64(i)*10*regelU, pdf.Gewoon, 10, kGedempt, s)
	}
	r.y += float64(len(samen)) * 10 * regelU
	d.Tekst(rand, r.y+10, pdf.Mono, 8, kGedempt, fmt.Sprintf("%d van %d in orde", g.InOrde, g.Totaal))
	r.y += 18
	d.Lijn(rand, r.y, rand+breed, r.y, 0.6, kLijn)
	for _, p := range g.Punten {
		h := r.punt(p, false)
		if r.y+h > onder {
			r.nieuwePagina()
			d.Lijn(rand, r.y, rand+breed, r.y, 0.6, kLijn)
		}
		r.punt(p, true)
		r.y += h
	}
}

// ontgrendel: het blauwe vlak van de pagina, met een link naar aanmelden.
func (r *pdfRapport) ontgrendel() {
	d := r.d
	tekst := "Log in op syncurity.nl en verifieer je domeinnaam. Dan zie je het volledige rapport."
	regels := pdf.Afbreken(pdf.Gewoon, 10.5, breed-80, tekst)
	h := 40 + 26 + float64(len(regels))*10.5*regelU + 24
	r.past(h + 24)
	r.y += 24
	d.Vlak(rand, r.y, breed, h, 0, kAccent)
	d.TekstMidden(midden, r.y+44, pdf.Vet, 18, kWit, "Ontgrendel de rest")
	for i, regel := range regels {
		d.TekstMidden(midden, r.y+68+float64(i)*10.5*regelU, pdf.Gewoon, 10.5, kWit, regel)
	}
	d.Link(rand, r.y, breed, h, site+"/aanmelden?domein="+url.QueryEscape(r.u.Domein))
	r.y += h
}
