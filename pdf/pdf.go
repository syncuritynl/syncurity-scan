// Package pdf schrijft eenvoudige PDF-bestanden: tekst, lijnen, vlakken,
// cirkels, bogen, paden en links. Genoeg voor het rapport van de scan, zonder
// bibliotheek van buiten en zonder iets op de server te installeren: de
// dienst blijft één statisch programma.
//
// De letters zijn de standaardletters die elke PDF-lezer heeft (Helvetica,
// Helvetica-Bold, Courier), in WinAnsi-codering. Ze worden dus niet
// ingesloten en het bestand blijft klein. Tekens buiten WinAnsi (zoals een
// pijl) worden vervangen door iets wat er wel in zit.
//
// Coördinaten gaan in punten (1/72 inch) vanaf linksboven, y naar beneden,
// zoals op een scherm. Bij het schrijven draait het pakket dat om.
package pdf

import (
	"bytes"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/unicode/norm"
)

// A4 in punten.
const (
	A4Breed = 595.28
	A4Hoog  = 841.89
)

// Letter is een van de drie standaardletters.
type Letter int

const (
	Gewoon Letter = iota // Helvetica
	Vet                  // Helvetica-Bold
	Mono                 // Courier
)

var letterNamen = [...]string{"Helvetica", "Helvetica-Bold", "Courier"}

// Kleur is een RGB-kleur met waarden van 0 tot 1.
type Kleur struct{ R, G, B float64 }

// Hex maakt een kleur van "#rrggbb". Een ongeldige waarde geeft zwart.
func Hex(s string) Kleur {
	s = strings.TrimPrefix(s, "#")
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil || len(s) != 6 {
		return Kleur{}
	}
	return Kleur{float64(v>>16&0xff) / 255, float64(v>>8&0xff) / 255, float64(v&0xff) / 255}
}

type link struct {
	x, y, b, h float64
	url        string
}

// Document is een PDF in opbouw. Elke pagina is A4 staand.
type Document struct {
	Titel, Maker string
	Tijd         time.Time

	paginas []*bytes.Buffer
	links   [][]link
	huidig  int
}

// NieuwePagina begint een nieuwe pagina; alles wat hierna getekend wordt,
// komt daarop.
func (d *Document) NieuwePagina() {
	d.paginas = append(d.paginas, &bytes.Buffer{})
	d.links = append(d.links, nil)
	d.huidig = len(d.paginas) - 1
}

// Paginas is het aantal pagina's tot nu toe.
func (d *Document) Paginas() int { return len(d.paginas) }

// OpPagina laat de volgende tekenopdrachten op pagina i (vanaf 0) landen,
// bijvoorbeeld om achteraf "pagina 2 van 5" te zetten.
func (d *Document) OpPagina(i int) { d.huidig = i }

func (d *Document) w() *bytes.Buffer {
	if len(d.paginas) == 0 {
		d.NieuwePagina()
	}
	return d.paginas[d.huidig]
}

func (d *Document) op(format string, a ...any) { fmt.Fprintf(d.w(), format+"\n", a...) }

func g(f float64) string { return strconv.FormatFloat(f, 'f', 2, 64) }

// y van boven naar beneden omzetten naar PDF (van onder naar boven).
func py(y float64) float64 { return A4Hoog - y }

func kleurVul(k Kleur) string  { return g(k.R) + " " + g(k.G) + " " + g(k.B) + " rg" }
func kleurLijn(k Kleur) string { return g(k.R) + " " + g(k.G) + " " + g(k.B) + " RG" }

// Tekst zet s met de basislijn op (x, y).
func (d *Document) Tekst(x, y float64, l Letter, maat float64, k Kleur, s string) {
	d.op("BT /F%d %s Tf %s 1 0 0 1 %s %s Tm (%s) Tj ET", l+1, g(maat), kleurVul(k), g(x), g(py(y)), escape(winAnsi(s)))
}

// TekstRechts zet s rechts uitgelijnd tegen x.
func (d *Document) TekstRechts(x, y float64, l Letter, maat float64, k Kleur, s string) {
	d.Tekst(x-Breedte(l, maat, s), y, l, maat, k, s)
}

// TekstMidden zet s gecentreerd rond x.
func (d *Document) TekstMidden(x, y float64, l Letter, maat float64, k Kleur, s string) {
	d.Tekst(x-Breedte(l, maat, s)/2, y, l, maat, k, s)
}

// Vlak vult een rechthoek; r is de straal van de hoeken (0 voor recht).
func (d *Document) Vlak(x, y, b, h, r float64, k Kleur) {
	d.op("%s", kleurVul(k))
	d.rechthoek(x, y, b, h, r)
	d.op("f")
}

// Kader tekent de rand van een rechthoek.
func (d *Document) Kader(x, y, b, h, r, dikte float64, k Kleur) {
	d.op("%s %s w", kleurLijn(k), g(dikte))
	d.rechthoek(x, y, b, h, r)
	d.op("S")
}

func (d *Document) rechthoek(x, y, b, h, r float64) {
	if r <= 0 {
		d.op("%s %s %s %s re", g(x), g(py(y+h)), g(b), g(h))
		return
	}
	r = min(r, b/2, h/2)
	const c = 0.5523 // afstand van de controlepunten voor een kwart cirkel
	x0, x1 := x, x+b
	y0, y1 := py(y+h), py(y) // onder, boven in PDF
	d.op("%s %s m", g(x0+r), g(y0))
	d.op("%s %s l", g(x1-r), g(y0))
	d.op("%s %s %s %s %s %s c", g(x1-r+c*r), g(y0), g(x1), g(y0+r-c*r), g(x1), g(y0+r))
	d.op("%s %s l", g(x1), g(y1-r))
	d.op("%s %s %s %s %s %s c", g(x1), g(y1-r+c*r), g(x1-r+c*r), g(y1), g(x1-r), g(y1))
	d.op("%s %s l", g(x0+r), g(y1))
	d.op("%s %s %s %s %s %s c", g(x0+r-c*r), g(y1), g(x0), g(y1-r+c*r), g(x0), g(y1-r))
	d.op("%s %s l", g(x0), g(y0+r))
	d.op("%s %s %s %s %s %s c h", g(x0), g(y0+r-c*r), g(x0+r-c*r), g(y0), g(x0+r), g(y0))
}

// Lijn tekent een rechte lijn.
func (d *Document) Lijn(x1, y1, x2, y2, dikte float64, k Kleur) {
	d.op("%s %s w %s %s m %s %s l S", kleurLijn(k), g(dikte), g(x1), g(py(y1)), g(x2), g(py(y2)))
}

// Stip vult een cirkel.
func (d *Document) Stip(cx, cy, r float64, k Kleur) {
	d.op("%s", kleurVul(k))
	d.boog(cx, cy, r, 0, 360)
	d.op("f")
}

// Boog tekent een stuk cirkelrand, van hoek van tot hoek tot in graden,
// met de klok mee vanaf boven (12 uur), zoals de scorering op de site.
func (d *Document) Boog(cx, cy, r, van, tot, dikte float64, k Kleur) {
	if tot <= van {
		return
	}
	d.op("%s %s w 1 J", kleurLijn(k), g(dikte))
	d.boog(cx, cy, r, van, tot)
	d.op("S 0 J")
}

// boog zet het pad van een boog neer in stukken van hooguit 90 graden.
func (d *Document) boog(cx, cy, r, van, tot float64) {
	punt := func(a float64) (float64, float64) {
		// 0 graden is boven, met de klok mee; in PDF loopt y omhoog.
		rad := a * math.Pi / 180
		return cx + r*math.Sin(rad), py(cy) + r*math.Cos(rad)
	}
	x, y := punt(van)
	d.op("%s %s m", g(x), g(y))
	for a := van; a < tot; {
		b := min(a+90, tot)
		k := 4.0 / 3 * math.Tan((b-a)*math.Pi/180/4) * r
		ax, ay := punt(a)
		bx, by := punt(b)
		ra, rb := a*math.Pi/180, b*math.Pi/180
		// raaklijn met de klok mee: (cos, -sin) in PDF-richting
		d.op("%s %s %s %s %s %s c",
			g(ax+k*math.Cos(ra)), g(ay-k*math.Sin(ra)),
			g(bx-k*math.Cos(rb)), g(by+k*math.Sin(rb)),
			g(bx), g(by))
		a = b
	}
}

// Pad tekent een gevulde vorm uit SVG-padopdrachten (alleen M, L, C en Z,
// absoluut), met de even-oneven-regel. trans is een lijst van matrices
// [a b c d e f] zoals in SVG, van buiten naar binnen; x, y en schaal leggen
// de linkerbovenhoek van het viewBox-stelsel op de pagina.
func (d *Document) Pad(x, y, schaal float64, trans [][6]float64, svg string, k Kleur) {
	d.op("q %s", kleurVul(k))
	d.op("%s 0 0 %s %s %s cm", g(schaal), g(-schaal), g(x), g(py(y)))
	for _, m := range trans {
		d.op("%s %s %s %s %s %s cm", f6(m[0]), f6(m[1]), f6(m[2]), f6(m[3]), f6(m[4]), f6(m[5]))
	}
	velden := strings.Fields(strings.NewReplacer(",", " ").Replace(svg))
	var getallen []string
	klaar := func(opdracht string) {
		if len(getallen) > 0 {
			d.op("%s %s", strings.Join(getallen, " "), opdracht)
		}
		getallen = getallen[:0]
	}
	var huidig string
	for _, v := range velden {
		switch v {
		case "M", "L", "C":
			huidig = map[string]string{"M": "m", "L": "l", "C": "c"}[v]
		case "Z", "z":
			d.op("h")
		default:
			getallen = append(getallen, v)
			nodig := map[string]int{"m": 2, "l": 2, "c": 6}[huidig]
			if nodig > 0 && len(getallen) == nodig {
				klaar(huidig)
				if huidig == "m" {
					huidig = "l" // na een M volgen losse punten als L
				}
			}
		}
	}
	d.op("f* Q")
}

func f6(f float64) string { return strconv.FormatFloat(f, 'f', 6, 64) }

// Link maakt een klikbaar vlak naar een webadres.
func (d *Document) Link(x, y, b, h float64, url string) {
	d.w()
	d.links[d.huidig] = append(d.links[d.huidig], link{x, y, b, h, url})
}

// ---------------------------------------------------------------- tekst

// Breedte van s in punten.
func Breedte(l Letter, maat float64, s string) float64 {
	var som int
	for _, c := range winAnsi(s) {
		som += tekenBreedte(l, c)
	}
	return float64(som) * maat / 1000
}

// Afbreken verdeelt s over regels van hooguit breed punten, op spaties.
// Een woord dat op zich al te breed is (een lange URL), wordt hard geknipt.
func Afbreken(l Letter, maat, breed float64, s string) []string {
	var regels []string
	for _, alinea := range strings.Split(s, "\n") {
		var regel string
		for _, woord := range strings.Fields(alinea) {
			for Breedte(l, maat, woord) > breed {
				// Hard knippen: zoveel tekens als passen.
				if regel != "" {
					regels = append(regels, regel)
					regel = ""
				}
				i := 1
				for i < len(woord) && Breedte(l, maat, woord[:nextRune(woord, i)]) <= breed {
					i = nextRune(woord, i)
				}
				regels = append(regels, woord[:i])
				woord = woord[i:]
			}
			if regel == "" {
				regel = woord
			} else if Breedte(l, maat, regel+" "+woord) <= breed {
				regel += " " + woord
			} else {
				regels = append(regels, regel)
				regel = woord
			}
		}
		if regel != "" || len(regels) == 0 {
			regels = append(regels, regel)
		}
	}
	return regels
}

func nextRune(s string, i int) int {
	_, n := utf8.DecodeRuneInString(s[i:])
	return i + max(n, 1)
}

// vervangers voor tekens die WinAnsi niet heeft.
var vervang = map[rune]string{
	'\u2192': "->", '\u2190': "<-", '\u21d2': "=>", '\u2265': ">=", '\u2264': "<=", '\u2260': "!=",
	'\u2212': "-", '\u2010': "-", '\u2011': "-", '\u2713': "v", '\u2714': "v", '\u2717': "x",
	'\u2009': " ", '\u202f': " ", '\u200b': "", '\u2060': "", '\ufeff': "",
}

// winAnsi zet tekst om naar WinAnsi (cp1252). Wat er niet in zit, wordt een
// vervanger, een letter zonder accent, of een vraagteken.
func winAnsi(s string) []byte {
	uit := make([]byte, 0, len(s))
	for _, r := range s {
		if b, ok := charmap.Windows1252.EncodeRune(r); ok {
			uit = append(uit, b)
			continue
		}
		if v, ok := vervang[r]; ok {
			uit = append(uit, v...)
			continue
		}
		if basis := []rune(norm.NFD.String(string(r))); len(basis) > 0 && basis[0] < 0x80 && basis[0] >= 0x20 {
			uit = append(uit, byte(basis[0]))
			continue
		}
		uit = append(uit, '?')
	}
	return uit
}

func escape(b []byte) string {
	var s strings.Builder
	for _, c := range b {
		switch c {
		case '\\', '(', ')':
			s.WriteByte('\\')
			s.WriteByte(c)
		case '\r', '\n', '\t':
			s.WriteByte(' ')
		default:
			s.WriteByte(c)
		}
	}
	return s.String()
}

// ---------------------------------------------------------------- uitvoer

// Bytes schrijft het hele document.
func (d *Document) Bytes() []byte {
	if len(d.paginas) == 0 {
		d.NieuwePagina()
	}
	var b bytes.Buffer
	var plek []int
	obj := func(inhoud string) int {
		plek = append(plek, b.Len())
		n := len(plek)
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", n, inhoud)
		return n
	}
	b.WriteString("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")

	// Vaste nummers: 1 catalogus, 2 paginaboom, 3-5 letters, 6 info.
	n := len(d.paginas)
	eerstePagina := 7
	// Per pagina: pagina, inhoud, en een object per link.
	nummers := make([]int, n)
	volgende := eerstePagina
	for i := range d.paginas {
		nummers[i] = volgende
		volgende += 2 + len(d.links[i])
	}
	var kids []string
	for _, k := range nummers {
		kids = append(kids, fmt.Sprintf("%d 0 R", k))
	}
	obj("<< /Type /Catalog /Pages 2 0 R /Lang (nl-NL) /ViewerPreferences << /DisplayDocTitle true >> >>")
	obj(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), n))
	for _, naam := range letterNamen {
		obj("<< /Type /Font /Subtype /Type1 /BaseFont /" + naam + " /Encoding /WinAnsiEncoding >>")
	}
	tijd := d.Tijd
	if tijd.IsZero() {
		tijd = time.Now()
	}
	_, off := tijd.Zone()
	teken := "+"
	if off < 0 {
		teken, off = "-", -off
	}
	datum := fmt.Sprintf("D:%s%s%02d'%02d'", tijd.Format("20060102150405"), teken, off/3600, off%3600/60)
	obj(fmt.Sprintf("<< /Title (%s) /Producer (%s) /Creator (%s) /CreationDate (%s) >>",
		escape(winAnsi(d.Titel)), escape(winAnsi(d.Maker)), escape(winAnsi(d.Maker)), datum))

	for i, p := range d.paginas {
		var annots []string
		for j := range d.links[i] {
			annots = append(annots, fmt.Sprintf("%d 0 R", nummers[i]+2+j))
		}
		a := ""
		if len(annots) > 0 {
			a = " /Annots [" + strings.Join(annots, " ") + "]"
		}
		obj(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %s %s] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents %d 0 R%s >>",
			g(A4Breed), g(A4Hoog), nummers[i]+1, a))
		obj(fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", p.Len(), p.Bytes()))
		for _, l := range d.links[i] {
			obj(fmt.Sprintf("<< /Type /Annot /Subtype /Link /Rect [%s %s %s %s] /Border [0 0 0] /A << /S /URI /URI (%s) >> >>",
				g(l.x), g(py(l.y+l.h)), g(l.x+l.b), g(py(l.y)), escape(winAnsi(l.url))))
		}
	}

	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(plek)+1)
	for _, p := range plek {
		fmt.Fprintf(&b, "%010d 00000 n \n", p)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R /Info 6 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(plek)+1, xref)
	return b.Bytes()
}
