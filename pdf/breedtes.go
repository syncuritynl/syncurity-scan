package pdf

import (
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/unicode/norm"
)

// Breedtes van de tekens 32 tot en met 126, in duizendsten van de lettermaat,
// uit de AFM-bestanden van Adobe (Helvetica en Helvetica-Bold, de standaard
// 14 letters). Courier is overal 600.
var helvetica = [95]int{
	278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, // spatie tot /
	556, 556, 556, 556, 556, 556, 556, 556, 556, 556, // 0-9
	278, 278, 584, 584, 584, 556, 1015, // : tot @
	667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, // A-M
	722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, // N-Z
	278, 278, 278, 469, 556, 333, // [ tot `
	556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, // a-m
	556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, // n-z
	334, 260, 334, 584, // { tot ~
}

var helveticaVet = [95]int{
	278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
	556, 556, 556, 556, 556, 556, 556, 556, 556, 556,
	333, 333, 584, 584, 584, 611, 975,
	722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833,
	722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611,
	333, 278, 333, 584, 556, 333,
	556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889,
	611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500,
	389, 280, 389, 584,
}

// Tekens boven 127 die geen letter met accent zijn: [gewoon, vet].
var bijzonder = map[byte][2]int{
	0x80: {556, 556},                   // euro
	0x85: {1000, 1000},                 // beletselteken
	0x91: {222, 278}, 0x92: {222, 278}, // enkele aanhalingstekens
	0x93: {333, 500}, 0x94: {333, 500}, // dubbele aanhalingstekens
	0x95: {350, 350},                   // opsommingsteken
	0x96: {556, 556},                   // en-streepje
	0x97: {1000, 1000},                 // em-streepje
	0xa0: {278, 278},                   // vaste spatie
	0xa9: {737, 737},                   // copyright
	0xab: {556, 556}, 0xbb: {556, 556}, // guillemets
	0xb0: {400, 400}, // graden
	0xb7: {278, 278}, // middenpunt
	0xd7: {584, 584}, // maal
	0xdf: {611, 611}, // ringel-s
	0xe6: {889, 889}, // ae
}

func tekenBreedte(l Letter, c byte) int {
	if l == Mono {
		return 600
	}
	tabel := &helvetica
	vet := 0
	if l == Vet {
		tabel, vet = &helveticaVet, 1
	}
	switch {
	case c >= 32 && c <= 126:
		return tabel[c-32]
	case c < 32:
		return 0
	}
	if b, ok := bijzonder[c]; ok {
		return b[vet]
	}
	// Een letter met accent is even breed als de letter zonder.
	r := charmap.Windows1252.DecodeByte(c)
	if basis := []rune(norm.NFD.String(string(r))); len(basis) > 0 && basis[0] >= 32 && basis[0] <= 126 {
		return tabel[basis[0]-32]
	}
	return 556
}
