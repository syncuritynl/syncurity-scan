// keur: de domeinkeuring vanaf de opdrachtregel, om te testen en voor de
// handmatige pilot. Gebruik: keur [-json] [-vol] [-resolver 1.1.1.1:53] domein
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"syncurity.nl/keuring/keuring"
)

func main() {
	alsJSON := flag.Bool("json", false, "uitslag als JSON")
	vol := flag.Bool("vol", false, "het volledige rapport: details, oplossingen en subdomeinen (alleen voor je eigen domein)")
	resolver := flag.String("resolver", "1.1.1.1:53,9.9.9.9:53", "validerende resolvers, komma-gescheiden")
	ehlo := flag.String("ehlo", "", "naam bij EHLO voor de STARTTLS-meting van mailservers (leeg: niet meten)")
	data := flag.String("data", "", "map met rpki.txt.gz en hsts.txt.gz (leeg: die punten zijn niet te meten)")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "gebruik: keur [-json] [-vol] [-resolver host:poort] [-data map] [-ehlo naam] domein")
		os.Exit(2)
	}
	in := keuring.Standaard
	in.Resolvers = strings.Split(*resolver, ",")
	if *data != "" {
		in.Lijsten = keuring.NieuweLijsten(*data)
	}
	in.EHLO = *ehlo

	var (
		u   *keuring.Uitslag
		v   *keuring.Volledig
		err error
	)
	if *vol {
		v, err = keuring.KeurVolledig(context.Background(), flag.Arg(0), in)
		if v != nil {
			u = &v.Uitslag
		}
	} else {
		u, err = keuring.Keur(context.Background(), flag.Arg(0), in)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	teken := map[keuring.Status]string{keuring.Goed: "✓", keuring.Matig: "~", keuring.Slecht: "✕", keuring.NVT: "·", keuring.Fout: "?"}
	if *alsJSON {
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		if v != nil {
			_ = e.Encode(v)
		} else {
			_ = e.Encode(u)
		}
		return
	}
	fmt.Printf("%s: %d van %d in orde (%.1fs)\n", keuring.Weergave(u.Domein), u.InOrde, u.Totaal, u.Duur.Seconds())
	if u.Melding != "" {
		fmt.Println("  ! " + u.Melding)
	}
	for _, f := range u.Feiten {
		fmt.Printf("  %-12s %s\n", f.Naam, f.Waarde)
	}
	if len(u.Eerst) > 0 {
		fmt.Println("\nEerst aanpakken")
		for _, p := range u.Eerst {
			fmt.Printf("  %s %s\n", teken[p.Status], p.Titel)
		}
	}
	for _, g := range u.Groepen {
		a, b := g.Telling()
		fmt.Printf("\n%s  %d/%d  %s\n", g.Naam, a, b, g.Samen)
		for _, p := range g.Punten {
			fmt.Printf("  %s %-52s %s\n", teken[p.Status], p.Titel, p.Oordeel)
			fmt.Printf("      %s\n", p.Uitleg)
			if p.Gezien != "" {
				fmt.Printf("      gezien: %s\n", p.Gezien)
			}
			for _, d := range p.Detail {
				fmt.Printf("      > %s\n", d)
			}
			if o := p.Oplossing; o != nil {
				fmt.Printf("      oplossing (%s):\n", o.Wie)
				for i, s := range o.Stappen {
					fmt.Printf("        %d. %s\n", i+1, s)
				}
				if o.Voorstel != "" {
					fmt.Printf("        voorstel voor %s:\n", o.Naam)
					for _, r := range strings.Split(o.Voorstel, "\n") {
						fmt.Printf("          | %s\n", r)
					}
				}
				if o.Toelichting != "" {
					fmt.Printf("        (%s)\n", o.Toelichting)
				}
			}
		}
	}
	if v == nil {
		return
	}
	fmt.Printf("\nSubdomeinen (%s): %d\n", leegAls(v.SubBron, "geen bron"), len(v.Subdomeinen))
	if v.SubMelding != "" {
		fmt.Println("  ! " + v.SubMelding)
	}
	for _, s := range v.Subdomeinen {
		fmt.Printf("  %s %-40s %s", teken[s.Status], s.Naam, s.Oordeel)
		if s.CNAME != "" {
			fmt.Printf("  → %s", s.CNAME)
		}
		if s.HTTPS != "" {
			fmt.Printf("  [https: %s]", s.HTTPS)
		}
		fmt.Println()
		if s.Status == keuring.Slecht || s.Status == keuring.Matig {
			fmt.Printf("      %s\n", s.Uitleg)
		}
	}
}

func leegAls(s, anders string) string {
	if s == "" {
		return anders
	}
	return s
}
