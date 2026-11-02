package keuring

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Vier punten over TLS 1.2 die internet.nl en SSL Labs ook meten, met de
// eigen proef uit tlsproef.go: hooguit drie verbindingen.

// oudeTLS is wat de proeven zagen.
type oudeTLS struct {
	fout     error // de eerste proef lukte niet: alles niet te meten
	alleen13 bool  // de server weigert TLS 1.2
	zwakVoor uint16
	opties   proefAntwoord // compressie, heronderhandeling en de volgorde
	dh       proefAntwoord
	dhFout   error
	hash     proefAntwoord
	hashFout error
}

// sterkeSuites: ECDHE met GCM of ChaCha20, zoals een moderne browser.
var sterkeSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

const alleen13Tekst = "Je website gebruikt alleen TLS 1.3; daar bestaan deze oude opties niet meer."

// meetOudeTLS doet de proeven. De eerste biedt sterke suites aan (met de
// verouderde suite die de server accepteert vooraan, voor de volgorde),
// compressie en renegotiation_info; weigert de server die terwijl hij TLS
// 1.3 spreekt, dan doet hij geen TLS 1.2 en stoppen we. Daarna één proef met
// alleen DHE en één met ECDHE en alleen SHA-1-handtekeningen.
func meetOudeTLS(dial func() (net.Conn, error), naam string, versie, zwak uint16, timeout time.Duration) oudeTLS {
	proef := func(h proefHello) (proefAntwoord, error) {
		c, err := dial()
		if err != nil {
			return proefAntwoord{}, err
		}
		defer c.Close()
		h.naam = naam
		return tlsProef(c, h, timeout)
	}
	o := oudeTLS{zwakVoor: zwak}
	suites := append(append([]uint16{}, sterkeSuites...), verouderd...)
	if zwak != 0 {
		suites = append([]uint16{zwak}, suites...)
	}
	o.opties, o.fout = proef(proefHello{suites: suites, compressie: []byte{1, 0}})
	switch {
	case o.fout != nil:
		return o
	case o.opties.tls13 || (o.opties.geweigerd && o.opties.versie == 0 && versie >= tls.VersionTLS13):
		o.alleen13 = true
		return o
	case o.opties.geweigerd:
		o.fout = fmt.Errorf("de server weigerde de proef (alert %d)", o.opties.alert)
		return o
	}
	// De andere twee tegelijk, zodat een trage server niet twee keer telt.
	ecdhe := append(append([]uint16{}, sterkeSuites...), tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
	var wg sync.WaitGroup
	wg.Go(func() { o.dh, o.dhFout = proef(proefHello{suites: dheSuites}) })
	wg.Go(func() { o.hash, o.hashFout = proef(proefHello{suites: ecdhe, handtekening: sha1Handtekeningen}) })
	wg.Wait()
	return o
}

func (k *keurder) oudeTLS(ctx context.Context, w *web) oudeTLS {
	dial := func() (net.Conn, error) { return k.kiezer.DialContext(ctx, "tcp", net.JoinHostPort(w.host, "443")) }
	return meetOudeTLS(dial, w.host, w.staat.Version, w.verouderID, k.timeout)
}

// nietTeMeten: de gezamenlijke uitkomst als de proef niet lukte of de server
// alleen TLS 1.3 doet. ok is false als het punt zelf moet oordelen.
func (o oudeTLS) nietTeMeten(id, tech, titel string) (Punt, bool) {
	switch {
	case o.alleen13:
		return punt(id, tech, Goed, titel, alleen13Tekst).met("Alleen TLS 1.3"), true
	case o.fout != nil:
		return punt(id, tech, Fout, titel, "We konden dit niet meten: de server gaf geen bruikbaar antwoord op onze proef.").metDetail("Proef: " + o.fout.Error()), true
	}
	return Punt{}, false
}

func tlsDH(o oudeTLS) Punt {
	const id, tech, titel = "tls-dh", "DHE", "Sterke sleuteluitwisseling"
	if p, klaar := o.nietTeMeten(id, tech, titel); klaar {
		return p
	}
	d := o.dh
	switch {
	case o.dhFout != nil || (!d.geweigerd && !d.sleutel) || (d.geweigerd && isDHE(d.suite)):
		return punt(id, tech, Fout, titel, "We konden niet meten of je server ouderwetse sleuteluitwisseling (DHE) aanbiedt.").metDetail("Proef: " + fmt.Sprint(leegFout(o.dhFout)))
	case d.geweigerd:
		return punt(id, tech, Goed, titel,
			"Je website gebruikt geen ouderwetse sleuteluitwisseling met DH (DHE), maar de snellere en sterkere ECDHE.").met("DHE niet aangeboden")
	}
	gezien := fmt.Sprintf("DHE met %d bits", d.dhBits)
	if d.dhGroep != "" {
		gezien += " (" + d.dhGroep + ")"
	}
	detail := []string{"Gekozen: " + suiteNaam(d.suite), fmt.Sprintf("Lengte van de DH-priem (p): %d bits", d.dhBits), "Handtekening: " + handtekeningNaam(d.handtekening)}
	if d.dhBits < 2048 {
		return punt(id, tech, Slecht, "Zwakke sleuteluitwisseling",
			fmt.Sprintf("Je website gebruikt nog sleuteluitwisseling met DH van maar %d bits. Die is met genoeg rekenkracht te kraken (de Logjam-aanval), zodat iemand versleuteld verkeer kan meelezen.", d.dhBits)).
			met(gezien).metDetail(detail...)
	}
	return punt(id, tech, Matig, "Sleuteluitwisseling met DH is uit te faseren",
		"Je website accepteert nog sleuteluitwisseling met DH (DHE). Die is nog niet gekraakt, maar internet.nl en het NCSC noemen hem uit te faseren, en 2048 bits als onvoldoende. ECDHE is sneller en sterker.").
		met(gezien).metDetail(detail...)
}

func tlsVolgorde(o oudeTLS) Punt {
	const id, tech, titel = "tls-volgorde", "cipher order", "Server kiest de sterkste versleuteling"
	if p, klaar := o.nietTeMeten(id, tech, titel); klaar {
		return p
	}
	gekozen := suiteNaam(o.opties.suite)
	switch {
	case o.zwakVoor == 0:
		return punt(id, tech, Goed, titel, "Je website accepteert alleen sterke versleuteling, dus er valt niets te kiezen.").met("Gekozen: " + gekozen)
	case o.opties.suite == o.zwakVoor:
		return punt(id, tech, Matig, "De bezoeker kiest de versleuteling",
			"Je website accepteert naast sterke ook verouderde versleuteling, en laat de bezoeker kiezen. Biedt een oud of slecht ingesteld programma de zwakkere als eerste aan, dan neemt je server die. Een goed ingestelde server kiest zelf de sterkste.").
			met("Gekozen: " + gekozen + ", die we als eerste aanboden").metDetail("We boden eerst " + gekozen + " aan, en daarna sterke suites met ECDHE en GCM.")
	default:
		return punt(id, tech, Goed, titel, "Ook als een bezoeker eerst een zwakkere versleuteling aanbiedt, kiest je server de sterkste.").met("Gekozen: " + gekozen)
	}
}

func tlsOpties(o oudeTLS) Punt {
	const id, tech, titel = "tls-opties", "compressie · heronderhandeling", "Geen oude TLS-opties"
	if p, klaar := o.nietTeMeten(id, tech, titel); klaar {
		return p
	}
	compressie := o.opties.compressie != 0
	gezien := fmt.Sprintf("Compressie: %s · veilige heronderhandeling: %s", map[bool]string{true: "aan", false: "uit"}[compressie], map[bool]string{true: "ja", false: "nee"}[o.opties.heronder])
	switch {
	case compressie && !o.opties.heronder:
		return punt(id, tech, Slecht, "Twee oude, onveilige TLS-opties",
			"Je server zet compressie aan op de versleutelde verbinding (de CRIME-aanval), en kent de veilige manier van heronderhandelen niet. Daarmee kan een aanvaller stukjes van de verbinding raden of eigen verzoeken naar binnen smokkelen.").met(gezien)
	case compressie:
		return punt(id, tech, Slecht, "Compressie op de versleutelde verbinding",
			"Je server zet compressie aan op de versleutelde verbinding. Daarmee kan een aanvaller stukjes ervan raden, zoals een inlogcookie (de CRIME-aanval).").met(gezien)
	case !o.opties.heronder:
		return punt(id, tech, Slecht, "Onveilige heronderhandeling",
			"Je server kent de veilige manier van heronderhandelen niet (RFC 5746). Daardoor kan een aanvaller die tussen een bezoeker en je site zit, eigen verzoeken naar binnen smokkelen.").met(gezien)
	}
	return punt(id, tech, Goed, titel, "Je server zet geen compressie aan en kent alleen de veilige manier van heronderhandelen.").met(gezien)
}

func tlsHash(o oudeTLS) Punt {
	const id, tech, titel = "tls-hash", "SHA-1 · SHA-2", "Moderne handtekening bij de sleuteluitwisseling"
	if p, klaar := o.nietTeMeten(id, tech, titel); klaar {
		return p
	}
	h := o.hash
	switch {
	case o.hashFout != nil || (!h.geweigerd && !h.sleutel):
		return punt(id, tech, Fout, titel, "We konden de handtekening bij de sleuteluitwisseling niet meten.").metDetail("Proef: " + fmt.Sprint(leegFout(o.hashFout)))
	case h.geweigerd:
		return punt(id, tech, Goed, titel, "Je server weigert een handtekening met SHA-1 bij de sleuteluitwisseling en gebruikt dus SHA-2.").met("SHA-1 geweigerd")
	case sha1Handtekening(h.handtekening):
		return punt(id, tech, Matig, "Handtekening met SHA-1 bij de sleuteluitwisseling",
			"Vraagt een bezoeker erom, dan zet je server nog een handtekening met SHA-1 onder de sleuteluitwisseling. SHA-1 is verouderd en internet.nl noemt dit onvoldoende. Dit stelt meestal je hostingpartij of de software van je webserver in.").
			met("Handtekening: " + handtekeningNaam(h.handtekening)).metDetail("Op een proef met alleen SHA-1 (rsa_pkcs1_sha1, ecdsa_sha1) ondertekende de server met " + handtekeningNaam(h.handtekening) + ".")
	default:
		return punt(id, tech, Goed, titel, "Je server gebruikt bij de sleuteluitwisseling SHA-2, ook als een bezoeker om SHA-1 vraagt.").met("Handtekening: " + handtekeningNaam(h.handtekening))
	}
}

// leegFout: een fout, of een uitleg als er geen was.
func leegFout(err error) error {
	if err == nil {
		return errors.New("geen sleuteluitwisseling in het antwoord")
	}
	return err
}
