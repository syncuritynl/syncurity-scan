package keuring

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/miekg/dns"
)

// Feiten zijn dingen die we zagen, zonder oordeel. Ze maken het rapport
// herkenbaar ("ja, wij zitten bij Microsoft") en staan allemaal openbaar.

var mailLeveranciers = []struct{ achter, naam string }{
	{"mail.protection.outlook.com", "Microsoft 365"}, {"mx.microsoft", "Microsoft 365"},
	{"google.com", "Google Workspace"}, {"googlemail.com", "Google Workspace"},
	{"transip.email", "TransIP"}, {"transip.nl", "TransIP"}, {"zoho.eu", "Zoho Mail"}, {"zoho.com", "Zoho Mail"},
	{"protonmail.ch", "Proton Mail"}, {"messagingengine.com", "Fastmail"}, {"mijndomein.nl", "Mijndomein"},
	{"hostnet.nl", "Hostnet"}, {"versio.nl", "Versio"}, {"one.com", "one.com"}, {"strato.de", "Strato"},
	{"antagonist.nl", "Antagonist"}, {"mailprotect.be", "Combell"}, {"kpnmail.nl", "KPN"},
	{"mimecast.com", "Mimecast"}, {"pphosted.com", "Proofpoint"}, {"spamexperts.com", "SpamExperts"},
}

var dnsLeveranciers = []struct{ achter, naam string }{
	{"transip.net", "TransIP"}, {"transip.nl", "TransIP"}, {"transip.eu", "TransIP"},
	{"cloudflare.com", "Cloudflare"}, {"awsdns", "Amazon Route 53"}, {"azure-dns", "Microsoft Azure"},
	{"googledomains.com", "Google"}, {"google.com", "Google"}, {"versio.nl", "Versio"}, {"versio.eu", "Versio"},
	{"hostnet.nl", "Hostnet"}, {"mijndomein.nl", "Mijndomein"}, {"strato.de", "Strato"}, {"one.com", "one.com"},
	{"antagonist.nl", "Antagonist"}, {"openprovider", "Openprovider"}, {"domaincontrol.com", "GoDaddy"},
	{"vimexx.nl", "Vimexx"}, {"argewebhosting.nl", "Argeweb"}, {"yourhosting.nl", "Yourhosting"},
	{"hostinger", "Hostinger"}, {"wixdns.net", "Wix"}, {"squarespacedns.com", "Squarespace"},
}

var systemen = []struct {
	teken *regexp.Regexp
	naam  string
}{
	{regexp.MustCompile(`(?i)/wp-content/|/wp-includes/`), "WordPress"},
	{regexp.MustCompile(`(?i)cdn\.shopify\.com|Shopify\.theme`), "Shopify"},
	{regexp.MustCompile(`(?i)static\.wixstatic\.com|wix\.com`), "Wix"},
	{regexp.MustCompile(`(?i)squarespace\.com|static1\.squarespace`), "Squarespace"},
	{regexp.MustCompile(`(?i)webflow\.(com|io)`), "Webflow"},
	{regexp.MustCompile(`(?i)/media/jui/|joomla`), "Joomla"},
	{regexp.MustCompile(`(?i)/sites/default/files/|drupal`), "Drupal"},
	{regexp.MustCompile(`(?i)jimdo`), "Jimdo"},
	{regexp.MustCompile(`(?i)_next/static/`), "Next.js"},
}

func leverancier(namen []string, lijst []struct{ achter, naam string }) string {
	gezien := map[string]bool{}
	var uit []string
	for _, n := range namen {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		for _, l := range lijst {
			if strings.Contains(n, l.achter) && !gezien[l.naam] {
				gezien[l.naam] = true
				uit = append(uit, l.naam)
			}
		}
	}
	if len(uit) == 0 && len(namen) > 0 {
		// Onbekend: toon het domein van de eerste server.
		delen := strings.Split(strings.TrimSuffix(namen[0], "."), ".")
		if len(delen) >= 2 {
			return strings.Join(delen[len(delen)-2:], ".")
		}
	}
	return strings.Join(uit, " en ")
}

func (k *keurder) feiten(ctx context.Context, w *web) []Feit {
	var f []Feit
	mx, nullMX := k.r.MX(ctx, k.domein)
	switch {
	case len(mx) > 0:
		f = append(f, Feit{"E-mail", leverancier(mx, mailLeveranciers)})
	case nullMX:
		f = append(f, Feit{"E-mail", "ontvangt bewust geen mail"})
	default:
		f = append(f, Feit{"E-mail", "geen mailserver"})
	}
	rrs, _, _, _ := k.r.Records(ctx, k.domein, dns.TypeNS)
	var ns []string
	for _, rr := range rrs {
		ns = append(ns, rr.(*dns.NS).Ns)
	}
	if len(ns) > 0 {
		f = append(f, Feit{"DNS", leverancier(ns, dnsLeveranciers)})
	}
	if w.host == "" {
		f = append(f, Feit{"Website", "geen website gevonden"})
		return f
	}
	if s := w.kop("Server"); s != "" {
		// Alleen de naam, zonder versie: die hoort er niet in (zie versie()).
		f = append(f, Feit{"Webserver", strings.TrimSpace(cijfers.ReplaceAllString(strings.SplitN(s, "/", 2)[0], ""))})
	}
	for _, s := range systemen {
		if s.teken.Match(w.body) {
			f = append(f, Feit{"Gemaakt met", s.naam})
			break
		}
	}
	if w.staat != nil && len(w.staat.PeerCertificates) > 0 {
		f = append(f, Feit{"Certificaat", uitgever(w.staat.PeerCertificates[0])})
	}
	if c := cdn(w); c != "" {
		f = append(f, Feit{"CDN", c})
	}
	if w.staat != nil {
		f = append(f, Feit{"Kwantumveilig", jaNee(kwantumveilig(w.staat))})
	}
	if w.robotsOK {
		f = append(f, Feit{"AI-training", aiTraining(w.robots)})
	}
	if v := buitenEU(k.domein, w); v != "" {
		f = append(f, Feit{"Diensten buiten de EU", v})
	}
	return f
}

// cdn herkent een CDN aan zijn kopregels.
func cdn(w *web) string {
	for _, c := range []struct{ kop, naam string }{
		{"Cf-Ray", "Cloudflare"}, {"X-Amz-Cf-Id", "Amazon CloudFront"}, {"X-Azure-Ref", "Azure Front Door"},
		{"X-Fastly-Request-Id", "Fastly"}, {"X-Akamai-Transformed", "Akamai"}, {"X-Sucuri-Id", "Sucuri"}, {"X-Bunny-Cache", "Bunny"},
	} {
		if w.kop(c.kop) != "" {
			return c.naam
		}
	}
	if strings.Contains(strings.ToLower(w.kop("Server")), "cloudflare") {
		return "Cloudflare"
	}
	if strings.Contains(strings.ToLower(w.kop("Via")), "varnish") && w.kop("X-Served-By") != "" {
		return "Fastly"
	}
	return ""
}

// aiTraining: mogen de trainingscrawlers van AI-bedrijven je tekst ophalen?
// Geen oordeel: dat is een keuze van de eigenaar.
func aiTraining(robots string) string {
	dicht, totaal := 0, 0
	agents, _ := dichteCrawlers(robots)
	geblokt := map[string]bool{}
	for _, a := range agents {
		geblokt[a] = true
	}
	for _, c := range aiCrawlers {
		if c.zoek {
			continue
		}
		totaal++
		if geblokt[c.agent] {
			dicht++
		}
	}
	switch {
	case dicht == 0:
		return "toegestaan"
	case dicht == totaal:
		return "geweigerd"
	default:
		return fmt.Sprintf("deels geweigerd (%d van %d)", dicht, totaal)
	}
}

// Partijen buiten de EU die pagina's vaak inladen, herkend aan hun domein.
var buitenEUPartijen = []struct{ achter, naam string }{
	{"google", "Google"}, {"gstatic.com", "Google"}, {"doubleclick.net", "Google"}, {"youtube", "Google"}, {"ytimg.com", "Google"},
	{"facebook", "Meta"}, {"fbcdn.net", "Meta"}, {"instagram.com", "Meta"}, {"clarity.ms", "Microsoft"}, {"bing.com", "Microsoft"},
	{"licdn.com", "LinkedIn"}, {"linkedin.com", "LinkedIn"}, {"tiktok", "TikTok"}, {"twitter.com", "X"}, {"twimg.com", "X"},
	{"cloudflare", "Cloudflare"}, {"jsdelivr.net", "jsDelivr"}, {"unpkg.com", "unpkg"}, {"hubspot", "HubSpot"}, {"hs-scripts.com", "HubSpot"},
	{"vimeo", "Vimeo"}, {"fullstory.com", "FullStory"}, {"intercom", "Intercom"}, {"typekit.net", "Adobe"}, {"fontawesome.com", "Font Awesome"},
}

func buitenEU(domein string, w *web) string {
	gezien := map[string]bool{}
	var uit []string
	for _, b := range append(append([]string{}, w.info.bronnen...), w.info.x.iframes...) {
		u, err := url.Parse(strings.TrimSpace(b))
		if err != nil || u.Host == "" {
			continue
		}
		h := strings.ToLower(u.Hostname())
		if h == domein || strings.HasSuffix(h, "."+domein) {
			continue
		}
		for _, p := range buitenEUPartijen {
			if strings.Contains(h, p.achter) && !gezien[p.naam] {
				gezien[p.naam] = true
				uit = append(uit, p.naam)
			}
		}
	}
	return strings.Join(uit, ", ")
}
