package keuring

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Het eerste eigen stylesheet halen we op (GET, begrensd); zonder stylesheet
// blijft het bij de kop van het eerste eigen script. Altijd één verzoek.
func TestHaalStijl(t *testing.T) {
	groot := strings.Repeat("a{color:red}", maxStijl/12+10)
	var mu sync.Mutex
	var verzoeken []string
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		verzoeken = append(verzoeken, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Cache-Control", "max-age=31536000")
		switch r.URL.Path {
		case "/css/stijl.css":
			w.Header().Set("Content-Type", "text/css")
			_, _ = w.Write([]byte("body { margin: 0; }"))
		case "/css/groot.css":
			w.Header().Set("Content-Type", "text/css")
			_, _ = w.Write([]byte(groot))
		default:
			_, _ = w.Write([]byte("var x;"))
		}
	}))
	defer s.Close()
	k := &keurder{domein: "voorbeeld.nl", web: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", s.Listener.Addr().String())
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}}
	for _, tc := range []struct {
		naam, html, verzoek, stijl string
		af                         bool
	}{
		{"eigen stylesheet", `<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter"><link rel="stylesheet" href="/css/stijl.css"><script src="/a.js"></script>`,
			"GET /css/stijl.css", "body { margin: 0; }", false},
		{"alleen een script", `<script src="https://cdn.ander.nl/x.js"></script><script src="/js/a.js"></script>`, "HEAD /js/a.js", "", false},
		{"groot stylesheet", `<link rel="stylesheet" href="https://www.voorbeeld.nl/css/groot.css">`, "GET /css/groot.css", groot[:maxStijl], true},
	} {
		verzoeken = nil
		w := &web{host: "voorbeeld.nl"}
		w.info = ontleed([]byte("<html><head>" + tc.html + "</head><body></body></html>"))
		w.haalStijl(context.Background(), k, "https://voorbeeld.nl")
		if strings.Join(verzoeken, ", ") != tc.verzoek {
			t.Errorf("%s: verzoeken %v, verwacht %s", tc.naam, verzoeken, tc.verzoek)
		}
		if w.stijl != tc.stijl || w.stijlAf != tc.af || w.cache != "max-age=31536000" || !strings.HasSuffix(tc.verzoek, w.cacheURL) {
			t.Errorf("%s: stijl %d tekens (af %v), cache %q op %q", tc.naam, len(w.stijl), w.stijlAf, w.cache, w.cacheURL)
		}
	}
}
