package download

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func newClient(srv *httptest.Server, opts ...Option) *Client {
	return New("cerberus-test", append([]Option{WithHTTPClient(srv.Client())}, opts...)...)
}

func TestRetriesTransientErrors(t *testing.T) {
	var calls int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path == "/flaky" && calls < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/down" {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Length", "4321")
	}))
	defer srv.Close()
	c := newClient(srv)
	c.retryWaits = []time.Duration{time.Millisecond, time.Millisecond}
	if n, err := c.Size(context.Background(), srv.URL+"/flaky"); err != nil || n != 4321 {
		t.Fatalf("two 503s then 200: Size = %d, %v; want 4321 after retries", n, err)
	}
	calls = 0
	if _, err := c.Size(context.Background(), srv.URL+"/down"); err == nil || !strings.Contains(err.Error(), "502") || calls != 3 {
		t.Fatalf("persistent 502: err %v after %d calls, want a 502 error after 3", err, calls)
	}
}

func TestRedirects(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/plain":
			http.Redirect(w, r, "http://"+r.Host+"/doc", http.StatusFound)
		case r.URL.Path == "/hop":
			http.Redirect(w, r, "/doc", http.StatusFound)
		case strings.HasPrefix(r.URL.Path, "/loop/"):
			n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/loop/"))
			http.Redirect(w, r, fmt.Sprintf("/loop/%d", n+1), http.StatusFound)
		default:
			fmt.Fprint(w, "ok")
		}
	}))
	defer srv.Close()
	c := newClient(srv)
	for _, tc := range []struct {
		name, url, wantErr string
	}{
		{"https to http refused", srv.URL + "/plain", "non-https"},
		{"too many redirects", srv.URL + "/loop/0", "10 redirects"},
		{"http first url refused", strings.Replace(srv.URL, "https", "http", 1) + "/doc", "non-https"},
		{"https redirect followed", srv.URL + "/hop", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := c.Get(context.Background(), tc.url)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || string(d.Body) != "ok" || d.FinalURL != srv.URL+"/doc" {
				t.Fatalf("got %+v, %v", d, err)
			}
		})
	}
}

func TestWithHTTPClientLeavesOriginal(t *testing.T) {
	hc := &http.Client{}
	New("ua", WithHTTPClient(hc))
	if hc.CheckRedirect != nil {
		t.Fatal("WithHTTPClient modified the caller's client")
	}
}

func TestGet(t *testing.T) {
	var gotUA, gotAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA, gotAuth = r.Header.Get("User-Agent"), r.Header.Get("Authorization")
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
		w.Write(bytes.Repeat([]byte("x"), n))
	}))
	defer srv.Close()
	c := newClient(srv, WithMaxDocBytes(10), WithGitHubToken("secret"))
	ctx := context.Background()

	if d, err := c.Get(ctx, srv.URL+"/10"); err != nil || len(d.Body) != 10 || d.Status != 200 {
		t.Fatalf("at cap: %+v, %v", d, err)
	}
	if gotUA != "cerberus-test" || gotAuth != "" {
		t.Fatalf("User-Agent %q, Authorization %q", gotUA, gotAuth)
	}
	if _, err := c.Get(ctx, srv.URL+"/11"); err == nil || !strings.Contains(err.Error(), "exceeds 10 bytes") {
		t.Fatalf("over cap: %v", err)
	}
	_, err := c.Get(ctx, srv.URL+"/missing")
	if err == nil || !strings.Contains(err.Error(), "404") || !strings.Contains(err.Error(), srv.URL+"/missing") {
		t.Fatalf("404: %v", err)
	}
}

func TestAuthorization(t *testing.T) {
	for _, tc := range []struct {
		url, token, want string
	}{
		{"https://api.github.com/repos/x/y/releases", "tok", "Bearer tok"},
		{"https://api.github.com/repos/x/y/releases", "", ""},
		{"https://github.com/x/y/releases", "tok", ""},
		{"https://objects.githubusercontent.com/x", "tok", ""},
		{"https://api.github.com.evil.example/x", "tok", ""},
		{"https://api.github.com:8443/x", "tok", ""},
	} {
		u, _ := url.Parse(tc.url)
		if got := authorization(u, tc.token); got != tc.want {
			t.Errorf("authorization(%s, %q) = %q, want %q", tc.url, tc.token, got, tc.want)
		}
	}

	// A redirect away from api.github.com drops the token net/http copied.
	req, _ := http.NewRequest(http.MethodGet, "https://objects.githubusercontent.com/x", nil)
	req.Header.Set("Authorization", "Bearer tok")
	if err := checkRedirect(req, make([]*http.Request, 1)); err != nil || req.Header.Get("Authorization") != "" {
		t.Fatalf("checkRedirect = %v, Authorization %q", err, req.Header.Get("Authorization"))
	}
}

// rangedOnlyServer refuses HEAD with 405 and answers a ranged GET with 206.
func rangedOnlyServer(t *testing.T, gotRange *string) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		*gotRange = r.Header.Get("Range")
		w.Header().Set("Content-Range", "bytes 0-0/12345")
		w.WriteHeader(http.StatusPartialContent)
		w.Write([]byte("x"))
	}))
}

func TestHeadFallback(t *testing.T) {
	var gotRange string
	srv := rangedOnlyServer(t, &gotRange)
	defer srv.Close()
	d, err := newClient(srv).Head(context.Background(), srv.URL+"/x.iso")
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != http.StatusPartialContent || d.Body != nil || gotRange != "bytes=0-0" || d.Header.Get("Content-Range") != "bytes 0-0/12345" {
		t.Fatalf("got %+v, Range %q", d, gotRange)
	}
}

func TestSize(t *testing.T) {
	var gotRange string
	ranged := rangedOnlyServer(t, &gotRange)
	defer ranged.Close()
	plain := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", "1234")
	}))
	defer plain.Close()
	for _, tc := range []struct {
		name string
		srv  *httptest.Server
		path string
		want int64
	}{
		{"content-length", plain, "/x.iso", 1234},
		{"content-range", ranged, "/x.iso", 12345},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := newClient(tc.srv).Size(context.Background(), tc.srv.URL+tc.path)
			if err != nil || got != tc.want {
				t.Fatalf("Size = %d, %v; want %d", got, err, tc.want)
			}
		})
	}
	// A missing ISO is an error, never "size unknown", so catalog check
	// catches a broken download URL.
	if _, err := newClient(plain).Size(context.Background(), plain.URL+"/missing"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("Size of a missing file = %v, want a 404 error", err)
	}
}

func TestParseContentRange(t *testing.T) {
	for _, tc := range []struct {
		in           string
		start, total int64
		ok           bool
	}{
		{"bytes 0-0/12345", 0, 12345, true},
		{"bytes 100-199/200", 100, 200, true},
		{"bytes 5-9/*", 5, -1, true},
		{"bytes */200", 0, 0, false},
		{"items 0-1/2", 0, 0, false},
		{"", 0, 0, false},
	} {
		start, total, ok := parseContentRange(tc.in)
		if start != tc.start || total != tc.total || ok != tc.ok {
			t.Errorf("parseContentRange(%q) = %d, %d, %v", tc.in, start, total, ok)
		}
	}
}

// isoServer serves content with an ETag through http.ServeContent, which
// honors Range and If-Range. With cut > 0 the next reply declares the full
// length but stops after cut bytes.
type isoServer struct {
	mu      sync.Mutex
	content []byte
	etag    string
	cut     int
	stall   bool
	reqs    []http.Header
}

func (s *isoServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	content, etag, cut, stall := s.content, s.etag, s.cut, s.stall
	s.cut = 0
	s.reqs = append(s.reqs, r.Header.Clone())
	s.mu.Unlock()
	w.Header().Set("ETag", etag)
	switch {
	case stall:
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		w.Write(content[:100])
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	case cut > 0:
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		w.Write(content[:cut])
	default:
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(content))
	}
}

func (s *isoServer) set(f func(*isoServer)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

func (s *isoServer) lastReq() http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reqs[len(s.reqs)-1]
}

func randomBytes(n int, seed uint64) []byte {
	r := rand.New(rand.NewPCG(seed, seed))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

// progressCheck records progress calls and fails on any decrease.
type progressCheck struct {
	t     *testing.T
	last  int64
	total int64
	calls int
}

func (p *progressCheck) fn(done, total int64) {
	if done <= p.last && p.calls > 0 {
		p.t.Errorf("progress went from %d to %d", p.last, done)
	}
	p.last, p.total = done, total
	p.calls++
}

func fileIs(t *testing.T, p string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: %d bytes, want %d matching bytes", p, len(got), len(want))
	}
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func TestFetchFresh(t *testing.T) {
	content := randomBytes(1<<20+17, 1)
	is := &isoServer{content: content, etag: `"v1"`}
	srv := httptest.NewTLSServer(is)
	defer srv.Close()
	part := filepath.Join(t.TempDir(), "x.iso.part")
	metaSeen := false
	p := &progressCheck{t: t}
	res, err := newClient(srv).Fetch(context.Background(), srv.URL+"/x.iso", part, func(done, total int64) {
		if !metaSeen {
			metaSeen = exists(part + ".meta")
		}
		p.fn(done, total)
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Bytes != int64(len(content)) || res.Resumed {
		t.Fatalf("result %+v", res)
	}
	fileIs(t, part, content)
	if !metaSeen || exists(part+".meta") {
		t.Fatalf("meta seen during transfer %v, still there after %v", metaSeen, exists(part+".meta"))
	}
	if p.last != int64(len(content)) || p.total != int64(len(content)) {
		t.Fatalf("final progress %d/%d", p.last, p.total)
	}
	if h := is.lastReq(); h.Get("Range") != "" || h.Get("User-Agent") != "cerberus-test" {
		t.Fatalf("request headers %v", h)
	}
}

func TestFetchResume(t *testing.T) {
	content := randomBytes(1<<20, 2)
	changed := randomBytes(1<<20+5, 3)
	for _, tc := range []struct {
		name        string
		newContent  []byte
		newETag     string
		wantResumed bool
	}{
		{"matching etag appends", content, `"v1"`, true},
		{"changed etag restarts", changed, `"v2"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			is := &isoServer{content: content, etag: `"v1"`, cut: 300_000}
			srv := httptest.NewTLSServer(is)
			defer srv.Close()
			c := newClient(srv)
			part := filepath.Join(t.TempDir(), "x.iso.part")
			u := srv.URL + "/x.iso"

			if _, err := c.Fetch(context.Background(), u, part, nil); err == nil {
				t.Fatal("cut-off transfer succeeded")
			}
			fileIs(t, part, content[:300_000])
			if !exists(part + ".meta") {
				t.Fatal("meta missing after cut-off")
			}

			is.set(func(s *isoServer) { s.content, s.etag = tc.newContent, tc.newETag })
			p := &progressCheck{t: t}
			res, err := c.Fetch(context.Background(), u, part, p.fn)
			if err != nil {
				t.Fatal(err)
			}
			h := is.lastReq()
			if h.Get("Range") != "bytes=300000-" || h.Get("If-Range") != `"v1"` {
				t.Fatalf("resume headers Range %q If-Range %q", h.Get("Range"), h.Get("If-Range"))
			}
			if res.Resumed != tc.wantResumed || res.Bytes != int64(len(tc.newContent)) {
				t.Fatalf("result %+v", res)
			}
			fileIs(t, part, tc.newContent)
			if exists(part + ".meta") {
				t.Fatal("meta left after success")
			}
			if p.last != int64(len(tc.newContent)) {
				t.Fatalf("final progress %d", p.last)
			}
		})
	}
}

func TestFetchLastModifiedValidator(t *testing.T) {
	is := &isoServer{content: []byte("hello"), etag: `"v1"`}
	srv := httptest.NewTLSServer(is)
	defer srv.Close()
	part := filepath.Join(t.TempDir(), "x.iso.part")
	os.WriteFile(part, []byte("he"), 0o644)
	os.WriteFile(part+".meta", []byte(`{"url":"`+srv.URL+`/x.iso","last_modified":"Mon, 02 Jan 2006 15:04:05 GMT","total":5}`), 0o644)
	if _, err := newClient(srv).Fetch(context.Background(), srv.URL+"/x.iso", part, nil); err != nil {
		t.Fatal(err)
	}
	if h := is.lastReq(); h.Get("If-Range") != "Mon, 02 Jan 2006 15:04:05 GMT" || h.Get("Range") != "bytes=2-" {
		t.Fatalf("headers %v", h)
	}
	fileIs(t, part, []byte("hello"))
}

func TestFetch416(t *testing.T) {
	content := []byte("complete iso")
	for _, tc := range []struct {
		name    string
		part    []byte
		total   int
		wantErr bool
	}{
		{"part is complete", content, len(content), false},
		{"part longer than recorded total", append(content, '!'), len(content), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			is := &isoServer{content: content, etag: `"v1"`}
			srv := httptest.NewTLSServer(is)
			defer srv.Close()
			part := filepath.Join(t.TempDir(), "x.iso.part")
			u := srv.URL + "/x.iso"
			os.WriteFile(part, tc.part, 0o644)
			os.WriteFile(part+".meta", []byte(fmt.Sprintf(`{"url":%q,"etag":"\"v1\"","total":%d}`, u, tc.total)), 0o644)
			res, err := newClient(srv).Fetch(context.Background(), u, part, nil)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "416") {
					t.Fatalf("error = %v, want 416", err)
				}
			} else if err != nil || res.Bytes != int64(len(content)) || !res.Resumed {
				t.Fatalf("got %+v, %v", res, err)
			}
			if exists(part + ".meta") {
				t.Fatal("meta left; the next attempt would repeat the 416")
			}
		})
	}
}

func TestFetchWithoutMetaStartsOver(t *testing.T) {
	is := &isoServer{content: []byte("fresh content"), etag: `"v1"`}
	srv := httptest.NewTLSServer(is)
	defer srv.Close()
	part := filepath.Join(t.TempDir(), "x.iso.part")
	os.WriteFile(part, []byte("stale bytes from elsewhere, longer"), 0o644)
	res, err := newClient(srv).Fetch(context.Background(), srv.URL+"/x.iso", part, nil)
	if err != nil || res.Resumed {
		t.Fatalf("got %+v, %v", res, err)
	}
	if is.lastReq().Get("Range") != "" {
		t.Fatal("sent Range without a meta record")
	}
	fileIs(t, part, []byte("fresh content"))
}

func TestFetchStall(t *testing.T) {
	is := &isoServer{content: randomBytes(4096, 4), etag: `"v1"`, stall: true}
	srv := httptest.NewTLSServer(is)
	defer srv.Close()
	part := filepath.Join(t.TempDir(), "x.iso.part")
	start := time.Now()
	_, err := newClient(srv, WithStallTimeout(200*time.Millisecond)).Fetch(context.Background(), srv.URL+"/x.iso", part, nil)
	if err == nil || !strings.Contains(err.Error(), "stalled") {
		t.Fatalf("error = %v, want stalled", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("stall detection took %v", time.Since(start))
	}
	fileIs(t, part, is.content[:100])
	if !exists(part + ".meta") {
		t.Fatal("meta removed after stall")
	}
}

func TestNoSpace(t *testing.T) {
	enospc := &os.PathError{Op: "write", Path: "/srv/isos/x.iso.part", Err: syscall.ENOSPC}
	err := noSpace(enospc)
	if !errors.Is(err, ErrNoSpace) || !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("noSpace(ENOSPC) = %v", err)
	}
	if err := noSpace(&os.PathError{Op: "write", Path: "x", Err: syscall.EIO}); errors.Is(err, ErrNoSpace) {
		t.Fatalf("noSpace(EIO) = %v", err)
	}
}

func TestReserve(t *testing.T) {
	for _, tc := range []struct {
		total     uint64
		pct       float64
		min, want uint64
	}{
		{1000, 10, 0, 100},
		{1000, 10, 500, 500},
		{1000, 0, 0, 0},
		{200e9, 10, 10e9, 20e9},
		{50e9, 10, 10e9, 10e9},
	} {
		if got := Reserve(tc.total, tc.pct, tc.min); got != tc.want {
			t.Errorf("Reserve(%d, %v, %d) = %d, want %d", tc.total, tc.pct, tc.min, got, tc.want)
		}
	}
}

func TestCheckSpace(t *testing.T) {
	dir := t.TempDir()
	avail, total, err := FreeSpace(dir)
	if err != nil || total == 0 || avail > total {
		t.Fatalf("FreeSpace = %d, %d, %v", avail, total, err)
	}
	if err := CheckSpace(dir, 0, 0, 0); err != nil {
		t.Fatalf("need 0: %v", err)
	}
	err = CheckSpace(dir, 1<<62, 0, 0)
	if !errors.Is(err, ErrNoSpace) || !strings.Contains(err.Error(), "need 4611.7 PB") {
		t.Fatalf("huge need: %v", err)
	}
	// Unknown size counts as 0, but the reserve still applies.
	if err := CheckSpace(dir, -1, 0, 0); err != nil {
		t.Fatalf("need -1: %v", err)
	}
	if err := CheckSpace(dir, -1, 0, total+1); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("need -1 with a reserve over the disk: %v", err)
	}
	if err := CheckSpace(filepath.Join(dir, "missing"), 0, 0, 0); err == nil {
		t.Fatal("missing dir passed")
	}
}

func TestHuman(t *testing.T) {
	for n, want := range map[uint64]string{
		0:       "0 B",
		999:     "999 B",
		1500:    "1.5 kB",
		12e9:    "12.0 GB",
		3.2e12:  "3.2 TB",
		4.6e18:  "4600.0 PB",
		1 << 20: "1.0 MB",
	} {
		if got := human(n); got != want {
			t.Errorf("human(%d) = %q, want %q", n, got, want)
		}
	}
}
