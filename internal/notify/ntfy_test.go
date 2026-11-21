package notify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

type hit struct {
	path, body string
	h          http.Header
}

func setup(t *testing.T, status int) (*Ntfy, *[]hit, string) {
	t.Helper()
	var hits []hit
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		hits = append(hits, hit{r.URL.Path, string(b), r.Header.Clone()})
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	file := filepath.Join(t.TempDir(), "topic")
	if err := os.WriteFile(file, []byte(" secret-topic_1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Ntfy{Server: srv.URL + "/", TopicFile: file, Client: srv.Client()}, &hits, file
}

func TestSend(t *testing.T) {
	n, hits, file := setup(t, 200)
	err := n.Send(context.Background(), Message{Title: "Synced", Body: "1 updated", Tags: []string{"a", "b"}, Priority: 4})
	if err != nil {
		t.Fatal(err)
	}
	h := (*hits)[0]
	if h.path != "/secret-topic_1" || h.body != "1 updated" {
		t.Errorf("got path %q body %q", h.path, h.body)
	}
	if h.h.Get("Title") != "Synced" || h.h.Get("Tags") != "a,b" || h.h.Get("Priority") != "4" {
		t.Errorf("headers: %v", h.h)
	}
	// Zero priority and no tags send no such headers.
	if err := n.Send(context.Background(), Message{Body: "x"}); err != nil {
		t.Fatal(err)
	}
	if h := (*hits)[1]; h.h.Get("Priority") != "" || h.h.Get("Tags") != "" {
		t.Errorf("unexpected headers: %v", h.h)
	}
	// The topic is read at send time.
	if err := os.WriteFile(file, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := n.Send(context.Background(), Message{Body: "y"}); err != nil {
		t.Fatal(err)
	}
	if got := (*hits)[2].path; got != "/other" {
		t.Errorf("second topic: got %q", got)
	}
}

func TestSendRejectsInvalidTopic(t *testing.T) {
	for _, topic := range []string{"", "has space", "bad/slash", "bad?q=1", strings.Repeat("a", 65), "ünï"} {
		n, hits, file := setup(t, 200)
		os.WriteFile(file, []byte(topic), 0o600)
		err := n.Send(context.Background(), Message{Body: "x"})
		if err == nil {
			t.Errorf("topic %q: want error", topic)
			continue
		}
		if topic != "" && strings.Contains(err.Error(), topic) {
			t.Errorf("topic %q leaked: %v", topic, err)
		}
		if len(*hits) != 0 {
			t.Errorf("topic %q: request was sent", topic)
		}
	}
}

func TestSendErrorsDoNotLeakTopic(t *testing.T) {
	n, _, _ := setup(t, 500)
	err := n.Send(context.Background(), Message{Body: "x"})
	if err == nil || !strings.Contains(err.Error(), "status 500") || !strings.Contains(err.Error(), n.Server[:len(n.Server)-1]) {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "secret-topic_1") {
		t.Errorf("leaked: %v", err)
	}

	// A transport failure wraps *url.Error, which carries the URL.
	n, _, _ = setup(t, 200)
	n.Client = &http.Client{} // does not trust the test server's certificate
	err = n.Send(context.Background(), Message{Body: "x"})
	if err == nil {
		t.Fatal("want TLS error")
	}
	if strings.Contains(err.Error(), "secret-topic_1") {
		t.Errorf("leaked: %v", err)
	}
}

func TestSendRejectsPlainHTTP(t *testing.T) {
	n, hits, _ := setup(t, 200)
	n.Server = "http://example.com"
	if err := n.Send(context.Background(), Message{Body: "x"}); err == nil || !strings.Contains(err.Error(), "https://") {
		t.Errorf("got %v", err)
	}
	if len(*hits) != 0 {
		t.Error("request was sent")
	}
}

func TestSendMissingTopicFile(t *testing.T) {
	n := &Ntfy{TopicFile: filepath.Join(t.TempDir(), "none")}
	if err := n.Send(context.Background(), Message{Body: "x"}); err == nil {
		t.Error("want error")
	}
}

func TestTopicFileWarning(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		mode os.FileMode
		warn bool
	}{{0o600, false}, {0o644, true}, {0o640, true}, {0o660, true}} {
		p := filepath.Join(dir, "t")
		os.Remove(p)
		os.WriteFile(p, []byte("x"), tc.mode)
		os.Chmod(p, tc.mode)
		got := TopicFileWarning(p)
		if tc.warn {
			want := p + " is readable by other users; run chmod 600 " + p + "."
			if got != want {
				t.Errorf("mode %o: got %q", tc.mode, got)
			}
		} else if got != "" {
			t.Errorf("mode %o: got %q", tc.mode, got)
		}
	}
	if got := TopicFileWarning(filepath.Join(dir, "missing")); got != "" {
		t.Errorf("missing: got %q", got)
	}
}

func TestSendRefusesRedirectToPlainHTTP(t *testing.T) {
	var leaked atomic.Value
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Store(r.URL.Path)
	}))
	defer plain.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+r.URL.Path, http.StatusMovedPermanently)
	}))
	defer srv.Close()
	file := filepath.Join(t.TempDir(), "topic")
	if err := os.WriteFile(file, []byte("secret-topic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := srv.Client()
	n := &Ntfy{Server: srv.URL, TopicFile: file, Client: client}
	err := n.Send(context.Background(), Message{Body: "1 updated"})
	if p := leaked.Load(); p != nil {
		t.Fatalf("followed a redirect to http:// and sent %s in plaintext", p)
	}
	if err == nil || strings.Contains(err.Error(), "secret-topic") {
		t.Errorf("a redirect should be an error that hides the topic: %v", err)
	}
	if client.CheckRedirect != nil {
		t.Error("Send modified the caller's client")
	}
}
