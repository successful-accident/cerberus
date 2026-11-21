// Package notify sends sync summaries to ntfy.
package notify

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var topicRE = regexp.MustCompile(`^[-_A-Za-z0-9]{1,64}$`)

// Defaults for Ntfy.
const (
	DefaultServer    = "https://ntfy.sh"
	DefaultTopicFile = "/etc/cerberus/ntfy-topic"
)

// Ntfy posts messages to a topic. The topic itself is a secret, since anyone
// who knows it can read the messages. It lives only in TopicFile, is read
// at send time, and never appears in errors or logs.
type Ntfy struct {
	Server    string       // https:// only; "" means DefaultServer
	TopicFile string       // "" means DefaultTopicFile
	Client    *http.Client // nil means http.DefaultClient
}

// Message is one notification.
type Message struct {
	Title    string
	Body     string
	Tags     []string // ntfy tags, such as "white_check_mark" or "warning"
	Priority int      // 1 to 5; 0 means ntfy's default
}

// Send reads the topic, which must match ^[-_A-Za-z0-9]{1,64}$, and POSTs
// m.Body to <Server>/<topic> with Title, Tags and Priority headers. A
// non-2xx reply is an error. Errors name the server but never the topic.
func (n *Ntfy) Send(ctx context.Context, m Message) error {
	server := strings.TrimRight(n.Server, "/")
	if server == "" {
		server = DefaultServer
	}
	if !strings.HasPrefix(server, "https://") {
		return fmt.Errorf("ntfy server %s must start with https://", server)
	}
	file := n.TopicFile
	if file == "" {
		file = DefaultTopicFile
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("read ntfy topic file: %w", err)
	}
	topic := strings.TrimSpace(string(raw))
	if !topicRE.MatchString(topic) {
		return fmt.Errorf("ntfy topic file %s: topic must be 1 to 64 letters, digits, - or _", file)
	}
	scrub := func(err error) error {
		return fmt.Errorf("ntfy at %s: %s", server, strings.ReplaceAll(err.Error(), topic, "<topic>"))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+"/"+topic, strings.NewReader(m.Body))
	if err != nil {
		return scrub(err)
	}
	if m.Title != "" {
		req.Header.Set("Title", m.Title)
	}
	if len(m.Tags) > 0 {
		req.Header.Set("Tags", strings.Join(m.Tags, ","))
	}
	if m.Priority > 0 {
		req.Header.Set("Priority", strconv.Itoa(m.Priority))
	}
	client := n.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return scrub(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("ntfy at %s: status %d", server, resp.StatusCode)
	}
	return nil
}

// TopicFileWarning returns a sentence when the topic file at path is
// readable by group or others, and "" when it's private or missing.
func TopicFileWarning(path string) string {
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm()&0o077 == 0 {
		return ""
	}
	return fmt.Sprintf("%s is readable by other users; run chmod 600 %s.", path, path)
}
