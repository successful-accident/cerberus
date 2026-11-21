// Package notify sends sync summaries to ntfy.
package notify

import (
	"context"
	"net/http"
)

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
	panic("notify.Ntfy.Send: not implemented (phase 1)")
}

// TopicFileWarning returns a sentence when the topic file at path is
// readable by group or others, and "" when it's private or missing.
func TopicFileWarning(path string) string {
	panic("notify.TopicFileWarning: not implemented (phase 1)")
}
