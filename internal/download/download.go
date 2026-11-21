// Package download is cerberus's HTTPS client. It fetches small documents
// for the resolver and large ISOs with resume, and checks free space before
// writing.
package download

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Doc is a fetched document.
type Doc struct {
	Status   int
	Body     []byte // nil for Head
	FinalURL string // the URL after redirects
	Header   http.Header
}

// Client fetches over HTTPS only. The first URL and every redirect must be
// https://, with at most 10 redirects.
type Client struct {
	hc          *http.Client
	userAgent   string
	githubToken string
	maxDoc      int64
	stall       time.Duration
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient uses hc's transport. Tests pass an httptest TLS server's
// client. The HTTPS-only redirect policy still applies, and hc itself isn't
// modified.
func WithHTTPClient(hc *http.Client) Option {
	panic("download.WithHTTPClient: not implemented (phase 1)")
}

// WithGitHubToken sends token as a bearer token, only to api.github.com.
func WithGitHubToken(token string) Option {
	panic("download.WithGitHubToken: not implemented (phase 1)")
}

// WithMaxDocBytes caps Get bodies. The default is 64 MiB.
func WithMaxDocBytes(n int64) Option {
	panic("download.WithMaxDocBytes: not implemented (phase 1)")
}

// WithStallTimeout aborts a transfer that receives no bytes for d. The
// default is 2 minutes.
func WithStallTimeout(d time.Duration) Option {
	panic("download.WithStallTimeout: not implemented (phase 1)")
}

// New returns a Client that sends userAgent with every request. The default
// transport has 30-second dial, TLS and response-header timeouts, and no
// overall timeout, because an ISO can take an hour.
func New(userAgent string, opts ...Option) *Client {
	panic("download.New: not implemented (phase 1)")
}

// Get fetches url and returns its body. A non-2xx status is an error that
// includes the status. A body over the cap is an error, not a truncation.
func (c *Client) Get(ctx context.Context, url string) (*Doc, error) {
	panic("download.Client.Get: not implemented (phase 1)")
}

// Head fetches url's headers. When the server refuses HEAD with 403, 405 or
// 501, Head retries as a GET for bytes=0-0 and reports that response's
// headers, without a body.
func (c *Client) Head(ctx context.Context, url string) (*Doc, error) {
	panic("download.Client.Head: not implemented (phase 1)")
}

// Size returns the length of the resource at url. It uses the
// Content-Length from Head, or the total in a ranged reply's Content-Range,
// and returns -1 when the server doesn't say.
func (c *Client) Size(ctx context.Context, url string) (int64, error) {
	panic("download.Client.Size: not implemented (phase 1)")
}

// Progress reports bytes written so far and the expected total, which is -1
// when unknown.
type Progress func(done, total int64)

// Result describes a finished Fetch.
type Result struct {
	Bytes   int64 // final size of the part file
	Resumed bool  // the transfer continued an existing part file
}

// Fetch downloads url into partPath and never renames it; the caller
// verifies and places the file.
//
// With an existing part file and its partPath+".meta" record (JSON: url,
// ETag, Last-Modified, total), Fetch asks for the rest with Range and
// If-Range set to the recorded ETag, or Last-Modified when there's no ETag.
// A 206 reply appends; a 200 reply means the resource changed, so it
// truncates and starts over. Without a validator it starts over. It writes
// the meta record before the first byte and removes it on success. Writes
// fsync before return. A write that fails for lack of space returns an error
// wrapping ErrNoSpace. A transfer stalled past the stall timeout returns an
// error and leaves the part file for the next attempt.
func (c *Client) Fetch(ctx context.Context, url, partPath string, progress Progress) (*Result, error) {
	panic("download.Client.Fetch: not implemented (phase 1)")
}

// ErrNoSpace is wrapped by every out-of-space failure: ENOSPC while
// writing, or a CheckSpace refusal.
var ErrNoSpace = errors.New("not enough free space")

// FreeSpace returns the bytes available to unprivileged users, and the total
// size, of the filesystem holding path.
func FreeSpace(path string) (avail, total uint64, err error) {
	panic("download.FreeSpace: not implemented (phase 1)")
}

// Reserve returns the bytes to keep free on a filesystem of size total: pct
// percent of it, but at least min.
func Reserve(total uint64, pct float64, min uint64) uint64 {
	panic("download.Reserve: not implemented (phase 1)")
}

// CheckSpace returns an error wrapping ErrNoSpace when writing need more
// bytes to dir's filesystem would leave less than Reserve(total, pct, min)
// available. The error message gives the numbers in human units.
func CheckSpace(dir string, need int64, pct float64, min uint64) error {
	panic("download.CheckSpace: not implemented (phase 1)")
}
