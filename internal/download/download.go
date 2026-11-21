// Package download is cerberus's HTTPS client. It fetches small documents
// for the resolver and large ISOs with resume, and checks free space before
// writing.
package download

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
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
	return func(c *Client) {
		cp := *hc
		cp.CheckRedirect = checkRedirect
		c.hc = &cp
	}
}

// WithGitHubToken sends token as a bearer token, only to api.github.com.
func WithGitHubToken(token string) Option {
	return func(c *Client) { c.githubToken = token }
}

// WithMaxDocBytes caps Get bodies. The default is 64 MiB.
func WithMaxDocBytes(n int64) Option {
	return func(c *Client) { c.maxDoc = n }
}

// WithStallTimeout aborts a transfer that receives no bytes for d. The
// default is 2 minutes.
func WithStallTimeout(d time.Duration) Option {
	return func(c *Client) { c.stall = d }
}

// New returns a Client that sends userAgent with every request. The default
// transport has 30-second dial, TLS and response-header timeouts, and no
// overall timeout, because an ISO can take an hour.
func New(userAgent string, opts ...Option) *Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = http.ProxyFromEnvironment
	t.DialContext = (&net.Dialer{Timeout: 30 * time.Second}).DialContext
	t.TLSHandshakeTimeout = 30 * time.Second
	t.ResponseHeaderTimeout = 30 * time.Second
	c := &Client{
		hc:        &http.Client{Transport: t, CheckRedirect: checkRedirect},
		userAgent: userAgent,
		maxDoc:    64 << 20,
		stall:     2 * time.Minute,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("stopped after 10 redirects at %s", req.URL)
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing redirect to non-https url %s", req.URL)
	}
	// net/http copies headers onto redirects; the token never leaves
	// api.github.com.
	if req.URL.Host != "api.github.com" {
		req.Header.Del("Authorization")
	}
	return nil
}

// authorization returns the Authorization header value for a request to u,
// or "" when none should be sent.
func authorization(u *url.URL, token string) string {
	if token == "" || u.Host != "api.github.com" {
		return ""
	}
	return "Bearer " + token
}

func (c *Client) do(ctx context.Context, method, rawURL string, header http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("refusing non-https url %s", rawURL)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("User-Agent", c.userAgent)
	if a := authorization(req.URL, c.githubToken); a != "" {
		req.Header.Set("Authorization", a)
	}
	return c.hc.Do(req)
}

// Get fetches url and returns its body. A non-2xx status is an error that
// includes the status. A body over the cap is an error, not a truncation.
func (c *Client) Get(ctx context.Context, url string) (*Doc, error) {
	resp, err := c.do(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("get %s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxDoc+1))
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", url, err)
	}
	if int64(len(body)) > c.maxDoc {
		return nil, fmt.Errorf("get %s: body exceeds %d bytes", url, c.maxDoc)
	}
	return &Doc{Status: resp.StatusCode, Body: body, FinalURL: resp.Request.URL.String(), Header: resp.Header}, nil
}

// Head fetches url's headers. When the server refuses HEAD with 403, 405 or
// 501, Head retries as a GET for bytes=0-0 and reports that response's
// headers, without a body.
func (c *Client) Head(ctx context.Context, url string) (*Doc, error) {
	resp, err := c.do(ctx, http.MethodHead, url, nil)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusForbidden, http.StatusMethodNotAllowed, http.StatusNotImplemented:
		resp, err = c.do(ctx, http.MethodGet, url, http.Header{"Range": {"bytes=0-0"}})
		if err != nil {
			return nil, err
		}
		resp.Body.Close()
	}
	return &Doc{Status: resp.StatusCode, FinalURL: resp.Request.URL.String(), Header: resp.Header}, nil
}

// Size returns the length of the resource at url. It uses the
// Content-Length from Head, or the total in a ranged reply's Content-Range,
// and returns -1 when the server doesn't say.
func (c *Client) Size(ctx context.Context, url string) (int64, error) {
	d, err := c.Head(ctx, url)
	if err != nil {
		return -1, err
	}
	switch d.Status {
	case http.StatusOK:
		if n, err := strconv.ParseInt(d.Header.Get("Content-Length"), 10, 64); err == nil && n >= 0 {
			return n, nil
		}
	case http.StatusPartialContent:
		if _, total, ok := parseContentRange(d.Header.Get("Content-Range")); ok {
			return total, nil
		}
	}
	return -1, nil
}

// parseContentRange reads "bytes <start>-<end>/<total>" and returns start
// and total, with total -1 when it's "*".
func parseContentRange(s string) (start, total int64, ok bool) {
	rng, tot, found := strings.Cut(strings.TrimPrefix(s, "bytes "), "/")
	first, _, found2 := strings.Cut(rng, "-")
	if !strings.HasPrefix(s, "bytes ") || !found || !found2 {
		return 0, 0, false
	}
	start, err := strconv.ParseInt(first, 10, 64)
	if err != nil {
		return 0, 0, false
	}
	if tot == "*" {
		return start, -1, true
	}
	total, err = strconv.ParseInt(tot, 10, 64)
	return start, total, err == nil
}

// Progress reports bytes written so far and the expected total, which is -1
// when unknown.
type Progress func(done, total int64)

// Result describes a finished Fetch.
type Result struct {
	Bytes   int64 // final size of the part file
	Resumed bool  // the transfer continued an existing part file
}

// meta is the partPath+".meta" record that makes a resume safe.
type meta struct {
	URL          string `json:"url"`
	ETag         string `json:"etag"`
	LastModified string `json:"last_modified"`
	Total        int64  `json:"total"`
}

var errStalled = errors.New("stalled")

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
	metaPath := partPath + ".meta"
	var offset int64 = -1 // -1: no resume
	var old meta
	header := http.Header{}
	if fi, err := os.Stat(partPath); err == nil {
		if b, err := os.ReadFile(metaPath); err == nil && json.Unmarshal(b, &old) == nil && old.URL == url {
			validator := old.ETag
			if validator == "" {
				validator = old.LastModified
			}
			if validator != "" {
				offset = fi.Size()
				header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
				header.Set("If-Range", validator)
			}
		}
	}

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	stall := time.AfterFunc(c.stall, func() { cancel(errStalled) })
	defer stall.Stop()
	fail := func(err error) (*Result, error) {
		if errors.Is(context.Cause(ctx), errStalled) {
			return nil, fmt.Errorf("fetch %s: stalled, no data for %s", url, c.stall)
		}
		return nil, fmt.Errorf("fetch %s: %w", url, noSpace(err))
	}

	resp, err := c.do(ctx, http.MethodGet, url, header)
	if err != nil {
		return fail(err)
	}
	defer resp.Body.Close()

	flags := os.O_WRONLY | os.O_CREATE
	var done int64
	total := resp.ContentLength
	resumed := false
	switch {
	case resp.StatusCode == http.StatusPartialContent && offset >= 0:
		start, t, ok := parseContentRange(resp.Header.Get("Content-Range"))
		if !ok || start != offset {
			return nil, fmt.Errorf("fetch %s: asked for bytes from %d, got range %q", url, offset, resp.Header.Get("Content-Range"))
		}
		flags |= os.O_APPEND
		done, total, resumed = offset, t, true
	case resp.StatusCode == http.StatusRequestedRangeNotSatisfiable && offset >= 0:
		if offset != old.Total {
			// The part file doesn't fit the resource; the next attempt
			// starts over.
			os.Remove(metaPath)
			return nil, fmt.Errorf("fetch %s: %s for a %d-byte part file", url, resp.Status, offset)
		}
		if err := syncFile(partPath); err != nil {
			return fail(err)
		}
		os.Remove(metaPath)
		return &Result{Bytes: offset, Resumed: true}, nil
	case resp.StatusCode == http.StatusOK:
		flags |= os.O_TRUNC
	default:
		return nil, fmt.Errorf("fetch %s: %s", url, resp.Status)
	}

	m, _ := json.Marshal(meta{URL: url, ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified"), Total: total})
	if err := os.WriteFile(metaPath, m, 0o644); err != nil {
		return fail(err)
	}
	f, err := os.OpenFile(partPath, flags, 0o644)
	if err != nil {
		return fail(err)
	}
	defer f.Close()

	buf := make([]byte, 256<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			stall.Reset(c.stall)
			if _, err := f.Write(buf[:n]); err != nil {
				return fail(err)
			}
			done += int64(n)
			if progress != nil {
				progress(done, total)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return fail(rerr)
		}
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		return fail(err)
	}
	os.Remove(metaPath)
	return &Result{Bytes: done, Resumed: resumed}, nil
}

func syncFile(p string) error {
	f, err := os.OpenFile(p, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// noSpace wraps err with ErrNoSpace when it's ENOSPC, keeping the cause.
func noSpace(err error) error {
	if errors.Is(err, syscall.ENOSPC) {
		return fmt.Errorf("%w: %w", ErrNoSpace, err)
	}
	return err
}

// ErrNoSpace is wrapped by every out-of-space failure: ENOSPC while
// writing, or a CheckSpace refusal.
var ErrNoSpace = errors.New("not enough free space")

// FreeSpace returns the bytes available to unprivileged users, and the total
// size, of the filesystem holding path.
func FreeSpace(path string) (avail, total uint64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	return st.Bavail * uint64(st.Bsize), st.Blocks * uint64(st.Bsize), nil
}

// Reserve returns the bytes to keep free on a filesystem of size total: pct
// percent of it, but at least min.
func Reserve(total uint64, pct float64, min uint64) uint64 {
	return max(uint64(float64(total)*pct/100), min)
}

// CheckSpace returns an error wrapping ErrNoSpace when writing need more
// bytes to dir's filesystem would leave less than Reserve(total, pct, min)
// available. The error message gives the numbers in human units.
func CheckSpace(dir string, need int64, pct float64, min uint64) error {
	avail, total, err := FreeSpace(dir)
	if err != nil {
		return err
	}
	n := uint64(max(need, 0)) // -1, unknown, counts as 0
	reserve := Reserve(total, pct, min)
	if avail < n || avail-n < reserve {
		return fmt.Errorf("%w on %s: need %s plus a %s reserve, %s available",
			ErrNoSpace, dir, human(n), human(reserve), human(avail))
	}
	return nil
}

// human formats n bytes in decimal units, such as "12.0 GB".
func human(n uint64) string {
	if n < 1000 {
		return fmt.Sprintf("%d B", n)
	}
	f := float64(n)
	for _, unit := range []string{"kB", "MB", "GB", "TB"} {
		f /= 1000
		if f < 1000 {
			return fmt.Sprintf("%.1f %s", f, unit)
		}
	}
	return fmt.Sprintf("%.1f PB", f/1000)
}
