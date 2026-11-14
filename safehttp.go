package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	safeHTTPMaxRedirects = 5
	safeHTTPDefaultBytes = int64(32 << 20)
	safeHTTPDefaultTO    = 30 * time.Second
)

var (
	errSafeHTTPBadURL   = errors.New("safehttp: invalid url")
	errSafeHTTPBadHost  = errors.New("safehttp: blocked host")
	errSafeHTTPBadProto = errors.New("safehttp: blocked scheme")
	errSafeHTTPTooBig   = errors.New("safehttp: body exceeds limit")
	errSafeHTTPStatus   = errors.New("safehttp: unexpected status")
	errSafeHTTPRedirect = errors.New("safehttp: too many redirects")
)

type SafeHTTPOptions struct {
	MaxBytes   int64
	Timeout    time.Duration
	AllowHosts []string
	AllowHTTP  bool
}

func defaultSafeHTTPOptions() SafeHTTPOptions {
	return SafeHTTPOptions{
		MaxBytes:  safeHTTPDefaultBytes,
		Timeout:   safeHTTPDefaultTO,
		AllowHosts: nil,
		AllowHTTP:  false,
	}
}

func hostAllowed(host string, allow []string) bool {
	if len(allow) == 0 {
		return true
	}
	h := strings.ToLower(host)
	for _, item := range allow {
		a := strings.ToLower(strings.TrimSpace(item))
		if a == "" {
			continue
		}
		if strings.HasPrefix(a, "*.") {
			if strings.HasSuffix(h, a[1:]) && len(h) > len(a)-1 {
				return true
			}
			continue
		}
		if h == a || strings.HasSuffix(h, "."+a) {
			return true
		}
	}
	return false
}

func validateFetchURL(raw string, opt SafeHTTPOptions) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsRune(raw, '\x00') {
		return nil, errSafeHTTPBadURL
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Host == "" {
		return nil, errSafeHTTPBadURL
	}
	if u.User != nil {
		return nil, errSafeHTTPBadURL
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && !(opt.AllowHTTP && scheme == "http") {
		return nil, errSafeHTTPBadProto
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.HasSuffix(host, ".") {
		return nil, errSafeHTTPBadHost
	}
	if host == "localhost" || strings.HasSuffix(host, ".local") {
		return nil, errSafeHTTPBadHost
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, errSafeHTTPBadHost
		}
	}
	if !hostAllowed(host, opt.AllowHosts) {
		return nil, errSafeHTTPBadHost
	}
	if strings.Contains(u.Path, "..") {
		return nil, errSafeHTTPBadURL
	}
	if len(u.String()) > 2048 {
		return nil, errSafeHTTPBadURL
	}
	return u, nil
}

func readBounded(r io.Reader, max int64) ([]byte, error) {
	if max <= 0 {
		max = safeHTTPDefaultBytes
	}
	limited := io.LimitReader(r, max+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, errSafeHTTPTooBig
	}
	return data, nil
}

func fetchBounded(ctx context.Context, raw string, opt SafeHTTPOptions) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := validateFetchURL(raw, opt); err != nil {
		return nil, err
	}
	maxBytes := opt.MaxBytes
	if maxBytes <= 0 {
		maxBytes = safeHTTPDefaultBytes
	}
	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = safeHTTPDefaultTO
	}
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= safeHTTPMaxRedirects {
				return errSafeHTTPRedirect
			}
			if _, err := validateFetchURL(req.URL.String(), opt); err != nil {
				return err
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, errSafeHTTPBadURL
	}
	req.Header.Set("User-Agent", "QingLongLauncher/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, errSafeHTTPStatus
	}
	return readBounded(resp.Body, maxBytes)
}

func doBoundedRaw(ctx context.Context, method string, raw string, contentType string, payload []byte, opt SafeHTTPOptions) (int, []byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := validateFetchURL(raw, opt); err != nil {
		return 0, nil, err
	}
	maxBytes := opt.MaxBytes
	if maxBytes <= 0 {
		maxBytes = safeHTTPDefaultBytes
	}
	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = safeHTTPDefaultTO
	}
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= safeHTTPMaxRedirects {
				return errSafeHTTPRedirect
			}
			if _, err := validateFetchURL(req.URL.String(), opt); err != nil {
				return err
			}
			return nil
		},
	}
	var reader io.Reader
	if len(payload) > 0 {
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, raw, reader)
	if err != nil {
		return 0, nil, errSafeHTTPBadURL
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("User-Agent", "QingLongLauncher/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, rerr := readBounded(resp.Body, maxBytes)
	if rerr != nil {
		return resp.StatusCode, nil, rerr
	}
	return resp.StatusCode, body, nil
}

func postBounded(ctx context.Context, raw string, contentType string, payload []byte, opt SafeHTTPOptions) ([]byte, error) {
	return doBounded(ctx, http.MethodPost, raw, contentType, payload, opt)
}

func getBounded(ctx context.Context, raw string, opt SafeHTTPOptions) ([]byte, error) {
	return doBounded(ctx, http.MethodGet, raw, "", nil, opt)
}

func doBounded(ctx context.Context, method string, raw string, contentType string, payload []byte, opt SafeHTTPOptions) ([]byte, error) {
	status, body, err := doBoundedRaw(ctx, method, raw, contentType, payload, opt)
	if err != nil {
		return nil, err
	}
	if status < 200 || status > 299 {
		return nil, errSafeHTTPStatus
	}
	return body, nil
}
