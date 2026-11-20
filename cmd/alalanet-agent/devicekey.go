package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The install hook's free device key (alalanet's QUOTA-ONE-BUCKET-1). alalanet gives the hook 1,000 checks a day only
// through a key it issues without sign-up (POST /v1/device-keys); without one the hook shares the address's 100 checks
// a day with every other route. The hook sends the key in X-Alalanet-Device-Key when no plan token is set. Where it
// comes from, in order:
//   - ALALANET_DEVICE_KEY;
//   - the file alalanet/device-key in the user's configuration folder (os.UserConfigDir: ~/.config on Linux,
//     ~/Library/Application Support on macOS, %AppData% on Windows);
//   - else the hook asks alalanet for one once, saves it there (0600) and uses it. A refused or failed request is not
//     asked again for a day (alalanet/device-key.retry holds when), and the check goes ahead without a key.
//
// The file and the request are for alalanet.com only: with ALALANET_API set to another server (a test server, a
// staging copy) only ALALANET_DEVICE_KEY is sent, and nothing is written.
//
// The key is bound to nothing and says nothing about the machine; it is never printed.

const (
	deviceKeyHeader = "X-Alalanet-Device-Key"
	deviceKeyPrefix = "ald_"
	deviceKeyMax    = 128
	deviceKeyRetry  = 24 * time.Hour
	deviceKeyWait   = 5 * time.Second
)

// deviceKeySource finds or obtains the device key (deviceKey); its fields are the process's, tests set their own.
type deviceKeySource struct {
	getenv    func(string) string
	configDir string // the user's configuration folder; "" keeps no file and asks for no key (another API than alalanet.com)
	client    *http.Client
	api       string
	now       func() time.Time
}

func newDeviceKeySource(getenv func(string) string, client *http.Client, api string) *deviceKeySource {
	dir, err := os.UserConfigDir()
	if err != nil || api != defaultAPI {
		dir = ""
	}
	return &deviceKeySource{getenv: getenv, configDir: dir, client: client, api: api, now: time.Now}
}

// deviceKeyOK: a key the server could have issued, and a header can carry.
func deviceKeyOK(k string) bool {
	if !strings.HasPrefix(k, deviceKeyPrefix) || len(k) > deviceKeyMax || len(k) <= len(deviceKeyPrefix) {
		return false
	}
	for i := range len(k) {
		c := k[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func (s *deviceKeySource) file() string { return filepath.Join(s.configDir, "alalanet", "device-key") }

// key is the device key to send, or "" for none.
func (s *deviceKeySource) key(ctx context.Context) string {
	if s == nil {
		return ""
	}
	if k := strings.TrimSpace(s.getenv("ALALANET_DEVICE_KEY")); k != "" {
		if deviceKeyOK(k) {
			return k
		}
		return "" // set but not a key: sent nowhere, the hook takes the address's checks
	}
	if s.configDir == "" {
		return ""
	}
	if b, err := readSmall(s.file(), deviceKeyMax+2); err == nil {
		if k := strings.TrimSpace(string(b)); deviceKeyOK(k) {
			return k
		}
		return ""
	}
	if b, err := readSmall(s.file()+".retry", 32); err == nil {
		if at, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && s.now().Sub(time.Unix(at, 0)) < deviceKeyRetry {
			return "" // asked less than a day ago and refused
		}
	}
	k := s.issue(ctx)
	if k == "" {
		s.save(s.file()+".retry", strconv.FormatInt(s.now().Unix(), 10))
		return ""
	}
	if !s.save(s.file(), k) {
		return k // used now; asked again next time
	}
	_ = os.Remove(s.file() + ".retry")
	return k
}

// issue asks alalanet for a key: over https, or plain http to this machine only (a local test server).
func (s *deviceKeySource) issue(ctx context.Context) string {
	if s.client == nil || plainRemote(s.api) {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, deviceKeyWait)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(s.api, "/")+"/v1/device-keys", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "alalanet-agent/"+version+" (device key)")
	client := *s.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return ""
	}
	var out struct {
		Key string `json:"device_key"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&out) != nil || !deviceKeyOK(out.Key) {
		return ""
	}
	return out.Key
}

// save writes text to path whole (a temporary file renamed into place), readable by the user only.
func (s *deviceKeySource) save(path, text string) bool {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".device-key-*")
	if err != nil {
		return false
	}
	_, werr := tmp.WriteString(text + "\n")
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Chmod(tmp.Name(), 0o600) != nil || os.Rename(tmp.Name(), path) != nil {
		_ = os.Remove(tmp.Name())
		return false
	}
	return true
}

func readSmall(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}
