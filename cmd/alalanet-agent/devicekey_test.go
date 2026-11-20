package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The hook's free device key (QUOTA-ONE-BUCKET-1): from ALALANET_DEVICE_KEY, else the saved file, else asked for once
// and saved readable by the user only; a refused request is not asked again for a day; a plan token sends no key.
func TestHookDeviceKey(t *testing.T) {
	const key = "ald_" + "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrsta"
	var issued atomic.Int32
	var refuse atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/device-keys" || r.ContentLength > 0 {
			t.Errorf("request %s %s (%d bytes)", r.Method, r.URL.Path, r.ContentLength)
		}
		issued.Add(1)
		if refuse.Load() {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"device_key":"` + key + `"}`))
	}))
	defer srv.Close()
	env := map[string]string{}
	now := time.Unix(1_800_000_000, 0)
	src := func(dir string) *deviceKeySource {
		return &deviceKeySource{getenv: func(k string) string { return env[k] }, configDir: dir, client: srv.Client(), api: srv.URL, now: func() time.Time { return now }}
	}
	ctx := context.Background()

	dir := t.TempDir()
	if got := src(dir).key(ctx); got != key || issued.Load() != 1 {
		t.Fatalf("first use: %q, %d requests (want the issued key, one request)", got, issued.Load())
	}
	fi, err := os.Stat(filepath.Join(dir, "alalanet", "device-key"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the saved key: %v %v (want mode 0600)", fi, err)
	}
	if got := src(dir).key(ctx); got != key || issued.Load() != 1 {
		t.Fatalf("second use: %q, %d requests (want the saved key, no new request)", got, issued.Load())
	}
	env["ALALANET_DEVICE_KEY"] = "ald_fromenv"
	if got := src(dir).key(ctx); got != "ald_fromenv" {
		t.Fatalf("the environment's key: %q", got)
	}
	env["ALALANET_DEVICE_KEY"] = "not a key\r\nX: y"
	if got := src(dir).key(ctx); got != "" {
		t.Fatalf("a variable that is no key was sent: %q", got)
	}
	delete(env, "ALALANET_DEVICE_KEY")

	refuse.Store(true)
	other := t.TempDir()
	if got := src(other).key(ctx); got != "" || issued.Load() != 2 {
		t.Fatalf("a refused request: %q, %d requests", got, issued.Load())
	}
	if got := src(other).key(ctx); got != "" || issued.Load() != 2 {
		t.Fatalf("asked again within the day: %d requests", issued.Load())
	}
	now = now.Add(25 * time.Hour)
	refuse.Store(false)
	if got := src(other).key(ctx); got != key || issued.Load() != 3 {
		t.Fatalf("after a day: %q, %d requests", got, issued.Load())
	}
	if _, err := os.Stat(filepath.Join(other, "alalanet", "device-key.retry")); !os.IsNotExist(err) {
		t.Fatalf("the retry mark outlived the key: %v", err)
	}
	// another API than alalanet.com (ALALANET_API): no file read, no request, only the variable
	if s := newDeviceKeySource(func(string) string { return "" }, srv.Client(), srv.URL); s.configDir != "" {
		t.Fatalf("a test server's source keeps a folder: %q", s.configDir)
	}
	// plain http to another machine: never asked
	remote := &deviceKeySource{getenv: func(string) string { return "" }, configDir: t.TempDir(), client: srv.Client(), api: "http://198.51.100.9", now: time.Now}
	if got := remote.key(ctx); got != "" || issued.Load() != 3 {
		t.Fatalf("plain http to another machine: %q, %d requests", got, issued.Load())
	}

	// the hook request: the key without a token, none with one
	f := &fakeHook{}
	hook := f.server(t)
	for _, token := range []string{"", "aln_tok"} {
		var out bytes.Buffer
		call := hookCall{client: hook.Client(), api: hook.URL, token: token, device: src(dir)}
		if err := runHookContext(ctx, "codex", strings.NewReader(codexInput("Bash", "npm install left-pad")), &out, call); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.headers) != 2 || f.headers[0].Get("X-Alalanet-Device-Key") != key || f.headers[1].Get("X-Alalanet-Device-Key") != "" || f.headers[1].Get("Authorization") != "Bearer aln_tok" {
		t.Fatalf("hook requests' headers: %v", f.headers)
	}
}
