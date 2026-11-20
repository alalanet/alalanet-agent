package main

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ECO-1 Go, round 3, P3-5: the user's own Go settings — the hook's environment and the go env file — are read on the
// machine. A go: target they fetch from somewhere other than the public Go proxy is answered here and the line is not
// sent (alalanet's check would read its path from proxy.golang.org and sum.golang.org); what moves the module also
// binds an exception, as a registry setting does.

func goPolicyFiles(t *testing.T, home string, env []string) *policyFiles {
	t.Helper()
	return &policyFiles{getwd: func() (string, error) { return "", os.ErrNotExist }, environ: func() []string { return env },
		home: func() (string, error) { return home, nil }}
}

func TestGoUserSettingsMove(t *testing.T) {
	home := t.TempDir()
	goenv := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(goenv, []byte("GOPROXY=https://proxy.golang.org,direct\nGOPRIVATE=corp.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := []string{"go:corp.example/zz@v1.0.0"}
	for name, c := range map[string]struct {
		env  []string
		want string
	}{
		"GOPRIVATE in the environment":       {[]string{"GOPRIVATE=corp.example"}, "the environment variable GOPRIVATE"},
		"GOPROXY of the user's own":          {[]string{"GOPROXY=https://athens.corp.example"}, "the environment variable GOPROXY"},
		"GOPRIVATE in the go env file":       {[]string{"GOENV=" + goenv}, goenv + " GOPRIVATE"},
		"the environment wins over the file": {[]string{"GOENV=" + goenv, "GOPRIVATE=other.example"}, ""},
		"GOPRIVATE for another host":         {[]string{"GOPRIVATE=other.example"}, ""},
		"the default proxy":                  {[]string{"GOPROXY=https://proxy.golang.org,direct"}, ""},
		"GOENV=off reads no file":            {[]string{"GOENV=off"}, ""},
	} {
		pf := goPolicyFiles(t, home, c.env)
		got := goPrivateHere(pf, "", target)
		if got != c.want {
			t.Errorf("%s: goPrivateHere %q; want %q", name, got, c.want)
		}
		moved := registryMoved(pf, "", "go install corp.example/zz@v1.0.0", target)
		if (moved == "") != (c.want == "") || c.want != "" && !strings.Contains(moved, c.want) {
			t.Errorf("%s: registryMoved %q", name, moved)
		}
	}
	// GOFLAGS of the user's own that runs code binds an exception, though it does not make the path private
	pf := goPolicyFiles(t, home, []string{"GOFLAGS=-toolexec=/opt/w"})
	if goPrivateHere(pf, "", target) != "" || !strings.Contains(registryMoved(pf, "", "go install corp.example/zz@v1.0.0", target), "GOFLAGS") {
		t.Errorf("GOFLAGS -toolexec: private %q, moved %q", goPrivateHere(pf, "", target), registryMoved(pf, "", "", target))
	}
	// the user's config folder on this system: ~/.config/go/env (XDG_CONFIG_HOME first) or macOS's Application Support
	dir := filepath.Join(home, ".config", "go")
	if p := filepath.Join(home, "Library", "Application Support", "go"); runtime.GOOS == "darwin" {
		dir = p
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "env"), []byte("GONOSUMDB=corp.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := goPrivateHere(goPolicyFiles(t, home, nil), "", target); !strings.HasSuffix(got, filepath.Join("go", "env")+" GONOSUMDB") {
		t.Errorf("the user's go env file: %q", got)
	}
}

// The hook answers such a line on the machine: alalanet is not called.
func TestGoUserSettingsLineNotSent(t *testing.T) {
	f := &fakeHook{answer: func(w http.ResponseWriter) {
		_, _ = w.Write([]byte(`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}`))
	}}
	srv := f.server(t)
	for line, sent := range map[string]bool{"go install corp.example/zz@v1.0.0": false, "go install example.com/zz@v1.0.0": true} {
		before := len(f.calls())
		var out bytes.Buffer
		call := hookCall{client: &http.Client{Timeout: 2 * time.Second}, api: srv.URL,
			policy: goPolicyFiles(t, t.TempDir(), []string{"GOPRIVATE=corp.example"})}
		if err := runHookContext(t.Context(), "codex", strings.NewReader(runtimeInputs["codex"](line)), &out, call); err != nil {
			t.Fatal(err)
		}
		if got := len(f.calls()) > before; got != sent {
			t.Errorf("%s: sent %v; want %v (answer %s)", line, got, sent, out.String())
		}
		if !sent && !strings.Contains(out.String(), "GOPRIVATE") {
			t.Errorf("%s: the local answer does not say why: %s", line, out.String())
		}
	}
}

// XDG_CONFIG_HOME names the config folder outside macOS and Windows (os.UserConfigDir).
func TestGoUserSettingsXDG(t *testing.T) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" || runtime.GOOS == "ios" {
		t.Skip("os.UserConfigDir ignores XDG_CONFIG_HOME here")
	}
	xdg := t.TempDir()
	if err := os.MkdirAll(filepath.Join(xdg, "go"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(xdg, "go", "env"), []byte("GOPRIVATE=corp.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := goPrivateHere(goPolicyFiles(t, t.TempDir(), []string{"XDG_CONFIG_HOME=" + xdg}), "", []string{"go:corp.example/zz@v1.0.0"})
	if got != filepath.Join(xdg, "go", "env")+" GOPRIVATE" {
		t.Errorf("XDG_CONFIG_HOME's go env file: %q", got)
	}
}
