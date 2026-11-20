package installread

import (
	"slices"
	"strings"
	"testing"
)

// ECO-1, Go (ADR "go install and go run"): the reader names the module a `go install <path>@<version>` or a
// `go run <path>@<version>` fetches as the target "go:<path>@<version>". Only the module-aware forms with a
// version fetch a module the line names; every other go command (go build, go install ./cmd, go run main.go,
// go version) stays a command the reader does not read, as before.
func TestGoReaderNamesTheModule(t *testing.T) {
	for line, want := range map[string][]string{
		"go install golang.org/x/tools/gopls@latest":                                   {"go:golang.org/x/tools/gopls@latest"},
		"go install golang.org/x/tools/gopls@v0.24.0":                                  {"go:golang.org/x/tools/gopls@v0.24.0"},
		"go run github.com/zz-go/tool/cmd/x@v1.2.3 --flag arg":                         {"go:github.com/zz-go/tool/cmd/x@v1.2.3"},
		"go run github.com/zz-go/t@v1.0.0 example.com/other@v2.0.0":                    {"go:github.com/zz-go/t@v1.0.0"}, // the program's own argument
		"go run -race -tags 'a b' github.com/zz-go/t@v1.0.0":                           {"go:github.com/zz-go/t@v1.0.0"},
		"go run --tags=x -p 4 github.com/zz-go/t@v1.0.0":                               {"go:github.com/zz-go/t@v1.0.0"},
		"go install -ldflags=-s -trimpath example.com/zz/cmd/...@v1.0.0":               {"go:example.com/zz/cmd/...@v1.0.0"},
		"go install -C /tmp example.com/zz@v1.0.0":                                     {"go:example.com/zz@v1.0.0"},
		"go install -- example.com/zz@v1.0.0":                                          {"go:example.com/zz@v1.0.0"},
		"sudo go install example.com/zz@latest":                                        {"go:example.com/zz@latest"},
		"GOBIN=/opt/bin go install example.com/zz@latest":                              {"go:example.com/zz@latest"},
		"/usr/local/go/bin/go install example.com/zz@latest":                           {"go:example.com/zz@latest"},
		"sh -c 'go install example.com/zz@latest'":                                     {"go:example.com/zz@latest"},
		"cd d && go install example.com/zz@v1.0.0":                                     {"go:example.com/zz@v1.0.0"},
		"go install example.com/a@v1.0.0 example.com/b@v1.0.0":                         {"go:example.com/a@v1.0.0", "go:example.com/b@v1.0.0"},
		"go run github.com/zz-go/t@v1.0.0 && npm i left-pad":                           {"go:github.com/zz-go/t@v1.0.0", "npm:left-pad"},
		"go install github.com/ZzUpper/Tool@4f2d1c0":                                   {"go:github.com/ZzUpper/Tool@4f2d1c0"},
		"GOPROXY=https://proxy.golang.org,direct go install example.com/zz@v1.0.0":     {"go:example.com/zz@v1.0.0"},
		"GONOSUMDB=corp.zz GOPRIVATE=corp.zz/* go install example.com/zz@v1.0.0":       {"go:example.com/zz@v1.0.0"},
		"GOFLAGS=-trimpath go install example.com/zz@v1.0.0":                           {"go:example.com/zz@v1.0.0"},
		"GOSUMDB=sum.golang.org go install example.com/zz@v1.0.0":                      {"go:example.com/zz@v1.0.0"},
		"GOFLAGS='-mod=mod -trimpath' go install example.com/zz@v1.0.0":                {"go:example.com/zz@v1.0.0"},
		"go install -buildvcs=false -race=true -json example.com/zz@v1.0.0":            {"go:example.com/zz@v1.0.0"},
		"go run -modcacherw -pgo=off -gcflags=all=-N example.com/zz@v1.0.0 -- -v":      {"go:example.com/zz@v1.0.0"},
		"go install -asmflags=-S -installsuffix x -mod readonly example.com/zz@v1.0.0": {"go:example.com/zz@v1.0.0"},
		"go run -- example.com/zz@v1.0.0 -v":                                           {"go:example.com/zz@v1.0.0"},
		"go install example.com/a/b/c/d/e/f/g/h/i@v1.0.0":                              {"go:example.com/a/b/c/d/e/f/g/h/i@v1.0.0"}, // ten elements
		"GOAUTH=netrc GOENV=off go install example.com/zz@v1.0.0":                      {"go:example.com/zz@v1.0.0"},
	} {
		targets, unread, other, _ := ParseLine(line)
		if !slices.Equal(targets, want) || len(unread) > 0 || other {
			t.Errorf("ParseLine(%q) = %q, unread %q, other %v; want %q", line, targets, unread, other, want)
		}
	}
}

// The go commands that fetch no module the line names stay as they were: no target, no reason, a command the reader
// does not read (ECO-1's counter still names "go" for them). A path Go refuses (no dot in its first element, a
// relative or absolute path, a file) installs nothing.
func TestGoReaderLeavesOtherGoCommands(t *testing.T) {
	for _, line := range []string{"go build ./...", "go install ./cmd/x", "go install", "go run main.go", "go run .",
		"go install golang.org/x/tools/gopls", "go test -run x ./...", "go version", "go install zz@latest", "go install x@latest",
		"go run ./zz@v1.0.0", "go run /abs/zz@v1.0.0", "go get example.com/zz@v1.0.0", "go mod download example.com/zz@v1.0.0",
		"go install EXAMPLE.com/zz@v1.0.0", "go install example.com/../zz@v1.0.0",
		"go install example.com//zz@v1.0.0", "go install .example.com/zz@v1.0.0", "go install example.com/a...b@v1.0.0",
		"GOFLAGS=-mod=mod go build ./...", "GOPROXY=https://zz-evil.example go build ./...", "GOFLAGS=-toolexec=/tmp/x go test ./...",
		"go install example.com/zz@"} {
		targets, unread, other, _ := ParseLine(line)
		if len(targets) > 0 || len(unread) > 0 || !other {
			t.Errorf("ParseLine(%q) = %q, unread %q, other %v; want no target, no reason, other", line, targets, unread, other)
		}
		if OtherProgram(line) != "go" {
			t.Errorf("OtherProgram(%q) = %q; want go", line, OtherProgram(line))
		}
	}
}

// What moves the module's source or the checksum check, what runs other code, and what the line does not show hold
// the line, each with the reason code the other ecosystems' lines get for it.
func TestGoReaderHolds(t *testing.T) {
	for line, code := range map[string]string{
		"GOPROXY=https://zz-evil.example go install example.com/zz@v1.0.0":                "custom_registry",
		"GOPROXY=https://zz-evil.example,direct go install example.com/zz@v1.0.0":         "custom_registry",
		"GOPROXY='https://proxy.golang.org|https://zz-evil.example' go install a.zz/b@v1": "custom_registry",
		"export GOPROXY=https://zz-evil.example && go install example.com/zz@v1.0.0":      "custom_registry",
		"GOSUMDB=off go install example.com/zz@v1.0.0":                                    "custom_registry",
		"GOSUMDB=sum.zz-evil.example go install example.com/zz@v1.0.0":                    "custom_registry",
		"GONOSUMDB=example.com go install example.com/zz@v1.0.0":                          "custom_registry",
		"GONOSUMCHECK=1 GONOSUMDB=example.com/zz go install example.com/zz/cmd/x@v1.0.0":  "custom_registry",
		"GOPRIVATE='*.zz' go install a.zz/x@v1.0.0":                                       "custom_registry",
		"GONOPROXY=example.com go install example.com/zz@v1.0.0":                          "custom_registry",
		"GOINSECURE=example.com go install example.com/zz@v1.0.0":                         "custom_registry",
		"GOENV=/tmp/zz.env go install example.com/zz@v1.0.0":                              "custom_registry",
		"GOFLAGS=-toolexec=/tmp/x go install example.com/zz@v1.0.0":                       "code_from_environment",
		"GOFLAGS=-zz go install example.com/zz@v1.0.0":                                    "code_from_environment",
		"GOAUTH='git dir' go install example.com/zz@v1.0.0":                               "code_from_environment",
		"go install -toolexec /tmp/x example.com/zz@v1.0.0":                               "code_from_environment",
		"go install -toolexec=/tmp/x example.com/zz@v1.0.0":                               "code_from_environment",
		"go run -exec sudo example.com/zz@v1.0.0":                                         "code_from_environment",
		"go install -overlay o.json example.com/zz@v1.0.0":                                "code_from_environment",
		"go install -ldflags='-extld=/tmp/x' example.com/zz@v1.0.0":                       "code_from_environment",
		"go install -zz example.com/zz@v1.0.0":                                            "unknown_install_form",
		"go install example.com/a/b/c/d/e/f/g/h/i/j@v1.0.0":                               "unknown_install_form", // past the ten elements read
		"go install -exec sudo example.com/zz@v1.0.0":                                     "unknown_install_form", // -exec is go run's
		"go install example.com/zz@-v1":                                                   "unknown_install_form",
		"GONOPROXY=example.com/zz go install example.com/zz@v1.0.0":                       "custom_registry",
		"GOFLAGS=trimpath go install example.com/zz@v1.0.0":                               "code_from_environment",
		"goproxy=https://zz-evil.example go install example.com/zz@v1.0.0":                "custom_registry", // cmd.exe's names fold case
		"go install 'example.com/zz@>=v1.0.0'":                                            "unknown_install_form",
		"go install example.com/zz@feature/x":                                             "unknown_install_form",
		"go install $PKG@v1.0.0":                                                          "variable_argument",
		"go install example.com/zz@$V":                                                    "variable_argument",
		"go $SUB example.com/zz@v1.0.0":                                                   "variable_argument",
		"go install -$F example.com/zz@v1.0.0":                                            "variable_argument",
		"echo example.com/zz@v1.0.0 | xargs go install":                                   "stdin_arguments",
		"echo example.com/zz@v1.0.0 | xargs go run":                                       "stdin_arguments",
	} {
		_, unread, _, _ := ParseLine(line)
		var codes []string
		for _, u := range unread {
			codes = append(codes, UnreadCode(u))
		}
		if !slices.Contains(codes, code) {
			t.Errorf("ParseLine(%q): unread %q (codes %q); want %s", line, unread, codes, code)
		}
	}
}

// The reasons name only what alalanet judged by: a variable's name and the host of a proxy, never the module's other
// settings (a GOPRIVATE list may name a company's hosts: the reason quotes the variable alone).
func TestGoReaderReasonsQuoteLittle(t *testing.T) {
	_, unread, _, _ := ParseLine("GOPRIVATE=corp-secret.zz,example.com go install example.com/zz@v1.0.0")
	if len(unread) != 1 || strings.Contains(unread[0], "corp-secret") || !strings.Contains(unread[0], "GOPRIVATE") {
		t.Errorf("unread %q: want one reason that names GOPRIVATE and not its value", unread)
	}
}
