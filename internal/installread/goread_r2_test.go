package installread

import (
	"slices"
	"strings"
	"testing"
)

// ECO-1 Go, round 2 (review of 7464aae2, an internal review note; its probes adopted as
// assertions): go env -w, the code-location variables, GOSUMDB's key, the paths a line marks private, HOME and the
// cgo and gccgo programs.

func codesOf(line string) (targets, codes []string) {
	targets, unread, _, _ := ParseLine(line)
	for _, u := range unread {
		codes = append(codes, UnreadCode(u))
	}
	return targets, codes
}

func TestGoR2Holds(t *testing.T) {
	for line, code := range map[string]string{
		// P2-1: go env -w writes the go env file the next go command reads
		"go env -w GOPROXY=https://evil.example,direct && go install example.com/zz@v1.0.0": "custom_registry",
		"go env -w GOSUMDB=off; go install example.com/zz@v1.0.0":                           "custom_registry",
		"go env -w GOFLAGS=-toolexec=./w && go run example.com/zz@v1.0.0":                   "code_from_environment",
		"go env -w GONOSUMDB=example.com && go install example.com/zz@v1.0.0":               "custom_registry",
		"go env -w GOTOOLCHAIN=local GOMODCACHE=./c && go install example.com/zz@v1.0.0":    "code_from_environment",
		// P2-2: where the go command takes code from
		"GOMODCACHE=./.cache go install golang.org/x/tools/cmd/goimports@v0.24.0": "code_from_environment",
		"GOPATH=./gopath go install golang.org/x/tools/cmd/goimports@v0.24.0":     "code_from_environment",
		"GOPATH=/usr/local/go-path:/tmp/gp go install example.com/zz@v1.0.0":      "code_from_environment",
		"GOROOT=./goroot go install golang.org/x/tools/cmd/goimports@v0.24.0":     "code_from_environment",
		"GOCACHE=./.gocache go install example.com/zz@v1.0.0":                     "code_from_environment",
		"export GOMODCACHE=$PWD/vendor-cache; go install example.com/zz@v1.0.0":   "code_from_environment",
		"GOMODCACHE=${PWD}/c go install example.com/zz@v1.0.0":                    "code_from_environment",
		"GOTOOLCHAIN=go1.99.0+path go install example.com/zz@v1.0.0":              "code_from_environment",
		"GOTOOLCHAIN=path go install example.com/zz@v1.0.0":                       "code_from_environment",
		// P2-3: a checksum database other than Go's own
		`GOPROXY=https://proxy.golang.org GOSUMDB="sum.golang.org+0123abcd+AQ https://sum.evil.example" go install example.com/zz@v1.0.0`: "custom_registry",
		"GOSUMDB=sum.golang.org+0123abcd+zz go install example.com/zz@v1.0.0":                                                             "custom_registry",
		"GOSUMDB=sum.golang.org+033de0ae+Ac4zctda0e5eza go install example.com/zz@v1.0.0":                                                 "custom_registry",
		"GOSUMDB='sum.golang.org extra words' go install example.com/zz@v1.0.0":                                                           "custom_registry",
		// P3-2: the module's own repository or the local cache, not a proxy alalanet reads
		"GOPROXY=direct go install example.com/zz@v1.0.0":           "custom_registry",
		"GOPROXY=off go install example.com/zz@v1.0.0":              "custom_registry",
		"GOPROXY='direct|off' go install example.com/zz@v1.0.0":     "custom_registry",
		"GOPRIVATE=corp.example go install corp.example/zz@v1.0.0":  "custom_registry",
		"GOINSECURE=corp.example go install corp.example/zz@v1.0.0": "custom_registry",
		// P3-4: HOME and XDG_CONFIG_HOME move the go env file (and the default GOPATH and GOCACHE)
		"HOME=$PWD go install example.com/zz@v1.0.0":             "custom_registry",
		"HOME=. go install example.com/zz@v1.0.0":                "custom_registry",
		"XDG_CONFIG_HOME=./cfg go install example.com/zz@v1.0.0": "custom_registry",
		"APPDATA=.\\cfg go install example.com/zz@v1.0.0":        "custom_registry",
		// P3-5: the programs cgo and gccgo run
		"CC=./evilcc CGO_ENABLED=1 go install example.com/zz@v1.0.0":                       "code_from_environment",
		"CXX=/tmp/x go install example.com/zz@v1.0.0":                                      "code_from_environment",
		"CC=$CCX go install example.com/zz@v1.0.0":                                         "code_from_environment",
		"go install -compiler=gccgo -gccgoflags=all=-fplugin=./x.so example.com/zz@v1.0.0": "code_from_environment",
		"CGO_LDFLAGS=-fuse-ld=./evil go install example.com/zz@v1.0.0":                     "code_from_environment",
		"CGO_CFLAGS=-fplugin=./p.so go install example.com/zz@v1.0.0":                      "code_from_environment",
		"go install -compiler=gccgo -gccgoflags=-fplugin=./x.so example.com/zz@v1.0.0":     "code_from_environment",
		"go install -compiler gccgo -gccgoflags '-B ./bin' example.com/zz@v1.0.0":          "code_from_environment",
	} {
		_, codes := codesOf(line)
		if !slices.Contains(codes, code) {
			t.Errorf("ParseLine(%q): codes %q; want %s", line, codes, code)
		}
	}
}

// What the go command takes from a trusted place stays an allow: the default proxy and database (and the official
// China alias of the database), the user's own Go folders, a compiler named by its system path.
func TestGoR2StillRead(t *testing.T) {
	const key = "sum.golang.org+033de0ae+" + "Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"
	for _, line := range []string{
		"GOSUMDB=sum.golang.google.cn go install example.com/zz@v1.0.0",
		`GOSUMDB="sum.golang.org https://sum.golang.google.cn" go install example.com/zz@v1.0.0`,
		"GOSUMDB=" + key + " go install example.com/zz@v1.0.0",
		`GOSUMDB="` + key + ` https://sum.golang.google.cn" go install example.com/zz@v1.0.0`,
		"GOPROXY=https://proxy.golang.org,direct go install example.com/zz@v1.0.0",
		"GOMODCACHE=$HOME/go/pkg/mod GOPATH=~/go GOCACHE=/home/u/.cache/go-build go install example.com/zz@v1.0.0",
		"GOROOT=/usr/local/go go install example.com/zz@v1.0.0",
		"GOTOOLCHAIN=local go install example.com/zz@v1.0.0",
		"GOTOOLCHAIN=go1.27.4+auto go install example.com/zz@v1.0.0",
		"CC=clang CXX=/usr/bin/clang++ go install example.com/zz@v1.0.0",
		"HOME=/home/u go install example.com/zz@v1.0.0",
		"go env -u GOPROXY && go install example.com/zz@v1.0.0",
		"GOMODCACHE=./c go build ./... && CC=./x go test ./...",
		"go env GOPROXY=https://zz-evil.example; go install example.com/zz@v1.0.0", // only -w writes
	} {
		targets, codes := codesOf(line)
		if len(codes) > 0 || !strings.Contains(line, "go install") && len(targets) > 0 {
			t.Errorf("ParseLine(%q): codes %q", line, codes)
		}
		if strings.Contains(line, "go install") && !slices.Contains(targets, "go:example.com/zz@v1.0.0") {
			t.Errorf("ParseLine(%q): targets %q", line, targets)
		}
	}
}

// P3-2: a module the line fetches from somewhere other than the public proxy — its own repository, the local cache,
// a proxy of the user's, or a path marked private — is never named as a target: the check would send its path to
// proxy.golang.org and sum.golang.org and sign it into the public log. The line holds by its reason alone.
func TestGoR2PrivatePathsNotNamed(t *testing.T) {
	for _, line := range []string{
		"GOPRIVATE=corp.example go install corp.example/zz@v1.0.0",
		"GONOPROXY=corp.example/* go install corp.example/zz@v1.0.0",
		"GONOSUMDB=corp.example go install corp.example/zz@v1.0.0",
		"GOINSECURE=corp.example go install corp.example/zz@v1.0.0",
		"GOPROXY=direct go install corp.example/zz@v1.0.0",
		"GOPROXY=off go install corp.example/zz@v1.0.0",
		"GOPROXY=https://athens.corp.example go install corp.example/zz@v1.0.0",
		"GOSUMDB=off go install corp.example/zz@v1.0.0",
		"go env -w GOPRIVATE=corp.example && go install corp.example/zz@v1.0.0",
	} {
		// since round 3 the path is named go-private:, which the server never reads from a registry (P3-4)
		targets, codes := codesOf(line)
		if slices.ContainsFunc(targets, func(t string) bool { return strings.HasPrefix(t, "go:") }) || !slices.Contains(codes, "custom_registry") {
			t.Errorf("ParseLine(%q): targets %q codes %q; want no go: target and custom_registry", line, targets, codes)
		}
	}
	// a pattern that does not match the module keeps the target
	if targets, codes := codesOf("GOPRIVATE=other.example go install corp.example/zz@v1.0.0"); len(codes) > 0 || len(targets) != 1 {
		t.Errorf("GOPRIVATE for another host: %q %q", targets, codes)
	}
}
