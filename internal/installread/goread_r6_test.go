package installread

import (
	"slices"
	"strings"
	"testing"
)

// ECO-1 Go, round 6 (review r5 of eco1-go, an internal review note, P3-1/P3-2; the
// reviewer's ln -s / cd hold cases adopted).

func TestGoR6RoutesIntoTheConfigFolder(t *testing.T) {
	for _, line := range []string{
		// a link the line makes to the folder or the file
		"ln -s ~/.config/go zzcfg && echo GOFLAGS=-toolexec=./w > zzcfg/env && go run example.com/zz@v1.0.0",
		"ln -sfn $HOME/.config zzc; printf 'GOFLAGS=-toolexec=./w\\n' >> zzc/go/env; go run example.com/zz@v1.0.0",
		"ln -s /root/.config/go/env zzenv && cat zz.txt > zzenv && go run example.com/zz@v1.0.0",
		// the current folder the line moves there, and a relative write after it
		"cd ~/.config/go && echo GOFLAGS=-toolexec=./w > env && cd - && go run example.com/zz@v1.0.0",
		"cd /root/.config && echo GOFLAGS=-toolexec=./w >> go/env && cd /tmp && go run example.com/zz@v1.0.0",
		"pushd ~/.config/go && echo GOFLAGS=-toolexec=./w > env; popd; go run example.com/zz@v1.0.0",
		"cd && echo GOFLAGS=-toolexec=./w > .config/go/env && go run example.com/zz@v1.0.0",
		"(cd ~/.config/go; echo GOFLAGS=-toolexec=./w > env) && go run example.com/zz@v1.0.0",
		"cd ~/.config/go && echo GOFLAGS=-toolexec=./w | tee env && go run example.com/zz@v1.0.0",
		"ln -sfn ~/.config zzc && cp zz.env zzc/go/ && go run example.com/zz@v1.0.0",
		"cd ? && echo x > env && go run example.com/zz@v1.0.0",
		"cd && cp -r zzcfg/. .config/go && go run example.com/zz@v1.0.0",
		// a cd the line does not show: where the relative write lands is unknown
		"cd $D && echo GOFLAGS=-toolexec=./w > env && go run example.com/zz@v1.0.0",
	} {
		targets, codes := codesOf(line)
		if len(codes) == 0 || slices.ContainsFunc(targets, func(t string) bool { return strings.HasPrefix(t, "go:") }) {
			t.Errorf("ParseLine(%q): targets %q codes %q; want a hold and no go: target", line, targets, codes)
		}
	}
	// the honest controls stay clean
	for _, line := range []string{
		"cd ~/src/zz && echo x > out.txt && go install golang.org/x/tools/gopls@latest",
		"ln -s ~/bin/tool tool && go install golang.org/x/tools/gopls@latest",
		"cd /tmp && echo x > a && cd - && go install golang.org/x/tools/gopls@latest",
		"cd ~/.config/go && cd - && echo x > env && go install golang.org/x/tools/gopls@latest",
		"pushd ~/.config/go && popd && echo x > env && go install golang.org/x/tools/gopls@latest",
		"pushd build && cp ../x . && popd && go install golang.org/x/tools/gopls@latest",
		"mkdir -p ~/.config/zz && cd ~/.config/zz && echo x > zz.toml && go install golang.org/x/tools/gopls@latest",
	} {
		if targets, codes := codesOf(line); len(codes) > 0 || len(targets) != 1 {
			t.Errorf("ParseLine(%q): targets %q codes %q", line, targets, codes)
		}
	}
}

// P3-2: a line that moves the go env file (GOENV, HOME, XDG_CONFIG_HOME, APPDATA) names its module go-private:.
func TestGoR6MovedEnvFileIsPrivate(t *testing.T) {
	for _, line := range []string{
		"GOENV=/tmp/zz.env go install corp.example/zz@v1.0.0",
		"go env -w GOENV=/tmp/zz.env && go install corp.example/zz@v1.0.0",
		"HOME=/tmp/zzhome go install corp.example/zz@v1.0.0",
		"XDG_CONFIG_HOME=/tmp/zzcfg go install corp.example/zz@v1.0.0",
	} {
		if targets, _ := codesOf(line); !slices.Contains(targets, "go-private:corp.example/zz@v1.0.0") {
			t.Errorf("ParseLine(%q): targets %q", line, targets)
		}
	}
}
