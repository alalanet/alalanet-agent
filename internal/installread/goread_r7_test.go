package installread

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// ECO-1 Go, round 7 (batch P3 review A of 2026-11-18, P3-5a/P3-5b): the links a line makes are followed as the
// filesystem follows them — again through a link made inside another or before its own target became one, the
// longest link first, a loop unknown — and ln is read with its options (-t DIR, --target-directory, -S SUFFIX, -T,
// several targets into a folder, a relative target against the link's folder, a hard link). A write is also judged
// where it lands if a link named an existing folder (ln into it), so a link cannot move a config write out of sight.

func TestGoR7LinksFollowedWhole(t *testing.T) {
	const run = " && go run example.com/zz@v1.0.0"
	const w = "echo GOFLAGS=-toolexec=./w > "
	for _, line := range []string{
		// P3-5b: a link made inside an earlier link, and one made before its own target became a link
		"ln -s /srv/x /tmp/a && ln -s ~/.config/go /tmp/a/b && " + w + "/tmp/a/b/env" + run,
		"ln -s /tmp/g /tmp/h && ln -s ~/.config/go /tmp/g && " + w + "/tmp/h/env" + run,
		"ln -s /tmp/g /tmp/h && ln -s /tmp/f /tmp/g && ln -s ~/.config/go /tmp/f && " + w + "/tmp/h/env" + run,
		"ln -s /srv/x /tmp/a && ln -s /srv/y /tmp/a/b && ln -s ~/.config /tmp/a/b/c && cp -r zz/. /tmp/a/b/c/go" + run,
		// a loop of links: where the write lands is unknown
		"ln -s /tmp/b /tmp/a && ln -s /tmp/a /tmp/b && " + w + "/tmp/a/q" + run,
		// ln's options: -t DIR in every spelling, -S SUFFIX before the link, several targets into a folder
		"ln -s -t /tmp ~/.config/go && cp zz.env ~/.config/go/env" + run,
		"ln -s -t /tmp ~/.config/go && cp -r zz/. /tmp/go" + run,
		"ln -s -t/tmp ~/.config/go && cp -r zz/. /tmp/go" + run,
		"ln -s --target=/tmp ~/.config/go && cp -r zz/. /tmp/go" + run,
		"cd /tmp && ln -s ~/.config/go && cp -r zz/. /tmp/go" + run,
		// -t with a second target last: the link into the folder, not the last word, carries the write
		"ln -s -t/tmp ~/.config/go /srv/zz && cp -r zz/. /tmp/go" + run,
		"ln -s --target=/tmp ~/.config/go /srv/zz && cp -r zz/. /tmp/go" + run,
		// a hard link's relative target is the current folder's, not the link's
		"cd ~/.config/go && ln env /tmp/e && cat z > /tmp/e" + run,
		"ln -st /tmp ~/.config/go && cp -r zz/. /tmp/go" + run,
		"ln -st/tmp ~/.config/go && cp -r zz/. /tmp/go" + run,
		"ln -s --target-directory=/tmp ~/.config/go && cp -r zz/. /tmp/go" + run,
		"ln -s --target-directory /tmp ~/.config/go && cp -r zz/. /tmp/go" + run,
		"ln -s ~/.config/go -S .bak /tmp/g && " + w + "/tmp/g/env" + run,
		"ln -s ~/.config/go --suffix=.bak /tmp/g && cp -r zz/. /tmp/g" + run,
		"ln -s ~/.config/go /srv/y /tmp/d && cp -r zz/. /tmp/d/go" + run,
		"ln -s -- ~/.config/go /tmp/g && cp -r zz/. /tmp/g" + run,
		"ln -sfnT ~/.config/go /tmp/g && cp -r zz/. /tmp/g" + run,
		"ln --symbolic --force ~/.config/go /tmp/g && cp -r zz/. /tmp/g" + run,
		// a relative target is the link's folder's, not the current one's
		"ln -s ../.config/go ~/zz && cp -r w/. ~/zz" + run,
		"ln -s .config/go ~/zz && cp -r w/. ~/zz" + run,
		"cd /tmp && ln -s ../root/.config/go /srv/g && cp -r w/. /srv/g" + run,
		// a link into an existing folder: the write is judged where it lands either way
		"ln -s /tmp/q ~/.config && cp -r zz/. ~/.config/go" + run,
		"ln -s /tmp/q ~/.config/go && " + w + "~/.config/go/env" + run,
		// a hard link to the env file, and POSIX link
		"ln ~/.config/go/env zzenv && " + w + "zzenv" + run,
		"link ~/.config/go/env zzenv && " + w + "zzenv" + run,
		"ln -f ~/.config/go/env /tmp/e && cat zz > /tmp/e" + run,
		// through a wrapper, and after a cd
		"sudo ln -s ~/.config/go /tmp/g && sudo cp -r zz/. /tmp/g" + run,
		"cd /tmp && ln -s ~/.config/go g && cp -r ../zz/. g" + run,
		"cd /tmp && ln -s /srv/x a && ln -s ~/.config/go a/b && " + w + "a/b/env" + run,
		// cp -s, cp -l: links of what cp would copy; the g-prefixed coreutils; wrappers and a path to ln
		"cp -s ~/.config/go/env zz && " + w + "zz" + run,
		"cp -l ~/.config/go/env zz && " + w + "zz" + run,
		"cp -rs ~/.config/go /tmp/g && " + w + "/tmp/g/env" + run,
		"cp --symbolic-link ~/.config/go/env /tmp/e && cat z > /tmp/e" + run,
		"cp -al ~/.config/go /tmp/g && cat z > /tmp/g/env" + run,
		"cp --link -r ~/.config/go /tmp/g && cat z > /tmp/g/env" + run,
		"gln -s ~/.config/go /tmp/g && cp -r zz/. /tmp/g" + run,
		"gcp -s ~/.config/go/env /tmp/e && cat z > /tmp/e" + run,
		"env ln -s ~/.config/go /tmp/g && cp -r zz/. /tmp/g" + run,
		"/bin/ln -s ~/.config/go /tmp/g && cp -r zz/. /tmp/g" + run,
		// the other spellings of home and of the config folder, a link to / and to ~
		"ln -s \"$HOME/.config/go\" /tmp/g && cp -r zz/. /tmp/g" + run,
		"ln -s ${HOME}/.config/go /tmp/g && cp -r zz/. /tmp/g" + run,
		"ln -s /root/.config/go /tmp/g && cp -r zz/. /tmp/g" + run,
		"ln -s ../../root/.config/go /tmp/x/g && cp -r zz/. /tmp/x/g" + run,
		"ln -s ~ /tmp/h && cp -r zz/. /tmp/h/.config/go" + run,
		"ln -s / /tmp/r && cp -r zz/. /tmp/r/root/.config/go" + run,
		"ln --sym ~/.config/go /tmp/g && cp -r zz/. /tmp/g" + run,
		"ln --tar=/tmp -s ~/.config/go && cp -r zz/. /tmp/go" + run,
		"ln -s ~/.config/go /tmp/g/ && cp -r zz/. /tmp/g/go" + run,
		"ln -s ~/.config/go && cp -r zz/. go" + run,
		"ln -s ~/.config /tmp/c && pushd /tmp/c/go && " + w + "env && popd" + run,
	} {
		targets, codes := codesOf(line)
		if len(codes) == 0 || slices.ContainsFunc(targets, func(t string) bool { return strings.HasPrefix(t, "go:") }) {
			t.Errorf("ParseLine(%q): targets %q codes %q; want a hold and no go: target", line, targets, codes)
		}
	}
	// honest lines: links that move nothing into the go config folder
	for _, line := range []string{
		"ln -s ~/bin/tool tool && go install golang.org/x/tools/gopls@latest",
		"ln -s /srv/a /tmp/a && ln -s /srv/b /tmp/a/b && echo x > /tmp/a/b/out && go install golang.org/x/tools/gopls@latest",
		"ln -s -t ~/bin ./zz && echo x > ~/bin/zz.log && go install golang.org/x/tools/gopls@latest",
		"ln zz.txt zz2.txt && echo x > zz2.txt && go install golang.org/x/tools/gopls@latest",
		"ln -s ../shared src/shared && cp -r x/. src/shared && go install golang.org/x/tools/gopls@latest",
		"ln -sf /opt/go/bin/go ~/bin/go && go install golang.org/x/tools/gopls@latest",
		"cd /tmp && ln -s /srv/data d && echo x > d/out && cd - && go install golang.org/x/tools/gopls@latest",
		"cp -rs ~/src/lib vendor/lib && echo x > vendor/lib/new.txt && go install golang.org/x/tools/gopls@latest",
		"cp -r ~/.config/go/. /tmp/backup && go install golang.org/x/tools/gopls@latest",
		"ln -s /tmp/b /tmp/a && ln -s /tmp/a /tmp/b && go install golang.org/x/tools/gopls@latest",
		// making a link writes the link, not through it
		"ln -s ~/.config/go /tmp/g && go install golang.org/x/tools/gopls@latest",
		"ln -sfn ~/.config/go ~/goconf && go install golang.org/x/tools/gopls@latest",
		"cp -rs ~/.config/go /tmp/g && go install golang.org/x/tools/gopls@latest",
	} {
		if targets, codes := codesOf(line); len(codes) > 0 || len(targets) != 1 {
			t.Errorf("ParseLine(%q): targets %q codes %q", line, targets, codes)
		}
	}
}

// P3-5a: one line, one reading — the links are tried longest first, never in a map's order.
func TestGoR7LinksSameEveryRun(t *testing.T) {
	for _, line := range []string{
		"ln -s ~/.config/go /tmp/a/b && ln -s /srv/x /tmp/a && echo GOFLAGS=-toolexec=./w > /tmp/a/b/env && go run example.com/zz@v1.0.0",
		"ln -s /srv/x /tmp/a && ln -s ~/.config/go /tmp/a/b && ln -s /srv/y /tmp/a/b/c && echo x > /tmp/a/b/c/d && go run example.com/zz@v1.0.0",
		"ln -s /a /t/1 && ln -s /b /t/1/2 && ln -s /c /t/1/2/3 && ln -s ~/.config /t/1/2/3/4 && cp -r z/. /t/1/2/3/4/go && go run example.com/zz@v1.0.0",
	} {
		seen := map[string]int{}
		for range 200 {
			tg, codes := codesOf(line)
			seen[fmt.Sprint(tg, codes)]++
		}
		if len(seen) != 1 {
			t.Errorf("ParseLine(%q): %d readings in 200 runs: %v", line, len(seen), seen)
		}
		for k := range seen {
			if !strings.Contains(k, "go-private:") && !strings.Contains(k, "[") {
				t.Logf("%s", k)
			}
		}
	}
}
