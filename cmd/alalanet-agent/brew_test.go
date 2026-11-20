package main

import "testing"

// ECO-1, Homebrew taps: the hook sends a brew line that names a third-party tap (the server checks the tap's GitHub
// repository) or that moves Homebrew's sources, and still sends nothing for an official formula alone.
func TestHookSendsBrewTaps(t *testing.T) {
	f := &fakeHook{}
	srv := f.server(t)
	for _, cmd := range []string{
		"brew install u/tap/formula", "brew tap u/r", "brew tap u/r https://gitlab.com/u/homebrew-r.git", "brew trust u/r",
		"brew install --cask u/r/app", "HOMEBREW_NO_REQUIRE_TAP_TRUST=1 brew install u/r/x", "brew install ./x.rb",
		// round 2 (review-1117): a leading -v, brew exec and x, a tap then a name, a variable command word, a moved brew.env
		"brew -v install u/r/x", "brew x --formulae=u/r/x -- x", "brew exec npx -y zz-evil-pkg",
		"brew tap u/r && brew install x", "brew $CMD u/r/x", "HOME=./h brew install wget",
		// round 3 (re-review): a trailing comma in --formulae, brew's other runners and wrappers
		"brew x --formulae=u/r/x, x", "brew sandbox-exec . -- npx -y zz-evil-pkg", "brew bundle exec npx -y zz-evil-pkg",
		"brew sh -c 'npx -y zz-evil-pkg'", "brew as-brew-user install u/r/x", "SUDO_ASKPASS=./a brew install wget",
		// round 4 (re-review): OptionParser's spellings, hyperfine's options, an alias defined and used, a script into brew sh
		"brew sh -vc 'npx -y zz-evil-pkg'", "brew sandbox-exec --den /tmp/s -- npx -y zz-evil-pkg",
		"brew benchmark --exec -- '--prepare=npx -y zz-evil-pkg' true", "brew alias i=install && brew i u/r/x",
		"echo 'npx -y zz-evil-pkg' | brew sh", "brew prof --sta install u/r/x",
	} {
		before := len(f.calls())
		_ = runCodex(t, srv.URL, codexInput("Bash", cmd))
		if len(f.calls()) != before+1 {
			t.Errorf("not sent: %q", cmd)
		}
	}
	for _, cmd := range []string{"brew install wget", "brew install --cask firefox", "brew upgrade", "brew tap homebrew/cask-fonts"} {
		before := len(f.calls())
		_ = runCodex(t, srv.URL, codexInput("Bash", cmd))
		if len(f.calls()) != before {
			t.Errorf("sent although nothing is read: %q", cmd)
		}
	}
}
