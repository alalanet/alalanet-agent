package installread

import (
	"slices"
	"strings"
	"testing"
)

// In an npm, pnpm, Yarn or bun line the subcommand is the first runner verb (exec, x, dlx) or install verb (i, install,
// add); a later word equal to one of them is a package. The reader used to look for a runner verb anywhere first, so a
// package named x, exec or dlx after an install verb left the packages before it unread: no target, nothing to hold
// (RT-1 review, round 2). A word that is the value of a long option before the verb is not the verb either.
func TestVerbWordAfterTheVerbIsAPackage(t *testing.T) {
	for line, want := range map[string][]string{
		"npm install left-pad x":            {"npm:left-pad", "npm:x"},
		"pnpm add left-pad dlx":             {"npm:left-pad", "npm:dlx"},
		"bun add left-pad exec":             {"npm:left-pad", "npm:exec"},
		"npm i x":                           {"npm:x"},
		"yarn add exec":                     {"npm:exec"},
		"yarn global add x":                 {"npm:x"},
		"sudo -n npm i x":                   {"npm:x"},
		"npm --prefix x install left-pad":   {"npm:left-pad"},
		"pnpm --filter dlx add left-pad":    {"npm:left-pad"},
		"yarn --cwd exec add left-pad":      {"npm:left-pad"},
		"npm --registry x install left-pad": {"npm:left-pad"},
		// unchanged: the runner verb comes first
		"npm x left-pad":           {"npm:left-pad"},
		"npm exec -- cowsay add":   {"npm:cowsay"},
		"pnpm dlx create-vite add": {"npm:create-vite"},
		"bun x install":            {"npm:install"},
		"npm -f install x":         {"npm:x"},
	} {
		targets, _, _, _ := parseInstallLineFull(line)
		if !slices.Equal(targets, want) {
			t.Errorf("%q: targets %q, want %q", line, targets, want)
		}
	}
}

// "{}" is one word, never a brace group: xargs -I{} keeps its replacement string, so an install whose packages come
// from standard input is held as one (RT-1 review, round 2), as it is with -I %.
func TestBracePairIsAWord(t *testing.T) {
	const stdin = "install arguments come from standard input (xargs) alalanet cannot see"
	for _, line := range []string{
		"cat list.txt | xargs -I{} npm install {}",
		"cat list.txt | xargs -I {} npm install {}",
		"xargs -I{} pip install {} < requirements.txt",
		"cat list.txt | xargs -I % npm install %",
	} {
		_, unread, _, _ := parseInstallLineFull(line)
		if !slices.Contains(unread, stdin) {
			t.Errorf("%q: unread %q, want the standard-input reason", line, unread)
		}
	}
	if sl := splitShell("find . -name '*.tmp' -exec rm {} +"); len(sl.segs) != 1 || !slices.Contains(sl.segs[0].words, "{}") {
		t.Errorf("find -exec rm {} +: %+v", sl.segs)
	}
	// a brace group is still read as one: its commands run
	for line, want := range map[string]string{
		"{ npm i left-pad; }":                    "npm:left-pad",
		"{ npm i left-pad; } 2>&1 | tail -5":     "npm:left-pad",
		"if true; then { pip install rich; } fi": "pypi:rich",
	} {
		if targets, _, _, _ := parseInstallLineFull(line); !slices.Contains(targets, want) {
			t.Errorf("%q: targets %q, want %s", line, targets, want)
		}
	}
	if w := splitShell("echo a{}b").segs[0].words; strings.Join(w, " ") != "echo a{}b" {
		t.Errorf("a{}b: %q", w)
	}
}

// The wrapper and shell forms alalanet-agent's local filter used to read with its own copies of the server's tables
// (the independent review's mutants of its first round): the shared reader must see the install through each. The
// agent's corpus test cannot tell, since it compares the agent with the server and both read through this code.
func TestWrapperAndShellFormsAreRead(t *testing.T) {
	for _, line := range []string{
		`eval "npm i left-pad"`, "command npm i left-pad", "nohup npm i left-pad &", "corepack pnpm add left-pad",
		"! npm i left-pad", "env -C /tmp npm i left-pad", "env - npm i left-pad", "timeout 1.5m npm i left-pad",
		"timeout -s KILL 60 npm i left-pad", "xargs -I % npm i left-pad", "echo `npm i left-pad`", "echo $(npm i left-pad)",
		"cd app\nnpm i left-pad", "(npm i left-pad)", `"npm" i left-pad`, "NPM i left-pad", `C:\nodejs\NPM.CMD i left-pad`,
	} {
		if targets, _, _, _ := parseInstallLineFull(line); !slices.Contains(targets, "npm:left-pad") {
			t.Errorf("%q: targets %q", line, targets)
		}
	}
	// "--" ends a wrapper's options: the next word is the command even when it starts with a dash (sudo runs "-u")
	if targets, unread, _, _ := parseInstallLineFull("sudo -- -u root npm i left-pad"); len(targets)+len(unread) != 0 {
		t.Errorf("sudo -- -u …: targets %q, unread %q", targets, unread)
	}
}

// An MCP entry's environment is read in the order of its sorted names, so the first reason (the code install_check
// signs) does not depend on Go's map order.
func TestEnvUnreadIsSorted(t *testing.T) {
	env := map[string]string{"NPM_CONFIG_REGISTRY": "https://evil.example", "LD_PRELOAD": "/tmp/x.so"}
	for range 32 {
		if u := EnvUnread(env); len(u) != 2 || !strings.Contains(u[0], "LD_PRELOAD") {
			t.Fatalf("%q", u)
		}
	}
}
