package installread

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// ECO-1, Homebrew taps (research work-1117/eco1-next §6.2). A third-party tap user/repo is the git repository a formula
// or cask comes from, and its Ruby runs with the user's rights at install ("Code in a tap can run with your user's
// privileges", docs.brew.sh/Taps). brew install|reinstall|upgrade user/repo/name, brew tap user/repo [URL], brew
// trust user/repo[/name] and brew exec|x --formulae=user/repo/name name the tap; its repository on GitHub is
// user/homebrew-repo (Homebrew's naming rule: the one-argument brew tap "is GitHub-only"), the target
// github:<user>/homebrew-<repo> that the existing GitHub check judges. Official taps (homebrew/*, linuxbrew/core) and
// bare names (homebrew-core and homebrew-cask, through Homebrew's API) are not read: no target and no reason, as
// before. Options are Homebrew 7.0.14's: Library/Homebrew/cmd/install.rb, reinstall.rb, upgrade.rb, tap.rb and
// trust.rb (cmd_args), cli/parser.rb (global_options, global_cask_options), command_constants.rb (instal is install, x
// is exec), brew.sh (a leading -v moves to the end), brew.rb (the command is the first word that is no help flag),
// cmd/exec.sh and utils/cmd.sh (brew exec's own words).

// brewGlobalSwitches: the options cli/parser.rb gives every command (global_options).
const brewGlobalSwitches = "-d --debug -q --quiet -v --verbose"

// brewCaskValues: the cask options of install, reinstall and upgrade that take a value (global_cask_options: the
// directory flags and the comma list --language).
const brewCaskValues = "--appdir --appimagedir --audio-unit-plugindir --colorpickerdir --dictionarydir --fontdir " +
	"--input-methoddir --internet-plugindir --keyboard-layoutdir --language --mdimporterdir --prefpanedir --qlplugindir " +
	"--screen-saverdir --servicedir --vst-plugindir --vst3-plugindir"

// brewOptions: per command, the options that take no value and those that take one (OptionParser reads a required
// argument from "=" or from the next word). --[no-]binaries is both spellings. --no-quarantine is gone from 7.0.14's
// parser (Homebrew 7 refuses the line, nothing installs) but read by the Homebrew before it: a switch, not a reason —
// as a reason it held only official casks, whose items are not read anyway (round 3).
var brewOptions = map[string]struct{ switches, values map[string]bool }{
	"install": {wordSet(brewGlobalSwitches + " --HEAD --binaries --no-binaries --adopt --as-dependency --ask --build-bottle " +
		"--build-from-source --cask --casks --debug-symbols --display-times --dry-run --fetch-HEAD --force --force-bottle " +
		"--formula --formulae --git --ignore-dependencies --include-test --interactive --keep-tmp --no-ask --no-quarantine " +
		"--only-dependencies --overwrite --require-sha --skip-cask-deps --skip-link --skip-post-install --yes --zap " +
		"-f -g -i -n -s -y"), wordSet(brewCaskValues + " --bottle-arch --cc --env")},
	"reinstall": {wordSet(brewGlobalSwitches + " --binaries --no-binaries --adopt --ask --build-from-source --cask --casks " +
		"--debug-symbols --display-times --force --force-bottle --formula --formulae --git --interactive --keep-tmp " +
		"--no-ask --no-quarantine --require-sha --skip-cask-deps --yes --zap -f -g -i -s -y"), wordSet(brewCaskValues)},
	"upgrade": {wordSet(brewGlobalSwitches + " --binaries --no-binaries --ask --build-from-source --cask --casks " +
		"--debug-symbols --display-times --dry-run --fetch-HEAD --force --force-bottle --formula --formulae --greedy " +
		"--greedy-auto-updates --greedy-latest --interactive --keep-tmp --no-ask --no-quarantine --no-quit --overwrite --require-sha " +
		"--skip-cask-deps --vulnerable --yes -f -g -i -n -s -y"), wordSet(brewCaskValues + " --min-version --minimum-version --severity")},
	"tap":   {wordSet(brewGlobalSwitches + " --custom-remote --eval-all --force --repair -f"), map[string]bool{}},
	"trust": {wordSet(brewGlobalSwitches + " --cask --casks --command --commands --formula --formulae --tap --taps"), wordSet("--json")},
}

// brewHelp: the words that make any brew command print its help instead (brew.rb's help_flag_list; OptionParser -h).
var brewHelp = wordSet("-h --help --usage -?")

// brewName: a GitHub owner or repository name as a tap's parts may be.
var brewName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// brewTapTarget: the target of tap user/repo, or "" for an official tap or a word that is no tap name (brewTap).
func brewTapTarget(tap string) string {
	t, _ := brewTap(tap)
	return t
}

// brewTap: the target of tap user/repo — github:<user>/homebrew-<repo>, in lower case — and whether it is an official
// tap, which is not read. Tap.fetch (tap.rb) takes off one of the prefixes homebrew- and linuxbrew- as written
// (HOMEBREW_OFFICIAL_REPO_PREFIXES_REGEX, case-sensitive: u/Homebrew-x is the repository homebrew-Homebrew-x) and names
// the tap in lower case; homebrew/* and linuxbrew/core (Linuxbrew/homebrew, the core tap) are Homebrew's own.
// target "" and official false: a word that is no tap name alalanet can place (u+x/r, u/.., u/r:x).
func brewTap(tap string) (target string, official bool) {
	u, r, ok := strings.Cut(tap, "/")
	if !ok {
		return "", false
	}
	if s, cut := strings.CutPrefix(r, "homebrew-"); cut {
		r = s
	} else if s, cut := strings.CutPrefix(r, "linuxbrew-"); cut {
		r = s
	}
	lu, lr := strings.ToLower(u), strings.ToLower(r)
	switch {
	case lu == "homebrew", lu == "linuxbrew" && (lr == "core" || lr == "homebrew"):
		return "", true
	case !brewName.MatchString(u) || !brewName.MatchString(r) || u == "." || u == ".." || r == "." || r == "..":
		return "", false
	}
	return "github:" + lu + "/homebrew-" + lr, false
}

// brewOfficialRemote: the GitHub repository an official tap clones from (Tap#default_remote; CoreTap's for
// linuxbrew/core and homebrew/homebrew), as a target; "" for a tap that is not official.
func brewOfficialRemote(tap string) string {
	if _, official := brewTap(tap); !official {
		return ""
	}
	_, r, _ := strings.Cut(tap, "/")
	if s, cut := strings.CutPrefix(r, "homebrew-"); cut {
		r = s
	} else if s, cut := strings.CutPrefix(r, "linuxbrew-"); cut {
		r = s
	}
	// the official linuxbrew taps are linuxbrew/core and linuxbrew/homebrew (brewTap): both the core tap, as homebrew/homebrew
	if r = strings.ToLower(r); r == "homebrew" {
		r = "core"
	}
	return "github:homebrew/homebrew-" + r
}

// brewGitHubURL: the target of a tap's URL on GitHub (https://github.com/x/y(.git), git@github.com:x/y.git,
// ssh://git@github.com/x/y), or "".
var brewGitHubURL = regexp.MustCompile(`^(?i:(?:https?://|git://|ssh://git@)github\.com/|git@github\.com:)([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$`)

// brewURLTarget: the GitHub repository a tap's URL names, in lower case, or "" for any other remote — another host, a
// path, a URL with a "." or ".." segment (the remote git cleans it to is not the one the URL spells).
func brewURLTarget(u string) string {
	m := brewGitHubURL.FindStringSubmatch(u)
	if m == nil || m[1] == "." || m[1] == ".." || m[2] == "." || m[2] == ".." {
		return ""
	}
	return "github:" + strings.ToLower(m[1]) + "/" + strings.ToLower(m[2])
}

// brewWords: brew's words as brew.sh passes them on — a leading -v moves to the end ("Shift the -v to the end of the
// parameter list"), so brew -v install x runs install x -v — and the command's own name (x is exec).
func brewWords(rest []string) []string {
	if len(rest) > 0 && rest[0] == "-v" {
		rest = append(slices.Clone(rest[1:]), "-v")
	}
	if len(rest) > 0 && rest[0] == "x" {
		rest = append([]string{"exec"}, rest[1:]...)
	}
	return rest
}

// brewExec reads brew exec's own words (cmd/exec.sh, utils/cmd.sh: bash, exact words): the --formulae items it installs
// (a comma list, after "=" or as the next word), and the command it runs after them (after "--", or the first word that
// is no option of exec's). ok false: exec runs nothing — its help (-h, -?, --help, --usage, a short cluster with h), an
// option it does not know, an option without its value, an empty --formulae entry; odd: the word, when it is an option
// (a reason, round 4: never "nothing" for a word the reader cannot place).
func brewExec(args []string) (formulae, command []string, ok bool, odd string) {
	list := func(v string) bool {
		if v == "" {
			return false // "`--formulae` requires a comma-separated formula list."
		}
		for _, f := range brewFormulaeList(v) {
			if f = strings.TrimSpace(f); f == "" {
				return false // "`--formulae` entries must not be empty."
			}
			formulae = append(formulae, f)
		}
		return true
	}
	for i := 0; i < len(args); i++ {
		x := args[i]
		short := len(x) > 1 && x[0] == '-' && x[1] != '-'
		switch {
		case brewHelp[x] || short && strings.Contains(x, "h"):
			return nil, nil, false, ""
		case x == "--verbose" || x == "--quiet" || x == "--debug" || short && strings.Trim(x[1:], "dqv") == "":
		case strings.HasPrefix(x, "--formulae="):
			if !list(x[len("--formulae="):]) {
				return nil, nil, false, ""
			}
		case x == "--formulae" || x == "--sandbox":
			if i+1 == len(args) || strings.HasPrefix(args[i+1], "-") {
				return nil, nil, false, x // odie: the option requires a value
			}
			if i++; x == "--formulae" && !list(args[i]) {
				return nil, nil, false, ""
			}
		case strings.HasPrefix(x, "--sandbox="), x == "--deny-network":
		case x == "--":
			return formulae, args[i+1:], true, ""
		case strings.HasPrefix(x, "--"):
			return nil, nil, false, x // "Unknown option"
		default:
			return formulae, args[i:], true, ""
		}
	}
	return formulae, nil, true, ""
}

// brewFormulaeList splits a --formulae value as exec.sh does, `IFS=',' read -r -a formulae <<<"${formulae_arg}"`:
// read takes the first line, splits it at each comma and ends the list at a trailing comma without an empty field
// (measured with bash 3.2.57 and 5.2.15: "a," is [a], "a,," is [a ""], "," is [""]). The empty pieces left are
// exec.sh's odie ("entries must not be empty"), judged by the caller after trimming.
func brewFormulaeList(v string) []string {
	if v, _, _ = strings.Cut(v, "\n"); v == "" {
		return nil // a first line that is empty: read gives no field, exec looks the command's formula up (round 3)
	}
	pieces := strings.Split(v, ",")
	if n := len(pieces); n > 1 && pieces[n-1] == "" {
		pieces = pieces[:n-1]
	}
	return pieces
}

// brewDashCommands: the brew commands spelled like an option (brew.sh's and command_constants.rb's names); any other
// option word in the command's place makes brew.rb refuse the line, a reason for the reader (round 4).
var brewDashCommands = wordSet("--version -v --prefix --cellar --repository --repo --cache --caskroom --env --config " +
	"--taps -S")

// brewUnwrap: the brew command after brewWords and the wrappers that run a brew command — as-brew-user and
// as-console-user (utils/as_user.sh, bash: past their help and the common options, brew "$@"), debugger and prof (Ruby:
// brewParse with their own options, then brew.rb with the named words). help: a wrapper's help, nothing runs. odd: the
// option words a wrapper does not place exactly (brewParse; a word as-*-user does not know is the command, which
// brewTargets judges). An empty result: a wrapper without its command (xargs may give it). deep: more than five wrappers,
// which brewTargets holds (nested too deep).
func brewUnwrap(rest []string) (words []string, deep, help bool, odd []string) {
	for depth := 0; depth < 5; depth++ {
		if rest = brewWords(rest); len(rest) == 0 {
			return rest, false, false, odd
		}
		switch rest[0] {
		case "as-brew-user", "as-console-user":
			i := 1
			for ; i < len(rest); i++ {
				x := rest[i]
				short := len(x) > 1 && x[0] == '-' && x[1] != '-'
				if brewHelp[x] || short && strings.Contains(x, "h") {
					return nil, false, true, odd // homebrew-command-help
				}
				if !brewGlobalSwitch(x) {
					break
				}
			}
			rest = rest[i:]
		case "debugger", "prof":
			own := brewDebuggerOpts
			if rest[0] == "prof" {
				own = brewProfOpts
			}
			b := brewParse(rest[1:], own)
			odd = append(odd, b.odd...)
			if b.help {
				return nil, false, true, odd
			}
			rest = b.named
		default:
			return rest, false, false, odd
		}
	}
	return nil, true, false, odd // wrappers nested past any honest line
}

// brewAliasLine: what brew alias [--edit] NAME=COMMAND defines (cmd/alias.rb: one named word; aliases/alias.rb writes a
// bash script "#{command} $*", command "brew VALUE", or VALUE without its "!" or "%"): the alias's name and the line its
// script runs, which the use's words complete; "" when the words define nothing (brew alias NAME shows it). odd: the
// option words not placed exactly.
func brewAliasLine(args []string) (name, line string, odd []string) {
	b := brewParse(args, brewAliasOpts)
	if b.help || len(b.named) == 0 {
		return "", "", b.odd
	}
	n, v, ok := strings.Cut(b.named[0], "=")
	if !ok || n == "" {
		return "", "", b.odd
	}
	if strings.HasPrefix(v, "!") || strings.HasPrefix(v, "%") {
		return n, v[1:], b.odd
	}
	return n, "brew " + v, b.odd
}

// brewRuns: what a brew command runs of its words for runsWhat (ECO-1-BREW rounds 2–4, Homebrew 7.0.14), the Ruby ones
// parsed as OptionParser does (brewParse):
//   - exec|x [--formulae=…] [--] COMMAND… (cmd/exec.sh);
//   - sandbox-exec [--deny-network] PATH COMMAND… (cmd/sandbox-exec.rb: Sandbox.run_command(*named.drop(1)));
//   - bundle [options] exec COMMAND… (bundle/subcommand/exec.rb; the subcommand is the first named word);
//   - sh -c|--cmd=SCRIPT, the last one (dev-cmd/sh.rb: the preferred shell -c SCRIPT); sh FILE and ruby (dev-cmd/ruby.rb)
//     run a file or Ruby code, which the reader does not read for bash FILE and ruby either (brewRunners: xargs);
//   - benchmark --exec WORD… (dev-cmd/benchmark.rb: hyperfine runs its commands in a shell, brewHyperfine);
//   - alias NAME=COMMAND: the bash line the alias's script runs (brewAliasLine).
//
// The wrappers that run a brew command (brewUnwrap) are read through.
func brewRuns(rest []string) (how int, script string, words []string) {
	rest, _, help, _ := brewUnwrap(rest)
	if help || len(rest) == 0 {
		return runNone, "", nil
	}
	switch rest[0] {
	case "exec":
		if _, c, _, _ := brewExec(rest[1:]); len(c) > 0 {
			return runWords, "", c
		}
	case "sandbox-exec":
		if b := brewParse(rest[1:], brewSandboxOpts); !b.help && len(b.named) > 1 {
			return runWords, "", b.named[1:]
		}
	case "bundle":
		if b := brewParse(rest[1:], brewBundleOpts); !b.help && len(b.named) > 1 && b.named[0] == "exec" {
			return runWords, "", b.named[1:]
		}
	case "sh":
		if b := brewParse(rest[1:], brewShOpts); !b.help && b.vals["cmd"] != "" {
			return runLine, b.vals["cmd"], nil
		}
	case "benchmark":
		if b := brewParse(rest[1:], brewBenchmarkOpts); !b.help && b.set("exec") {
			if lines, _ := brewHyperfine(b.named); len(lines) > 0 {
				return runLine, strings.Join(lines, "\n"), nil
			}
		}
	case "alias":
		if _, line, _ := brewAliasLine(rest[1:]); line != "" {
			return runLine, line, nil
		}
	}
	return runNone, "", nil
}

// brewRunnerOdd: the option words of a brew runner the reader does not place exactly (brewParse, brewHyperfine), each a
// reason (round 4).
func brewRunnerOdd(cmd string, args []string) []string {
	switch cmd {
	case "sandbox-exec":
		return brewParse(args, brewSandboxOpts).odd
	case "bundle":
		return brewParse(args, brewBundleOpts).odd
	case "sh":
		return brewParse(args, brewShOpts).odd
	case "alias":
		_, _, odd := brewAliasLine(args)
		return odd
	case "benchmark":
		b := brewParse(args, brewBenchmarkOpts)
		odd := b.odd
		if b.set("exec") {
			_, h := brewHyperfine(b.named)
			odd = append(odd, h...)
		}
		return odd
	}
	return nil
}

// brewStdinShell: brew words that start a shell reading its standard input as a script — brew sh and brew bundle sh
// with no script or file (Utils::Shell.shell_with_prompt runs the user's shell), brew sh with "-", /dev/stdin or
// /dev/fd/0 as its FILE (safe_system(shell, FILE)), and a runner whose command is a shell
// that reads its input (brew x bash, sandbox-exec P -- sh -s, bundle exec -- zsh). fed reads the input as sh's (P2-1).
func brewStdinShell(rest []string) bool {
	if how, _, words := brewRuns(rest); how == runWords {
		cmd, r := unwrapped(words)
		return shellReadsStdin(cmd, r) || cmd == "brew" && brewStdinShell(r)
	}
	rest, _, help, _ := brewUnwrap(rest)
	if help || len(rest) == 0 {
		return false
	}
	switch rest[0] {
	case "sh":
		b := brewParse(rest[1:], brewShOpts)
		// no FILE, or a FILE that is the input: "-", /dev/stdin, /dev/fd/0 — as bash - and bash /dev/stdin (round 5)
		return !b.help && !b.set("cmd") && (len(b.named) == 0 || b.named[0] == "-" || stdinFile(b.named[0]))
	case "bundle":
		b := brewParse(rest[1:], brewBundleOpts)
		return !b.help && len(b.named) > 0 && b.named[0] == "sh"
	}
	return false
}

// brewRunners: the brew commands brewRuns reads besides exec.
var brewRunners = wordSet("sandbox-exec bundle sh ruby benchmark alias")

// brewGlobalSwitch: an option every brew command takes (cli/parser.rb global_options; utils/cmd.sh's common options),
// alone or in a short cluster, spelled exactly — the bash commands' rule (exec, as-*-user).
func brewGlobalSwitch(x string) bool {
	return x == "--verbose" || x == "--quiet" || x == "--debug" || len(x) > 1 && x[0] == '-' && x[1] != '-' && strings.Trim(x[1:], "dqv") == ""
}

// brewMaintenance: brew commands that read or update Homebrew's own state and run no formula's code — no other command
// on a line that installs (brew update && brew tap u/r && brew install x judges the tap). info, deps, outdated and the
// like load formulae (their Ruby, before Homebrew 7's tap trust) and are not here.
var brewMaintenance = wordSet("update up update-reset doctor dr cleanup config list ls search -S --version --prefix " +
	"--cellar --repository --repo --cache --caskroom --env shellenv help commands analytics")

// brewHarmless: brew's words name one of brewMaintenance.
func brewHarmless(rest []string) bool {
	rest = brewWords(rest)
	return len(rest) > 0 && brewMaintenance[rest[0]]
}

// brewTargets reads brew install|reinstall|upgrade, brew tap, brew trust and brew exec: the targets of their
// third-party taps, and a reason for a tap from another remote, an item by URL or file, a word from a variable, an
// option this table does not hold, or an item it cannot place. recognized: one of these forms; names: its items come
// from its words.
func (p *hookParse) brewTargets(rest []string) (targets []string, recognized, names bool) {
	rest, deep, help, odd := brewUnwrap(rest)
	p.brewOdd(odd)
	switch {
	case deep:
		p.miss(whyDeep) // "shell wrappers nested too deep to read"
		return nil, true, true
	case help:
		return nil, false, false
	case len(rest) == 0:
		return nil, true, true // brew as-brew-user, brew alone: under xargs the words are the command
	}
	cmd := rest[0]
	if p.brewVariable(cmd) {
		return nil, true, true // brew $CMD u/r/x: the command is a word the line does not show
	}
	if len(cmd) > 1 && cmd[0] == '-' && !brewDashCommands[cmd] && !brewHelp[cmd] {
		p.brewOdd([]string{cmd}) // brew --verbose install x: brew.rb takes the option for the command and refuses it (round 4)
		return nil, true, true
	}
	if brewRunners[cmd] {
		// the command it runs is read by runsWhat (brewRuns); under xargs the words are it
		p.brewOdd(brewRunnerOdd(cmd, rest[1:]))
		if cmd == "alias" {
			// the one named word from a variable ("$A", ${A}, e=$V): an alias the line does not show (round 5)
			if b := brewParse(rest[1:], brewAliasOpts); !b.help && len(b.named) > 0 && p.brewVariable(b.named[0]) {
				return nil, true, true
			}
			if name, line, _ := brewAliasLine(rest[1:]); name != "" {
				if p.brewAliases == nil {
					p.brewAliases = map[string]string{}
				}
				p.brewAliases[name] = line
			}
		}
		return nil, true, true
	}
	if cmd == "instal" { // command_constants.rb: "instal" => "install"
		cmd = "install"
	}
	add := func(t string) {
		if t != "" {
			targets = append(targets, t)
		}
	}
	if cmd == "exec" {
		formulae, _, ok, odd := brewExec(rest[1:])
		if odd != "" {
			p.brewOdd([]string{odd})
		}
		if !ok {
			return nil, false, false
		}
		p.brewHome()
		for _, it := range formulae {
			add(p.brewItem(it))
		}
		p.brewTapped = p.brewTapped || len(targets) > 0
		return targets, true, true
	}
	opts, ok := brewOptions[cmd]
	if !ok {
		return nil, false, false
	}
	var items []string
	for i := 1; i < len(rest); i++ {
		x := rest[i]
		switch {
		case brewHelp[x]:
			return nil, false, false // the command's help: nothing runs
		case x == "--":
			items = append(items, rest[i+1:]...)
			i = len(rest)
		case strings.HasPrefix(x, "--"):
			name, _, eq := strings.Cut(x, "=")
			switch {
			case opts.values[name]:
				if !eq {
					i++ // OptionParser's required argument: the next word
				}
			case !opts.switches[name] || eq:
				p.miss("runs brew with an option alalanet does not read (" + clip(x, 40) + ")")
			}
		case strings.HasPrefix(x, "-") && len(x) > 1:
			for _, c := range x[1:] {
				if !opts.switches["-"+string(c)] {
					p.miss("runs brew with an option alalanet does not read (" + clip(x, 40) + ")")
					break
				}
			}
		default:
			items = append(items, x)
		}
	}
	p.brewHome()
	switch cmd {
	case "tap":
		if len(items) == 0 {
			return nil, true, true // brew tap: lists the taps; under xargs the words name them
		}
		p.brewTapped = true // a tap, read or held: the installs by name after it are from it
		tap := items[0]
		if p.brewVariable(tap) {
			return nil, true, true
		}
		if strings.Count(tap, "/") != 1 {
			p.miss("installs a Homebrew item alalanet cannot read (" + clip(tap, 60) + ")")
			return nil, true, true
		}
		if len(items) > 1 {
			// the two-argument form: the tap is cloned from the URL, any git remote
			u := items[1]
			if p.brewVariable(u) {
				return nil, true, true
			}
			t := brewURLTarget(u)
			switch official := brewOfficialRemote(tap); {
			case official != "" && t == official:
				// an official tap from its own repository: not read, as the one-argument form
			case official == "" && t != "":
				add(t)
			default:
				// another host, a path, a registry's host, an official tap from any other repository
				p.brewRemote(u)
			}
			return targets, true, true
		}
		t, official := brewTap(tap)
		if t == "" && !official {
			p.miss("installs a Homebrew item alalanet cannot read (" + clip(tap, 60) + ")")
		}
		add(t)
		return targets, true, true
	case "trust":
		for _, it := range items {
			if p.brewVariable(it) {
				continue
			}
			parts := strings.Split(it, "/")
			if len(parts) < 2 || len(parts) > 3 {
				p.miss("installs a Homebrew item alalanet cannot read (" + clip(it, 60) + ")")
				continue
			}
			t, official := brewTap(parts[0] + "/" + parts[1])
			if t == "" && !official {
				p.miss("installs a Homebrew item alalanet cannot read (" + clip(it, 60) + ")")
			}
			add(t)
		}
		p.brewTapped = true
		return targets, true, true
	}
	for _, it := range items { // install, reinstall, upgrade
		add(p.brewItem(it))
	}
	if len(targets) > 0 {
		p.brewTapped = true
	} else if p.brewTapped {
		p.hits++ // brew tap u/r && brew install name: the name is the tap's (or core's), one install with the tap
	}
	return targets, true, true
}

// brewOdd gives a reason for each option word of a brew command the reader does not place exactly (round 4).
func (p *hookParse) brewOdd(words []string) {
	for _, w := range words {
		p.miss("runs brew with an option alalanet does not read (" + clip(w, 40) + ")")
	}
}

// brewAliasUse: the line a brew command runs when it names an alias the line defined before (brew alias NAME=…;
// brewAliasLine), with the command's words appended as the alias's script appends $*; ok false for any other command.
func (p *hookParse) brewAliasUse(rest []string) (line, name string, ok bool) {
	if len(p.brewAliases) == 0 {
		return "", "", false
	}
	rest, _, help, _ := brewUnwrap(rest)
	if help || len(rest) == 0 {
		return "", "", false
	}
	l, ok := p.brewAliases[rest[0]]
	if !ok {
		return "", "", false
	}
	return strings.TrimSpace(l + " " + strings.Join(rest[1:], " ")), rest[0], true
}

// brewItem reads one item of install, reinstall, upgrade or exec --formulae: the target of a user/repo/name item, ""
// for a bare name (homebrew-core or homebrew-cask through Homebrew's API, not read: ECO-1), and a reason for an item
// by URL, file or variable or one it cannot place.
func (p *hookParse) brewItem(it string) string {
	switch parts := strings.Split(it, "/"); {
	case p.brewVariable(it):
	case strings.Contains(it, "://") || strings.HasSuffix(strings.ToLower(it), ".rb") || strings.HasPrefix(it, ".") ||
		strings.HasPrefix(it, "/") || strings.HasPrefix(it, "~"):
		// a formula or cask by URL or from a file: Homebrew reads its Ruby from there
		p.miss("installs a git or URL package (" + clip(it, 60) + "): alalanet checks registry packages, not arbitrary sources")
	case len(parts) == 1:
	case len(parts) == 3:
		t, official := brewTap(parts[0] + "/" + parts[1])
		if t == "" && !official {
			p.miss("installs a Homebrew item alalanet cannot read (" + clip(it, 60) + ")")
		}
		return t
	default:
		p.miss("installs a Homebrew item alalanet cannot read (" + clip(it, 60) + ")")
	}
	return ""
}

// brewRemote notes a tap cloned from a remote that is not the GitHub repository alalanet judges: any host, the
// registries' own hosts too (registryOverride passes those; no git remote is a public registry), a path.
func (p *hookParse) brewRemote(v string) {
	host := v
	if u, err := url.Parse(v); err == nil && u.Host != "" {
		host = u.Hostname()
	}
	p.miss("installs from a custom registry or index (" + clip(host, 60) + "): alalanet judges packages on the public registries only")
}

// brewVariable notes a word whose value the line does not show ($TAP/x, u/$R/x) and says whether it was one.
func (p *hookParse) brewVariable(w string) bool {
	if strings.ContainsAny(w, "$\\`") {
		p.miss(whyVarArgument + " (" + clip(w, 60) + ")")
		return true
	}
	return false
}

// brewHomes: the variables bin/brew finds brew.env under — ${XDG_CONFIG_HOME}/homebrew, else
// ${HOMEBREW_XDG_CONFIG_HOME}/homebrew, else ${HOME}/.homebrew — whose HOMEBREW_* lines it exports, the source and
// tap-trust variables brewEnv holds among them. HOME is also where git and ssh read the tap clone's config.
var brewHomes = []string{"XDG_CONFIG_HOME", "HOMEBREW_XDG_CONFIG_HOME", "HOME"}

// brewHome: one of brewHomes set by the line to a folder of the project, a temporary one, a climbing path or a
// variable (goDirWhy) moves brew.env to a file the line does not show (P2-4, ECO-1-BREW round 2).
func (p *hookParse) brewHome() {
	for _, k := range brewHomes {
		v, ok := p.assigned[k]
		if !ok {
			continue
		}
		if why := goDirWhy(v); why != "" {
			p.miss(whyOverride + " (" + k + " moves Homebrew's brew.env to " + clip(v, 60) + ": " + why + ")")
		}
	}
}

// brewSourceEnv: Homebrew's variables that move where formulae, casks, bottles and its own code come from
// (env_config.rb): any value is another source than the one alalanet judges.
var brewSourceEnv = map[string]bool{"HOMEBREW_BREW_GIT_REMOTE": true, "HOMEBREW_CORE_GIT_REMOTE": true,
	"HOMEBREW_API_DOMAIN": true, "HOMEBREW_BOTTLE_DOMAIN": true, "HOMEBREW_ARTIFACT_DOMAIN": true}

// brewEnv judges one of Homebrew's variables (called from configEnv): HOMEBREW_NO_REQUIRE_TAP_TRUST, set to any value
// (env_config.rb, boolean: :set), switches off Homebrew's own gate on third-party taps; brewSourceEnv moves the source.
// HOMEBREW_CURL_PATH, HOMEBREW_GIT_PATH and HOMEBREW_SVN name the curl, git and svn Homebrew runs, SUDO_ASKPASS (bin/brew
// passes it on; system_command.rb runs sudo -A with it, a pkg cask's sudo runs the program) the askpass program,
// HOMEBREW_SSH_CONFIG_PATH the ssh config it clones with (a ProxyCommand runs), HOMEBREW_CURLRC (an absolute path) a curl
// config: a reason in a folder of the project, a temporary one, a climbing path or a variable (goDirWhy); a program by
// name is looked up on PATH. The name is matched as written: Homebrew runs on macOS and Linux, where a variable's name
// has its case. The reason waits for a brew command on the line (brewFlush): npm and pip read none of these (round 3).
func (p *hookParse) brewEnv(k, v string) {
	switch {
	case v != "" && (k == "HOMEBREW_NO_REQUIRE_TAP_TRUST" || brewSourceEnv[k]):
		host := v
		if u, err := url.Parse(v); err == nil && u.Host != "" {
			host = u.Hostname()
		}
		p.brewWhy = append(p.brewWhy, "installs with a custom registry or config file alalanet cannot see ("+k+" "+clip(host, 60)+")")
	case brewProgramEnv[k] && strings.ContainsAny(v, "/\\$`"):
		if why := goDirWhy(v); why != "" {
			p.brewWhy = append(p.brewWhy, "runs with an environment that loads other code ("+k+" points at "+clip(v, 60)+": "+why+")")
		}
	case k == "HOMEBREW_SSH_CONFIG_PATH" && v != "", k == "HOMEBREW_CURLRC" && (strings.HasPrefix(v, "/") || strings.ContainsAny(v, "$`")):
		if why := goDirWhy(v); why != "" {
			p.brewWhy = append(p.brewWhy, "installs with a custom registry or config file alalanet cannot see ("+k+" points at "+clip(v, 60)+": "+why+")")
		}
	}
}

// brewProgramEnv: the variables that name a program Homebrew runs (brewEnv).
var brewProgramEnv = wordSet("HOMEBREW_CURL_PATH HOMEBREW_GIT_PATH HOMEBREW_SVN SUDO_ASKPASS")

// brewFlush gives the reasons of the Homebrew variables the line has set so far (brewEnv) once it runs brew.
func (p *hookParse) brewFlush() {
	for _, why := range p.brewWhy {
		p.miss(why)
	}
	p.brewWhy = nil
}

// BrewEntryPairs is the VAR=value words of an MCP entry's environment that the reader judges for a brew command — the
// HOMEBREW_* names, the brew.env homes (brewHomes) and SUDO_ASKPASS — in order, for its line; none for another command
// (EnvUnread reads the rest of the environment). As GoEntryPairs for go.
func BrewEntryPairs(command string, env map[string]string) []string {
	if launchBase(command) != "brew" {
		return nil
	}
	var out []string
	for k, v := range env {
		if strings.HasPrefix(k, "HOMEBREW_") || slices.Contains(brewHomes, k) || k == "SUDO_ASKPASS" {
			out = append(out, k+"="+v)
		}
	}
	slices.Sort(out)
	return out
}
