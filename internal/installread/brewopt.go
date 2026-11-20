package installread

import "strings"

// ECO-1-BREW round 4 (re-review review-1117/eco1-brew-r3): Homebrew 7.0.14's Ruby commands parse their words with
// CLI::Parser#parse_remaining (cli/parser.rb 424–458, split_non_options 1139) on Ruby's OptionParser, which it never
// tells require_exact. The reviewer modelled it on Homebrew's portable Ruby 4.0.9 (optmodel.rb, optmodel.txt); brewParse
// reads as that model does:
//   - the words before the first "--" are parsed one at a time, every word after it is named;
//   - a long name is the exact name, else a unique prefix among the command's own options, else among the global ones
//     (-d/--debug, -q/--quiet, -v/--verbose, -h/--help); a prefix of two names of one option is that option;
//   - a short word is a cluster, letter by letter: switches, then a value option takes the rest of the word or else the
//     next word (OptionParser's MissingArgument: parse_remaining hands it the next word, whatever it is);
//   - a value after "=" (a switch with "=" is refused), the last value of a repeated option.
//
// Two layers (the coordinator's decision): every option word that is not exactly one option of the command or a global
// one — a prefix, a cluster of several, an unknown name, an ambiguous prefix, a switch with "=", a missing value — is in
// odd, which the brew reader gives as a reason; and the parse goes on, the word refused taken for a named word, so
// that what the runner would run is read as well.

// brewOpt is one option of a brew command: its long names (without "--"), its short letter (0: none), and whether it
// takes a value (cli/parser.rb's flag "--x=") or none (switch).
type brewOpt struct {
	long  []string
	short byte
	value bool
}

// brewOptsOf reads a spec: options separated by spaces, an option's names by "|", "=" after a name that takes a value.
func brewOptsOf(spec string) []brewOpt {
	var out []brewOpt
	for _, f := range strings.Fields(spec) {
		var o brewOpt
		for _, n := range strings.Split(f, "|") {
			if strings.HasSuffix(n, "=") {
				o.value, n = true, strings.TrimSuffix(n, "=")
			}
			if strings.HasPrefix(n, "--") {
				o.long = append(o.long, n[2:])
			} else if len(n) == 2 && n[0] == '-' {
				o.short = n[1]
			}
		}
		out = append(out, o)
	}
	return out
}

// brewGlobalOpts: the options every Ruby brew command takes (cli/parser.rb global_options); --help prints the help.
var brewGlobalOpts = brewOptsOf("-d|--debug -q|--quiet -v|--verbose -h|--help")

// The own options of the Ruby commands the reader reads (Homebrew 7.0.14). bundle's are one OptionParser for all its
// subcommands (CLI::Parser#subcommand registers each subcommand's options on the same parser and checks them after
// parsing): cmd/bundle.rb, bundle/subcommand/*.rb and the extensions' --X, --no-X, --no-cleanup-X, --no-dump-X.
var (
	brewSandboxOpts   = brewOptsOf("--deny-network")
	brewShOpts        = brewOptsOf("-r|--ruby --env= -c=|--cmd=")
	brewBenchmarkOpts = brewOptsOf("--exec --runs=")
	brewDebuggerOpts  = brewOptsOf("-O|--open")
	brewProfOpts      = brewOptsOf("--stackprof --vernier --timings")
	brewAliasOpts     = brewOptsOf("--edit")
	brewBundleOpts    = brewOptsOf("--file= -g|--global --upgrade-formulae=|--upgrade-formula= --jobs= --sandbox= --all " +
		"--cask|--casks --check --cleanup --deny-network --describe --force-cleanup --formula|--formulae|--brews --install " +
		"--no-cask|--no-casks --no-cleanup-brew --no-cleanup-cask --no-cleanup-tap --no-describe --no-dump-brew " +
		"--no-dump-cask --no-dump-tap --no-formula|--no-formulae|--no-brews --no-restart --no-secrets --no-tap|--no-taps " +
		"--no-upgrade --services --tap|--taps --upgrade --zap -f|--force" + brewBundleExtensionOpts())
)

// brewBundleExtensionOpts: the switches of bundle's extensions (bundle/extensions/*.rb, Extension.flag of each type).
func brewBundleExtensionOpts() string {
	var b strings.Builder
	for _, e := range strings.Fields("cargo flatpak go krew mas npm uv vscode winget") {
		b.WriteString(" --" + e + " --no-" + e + " --no-cleanup-" + e + " --no-dump-" + e)
	}
	return b.String()
}

// brewParsed: what brewParse read.
type brewParsed struct {
	vals  map[string]string // each option set, by its first name, to its last value ("" for a switch)
	named []string          // the words that are no options, before "--", then every word after it
	odd   []string          // the option words not placed exactly (a reason each)
	help  bool              // --help or -h: the command prints its help, nothing runs
}

// set: whether the parse set the option named name (its first long name, or its short letter as "-x").
func (b brewParsed) set(name string) bool {
	_, ok := b.vals[name]
	return ok
}

// brewOptName: the key brewParsed.vals keeps an option under.
func brewOptName(o brewOpt) string {
	if len(o.long) > 0 {
		return o.long[0]
	}
	return "-" + string(o.short)
}

// brewLong finds a long name: exact (own, then global), else by completion among own, then among global, as Ruby's
// OptionParser::Completion.complete does: the candidates' names sorted by length, the shortest wins when every other
// candidate is the same option or has a name that starts with it (--up is --upgrade beside --upgrade-formulae, --forc
// is --force beside --force-cleanup); otherwise the prefix is ambiguous (AmbiguousOption), and the next list is not
// searched. exact false: found by completion.
func brewLong(name string, own []brewOpt) (o brewOpt, found, exact bool) {
	for _, set := range [][]brewOpt{own, brewGlobalOpts} {
		for _, c := range set {
			for _, l := range c.long {
				if l == name {
					return c, true, true
				}
			}
		}
	}
	type cand struct {
		o    int
		name string
	}
	for _, set := range [][]brewOpt{own, brewGlobalOpts} {
		var cs []cand
		for i, c := range set {
			for _, l := range c.long {
				if strings.HasPrefix(l, name) {
					cs = append(cs, cand{i, l})
				}
			}
		}
		if len(cs) == 0 {
			continue
		}
		short := cs[0]
		for _, c := range cs[1:] {
			if len(c.name) < len(short.name) {
				short = c
			}
		}
		for _, c := range cs {
			if c.o != short.o && !strings.HasPrefix(c.name, short.name) {
				return brewOpt{}, false, false // AmbiguousOption
			}
		}
		return set[short.o], true, false
	}
	return brewOpt{}, false, false // InvalidOption
}

// brewShort finds a short letter, own first.
func brewShort(c byte, own []brewOpt) (brewOpt, bool) {
	for _, set := range [][]brewOpt{own, brewGlobalOpts} {
		for _, o := range set {
			if o.short == c {
				return o, true
			}
		}
	}
	return brewOpt{}, false
}

// brewParse parses a Ruby brew command's words (after the command) as parse_remaining does, with own as its options.
func brewParse(args []string, own []brewOpt) brewParsed {
	b := brewParsed{vals: map[string]string{}}
	before, after := args, []string(nil)
	for i, x := range args {
		if x == "--" {
			before, after = args[:i], args[i+1:]
			break
		}
	}
	setv := func(o brewOpt, v string) {
		if name := brewOptName(o); name == "help" {
			b.help = true
		} else {
			b.vals[name] = v
		}
	}
	for i := 0; i < len(before); i++ {
		x := before[i]
		switch {
		case len(x) < 2 || x[0] != '-':
			b.named = append(b.named, x)
		case strings.HasPrefix(x, "--"):
			name, v, eq := strings.Cut(x[2:], "=")
			o, found, exact := brewLong(name, own)
			switch {
			case !found, !o.value && eq:
				b.odd = append(b.odd, x)
				b.named = append(b.named, x) // refused: read on, the word kept
				continue
			case !exact:
				b.odd = append(b.odd, x)
			}
			if o.value && !eq {
				if i+1 == len(before) {
					b.odd = append(b.odd, x) // MissingArgument
					continue
				}
				i++
				v = before[i]
			}
			setv(o, v)
		default: // a short cluster
			if len(x) > 2 && x[2] != '=' {
				if o, ok := brewShort(x[1], own); !ok || !o.value {
					b.odd = append(b.odd, x) // several options in one word
				}
			}
			for j := 1; j < len(x); j++ {
				o, ok := brewShort(x[j], own)
				if !ok && len(x) == 2 {
					// "-e" with no short -e: OptionParser completes the letter among the long names (-e is --exec)
					var found bool
					if o, found, _ = brewLong(x[1:], own); found {
						b.odd = append(b.odd, x)
						ok = true
					}
				}
				if !ok {
					b.odd = append(b.odd, x)
					b.named = append(b.named, x)
					break
				}
				if !o.value {
					setv(o, "")
					continue
				}
				switch {
				case j+1 < len(x):
					if x[j+1] == '=' {
						b.odd = append(b.odd, x) // -c=X: OptionParser keeps the "=" in the value; read without it (the safe side)
						setv(o, x[j+2:])
					} else {
						setv(o, x[j+1:])
					}
				case i+1 < len(before):
					i++
					setv(o, before[i])
				default:
					b.odd = append(b.odd, x) // MissingArgument
				}
				break
			}
		}
	}
	b.named = append(b.named, after...)
	return b
}

// brewHyperfine reads the words brew benchmark --exec hands hyperfine (dev-cmd/benchmark.rb: exec hyperfine,
// *args.named): the commands it runs — every word that is no option, and the values of its options that run a command
// (-p/--prepare, -s/--setup, --conclude, -c/--cleanup, --reference, and -S/--shell, the shell it runs them with) — as
// lines; odd: an option this table does not hold — among them its parameter options (-P/--parameter-scan,
// -L/--parameter-list: values put into the commands' {name}s, which the line does not show) and a cluster of short
// switches. hyperfine's options from its documented CLI
// (clap: "--x=v", "--x v", "-xv", "-x v"); hyperfine itself was not run (not on the build Mac).
func brewHyperfine(words []string) (lines, odd []string) {
	cmdOpts := map[string]bool{"prepare": true, "p": true, "setup": true, "s": true, "conclude": true, "cleanup": true, "c": true,
		"reference": true, "shell": true, "S": true}
	valOpts := map[string]bool{"warmup": true, "w": true, "min-runs": true, "m": true, "max-runs": true, "M": true, "runs": true,
		"r": true, "parameter-step-size": true, "D": true, "time-unit": true, "u": true, "style": true, "sort": true,
		"export-asciidoc": true, "export-csv": true, "export-json": true, "export-markdown": true, "export-orgmode": true,
		"output": true, "input": true, "command-name": true, "n": true}
	switches := map[string]bool{"N": true, "ignore-failure": true, "i": true, "show-output": true, "help": true, "h": true,
		"version": true, "V": true}
	for i := 0; i < len(words); i++ {
		x := words[i]
		if x == "--" {
			lines = append(lines, words[i+1:]...)
			break
		}
		if len(x) < 2 || x[0] != '-' {
			lines = append(lines, x)
			continue
		}
		name, v, eq := strings.Cut(strings.TrimPrefix(x, "--"), "=")
		if !strings.HasPrefix(x, "--") { // -pCMD, -p=CMD, -p CMD, -Ni
			name, v, eq = x[1:2], strings.TrimPrefix(x[2:], "="), len(x) > 2
		}
		switch {
		case cmdOpts[name] || valOpts[name]:
			if !eq {
				if i+1 == len(words) {
					odd = append(odd, x)
					continue
				}
				i++
				v = words[i]
			}
			if cmdOpts[name] {
				lines = append(lines, v)
			}
		case switches[name] && !eq:
		default:
			odd = append(odd, x)
		}
	}
	return lines, odd
}
