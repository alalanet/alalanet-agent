package installread

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// ECO-1-BREW round 4 (re-review review-1117/eco1-brew-r3). Homebrew 7.0.14's Ruby commands parse their words with
// CLI::Parser#parse_remaining on Ruby's OptionParser (cli/parser.rb; the reviewer's model optmodel.rb on Homebrew's Ruby
// 4.0.9): the words before the first "--", each on its own, an exact long name or else a unique prefix (the command's
// own options before the global -d/-q/-v/-h), short clusters, a value after "=" or attached or as the next word, the
// last value of a repeated option. Two layers: an option word the reader does not place exactly is a reason
// (never "nothing"), and the model reads what the runner runs. Placeholders only.

// brewR4Opt: an option as the tests know it, typed from Homebrew's sources independently of brew.go's tables.
type brewR4Opt struct {
	long  string // without "--"
	short byte   // 0: none
	value bool
}

// The runners' and wrappers' own options (cmd/sandbox-exec.rb, dev-cmd/sh.rb, dev-cmd/benchmark.rb, dev-cmd/debugger.rb,
// dev-cmd/prof.rb, cmd/alias.rb; bundle: cmd/bundle.rb with every subcommand's and extension's options).
var brewR4Runners = []struct {
	name     string
	opts     []brewR4Opt
	template string // %s: where the option words go
	want     string
}{
	{"sandbox-exec", []brewR4Opt{{"deny-network", 0, false}}, "brew sandbox-exec %s /tmp/s -- npx -y zz-evil-pkg", "npm:zz-evil-pkg"},
	{"sh", []brewR4Opt{{"ruby", 'r', false}, {"env", 0, true}}, "brew sh %s -c 'npx -y zz-evil-pkg'", "npm:zz-evil-pkg"},
	{"benchmark", []brewR4Opt{{"runs", 0, true}}, "brew benchmark %s --exec -- 'npx -y zz-evil-pkg'", "npm:zz-evil-pkg"},
	{"bundle", []brewR4Opt{{"file", 0, true}, {"global", 'g', false}, {"install", 0, false}, {"services", 0, false},
		{"check", 0, false}, {"no-secrets", 0, false}, {"sandbox", 0, true}, {"deny-network", 0, false}, {"jobs", 0, true},
		{"force", 'f', false}, {"zap", 0, false}, {"upgrade-formulae", 0, true}, {"upgrade", 0, false}, {"no-upgrade", 0, false}},
		"brew bundle %s exec -- npx -y zz-evil-pkg", "npm:zz-evil-pkg"},
	{"debugger", []brewR4Opt{{"open", 'O', false}}, "brew debugger %s install u/r/x", "github:u/homebrew-r"},
	{"prof", []brewR4Opt{{"stackprof", 0, false}, {"vernier", 0, false}, {"timings", 0, false}}, "brew prof %s install u/r/x", "github:u/homebrew-r"},
	{"alias", []brewR4Opt{{"edit", 0, false}}, "brew alias %s 'zz=!npx -y zz-evil-pkg'", "npm:zz-evil-pkg"},
}

var brewR4Global = []brewR4Opt{{"debug", 'd', false}, {"quiet", 'q', false}, {"verbose", 'v', false}}

// brewR4Forms: the spellings of one option, as OptionParser takes them: the exact word, every prefix of the long name, a
// value after "=" and as the next word (a value option), the short letter alone and in a cluster with a global switch.
func brewR4Forms(o brewR4Opt) (exact, other []string) {
	val := func(w string) []string {
		if !o.value {
			return []string{w}
		}
		return []string{w + "=zzv", w + " zzv"}
	}
	exact = val("--" + o.long)
	for n := 1; n < len(o.long); n++ {
		other = append(other, val("--"+o.long[:n])...)
	}
	if o.short != 0 {
		s := "-" + string(o.short)
		if o.value {
			exact = append(exact, s+" zzv", s+"zzv")
			other = append(other, "-v"+string(o.short)+" zzv", "-q"+string(o.short)+"zzv")
		} else {
			exact = append(exact, s)
			other = append(other, s+"v", "-v"+string(o.short), "-dq"+string(o.short))
		}
	}
	other = append(other, strings.Join(exact[:1], " ")+" "+exact[0]) // repeated
	return exact, other
}

// Every form of every option of every runner: the runner's command is read (its target), or there is a reason —
// never nothing; an exact option is read without a reason.
func TestBrewRound4Generated(t *testing.T) {
	n := 0
	for _, r := range brewR4Runners {
		for _, o := range append(slices.Clone(r.opts), brewR4Global...) {
			exact, other := brewR4Forms(o)
			other = slices.DeleteFunc(other, func(f string) bool { // a prefix that is another option's exact name is that option
				for _, q := range append(slices.Clone(r.opts), brewR4Global...) {
					if q.long != o.long && (f == "--"+q.long || strings.HasPrefix(f, "--"+q.long+" ") || strings.HasPrefix(f, "--"+q.long+"=")) {
						return true
					}
				}
				return false
			})
			for _, f := range exact {
				line := fmt.Sprintf(r.template, f)
				n++
				if tg, codes := codesOn(line); !slices.Contains(tg, r.want) {
					t.Errorf("%s: %q: targets %v codes %v, want %s", r.name, line, tg, codes, r.want)
				}
			}
			for _, f := range other {
				line := fmt.Sprintf(r.template, f)
				n++
				if tg, codes := codesOn(line); !slices.Contains(tg, r.want) && len(codes) == 0 {
					t.Errorf("%s: %q: read as nothing (targets %v)", r.name, line, tg)
				}
			}
		}
		// an option word no runner knows, in every position before "--": a reason
		for _, w := range []string{"--zzbogus", "-Z", "--zzbogus=1", "-vZ"} {
			line := fmt.Sprintf(r.template, w)
			n++
			if _, codes := codesOn(line); len(codes) == 0 {
				t.Errorf("%s: %q: no reason for an unknown option", r.name, line)
			}
		}
	}
	if n < 300 {
		t.Errorf("only %d generated lines", n)
	}
}

func TestBrewRound4(t *testing.T) {
	// targets and no reason: exact options, the last -c, hyperfine's command options
	for line, want := range map[string][]string{
		"brew sh -c true -c 'npx -y zz-evil-pkg'":                                   {"npm:zz-evil-pkg"},
		"brew sh --cmd=true '--cmd=npx -y zz-evil-pkg'":                             {"npm:zz-evil-pkg"},
		"brew sh x.sh -c 'npx -y zz-evil-pkg'":                                      {"npm:zz-evil-pkg"},
		"brew sandbox-exec /tmp/s --deny-network -- npx -y zz-evil-pkg":             {"npm:zz-evil-pkg"},
		"brew bundle --file Brewfile exec -- npx -y zz-evil-pkg":                    {"npm:zz-evil-pkg"},
		"brew bundle exec --sandbox /tmp/s --deny-network -- npx -y zz-evil-pkg":    {"npm:zz-evil-pkg"},
		"brew benchmark --exec -- '--prepare=npx -y zz-evil-pkg' true":              {"npm:zz-evil-pkg"},
		"brew benchmark --exec -- --prepare 'npx -y zz-evil-pkg' true":              {"npm:zz-evil-pkg"},
		"brew benchmark --exec -- '-pnpx -y zz-evil-pkg' true":                      {"npm:zz-evil-pkg"},
		"brew benchmark --exec -- -p 'npx -y zz-evil-pkg' true":                     {"npm:zz-evil-pkg"},
		"brew benchmark --exec -- '--setup=npx -y zz-evil-pkg' true":                {"npm:zz-evil-pkg"},
		"brew benchmark --exec -- -s 'npx -y zz-evil-pkg' true":                     {"npm:zz-evil-pkg"},
		"brew benchmark --exec -- '--conclude=npx -y zz-evil-pkg' true":             {"npm:zz-evil-pkg"},
		"brew benchmark --exec -- '--cleanup=npx -y zz-evil-pkg' true":              {"npm:zz-evil-pkg"},
		"brew benchmark --exec -- -c 'npx -y zz-evil-pkg' true":                     {"npm:zz-evil-pkg"},
		"brew benchmark --exec -- '--reference=npx -y zz-evil-pkg' true":            {"npm:zz-evil-pkg"},
		"brew benchmark --exec -- '--shell=npx -y zz-evil-pkg' true":                {"npm:zz-evil-pkg"},
		"brew benchmark --exec -- -S 'npx -y zz-evil-pkg' true":                     {"npm:zz-evil-pkg"},
		"brew benchmark --exec -- --warmup 3 --runs 5 -N 'npx -y zz-evil-pkg'":      {"npm:zz-evil-pkg"},
		"brew benchmark --exec -- --export-json out.json -n x 'npx -y zz-evil-pkg'": {"npm:zz-evil-pkg"},
		"brew debugger --open install u/r/x":                                        {"github:u/homebrew-r"},
		"brew prof --stackprof install u/r/x":                                       {"github:u/homebrew-r"},
	} {
		if tg, codes := codesOn(line); !slices.Equal(tg, want) || len(codes) > 0 {
			t.Errorf("%q: targets %v codes %v, want %v and no reason", line, tg, codes, want)
		}
	}
	// earlier rounds' lines the parser refuses (an option before "--" it does not know, -c=, a missing value): the target
	// where there is one, and a reason (layer 1)
	for line, want := range map[string]string{
		"brew sandbox-exec --deny-network /tmp/s npx -y zz-evil-pkg":          "npm:zz-evil-pkg",
		"brew debugger as-brew-user sandbox-exec . npx -y zz-evil-pkg":        "npm:zz-evil-pkg",
		"brew sandbox-exec . bash -c 'npx -y zz-evil-pkg'":                    "npm:zz-evil-pkg",
		"brew sh -c=npx\\ -y\\ zz-evil-pkg":                                   "npm:zz-evil-pkg",
		"brew sandbox-exec . --deny-network npx -y zz-evil-pkg":               "npm:zz-evil-pkg",
		"brew bundle exec npx -y zz-evil-pkg":                                 "npm:zz-evil-pkg",
		"brew bundle --file Brewfile exec npx -y zz-evil-pkg":                 "npm:zz-evil-pkg",
		"brew bundle exec --sandbox /tmp/s --deny-network npx -y zz-evil-pkg": "npm:zz-evil-pkg",
		"brew sandbox-exec . -y npx -y zz-evil-pkg":                           "",
		"brew sandbox-exec --deny-network=1 . npx":                            "",
		"brew bundle exec --sandbox":                                          "",
		"brew sandbox-exec --bogus npx -y zz-evil-pkg":                        "",
		"brew bundle check npx -y zz-evil-pkg":                                "",
		"brew bundle --help exec npx -y zz-evil-pkg":                          "",
		"brew sandbox-exec -h . npx -y zz-evil-pkg":                           "",
		"brew sandbox-exec --bogus . npx -y zz-evil-pkg":                      "",
		"brew sh -c":                           "",
		"brew x --bogus npx -y zz-evil-pkg":    "",
		"brew exec --formulae":                 "",
		"brew x --formulae --formulae=u/r/x x": "",
		"brew x --formulae=u/r/x --bogus x":    "",
	} {
		tg, codes := codesOn(line)
		if !slices.Contains(codes, "unknown_install_form") || want != "" && !slices.Contains(tg, want) {
			t.Errorf("%q: targets %v codes %v, want %s and unknown_install_form", line, tg, codes, want)
		}
	}
	// reasons (the target may be there too)
	for line, code := range map[string]string{
		// layer 1: a word the reader cannot place exactly
		"brew sandbox-exec --den /tmp/s -- npx -y zz-evil-pkg":         "unknown_install_form",
		"brew sh -vc 'npx -y zz-evil-pkg'":                             "unknown_install_form",
		"brew sh --cm 'npx -y zz-evil-pkg'":                            "unknown_install_form",
		"brew benchmark --exe -- 'npx -y zz-evil-pkg'":                 "unknown_install_form",
		"brew bundle --fil Brewfile exec -- npx -y zz-evil-pkg":        "unknown_install_form",
		"brew prof --sta install u/r/x":                                "unknown_install_form",
		"brew x --bogus npx -y zz-evil-pkg":                            "unknown_install_form",
		"brew x --formulae=u/r/x --sandbox":                            "unknown_install_form",
		"brew as-brew-user --bogus install u/r/x":                      "unknown_install_form",
		"brew --verbose install u/r/x":                                 "unknown_install_form",
		"brew -d install u/r/x":                                        "unknown_install_form",
		"brew sandbox-exec /tmp/s npx -y zz-evil-pkg":                  "unknown_install_form", // -y: the parser refuses it
		"brew bundle exec npx -y zz-evil-pkg":                          "unknown_install_form",
		"brew sh -c":                                                   "unknown_install_form", // the value is missing
		"brew sandbox-exec --deny-network=1 /tmp/s -- npx":             "unknown_install_form",
		"brew benchmark --exec -- --zzbogus 'npx -y zz-evil-pkg'":      "unknown_install_form",
		"brew benchmark --exec -- -L p zz-evil-pkg 'npx -y {p}'":       "unknown_install_form", // parameters fill the commands
		"brew benchmark --exec -- -P n 1 3 'npx -y zz-evil-pkg@{n}'":   "unknown_install_form",
		"brew benchmark --exec -- --parameter-list p a,b 'npx -y {p}'": "unknown_install_form",
		// P1-3: an alias the line defines, then uses
		"brew alias i=install && brew i u/r/x":                      "shadowed_command",
		"brew alias i=install; brew i u/r/x":                        "shadowed_command",
		"brew alias e='!npx -y' && brew e zz-evil-pkg":              "shadowed_command",
		"brew alias e='%npx -y' && brew e zz-evil-pkg":              "shadowed_command",
		"brew alias e='!sh -c' && brew e 'npx -y zz-evil-pkg'":      "shadowed_command",
		"brew alias i='install wget; npx -y zz-evil-pkg' && brew i": "shadowed_command",
		"brew alias --edit i=install && brew -v i u/r/x":            "shadowed_command",
		"brew alias i=install && brew as-brew-user i u/r/x":         "shadowed_command",
		"brew alias i=install && brew x -- brew i u/r/x":            "shadowed_command",
		// P2-1: a script into brew's shells
		"echo 'npx -y zz-evil-pkg' | brew sh":                          "script_not_read",
		"brew sh <<< 'npx -y zz-evil-pkg'":                             "script_not_read",
		"brew sh -r <<< 'npx -y zz-evil-pkg'":                          "script_not_read",
		"echo 'npx -y zz-evil-pkg' | brew bundle sh":                   "script_not_read",
		"echo 'npx -y zz-evil-pkg' | brew x bash":                      "script_not_read",
		"echo 'npx -y zz-evil-pkg' | brew x -- sh -s":                  "script_not_read",
		"echo 'npx -y zz-evil-pkg' | brew sandbox-exec /tmp/s -- bash": "script_not_read",
		"echo 'npx -y zz-evil-pkg' | brew bundle exec -- bash":         "script_not_read",
		"echo 'npx -y zz-evil-pkg' | brew as-brew-user sh":             "script_not_read",
		"brew x zsh <<< 'npx -y zz-evil-pkg'":                          "script_not_read",
	} {
		if _, codes := codesOn(line); !slices.Contains(codes, code) {
			t.Errorf("%q: codes %v, want %s", line, codes, code)
		}
	}
	// the alias's command is read as a bash line, the use's words appended ($*): the targets are there
	for line, want := range map[string]string{
		"brew alias i=install && brew i u/r/x":                      "github:u/homebrew-r",
		"brew alias e='!npx -y' && brew e zz-evil-pkg":              "npm:zz-evil-pkg",
		"brew alias i='install wget; npx -y zz-evil-pkg' && brew i": "npm:zz-evil-pkg",
		"brew alias zz='install u/r/x'":                             "github:u/homebrew-r",
		"brew alias zz='!npx -y zz-evil-pkg'":                       "npm:zz-evil-pkg",
	} {
		if tg, _ := codesOn(line); !slices.Contains(tg, want) {
			t.Errorf("%q: targets %v, want %s", line, tg, want)
		}
	}
	// mutation round 4: -e completed is odd; hyperfine's -r, --command-name and a second "--"; an alias with no name;
	// sandbox-exec's and bundle's help and other subcommands; scripts into a nested brew sh and next to -c or FILE
	for line, code := range map[string]string{
		"brew benchmark -e -- 'npx -y zz-evil-pkg'":                  "unknown_install_form",
		"echo 'npx -y zz-evil-pkg' | brew x -- brew sh":              "script_not_read",
		"echo 'npx -y zz-evil-pkg' | brew as-brew-user x -- brew sh": "script_not_read",
	} {
		if _, codes := codesOn(line); !slices.Contains(codes, code) {
			t.Errorf("%q: codes %v, want %s", line, codes, code)
		}
	}
	for _, line := range []string{
		"brew benchmark --exec -- -r 5 'npx -y zz-evil-pkg'", "brew benchmark --exec -- --command-name x 'npx -y zz-evil-pkg'",
		"brew benchmark --exec -- --warmup 1 -- 'npx -y zz-evil-pkg'",
	} {
		_, _, other, _ := ParseLine(line)
		if tg, codes := codesOn(line); !slices.Equal(tg, []string{"npm:zz-evil-pkg"}) || len(codes) > 0 || other {
			t.Errorf("%q: targets %v codes %v other %v, want npm:zz-evil-pkg alone", line, tg, codes, other)
		}
	}
	for _, line := range []string{
		"brew alias '=install u/r/x'", "brew sandbox-exec -h /tmp/s -- npx -y zz-evil-pkg", "brew bundle check -- npx -y zz-evil-pkg",
		"echo 'npx -y zz-evil-pkg' | brew sh -c 'echo hi'", "echo 'npx -y zz-evil-pkg' | brew sh x.sh",
		"echo 'npx -y zz-evil-pkg' | brew x bash -c 'echo hi'", "echo 'npx -y zz-evil-pkg' | bash -c 'echo hi'",
		"echo 'npx -y zz-evil-pkg' | brew x bash -sc 'echo hi'", "echo 'npx -y zz-evil-pkg' | bash -sc 'echo hi'",
	} {
		if tg, codes := codesOn(line); len(tg) > 0 || len(codes) > 0 {
			t.Errorf("%q: targets %v codes %v, want none", line, tg, codes)
		}
	}
	// nothing: honest forms, and what runs nothing for sure
	for _, line := range []string{
		"brew sh", "brew sh -r", "brew sh --env=std", "brew bundle sh", "brew x bash -c 'echo hi'", "brew alias zz",
		"brew --prefix wget", "brew --version", "brew -v", "brew --cache", "brew --repository", "brew --env", "brew --config",
		"echo hi | brew x -- cat", "brew sh <<< ''", "brew benchmark wget", "brew sandbox-exec /tmp/s -- true",
		"brew bundle exec -- true", "brew update --verbose", "brew list --versions", "brew info --json=v2 wget",
	} {
		if tg, codes := codesOn(line); len(tg) > 0 || len(codes) > 0 {
			t.Errorf("%q: targets %v codes %v, want none", line, tg, codes)
		}
	}
}

// hyperfine's command options in every spelling clap takes, generated: the command they name is read.
func TestBrewRound4HyperfineGenerated(t *testing.T) {
	for _, o := range []struct{ long, short string }{{"prepare", "p"}, {"setup", "s"}, {"conclude", ""}, {"cleanup", "c"},
		{"reference", ""}, {"shell", "S"}} {
		forms := []string{"'--" + o.long + "=npx -y zz-evil-pkg'", "--" + o.long + " 'npx -y zz-evil-pkg'"}
		if o.short != "" {
			forms = append(forms, "-"+o.short+" 'npx -y zz-evil-pkg'", "'-"+o.short+"npx -y zz-evil-pkg'", "'-"+o.short+"=npx -y zz-evil-pkg'")
		}
		for _, f := range forms {
			for _, tmpl := range []string{"brew benchmark --exec -- %s true", "brew benchmark --exec -- --warmup 1 %s -N true",
				"brew benchmark --e -- %s true", "brew benchmark -e -- %s true"} {
				line := fmt.Sprintf(tmpl, f)
				if tg, codes := codesOn(line); !slices.Contains(tg, "npm:zz-evil-pkg") {
					t.Errorf("%q: targets %v codes %v, want npm:zz-evil-pkg", line, tg, codes)
				}
			}
		}
	}
}
