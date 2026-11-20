package installread

import (
	"fmt"
	"strings"
	"testing"
)

// reasonRuns: how many runs of a reading the order test makes; a map's order differs between runs of one process, so
// a reason that followed it named another variable in some of them (2 of 6 on the base, work-1116/reader-pn-pnx).
const reasonRuns = 100

// sameEveryRun runs read reasonRuns times and fails unless every run gives want.
func sameEveryRun(t *testing.T, name, want string, read func() string) {
	t.Helper()
	seen := map[string]int{}
	for range reasonRuns {
		seen[read()]++
	}
	if len(seen) != 1 || seen[want] != reasonRuns {
		t.Errorf("%s: %d runs gave %v, want %q every run", name, reasonRuns, seen, want)
	}
}

// READER-REASON-ORDER-1 (ADR-0159 round 48): the own shell's last judgement checks the names a line's arithmetic,
// ${!NAME}, $NAME programs, -c scripts and joined program words read, and holds for the first that fails. Those names
// were sets (maps), so with two failing names the reason named either at random: the hold stood, its text did not.
// Now they are kept in the order the line first gives them, and the reason names the first one in the line.
func TestReaderReasonOrderOwnShell(t *testing.T) {
	own := func(why string) string { return "[" + whyOwnShell + " (" + why + ")]" }
	for _, c := range []struct{ line, want string }{
		{`t=ev; u=al; sh -c "${t}${u} PATH=./bin; pip install zz-pkg"`, "[runs a command whose name comes from a variable " +
			"alalanet cannot see (${t}${u} PATH=./bin) " + whyOwnShell + " (a -c script that expands $t, which the line sets)]"},
		{`u=al; t=ev; sh -c "${t}${u} PATH=./bin; pip install zz-pkg"`, "[runs a command whose name comes from a variable " +
			"alalanet cannot see (${t}${u} PATH=./bin) " + whyOwnShell + " (a -c script that expands $t, which the line sets)]"},
		{`a=1; b=2; sh -c "echo $a $b"; pip install zz-pkg`, own("a -c script that expands $a, which the line sets")},
		{`a=1; b=2; sh -c "echo $b $a"; pip install zz-pkg`, own("a -c script that expands $b, which the line sets")},
		{`a=x; b=y; echo $((a+b)); pip install zz-pkg`, own("arithmetic reads a, which the line sets to what is not a number")},
		{`a=x; b=y; echo $((b+a)); pip install zz-pkg`, own("arithmetic reads b, which the line sets to what is not a number")},
		// the first time the line reads a name places it: a second $a later does not move it past $b
		{`a=x; b=y; echo $((a+b+a)); pip install zz-pkg`, own("arithmetic reads a, which the line sets to what is not a number")},
		{`a=ev; b=al; $a x; $b y; $a z; pip install zz-pkg`, own("a command named by $a, which the line or the shell may set")},
		{`a='x y'; b='p q'; echo ${!a} ${!b}; pip install zz-pkg`, own("${!a} reads a name the line sets to what is not a name")},
		{`a='x y'; b='p q'; echo ${!b} ${!a}; pip install zz-pkg`, own("${!b} reads a name the line sets to what is not a name")},
		{`a=ev; b=al; $a x; $b y; pip install zz-pkg`, own("a command named by $a, which the line or the shell may set")},
		{`a=ev; b=al; $b y; $a x; pip install zz-pkg`, own("a command named by $b, which the line or the shell may set")},
		{`a=/x; b=/y; $a$b; pip install zz-pkg`, own("a command named by $a and more, which the line sets to what is not one path")},
		{`a=/x; b=/y; $b$a; pip install zz-pkg`, own("a command named by $b and more, which the line sets to what is not one path")},
	} {
		sameEveryRun(t, c.line, c.want, func() string {
			_, unread, _, _ := ParseLine(c.line)
			return fmt.Sprint(unread)
		})
		// the hook's answer, and the codes the server keeps, follow the same reasons
		sameEveryRun(t, c.line+" (codes)", fmt.Sprint(unreadCodes(c.line)), func() string { return fmt.Sprint(unreadCodes(c.line)) })
	}
}

func unreadCodes(line string) []string {
	_, codes := codesOn(line)
	return codes
}

// The second reader's MCP entry: a key that loads an environment file and a key in another case were reasons in the
// map's order, so an install_check target's code (LaunchExtraWhy's first reason) was env_file or case_variant_key at
// random, and with two file keys the reason named either. Now the file keys come first, in the entry's own order, as
// the repository reader (app mcpServerEntry) puts env_file before case_variant_key; then a key in another case.
func TestReaderReasonOrderEntry(t *testing.T) {
	file := func(k string) string { return "env_file | " + whyFromFile + " (" + k + ")" }
	for raw, want := range map[string]string{
		`{"command":"npx","args":["-y","ok-pkg"],"envFile":".env","env_file":".e2"}`: file("envFile"),
		`{"command":"npx","args":["-y","ok-pkg"],"env_file":".e2","envFile":".env"}`: file("env_file"),
		`{"Command":"npx","args":["-y","ok-pkg"],"envFile":".env"}`:                  file("envFile"),
		`{"envFile":".env","Command":"npx","args":["-y","ok-pkg"]}`:                  file("envFile"),
		`{"Command":"npx","ARGS":["-y","ok-pkg"],"Env":{}}`:                          "case_variant_key | " + whyVariant,
		// comments and trailing commas, as the clients read them: the keys' order is the text's
		"{\"command\":\"npx\", /* x */ \"ENV_FILE\":\".e\", // y\n \"envfile\":\".f\",}": file("ENV_FILE"),
	} {
		sameEveryRun(t, raw, want, func() string {
			code, why := LaunchExtraWhy(raw)
			return code + " | " + why
		})
		// every reason, in order: the hook's text joins them
		sameEveryRun(t, raw+" (all)", strings.Join(entryReasons(raw), "; "), func() string { return strings.Join(entryReasons(raw), "; ") })
	}
}

func entryReasons(raw string) []string {
	e := newExtraParse()
	e.pm++
	e.entry(raw, 0)
	return e.reasons()
}
