package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// REPO-POL-1 round 2 (ADR-0174): the hook applies the organisation's policy and the workspace's .alalanet.yml to the
// server's answer, locally.

// soon: an expiry within the year an exception may run (repopolicy.MaxAhead), from the clock the hook reads.
var (
	soon       = time.Now().UTC().AddDate(0, 6, 0).Format(time.DateOnly)
	exceptPyPI = "version: 1\nexceptions:\n  - {package: pypi:Acme_Tools, reason: ours, expires: " + soon + "}\n"
	exceptOurs = "version: 1\nexceptions:\n  - {package: npm:@acme/cli, reason: our CLI, expires: " + soon + "}\n  - {mcp_server: \"https://mcp.acme.dev/mcp\", reason: our server, expires: " + soon + "}\n"
)

// The answers are in the form internal/app InstallHook writes (installhook.go): "<target> — <codes>" items after HOLD.
const (
	denyHolds   = "version: 1\non_hold:\n  packages: deny\n"
	trustAcme   = "version: 1\ntrusted_repositories:\n  - github.com/acme/*\nrepository_exception_scopes:\n  - npm:@acme/*\n  - mcp:mcp.acme.dev\n"
	trustOthers = "version: 1\ntrusted_repositories:\n  - github.com/others/*\n"
	holdAnswer  = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"alalanet install_check: HOLD. npm:@acme/cli — new_package. Install only if the user confirms."}}`
	blockAnswer = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"alalanet install_check: BLOCK. npm:@acme/cli — known_malicious. Do not install; tell the user."}}`
	notChecked_ = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"alalanet install_check: NOT CHECKED. npm:@acme/cli — the check did not finish in time. Install only if the user confirms."}}`
	holdTwo     = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"alalanet install_check: HOLD. npm:@acme/cli@1.2.0 — new_package; npm:left-pad@1.3.0 — new_package. Install only if the user confirms."}}`
	holdChanged = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"alalanet install_check: HOLD. npm:@acme/cli@1.2.0 — new_package, maintainers_changed. Install only if the user confirms."}}`
	holdBoth    = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"alalanet install_check: HOLD. npm:@acme/cli@1.2.0 — new_package. NOT CHECKED. npm:other — the check did not finish in time. Install only if the user confirms."}}`
	holdLaunch  = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"alalanet install_check: HOLD. npm:@acme/cli@1.2.0 — new_package; npx -y evil — the launcher runs a package alalanet did not check. Install only if the user confirms."}}`
	holdServer  = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"alalanet install_check: HOLD. remote-mcp:https://mcp.acme.dev/mcp — unverified_yet. Install only if the user confirms."}}`
	holdEvilSrv = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"alalanet install_check: HOLD. remote-mcp:https://mcp.evil.example/mcp — unverified_yet. Install only if the user confirms."}}`
	holdPyPI    = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"alalanet install_check: HOLD. pypi:acme-tools@2.0.1 — new_package. Install only if the user confirms."}}`
	holdGitHub  = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"alalanet install_check: HOLD. github:acme/skill — new_repo; npm:@acme/cli@1.2.0 — new_package. Install only if the user confirms."}}`
	denyAsHold  = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"alalanet install_check: HOLD. npm:@acme/cli@1.2.0 — new_package. Install only if the user confirms."}}`
	holdLeftPad = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"alalanet install_check: HOLD. npm:left-pad@1.3.0 — new_package. Install only if the user confirms."}}`
)

// workspace makes a checkout: .git with origin's address (none for ""), the policy file (none for ""), and a
// subdirectory the agent works in. It returns the subdirectory.
func workspace(t *testing.T, origin, policy string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := "[core]\n\trepositoryformatversion = 0\n"
	if origin != "" {
		cfg += "[remote \"origin\"]\n\turl = " + origin + "\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
	}
	write(t, filepath.Join(root, ".git", "config"), cfg)
	if policy != "" {
		write(t, filepath.Join(root, ".alalanet.yml"), policy)
	}
	sub := filepath.Join(root, "pkg", "cli")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	return sub
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// managedFile places the organisation's policy ("" for none) and returns its path.
func managedFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.yml")
	if body != "" {
		write(t, p, body)
	}
	return p
}

func codexInputIn(cwd, command string) string {
	b, _ := json.Marshal(map[string]any{"session_id": "s", "cwd": cwd, "hook_event_name": "PreToolUse", "tool_name": "Bash",
		"tool_input": map[string]any{"command": command}})
	return string(b)
}

// runWithPolicy runs one hook call of runtime with the policy files and returns the answer's form, stdout and stderr.
func runWithPolicy(t *testing.T, runtime, answer, managed, input string, getwd func() (string, error)) (form, out, stderr string, f *fakeHook) {
	t.Helper()
	f = &fakeHook{answer: func(w http.ResponseWriter) {
		if answer != "" {
			_, _ = w.Write([]byte(answer))
		}
	}}
	srv := f.server(t)
	var o, e bytes.Buffer
	pf := &policyFiles{managed: managed, getwd: getwd}
	if pf.getwd == nil {
		pf.getwd = func() (string, error) { return "", os.ErrNotExist }
	}
	call := hookCall{client: &http.Client{Timeout: 2 * time.Second}, api: srv.URL, stderr: &e, policy: pf}
	if err := runHookContext(context.Background(), runtime, strings.NewReader(input), &o, call); err != nil {
		t.Fatal(err)
	}
	return answerForm(t, runtime, o.String()), o.String(), e.String(), f
}

func TestHookPolicyAppliedToTheVerdict(t *testing.T) {
	acme := "git@github.com:acme/app.git"
	for _, c := range []struct {
		name, origin, repo, managed, answer, command string
		want                                         string // silent | hold | deny
		note                                         string // a stderr line the call must give ("" for none about the policy)
	}{
		{"no policy anywhere: the verdict stands", acme, "", "", holdAnswer, "npm i @acme/cli", "hold", ""},
		{"the repository's exceptions, nobody trusts them", acme, exceptOurs, "", holdAnswer, "npm i @acme/cli", "hold", "not applied"},
		{"trusted by the organisation", acme, exceptOurs, trustAcme, holdAnswer, "npm i @acme/cli@1.2.0", "silent", "lets it go ahead"},
		{"trusted over https too", "https://github.com/Acme/App.git", exceptOurs, trustAcme, holdAnswer, "npm i @acme/cli", "silent", "lets it go ahead"},
		{"the organisation trusts other repositories", acme, exceptOurs, trustOthers, holdAnswer, "npm i @acme/cli", "hold", "not applied"},
		{"no origin: no identity, not trusted", "", exceptOurs, trustAcme, holdAnswer, "npm i @acme/cli", "hold", "not applied"},
		{"a local origin: not trusted", "/srv/git/app.git", exceptOurs, trustAcme, holdAnswer, "npm i @acme/cli", "hold", "not applied"},
		{"the organisation's own exception", "", "", exceptOurs, holdAnswer, "npm i @acme/cli", "silent", "lets it go ahead"},
		{"a repository's deny applies at once", "", denyHolds, "", holdAnswer, "npm i @acme/cli", "deny", "denies"},
		{"the organisation's deny over a trusted exception", acme, exceptOurs, trustAcme + "on_hold:\n  packages: deny\n", holdAnswer, "npm i @acme/cli", "deny", "denies"},
		{"a block stays a block", acme, exceptOurs, trustAcme, blockAnswer, "npm i @acme/cli", "deny", ""},
		{"an allow stays an allow", "", denyHolds, "", "", "npm i @acme/cli", "silent", ""},
		{"another package held in the line", acme, exceptOurs, trustAcme, holdTwo, "npm i @acme/cli left-pad", "hold", ""},
		{"only the excepted package is held", acme, exceptOurs, trustAcme, holdAnswer, "npm i @acme/cli left-pad", "silent", "lets it go ahead"},
		{"a code no exception covers", acme, exceptOurs, trustAcme, holdChanged, "npm i @acme/cli", "hold", ""},
		{"a target of another ecosystem in the hold", acme, exceptOurs, trustAcme, holdGitHub, "npm i @acme/cli && skills add acme/skill", "hold", ""},
		{"a deny is a deny, whatever its reason says", acme, exceptOurs, trustAcme, denyAsHold, "npm i @acme/cli", "deny", ""},
		{"a hold beside a NOT CHECKED part", acme, exceptOurs, trustAcme, holdBoth, "npm i @acme/cli other", "hold", ""},
		{"repository exceptions never apply", acme, exceptOurs, trustAcme + "repository_exceptions: never\n", holdAnswer, "npm i @acme/cli", "hold", "not applied"},
		{"an exception a year and more ahead", acme, "version: 1\nexceptions:\n  - {package: npm:@acme/cli, reason: ours, expires: 9999-12-31}\n", trustAcme, holdAnswer, "npm i @acme/cli", "hold", ""},
		{"install_check's pypi form", acme, "", exceptPyPI, holdPyPI, "pip install acme-tools==2.0.1", "silent", "lets it go ahead"},
		{"a moved registry is not covered", acme, exceptOurs, trustAcme, holdAnswer, "npm i --registry https://evil.example @acme/cli", "hold", ""},
		{"a command substitution is not covered", acme, exceptOurs, trustAcme, holdAnswer, "npm i @acme/cli $(cat extra)", "hold", ""},
		{"a command substitution elsewhere in the line", acme, exceptOurs, trustAcme, holdAnswer, "echo $(date) && npm i @acme/cli", "hold", ""},
		{"a covered package beside a launch line", acme, exceptOurs, trustAcme, holdLaunch, "npm i @acme/cli && claude mcp add x -- npx -y evil", "hold", ""},
		{"untrusted exceptions that would not cover it: no note", acme, exceptOurs, "", holdLeftPad, "npm i left-pad", "hold", ""},
		{"origin's urls disagree: no identity", "git@github.com:acme/app.git\n\turl = https://evil.example/x/app", exceptOurs, trustAcme, holdAnswer, "npm i @acme/cli", "hold", "not applied"},
		{"another remote's address is not origin's", "", exceptOurs, trustAcme, holdAnswer, "npm i @acme/cli", "hold", "not applied"},
		{"not checked is not covered", acme, exceptOurs, trustAcme, notChecked_, "npm i @acme/cli", "hold", ""},
		{"not checked under a deny", "", denyHolds, "", notChecked_, "npm i @acme/cli", "deny", "denies"},
		{"a launch line is not a package", acme, exceptOurs, trustAcme, holdLaunch, "claude mcp add acme -- npx -y @acme/cli", "hold", ""},
		{"a remote server by its URL", acme, exceptOurs, trustAcme, holdServer, "claude mcp add --transport http acme https://mcp.acme.dev/mcp", "silent", "lets it go ahead"},
		{"another server", acme, exceptOurs, trustAcme, holdEvilSrv, "claude mcp add --transport http x https://mcp.evil.example/mcp", "hold", ""},
		{"an unparsable repository file", acme, "version: [1\n", trustAcme, holdAnswer, "npm i @acme/cli", "hold", "is not a policy"},
		{"an unparsable organisation's file", acme, exceptOurs, "version: 7\n", holdAnswer, "npm i @acme/cli", "hold", "is not a policy"},
		{"an unparsable organisation's file holds an allow", acme, "", "version: 7\n", "", "npm i @acme/cli", "hold", "held until it is fixed"},
		{"an unparsable organisation's file under a repository deny", "", denyHolds, "nope: [", holdAnswer, "npm i @acme/cli", "deny", "is not a policy"},
		{"a repository cannot trust itself", acme, exceptOurs + "trusted_repositories:\n  - github.com/acme/*\n", "", holdAnswer, "npm i @acme/cli", "hold", "is not a policy"},
	} {
		dir := workspace(t, c.origin, c.repo)
		form, _, stderr, _ := runWithPolicy(t, "codex", c.answer, managedFile(t, c.managed), codexInputIn(dir, c.command), nil)
		if form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
		}
		if c.note != "" && !strings.Contains(stderr, c.note) {
			t.Errorf("%s: stderr %q lacks %q", c.name, stderr, c.note)
		}
		if c.note == "" && strings.Contains(stderr, "policy") {
			t.Errorf("%s: a policy note without cause: %q", c.name, stderr)
		}
	}
}

// The policy never leaves the machine: the request is the command alone, the same with a policy or without.
func TestHookPolicyIsNeverSent(t *testing.T) {
	dir := workspace(t, "git@github.com:acme/app.git", exceptOurs)
	_, _, _, with := runWithPolicy(t, "codex", holdAnswer, managedFile(t, trustAcme), codexInputIn(dir, "npm i @acme/cli"), nil)
	_, _, _, without := runWithPolicy(t, "codex", holdAnswer, managedFile(t, ""), codexInputIn(t.TempDir(), "npm i @acme/cli"), nil)
	a, b := with.calls(), without.calls()
	if len(a) != 1 || len(b) != 1 || a[0] != b[0] {
		t.Fatalf("requests differ: %q / %q", a, b)
	}
	for _, leak := range []string{"our CLI", "acme/app", "trusted", dir, "alalanet.yml"} {
		if strings.Contains(a[0], leak) {
			t.Errorf("the request carries %q: %s", leak, a[0])
		}
	}
}

// The workspace is where the runtime says the agent works (cwd, or Antigravity's toolCall.args.Cwd), else the hook's
// own working directory (Codex runs hooks with the session's cwd as theirs); the policy file is at the repository's
// root, found by .git above it.
func TestHookPolicyWorkspaceInEveryRuntime(t *testing.T) {
	dir := workspace(t, "https://github.com/acme/app", exceptOurs)
	managed := managedFile(t, trustAcme)
	inputs := map[string]string{
		"codex":  codexInputIn(dir, "npm i @acme/cli"),
		"cursor": mustJSON(map[string]any{"hook_event_name": "beforeShellExecution", "command": "npm i @acme/cli", "cwd": dir}),
		"copilot": mustJSON(map[string]any{"cwd": dir, "toolName": "bash",
			"toolArgs": mustJSON(map[string]string{"command": "npm i @acme/cli"})}),
		"antigravity": mustJSON(map[string]any{"toolCall": map[string]any{"name": "run_command", "args": map[string]any{"CommandLine": "npm i @acme/cli", "Cwd": dir}}}),
	}
	for rt, in := range inputs {
		if form, _, stderr, _ := runWithPolicy(t, rt, holdAnswer, managed, in, nil); form != "silent" {
			t.Errorf("%s: %s (stderr %q)", rt, form, stderr)
		}
	}
	// No cwd in the input: the process's working directory.
	in := mustJSON(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": map[string]any{"command": "npm i @acme/cli"}})
	if form, _, stderr, _ := runWithPolicy(t, "codex", holdAnswer, managed, in, func() (string, error) { return dir, nil }); form != "silent" {
		t.Errorf("the process's directory: %s (stderr %q)", form, stderr)
	}
	// A relative cwd is not read as a place (it would be read from wherever the hook runs): the hook's own directory is.
	if form, _, stderr, _ := runWithPolicy(t, "codex", holdAnswer, managed, codexInputIn("pkg/cli", "npm i @acme/cli"), func() (string, error) { return dir, nil }); form != "silent" {
		t.Errorf("a relative cwd: %s (stderr %q)", form, stderr)
	}
}

// A git worktree or submodule: .git is a file naming the git directory; origin's address is in the common directory's
// config (commondir), as git reads it.
func TestHookPolicyGitFile(t *testing.T) {
	main := t.TempDir()
	write(t, filepath.Join(main, "config"), "[remote \"origin\"]\n\turl = git@github.com:acme/app.git\n")
	wt := filepath.Join(main, "worktrees", "feature")
	if err := os.MkdirAll(wt, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(wt, "commondir"), "../..\n")
	checkout := t.TempDir()
	write(t, filepath.Join(checkout, ".git"), "gitdir: "+wt+"\n")
	write(t, filepath.Join(checkout, ".alalanet.yml"), exceptOurs)
	if form, _, stderr, _ := runWithPolicy(t, "codex", holdAnswer, managedFile(t, trustAcme), codexInputIn(checkout, "npm i @acme/cli"), nil); form != "silent" {
		t.Errorf("worktree: %s (stderr %q)", form, stderr)
	}
}

// The repository's file must be a regular file: a link (to a key, to /etc/passwd) is not read, and says so.
func TestHookPolicyFileLinkIsNotRead(t *testing.T) {
	dir := workspace(t, "git@github.com:acme/app.git", "")
	root := filepath.Dir(filepath.Dir(dir))
	target := filepath.Join(t.TempDir(), "elsewhere.yml")
	write(t, target, denyHolds)
	if err := os.Symlink(target, filepath.Join(root, ".alalanet.yml")); err != nil {
		t.Skip(err)
	}
	form, _, stderr, _ := runWithPolicy(t, "codex", holdAnswer, managedFile(t, ""), codexInputIn(dir, "npm i @acme/cli"), nil)
	if form != "hold" || !strings.Contains(stderr, "not a regular file") {
		t.Errorf("a link: %s (stderr %q)", form, stderr)
	}
}

// Without the policy files (the tests' runHook, the default before this round) nothing is read.
func TestHookWithoutPolicyFilesReadsNothing(t *testing.T) {
	dir := workspace(t, "", denyHolds)
	f := &fakeHook{answer: func(w http.ResponseWriter) { _, _ = w.Write([]byte(holdAnswer)) }}
	srv := f.server(t)
	if form := answerForm(t, "codex", runCodex(t, srv.URL, codexInputIn(dir, "npm i @acme/cli"))); form != "hold" {
		t.Errorf("runHook without policy files: %s", form)
	}
}

// The organisation's file is where an administrator's device management places it, beside Claude Code's managed
// settings (code.claude.com/docs/en/managed-settings, read 2026-11-15): never a user-writable folder.
func TestManagedPolicyPath(t *testing.T) {
	for goos, want := range map[string]string{
		"darwin":  "/Library/Application Support/alalanet/policy.yml",
		"linux":   "/etc/alalanet/policy.yml",
		"windows": `C:\Program Files\alalanet\policy.yml`,
		"freebsd": "/etc/alalanet/policy.yml",
	} {
		if got := managedPolicyPath(goos); got != want {
			t.Errorf("%s: %q, want %q", goos, got, want)
		}
	}
}

// An organisation's file that is there but cannot be read (no permission) fails closed, like one that does not parse.
func TestHookPolicyUnreadableOrganisationFile(t *testing.T) {
	managed := managedFile(t, trustAcme)
	if err := os.Chmod(managed, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(managed, 0o600) })
	if f, err := os.Open(managed); err == nil {
		f.Close()
		t.Skip("running as a user who reads any file")
	}
	dir := workspace(t, "git@github.com:acme/app.git", "")
	form, _, stderr, _ := runWithPolicy(t, "codex", "", managed, codexInputIn(dir, "npm i @acme/cli"), nil)
	if form != "hold" || !strings.Contains(stderr, "could not be read (permission denied)") {
		t.Errorf("an unreadable organisation's file: %s (stderr %q)", form, stderr)
	}
}

// Outside a git repository there is no repository file: the one check_repo_config judges is the root's (review of
// 2950215, F7) — a .alalanet.yml in a folder that is no checkout is not read.
func TestHookPolicyOutsideARepository(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, ".alalanet.yml"), denyHolds)
	form, _, stderr, _ := runWithPolicy(t, "codex", holdAnswer, managedFile(t, ""), codexInputIn(dir, "npm i @acme/cli"), nil)
	if form != "hold" || stderr != "" {
		t.Errorf("outside a repository: %s (stderr %q)", form, stderr)
	}
	// A nested file in a checkout is not the root's.
	sub := workspace(t, "git@github.com:acme/app.git", "")
	write(t, filepath.Join(sub, ".alalanet.yml"), denyHolds)
	if form, _, _, _ := runWithPolicy(t, "codex", holdAnswer, managedFile(t, ""), codexInputIn(sub, "npm i @acme/cli"), nil); form != "hold" {
		t.Errorf("a nested file: %s", form)
	}
}

// The hook's answer, read as internal/app InstallHook writes it: the HOLD part's targets in install_check's own forms
// and their codes; anything else is not read (and no exception covers it).
func TestHeldTargetsForms(t *testing.T) {
	items, ok := heldTargets("alalanet install_check: HOLD. npm:@acme/cli@1.2.0 — new_package, runs_install_script; pypi:acme-tools@2.0.1 — name_like_official:acme; remote-mcp:https://mcp.acme.dev/mcp — unverified_yet. Install only if the user confirms.")
	if !ok || len(items) != 3 || items[0].target != "npm:@acme/cli@1.2.0" || len(items[0].codes) != 2 || items[1].target != "pypi:acme-tools@2.0.1" ||
		items[1].codes[0] != "name_like_official:acme" || items[2].target != "remote-mcp:https://mcp.acme.dev/mcp" {
		t.Fatalf("%v %+v", ok, items)
	}
	for _, r := range []string{
		"",
		"alalanet install_check: BLOCK. npm:x — known_malicious. Do not install; tell the user.",
		"alalanet install_check: HOLD. npm:x — new_package", // cut short
		"alalanet install_check: HOLD. npm:x — new_package. NOT CHECKED. npm:y — the check did not finish in time. Install only if the user confirms.",
		"alalanet install_check: NOT CHECKED — the check did not finish in time. Install only if the user confirms.",
		"alalanet install_check: HOLD. npx -y evil — the launcher runs a package alalanet did not check. Install only if the user confirms.",
		"alalanet install_check: HOLD. npm:x — . Install only if the user confirms.",
		"alalanet install_check: HOLD. npm:x new_package. Install only if the user confirms.",
		"alalanet install_check: HOLD. npm:x — New Package. Install only if the user confirms.",
		"HOLD. npm:x — new_package. Install only if the user confirms.",
		"alalanet install_check: HOLD.  — new_package. Install only if the user confirms.", // no target
	} {
		if items, ok := heldTargets(r); ok {
			t.Errorf("%q read as %+v", r, items)
		}
	}
}
