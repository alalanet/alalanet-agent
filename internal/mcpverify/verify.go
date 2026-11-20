package mcpverify

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/alalanet/alalanet-agent/internal/tooldigest"
)

// Kind is what the check concludes about a server's tools.
type Kind int

const (
	// Silent: the tools are the ones this machine accepted, or the ones the server serves alalanet (a first sight is
	// pinned silently).
	Silent Kind = iota
	// Warn: a difference that honest servers show (more tools for signed-in users, an older set kept after a failed
	// refresh, a per-user list, fewer tools): one line, no hold.
	Warn
	// Hold: a known tool changed, a tool gained authority, the descriptions carry signs of instructions to the model,
	// or the policy holds what could not be checked.
	Hold
	// Unread: the server cannot be read by design (it needs authorization, runs on this machine, is on a private
	// network or its URL carries a key): no opinion, never held unless ALALANET_MCP_UNVERIFIED=hold.
	Unread
	// NotChecked: the read or alalanet's record could not be had this time and nothing usable is kept.
	NotChecked
)

func (k Kind) String() string {
	return [...]string{"ok", "warn", "hold", "unread", "not checked"}[k]
}

// Outcome is the check of one server.
type Outcome struct {
	Kind    Kind
	Reasons []string // short lines in plain words: no URL, tool names reduced to their safe characters
	Pinned  bool     // seen for the first time and pinned now
	Told    bool     // this session was already given this answer for this set
	Hash    string   // the set read ("" when none was)
	Listed  int      // alalanet lists the server: 1, does not: -1, unknown: 0
}

// Verifier checks configured MCP servers.
type Verifier struct {
	API      string // alalanet (ALALANET_API)
	StateDir string // DefaultStateDir
	Version  string // alalanet-agent's, in its User-Agent and clientInfo
	// ReadHTTP reads the servers; nil: a client that connects to public addresses only (netguard).
	ReadHTTP *http.Client
	// APIHTTP asks alalanet; nil: a client that follows no redirect.
	APIHTTP *http.Client
	// ReadBudget and WitnessBudget bound one read of a server and then one lookup at alalanet (3 s and 2 s by default).
	ReadBudget, WitnessBudget time.Duration
	Now                       func() time.Time
	// FailClosed (ALALANET_FAIL_CLOSED=1) holds a server that could not be checked, unless alalanet is known not to list
	// it. UnverifiedHold (ALALANET_MCP_UNVERIFIED=hold) also holds a server that cannot be read by design.
	FailClosed, UnverifiedHold bool
	beforeSave                 func() // tests: runs before a check saves its state
	beforeViewSave             func() // tests: runs before a check saves the agent's copy's pin
}

const (
	defaultRead    = 3 * time.Second
	defaultWitness = 2 * time.Second
	designTTL      = 24 * time.Hour
	failedTTL      = time.Minute
	notListedTTL   = 24 * time.Hour
	witnessTTL     = 10 * time.Minute // alalanet's own toolsFreshFor
	staleUse       = 24 * time.Hour   // a kept answer used when a new one cannot be had
)

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) userAgent() string { return "alalanet-agent/" + v.Version + " (mcp-verify)" }

func (v *Verifier) reader() reader {
	c := v.ReadHTTP
	if c == nil {
		c = newReadClient(v.userAgent(), false)
	}
	return reader{http: c, userAgent: v.userAgent()}
}

func (v *Verifier) witness() witness {
	c := v.APIHTTP
	if c == nil {
		c = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return witness{http: c, api: v.API, userAgent: v.userAgent()}
}

func budget(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// readTTL: the server's ttlMs, clamped to 1-60 minutes, 15 minutes without one.
func readTTL(r *readState) time.Duration {
	switch {
	case r.Design != "":
		return designTTL
	case r.Failed != "":
		return failedTTL
	case r.TTLMs <= 0:
		return 15 * time.Minute
	}
	return min(max(time.Duration(r.TTLMs)*time.Millisecond, time.Minute), time.Hour)
}

func witnessFresh(w *witnessState, now time.Time) bool {
	if w == nil {
		return false
	}
	ttl := witnessTTL
	if w.Listed < 0 {
		ttl = notListedTTL
	}
	return now.Sub(time.Unix(w.At, 0)) < ttl
}

// Check checks one configured server: from the kept state while it is fresh, otherwise with one read of the server
// and then one lookup at alalanet, each within its budget. session (kept hashed, never sent) makes an answer
// given once in a session say Told afterwards.
func (v *Verifier) Check(ctx context.Context, srv Server, session string) Outcome {
	return v.check(ctx, srv, session, false)
}

func (v *Verifier) check(ctx context.Context, srv Server, session string, fresh bool) Outcome {
	base := v.checkRead(ctx, srv, session, fresh)
	if srv.AgentView == nil {
		return base
	}
	return v.checkView(ctx, srv, session, base)
}

// stateKey is the state's key of a server: its configured URL's hash, else (a server read through its copy only) its
// runtime's and name's.
func stateKey(srv Server) string {
	if srv.URL == "" {
		return viewKey(srv)
	}
	return serverKey(srv.URL)
}

// checkView adds the agent's own copy to the check of the read (agentview.go): its pin and its flags hold, a
// difference from the read's descriptions warns; a server the read could not check is checked through it. The copy's
// pin follows a copy that holds nothing, unless it changed since this check read it.
func (v *Verifier) checkView(ctx context.Context, srv Server, session string, base Outcome) Outcome {
	d := digestView(srv.AgentView)
	ctx, cancel := context.WithTimeout(ctx, maxLockWait)
	defer cancel()
	key, now := stateKey(srv), v.now()
	e, err := snapshot(ctx, v.StateDir, key)
	if err != nil {
		base.Reasons = append(base.Reasons, "the agent's own copy was not compared: "+v.stateProblem(err))
		return base
	}
	var readDescs []sig
	if e.Read != nil && e.Read.Hash != "" {
		readDescs = e.Read.Descs
	}
	holds, warns := evaluateView(d, e.AVPin, readDescs)
	differ := false
	for _, other := range srv.AgentView.Others { // Cursor's copies of other projects: every one counts (R4-2)
		od := digestView(other)
		if od.hash == d.hash {
			continue
		}
		differ = true
		h, w := evaluateView(od, e.AVPin, readDescs)
		holds, warns = appendNew(holds, h), appendNew(warns, w)
	}
	if differ {
		warns = appendNew(warns, []string{"Cursor keeps copies of its tools that differ between projects, and the hook did not name the workspace: each was judged, none pinned"})
	}
	out := base
	switch {
	case len(holds) > 0:
		if base.Kind != Hold && base.Kind != Warn && base.Kind != NotChecked {
			out.Reasons = nil
		}
		out.Kind, out.Reasons = Hold, append(append(out.Reasons, holds...), warns...)
	case base.Kind == Hold || base.Kind == NotChecked:
		out.Reasons = append(out.Reasons, warns...)
	case len(warns) > 0:
		if base.Kind != Warn {
			out.Reasons, out.Told = nil, true
		}
		out.Kind, out.Reasons = Warn, append(out.Reasons, warns...)
	case base.Kind == Unread: // the read could not check it; its copy did
		out.Kind, out.Reasons = Silent, nil
	}
	if v.beforeViewSave != nil {
		v.beforeViewSave()
	}
	pinned := false
	err = update(ctx, v.StateDir, key, func(s *entry0) {
		if (out.Kind == Silent || out.Kind == Warn) && len(holds) == 0 && !differ && s.AVPin.same(e.AVPin) && (s.AVPin == nil || s.AVPin.Hash != d.hash) {
			pinned = s.AVPin == nil
			s.AVPin = newPin(s.AVPin, now.UnixNano(), d.hash, d.sigs, false)
		}
		if len(warns) > 0 {
			k := toldKey(session, "view", d.hash)
			out.Told = out.Told && s.told(k)
			s.tell(k)
		}
	})
	if err != nil && len(warns) > 0 {
		out.Told = false // not recorded: said again
	}
	out.Pinned = out.Pinned || pinned && err == nil
	return out
}

// checkRead is the check of the server's read and alalanet's record.
func (v *Verifier) checkRead(ctx context.Context, srv Server, session string, fresh bool) Outcome {
	if srv.Untrusted {
		return v.unread("it is named only by a project file of a workspace the runtime may not trust; alalanet-agent does not contact it")
	}
	switch srv.Transport {
	case TransportStdio:
		return v.unread("it runs on this machine (stdio)")
	case TransportSSE:
		return v.unread("it uses the SSE transport; alalanet reads tool lists over streamable HTTP only")
	}
	p := planURL(srv.URL)
	if p.design != "" {
		return v.unread(p.design)
	}
	// The whole check, the state's lock waits included, stays within the read's and the record's budgets (review F2).
	ctx, cancel := context.WithTimeout(ctx, budget(v.ReadBudget, defaultRead)+budget(v.WitnessBudget, defaultWitness))
	defer cancel()
	key, now := serverKey(srv.URL), v.now()
	e, err := snapshot(ctx, v.StateDir, key)
	// A state that cannot be read is never "no state" (a first sight would pass a changed set silently): the check
	// reads the server and alalanet's record without a pin, holds what the record holds, is not checked otherwise,
	// and writes nothing (review F2, N3).
	stateWhy := ""
	if err != nil {
		stateWhy, e = v.stateProblem(err), entry0{}
	}
	var r readOutcome
	var w witnessOutcome
	needRead := fresh || e.Read == nil || now.Sub(time.Unix(e.Read.At, 0)) >= readTTL(e.Read)
	// A lookup that failed is not repeated for a minute (review N4): alalanet down does not mean one lookup a call.
	backoff := !fresh && e.LookupFailedAt != 0 && now.Sub(time.Unix(e.LookupFailedAt, 0)) < failedTTL
	needWitness := len(p.lookups) > 0 && (fresh || !witnessFresh(e.Witness, now)) && !backoff
	// The read first, then alalanet's record: alalanet is not asked about a server that cannot be read.
	if needRead {
		rctx, cancel := context.WithTimeout(ctx, budget(v.ReadBudget, defaultRead))
		r = v.reader().read(rctx, p.read, v.Version)
		cancel()
		if r.design != "" {
			needWitness = false
		}
	} else if e.Read.Design != "" {
		needWitness = false
	}
	if needWitness {
		wctx, cancel := context.WithTimeout(ctx, budget(v.WitnessBudget, defaultWitness))
		w = v.witness().ask(wctx, p.lookups)
		cancel()
	}
	// What is kept stands in for what could not be had now (up to a day); a new answer replaces it.
	keptRead := e.Read
	if needRead {
		rs := &readState{At: now.Unix(), Design: r.design, Failed: r.failed, Hash: r.hash, Sigs: keep(r.sigs), Flags: r.flags, Scope: r.scope, TTLMs: r.ttlMs, Descs: r.descs}
		if r.failed == "" || keptRead == nil || keptRead.Hash == "" || now.Sub(time.Unix(keptRead.At, 0)) > staleUse {
			keptRead = rs
		}
	}
	keptWitness := e.Witness
	switch {
	case needWitness && w.failed == "":
		keptWitness = &witnessState{At: now.Unix(), Listed: w.listed, Current: w.current, Sigs: keep(w.sigs), Previous: w.previous}
	case len(p.lookups) == 0:
		keptWitness = nil
	case keptWitness != nil && now.Sub(time.Unix(keptWitness.At, 0)) > staleUse:
		keptWitness = nil
	}
	witnessFailed := w.failed
	if backoff && witnessFailed == "" {
		witnessFailed = "it could not be asked less than a minute ago"
	}
	out := v.evaluate(keptRead, keptWitness, e.Pin, len(p.lookups) > 0, witnessFailed)
	if srv.Shadowed { // the user's entry was checked; a project file names the server at another URL (R4-1)
		const why = "a project file names this server too, at another URL; the user's own entry was checked"
		if out.Kind == Silent {
			out.Kind = Warn
		}
		out.Reasons = append(out.Reasons, why)
	}
	if stateWhy != "" {
		switch out.Kind {
		case Hold:
			out.Reasons = append(out.Reasons, stateWhy)
		case Unread:
		default: // without its pin no server is checked, listed or not: the policy holds it
			listed := out.Listed
			out.Listed = 0
			out = v.notChecked(out, stateWhy)
			out.Listed = listed
		}
		return out
	}
	if v.beforeSave != nil {
		v.beforeSave()
	}
	// Saving gets what is left of the budget, and a quarter of a second at least: a read that used its budget is kept.
	uctx, ucancel := context.WithTimeout(context.WithoutCancel(ctx), max(time.Until(deadlineOf(ctx)), 250*time.Millisecond))
	defer ucancel()
	pinned := false
	err = update(uctx, v.StateDir, key, func(s *entry0) {
		s.Read, s.Witness = keptRead, keptWitness
		if needWitness && w.failed != "" {
			s.LookupFailedAt = now.Unix()
		}
		// The pin follows a set that holds nothing, unless it changed since this check read it: an approval made
		// meanwhile is never overwritten by an older read (review F10).
		if (out.Kind == Silent || out.Kind == Warn) && keptRead != nil && keptRead.Hash != "" && s.Pin.same(e.Pin) {
			if s.Pin == nil || s.Pin.Hash != keptRead.Hash {
				pinned = s.Pin == nil
				s.Pin = newPin(s.Pin, now.UnixNano(), keptRead.Hash, keptRead.Sigs, false)
			}
		}
		if out.Kind != Silent {
			k := toldKey(session, out.Kind.String(), out.Hash)
			out.Told = s.told(k)
			s.tell(k)
		}
	})
	out.Pinned = pinned && err == nil
	return out
}

// stateProblem says why the state cannot be read, where it is, and how the user starts again; it reaches stderr and,
// for a hold, the runtime's reason.
func (v *Verifier) stateProblem(err error) string {
	path := filepath.Join(v.StateDir, stateName)
	switch {
	case errors.Is(err, errState):
		return "alalanet-agent's MCP state " + path + " does not load and is kept as it is; remove it to start again (the tool sets this machine accepted are then forgotten)"
	case errors.Is(err, errLocked):
		return "alalanet-agent's MCP state is locked (" + filepath.Join(v.StateDir, lockName) + "); if no alalanet-agent is running, remove that file"
	}
	return "alalanet-agent's MCP state " + path + " could not be read (" + err.Error() + "); remove it to start again"
}

// appendNew appends the lines of add that list does not hold yet.
func appendNew(list, add []string) []string {
	for _, a := range add {
		if !slices.Contains(list, a) {
			list = append(list, a)
		}
	}
	return list
}

func deadlineOf(ctx context.Context) time.Time {
	d, ok := ctx.Deadline()
	if !ok {
		return time.Now()
	}
	return d
}

func (v *Verifier) unread(why string) Outcome {
	if v.UnverifiedHold {
		return Outcome{Kind: Hold, Reasons: []string{"it cannot be checked: " + why + "; this organisation holds such servers (ALALANET_MCP_UNVERIFIED=hold)"}}
	}
	return Outcome{Kind: Unread, Reasons: []string{why}}
}

// strongFlags are the description flags that hold: signs of instructions to the model. invisible_marks and
// instructions_ambiguous only warn.
var strongFlags = []string{"conceal_from_user", "cross_tool_instruction", "hidden_directive_tag", "hidden_unicode", "injection_phrase", "secret_access"}

// evaluate is the verdict on a read (nil: none), alalanet's record (nil: none) and the pin (nil: none).
func (v *Verifier) evaluate(r *readState, w *witnessState, pin *pinState, lookup bool, witnessFailed string) Outcome {
	out := Outcome{}
	if w != nil {
		out.Listed = w.Listed
	}
	switch {
	case r == nil:
		return v.notChecked(out, "it was not read")
	case r.Design != "" && pin != nil && pin.Hash != "" && !v.UnverifiedHold:
		// A server this machine read and pinned that now refuses alalanet-agent: cloaking by status code is told once a
		// session (review F10); its pin is kept.
		out.Kind, out.Reasons = Warn, []string{"it was read and accepted on this machine before, and no longer lets alalanet-agent read its tools (" + r.Design + "): they are not checked now"}
		return out
	case r.Design != "":
		o := v.unread(r.Design)
		o.Listed = out.Listed
		return o
	case r.Failed != "":
		return v.notChecked(out, r.Failed)
	}
	out.Hash = r.Hash
	var holds, warns []string
	cur := tools(r.Sigs)
	accepted := pin != nil && pin.Hash == r.Hash
	if f := onlyStrong(r.Flags); len(f) > 0 && !(accepted && pin.Approved) {
		holds = append(holds, "its tool descriptions carry signs of instructions to the model ("+strings.Join(f, ", ")+")")
	}
	if slices.Contains(r.Flags, tooldigest.InvisibleMarks) {
		warns = append(warns, "its descriptions carry invisible marks")
	}
	// The instructions given more than once with values the MCP clients read differently: no sign of instructions
	// to the model, but the user's client may receive another text than the one judged (FN10-TOOLDESC-NULL P3-2).
	if slices.Contains(r.Flags, tooldigest.InstructionsAmbiguous) {
		warns = append(warns, "its instructions read differently to different MCP clients")
	}
	if pin != nil && !accepted {
		prev := tools(pin.accepted()) // a tool gone from the set and back with another definition is changed (review F1)
		added, _, changed := tooldigest.DiffTools(prev, cur)
		switch esc := tooldigest.Escalations(prev, cur); {
		case len(changed) > 0 || len(esc) > 0:
			holds = append(holds, "since this machine accepted its tools, "+changes(changed, esc))
		case len(added) > 0:
			warns = append(warns, fmt.Sprintf("%s added since this machine accepted its tools", count(len(added), "tool")))
		}
	}
	// A difference from alalanet's record that the user saw and accepted (mcp-approve) on this exact set warns; a set
	// not accepted still holds (review F5).
	approved := accepted && pin.Approved
	againstRecord := func(why string) {
		if approved {
			warns = append(warns, why+"; this set was accepted on this machine (mcp-approve)")
		} else {
			holds = append(holds, why)
		}
	}
	if w != nil && w.Listed > 0 && w.Current != "" && r.Hash != w.Current {
		switch {
		case r.Hash == w.Previous:
			warns = append(warns, "it serves this machine an older tool set than the one it serves alalanet now")
		case !comparable(tools(w.Sigs), cur):
			warns = append(warns, "its tool set differs from the one it serves alalanet")
		default:
			theirs := tools(w.Sigs)
			added, removed, changed := tooldigest.DiffTools(theirs, cur)
			esc := tooldigest.Escalations(theirs, cur)
			switch {
			case (len(changed) > 0 || len(esc) > 0) && r.Scope == "private":
				warns = append(warns, "its tools differ from the ones it serves alalanet, and it says its tool list is per user")
			case len(changed) > 0 || len(esc) > 0:
				againstRecord("against what it serves alalanet, " + changes(changed, esc))
			case len(added) > 0:
				warns = append(warns, fmt.Sprintf("it lists %s alalanet's read does not have (signed-in users may see more)", count(len(added), "tool")))
			case len(removed) > 0:
				warns = append(warns, fmt.Sprintf("it lists %s fewer than alalanet's read", count(len(removed), "tool")))
			}
		}
	}
	switch {
	case len(holds) > 0:
		out.Kind, out.Reasons = Hold, append(holds, warns...)
	case lookup && w == nil && !accepted:
		return v.notChecked(out, "alalanet's record could not be read ("+orNone(witnessFailed)+") and this machine has accepted no tool set of it")
	case len(warns) > 0:
		out.Kind, out.Reasons = Warn, warns
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "no answer"
	}
	return s
}

func (v *Verifier) notChecked(out Outcome, why string) Outcome {
	out.Kind, out.Reasons = NotChecked, []string{"it could not be checked: " + why}
	if v.FailClosed && out.Listed >= 0 {
		out.Kind = Hold
		out.Reasons[0] += "; this organisation holds what alalanet-agent could not check (ALALANET_FAIL_CLOSED)"
	}
	return out
}

func onlyStrong(flags []string) []string {
	var out []string
	for _, f := range flags {
		if slices.Contains(strongFlags, f) {
			out = append(out, f)
		}
	}
	return out
}

// comparable: every signature of both sets is of the current format (digests of two formats cannot be compared).
func comparable(a, b []tooldigest.ToolSig) bool {
	for _, set := range [][]tooldigest.ToolSig{a, b} {
		for _, s := range set {
			if s.V != tooldigest.SigVersion {
				return false
			}
		}
	}
	return len(a) > 0
}

func changes(changed, esc []string) string {
	var parts []string
	if len(changed) > 0 {
		parts = append(parts, fmt.Sprintf("%s changed (%s)", count(len(changed), "tool"), names(changed)))
	}
	if len(esc) > 0 {
		parts = append(parts, "gained authority: "+names(esc))
	}
	return strings.Join(parts, "; ")
}

func count(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}

// names lists up to five tool names (with the words Escalations adds), each reduced to the characters MCP tool names
// are written in (toolName): a name is the server's text and reaches the model in a hold's reason, so it may not
// spell a sentence (review F10). The words Escalations adds are alalanet-agent's own and kept.
func names(list []string) string {
	var out []string
	for i, n := range list {
		if i == 5 {
			out = append(out, fmt.Sprintf("and %d more", len(list)-5))
			break
		}
		name, words := n, ""
		if i := strings.LastIndex(n, " ("); i >= 0 && escalationWords(n[i+2:]) {
			name, words = n[:i], n[i:]
		}
		out = append(out, toolName(name)+words)
	}
	return strings.Join(out, ", ")
}

// escalationWords: s is what Escalations writes after a name, "(no longer read-only, now destructive)".
func escalationWords(s string) bool {
	inner, ok := strings.CutSuffix(s, ")")
	if !ok {
		return false
	}
	for _, w := range strings.Split(inner, ", ") {
		if w != "no longer read-only" && w != "now destructive" && w != "now open-world" {
			return false
		}
	}
	return true
}

// toolName is a tool name with letters, digits and _ . - / only (the characters of MCP tool names), at most 64 bytes;
// any other character, a space included, is written "?".
func toolName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 64 {
			b.WriteString("...")
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune("_.-/", r):
			b.WriteRune(r)
		default:
			b.WriteByte('?')
		}
	}
	return b.String()
}

// SafeName is a name as alalanet-agent shows it: letters, digits and _ . - / ( ) , space, at most 64 bytes, any other
// character written "?".
func SafeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 64 {
			b.WriteString("...")
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune("_.-/(), ", r):
			b.WriteRune(r)
		default:
			b.WriteByte('?')
		}
	}
	return b.String()
}

// Approval is a fresh read of a server, to be pinned when the user confirms it.
type Approval struct {
	Outcome Outcome
	Tools   int
	commit  func() error
}

// Pin pins the read as accepted by the user: its flags no longer hold, and a later change against it does.
func (a Approval) Pin() error { return a.commit() }

// Approve reads srv afresh and says what it serves; Pin then keeps it, and the agent's own copy when there is one, as
// this machine's accepted set.
func (v *Verifier) Approve(ctx context.Context, srv Server) (Approval, error) {
	out := v.check(ctx, srv, "mcp-approve", true)
	if out.Hash == "" && srv.AgentView == nil {
		return Approval{Outcome: out}, fmt.Errorf("%s cannot be approved: %s", SafeName(srv.Name), strings.Join(out.Reasons, "; "))
	}
	key := stateKey(srv)
	e, err := snapshot(ctx, v.StateDir, key)
	if err != nil {
		return Approval{Outcome: out}, fmt.Errorf("%s cannot be approved: %v", SafeName(srv.Name), err)
	}
	var read *readState
	if out.Hash != "" {
		if e.Read == nil || e.Read.Hash != out.Hash {
			return Approval{Outcome: out}, fmt.Errorf("%s changed while it was read; run the approval again", SafeName(srv.Name))
		}
		r := *e.Read
		read = &r
	}
	var view *viewDigest
	n := 0
	if read != nil {
		n = len(read.Sigs)
	}
	if srv.AgentView != nil {
		d := digestView(srv.AgentView)
		view = &d
		n = max(n, len(d.sigs))
	}
	return Approval{Outcome: out, Tools: n, commit: func() error {
		ctx, cancel := context.WithTimeout(context.Background(), maxLockWait)
		defer cancel()
		return update(ctx, v.StateDir, key, func(s *entry0) {
			if read != nil {
				s.Pin = newPin(s.Pin, v.now().UnixNano(), read.Hash, read.Sigs, true)
			}
			if view != nil {
				s.AVPin = newPin(s.AVPin, v.now().UnixNano(), view.hash, view.sigs, true)
			}
		})
	}}, nil
}
