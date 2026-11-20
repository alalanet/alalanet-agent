package installread

import (
	"reflect"
	"testing"
)

// ENV-HASH-ASK (the ENV-S-1 round-6 review): envWords reads env's comment rule as GNU and macOS env do (a # that
// starts a word ends the split string; inside a word it is a letter; the words after -S's value still follow),
// so a # is no reason to ask by itself.
func TestEnvSplitHashIsReadAsEnvReadsIt(t *testing.T) {
	for _, c := range []struct {
		line    string
		targets []string
	}{
		{`env -S 'npm i zz-hash-a #npm i zz-hash-b'`, []string{"npm:zz-hash-a"}},              // the comment runs nothing
		{`env -S 'npm i zz-hash-a #x' zz-hash-c`, []string{"npm:zz-hash-a", "npm:zz-hash-c"}}, // the words after the value follow
		{`env -S '#npm i zz-hash-b' npm i zz-hash-d`, []string{"npm:zz-hash-d"}},
		{`env -S 'echo a#b' && npm i zz-hash-e`, []string{"npm:zz-hash-e"}},
	} {
		tg, unread, _, _ := ParseLine(c.line)
		if !reflect.DeepEqual(tg, c.targets) || len(unread) != 0 {
			t.Errorf("%q: targets %q, unread %q; want %q and no reason", c.line, tg, unread, c.targets)
		}
	}
	for _, line := range []string{`env -S 'echo #hi'`, `env -S 'echo a#b'`, `env -S 'true # a comment'`} {
		if tg, unread, _, _ := ParseLine(line); len(tg) != 0 || len(unread) != 0 {
			t.Errorf("%q: targets %q, unread %q; want nothing: it installs nothing", line, tg, unread)
		}
	}
}
