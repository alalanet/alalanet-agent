package installread

import (
	"slices"
	"testing"
)

// READER-ESCAPE-1, the seventh live form: uv's pip interface with an escaped or quoted verb installs the package
// (bash, dash and zsh drop the backslash and the quotes), so the hook's reader reads it as the plain line does.
func TestReaderEscapeUvPip(t *testing.T) {
	plainTg, plainUn, _, _ := ParseLine(`uv pip install requests`)
	for _, line := range []string{`uv pip in\stall requests`, `uv pip in'stall' requests`, `uv pip "install" requests`, `u\v pip install requests`} {
		tg, un, _, s := ParseLine(line)
		if !slices.Contains(tg, "pypi:requests") {
			t.Errorf("%q: targets %v, want pypi:requests", line, tg)
		}
		if !slices.Equal(tg, plainTg) || len(un) != len(plainUn) || len(HookExtra(line, tg, un, s)) != 0 {
			t.Errorf("%q reads %v %v, the plain line %v %v", line, tg, un, plainTg, plainUn)
		}
	}
}
