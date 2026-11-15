package installread

import (
	"reflect"
	"testing"
)

// P1-X round 6 (ADR-0173; the re-review of 58fe36a): inside a single-quoted part of a split string, GNU env and
// BSD/macOS env read \' as a quote and \\ as a backslash (their only escapes there). Read otherwise, the quote
// ends early and the package word after an option's value is swallowed into it: the hook said nothing while env
// ran the install. Inside a double-quoted part GNU decodes \t \n \v \f \r \# \' as well (content only).
func TestEnvWordsSingleQuoteEscapes(t *testing.T) {
	for in, want := range map[string][]string{
		`npm i --tag 'v\'b' zz-r6-c`: {"npm", "i", "--tag", "v'b", "zz-r6-c"},
		`a 'b\\' c`:                  {"a", `b\`, "c"},
		`a 'b\c' d`:                  {"a", `b\c`, "d"}, // any other backslash is a letter there
		`a 'b\"c' d`:                 {"a", `b\"c`, "d"},
		`a "b\tc\#d\'e" f`:           {"a", "b\tc#d'e", "f"},
		`a "b\nc\vd\fe\rf" g`:        {"a", "b\nc\vd\fe\rf", "g"},
	} {
		if got := envWords(in); !reflect.DeepEqual(got, want) {
			t.Errorf("envWords(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestEnvSplitSingleQuoteEscapeReadsThePackage(t *testing.T) {
	for _, line := range []string{
		`env -S "npm i --tag 'v\'b' zz-r6-c"`,
		`env -S "npm i --tag 'v\\\\' zz-r6-c"`,
		`env --split-string="npm i --tag 'v\'b' zz-r6-c"`,
	} {
		tg, unread, _, _ := ParseLine(line)
		if !reflect.DeepEqual(tg, []string{"npm:zz-r6-c"}) && len(unread) == 0 {
			t.Errorf("%q: targets %q, unread %q; want npm:zz-r6-c read (or a reason): env installs it", line, tg, unread)
		}
	}
}
