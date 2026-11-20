package installread

import (
	"strings"
	"testing"
)

// Review of ADR-0159 round 44 (c82a823f): uv's global options written between "tool" and its subcommand. clap's global
// arguments are taken at every level, so uv tool -q run x runs x as uv tool run x does. Each line must read as the
// same line without the option reads (a target or a hold), not silently. The lines are data only.
func TestZZReviewRRS44UvToolGlobals(t *testing.T) {
	for line, same := range map[string]string{
		"uv tool -q run zz-pkg":                                     "uv tool run zz-pkg",
		"uv tool --offline run zz-pkg":                              "uv tool run zz-pkg",
		"uv tool --directory /srv run zz-pkg":                       "uv tool run zz-pkg",
		"uv tool --cache-dir /tmp/c run zz-pkg":                     "uv tool run zz-pkg",
		"uv tool -q uvx zz-pkg":                                     "uv tool uvx zz-pkg",
		"uv -q tool -q run zz-pkg":                                  "uv tool run zz-pkg",
		"uv tool --offline run --from zz-pkg sh -c 'npm i zz-evil'": "uv tool run --from zz-pkg sh -c 'npm i zz-evil'",
		"uv tool -q run sh -c 'npm i zz-evil'":                      "uv tool run sh -c 'npm i zz-evil'",
	} {
		tg, un, _, s := ParseLine(line)
		ex := HookExtra(line, tg, un, s)
		tw, uw, _, sw := ParseLine(same)
		exw := HookExtra(same, tw, uw, sw)
		got := strings.Join(tg, " ") + " | holds " + strings.Repeat("x", len(un)+len(ex))
		want := strings.Join(tw, " ") + " | holds " + strings.Repeat("x", len(uw)+len(exw))
		t.Logf("%q -> %s (as %q: %s)", line, got, same, want)
		if len(tg) == 0 && len(un)+len(ex) == 0 {
			t.Errorf("%q passes silently, while %q gives %s", line, same, want)
		}
	}
}
