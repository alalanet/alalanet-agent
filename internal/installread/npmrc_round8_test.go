package installread

import (
	"slices"
	"testing"
)

// REPO-POL-NPMRC round 8 (ADR-0174): pip's and uv's -C, --config-setting(s) take a value, which is no target.
func TestConfigSettingIsAValue(t *testing.T) {
	for _, line := range []string{"pip install -C key=v acme-tools", "uv pip install -C key=v acme-tools",
		"pip install --config-settings key=v acme-tools", "uv pip install --config-setting key=v acme-tools"} {
		if targets, _, _, _ := ParseLine(line); !slices.Equal(targets, []string{"pypi:acme-tools"}) {
			t.Errorf("%s: %v", line, targets)
		}
	}
}

// Commands gives the commands ParseLine's walk visits: past a wrapper's valued option, into sh -c, after whichSubst.
func TestCommandsAreTheWalks(t *testing.T) {
	cmds := Commands("timeout 5 sh -c 'cd /srv && npm i x'; $(which env) FOO=1 npm i y")
	var progs []string
	for _, c := range cmds {
		progs = append(progs, c.Prog)
	}
	if want := []string{"sh", "cd", "npm", "npm"}; !slices.Equal(progs, want) {
		t.Errorf("programs %v, want %v (%+v)", progs, want, cmds)
	}
	if len(cmds) == 4 && (!slices.Equal(cmds[0].Wrappers, []string{"timeout", "5"}) || !slices.Equal(cmds[3].Assigns, []string{"FOO=1"})) {
		t.Errorf("wrappers %v, assigns %v", cmds[0].Wrappers, cmds[3].Assigns)
	}
}
