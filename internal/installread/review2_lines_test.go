package installread

import "testing"

func TestReview2Lines(t *testing.T) {
	for _, line := range []string{
		"pip install -r <(cat evil.txt)",
		"pip install -r /dev/fd/3 3< evil.txt",
		"pip install -r /dev/stdin < evil.txt",
		"echo evil.txt | xargs pip install -r",
		"D=sub; cd $D && pip install -r r.txt",
		"cd && pip install -r r.txt",
		"sudo -i pip install -r r.txt",
		"PIP_CONSTRAINT=c.txt pip install zz-pkg",
		"PIP_REQUIREMENT=r.txt pip install",
		"UV_CONSTRAINT=c.txt uv pip install zz-pkg",
		"UV_OVERRIDE=o.txt uv pip install zz-pkg",
		"export PIP_CONSTRAINT=c.txt; pip install zz-pkg",
	} {
		tg, un, _, subst := ParseLine(line)
		t.Logf("%-45q targets %v unread %v extra %v files %v", line, tg, un, HookExtra(line, tg, un, subst), RequirementFiles(line))
	}
}
