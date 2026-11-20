package main

// Review of VERIFY-AUTO-1 round 2 (8f23a0e): honest shell lines the widened mcp-approve rule holds.

import "testing"

func TestReviewR2ApproveRuleHonestLines(t *testing.T) {
	for _, line := range []string{
		`git commit -m "fix(agent): alalanet-agent asks the user to approve installs"`,
		`cd ~/src/alalanet && gh pr review 12 --approve`,
		`cd ~/src/alalanet && go test ./... -run TestExpect`,
		`cd ~/src/alalanet && npm run script`,
		`cd ~/src/alalanet/script && ./build.sh`,
		`alalanet-agent mcp-verify`,
		`alalanet-agent hook cursor < input.json`,
		`grep -rn approve ~/src/alalanet/docs`,
		`echo "alalanet: expect a 404 here" >> notes.md`,
		`pip install pexpect && cd alalanet`,
		`curl -fsS https://alalanet.com/v1/services/abc/tools`,
	} {
		t.Logf("%-80s held=%v", line, approvesMCP(line))
		if approvesMCP(line) { // round 3 (N2): honest lines stay plain
			t.Errorf("an honest line is held: %s", line)
		}
	}
}
