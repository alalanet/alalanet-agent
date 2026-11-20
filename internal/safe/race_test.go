//go:build race

package safe

// raceDetector: the tests run under the race detector, which slows Unseen's passes many times over
// (TestUnseenCost; the prober's raceDetector likewise).
const raceDetector = true
