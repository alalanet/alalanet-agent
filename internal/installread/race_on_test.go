//go:build race

package installread

// raceDetector: this test binary runs under the race detector (go test -race), which make ci and the pipeline use;
// the cost bounds then allow the detector's slowdown (READER-SHELLS round 10, R5-1).
const raceDetector = true
