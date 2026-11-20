//go:build race

package main

// raceDetector: this test binary runs under the race detector, which slows the reading several times over; a timing
// bound of a test scales by it (ADR-0159 round 14).
const raceDetector = true
