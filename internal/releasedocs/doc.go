// Package releasedocs holds no code: its test checks that the image digests
// the repository's documents record for each release agree with each other
// (Phase 262). A digest reaches README.md, CHANGELOG.md and ROADMAP.md by
// hand, in a follow-up PR after the release publishes, and nothing else would
// notice a mistyped copy, a stale README line or a placeholder left behind.
//
// Its other tests hold the documentation's currency stamps to each other
// (Phase 267), and keep the project's name PAMv1 in prose across every
// tracked file, lowercase only where it is an identifier (house style §8).
package releasedocs
