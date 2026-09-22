//go:build !windows

package probe

// NewPlatform reports ErrUnsupported: the probe's session model is Windows'.
// The protocol, enforcement loop and hub are exercised against a fake
// Platform in this package's tests on every OS.
func NewPlatform() (Platform, error) { return nil, ErrUnsupported }
