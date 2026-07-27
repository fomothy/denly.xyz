package buildinfo

import (
	"runtime"
	"strings"
	"testing"
)

func TestGetFillsPlatformAndGoVersion(t *testing.T) {
	info := Get()

	if want := runtime.GOOS + "/" + runtime.GOARCH; info.Platform != want {
		t.Errorf("Platform = %q, want %q", info.Platform, want)
	}
	if info.GoVersion != runtime.Version() {
		t.Errorf("GoVersion = %q, want %q", info.GoVersion, runtime.Version())
	}
}

// An unstamped build must be recognisable as such, so a `go build` binary is
// never mistaken for a release in a bug report.
func TestIsReleaseFalseForDevDefault(t *testing.T) {
	original := Version
	t.Cleanup(func() { Version = original })

	Version = "dev"
	if IsRelease() {
		t.Error("IsRelease() = true for the dev default, want false")
	}

	Version = "v1.2.3"
	if !IsRelease() {
		t.Error("IsRelease() = false for a stamped version, want true")
	}
}

func TestStringIncludesVersionAndPlatform(t *testing.T) {
	originalVersion, originalCommit := Version, Commit
	t.Cleanup(func() { Version, Commit = originalVersion, originalCommit })

	Version = "v9.9.9"
	Commit = "abcdef0123456789abcdef"

	got := Get().String()

	if !strings.Contains(got, "v9.9.9") {
		t.Errorf("String() = %q, want it to contain the version", got)
	}
	if !strings.Contains(got, runtime.GOOS) {
		t.Errorf("String() = %q, want it to contain the platform", got)
	}
	if !strings.HasPrefix(got, "denly ") {
		t.Errorf("String() = %q, want it to start with the binary name", got)
	}
}

// The status page and /healthz both render the commit; a full SHA is noise.
func TestShortCommitTruncates(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"abcdef0123456789abcdef", "abcdef012345"},
		{"abc", "abc"},
		{"", ""},
	}
	for _, tt := range tests {
		got := Info{Commit: tt.in}.shortCommit()
		if got != tt.want {
			t.Errorf("shortCommit(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
