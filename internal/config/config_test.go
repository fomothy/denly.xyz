package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestResolveDataDirPrecedence(t *testing.T) {
	envDir := t.TempDir()
	flagDir := t.TempDir()

	t.Setenv(EnvDataDir, envDir)

	t.Run("flag beats env", func(t *testing.T) {
		got, err := ResolveDataDir(flagDir)
		if err != nil {
			t.Fatalf("ResolveDataDir: %v", err)
		}
		if got != flagDir {
			t.Errorf("got %q, want flag value %q", got, flagDir)
		}
	})

	t.Run("env beats platform default", func(t *testing.T) {
		got, err := ResolveDataDir("")
		if err != nil {
			t.Fatalf("ResolveDataDir: %v", err)
		}
		if got != envDir {
			t.Errorf("got %q, want env value %q", got, envDir)
		}
	})
}

func TestResolveDataDirPlatformDefault(t *testing.T) {
	t.Setenv(EnvDataDir, "")

	got, err := ResolveDataDir("")
	if err != nil {
		t.Fatalf("ResolveDataDir: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("default data dir %q is not absolute", got)
	}
	if filepath.Base(got) != dirName {
		t.Errorf("default data dir %q does not end in %q", got, dirName)
	}

	// Guard the specific convention per platform, since install.sh, the
	// Docker image, and the backup command all assume it.
	switch runtime.GOOS {
	case "darwin":
		if !strings.Contains(got, filepath.Join("Library", "Application Support")) {
			t.Errorf("darwin default %q is not in Application Support", got)
		}
	case "linux":
		if !strings.Contains(got, filepath.Join(".local", "share")) {
			t.Errorf("linux default %q is not in ~/.local/share", got)
		}
	}
}

func TestResolveDataDirRespectsXDG(t *testing.T) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		t.Skip("XDG only applies to linux/BSD")
	}
	xdg := t.TempDir()
	t.Setenv(EnvDataDir, "")
	t.Setenv("XDG_DATA_HOME", xdg)

	got, err := ResolveDataDir("")
	if err != nil {
		t.Fatalf("ResolveDataDir: %v", err)
	}
	if want := filepath.Join(xdg, dirName); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolveDataDirRelativeBecomesAbsolute(t *testing.T) {
	t.Setenv(EnvDataDir, "")

	got, err := ResolveDataDir("relative/data")
	if err != nil {
		t.Fatalf("ResolveDataDir: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("got %q, want an absolute path", got)
	}
}

func TestResolveDataDirExpandsHome(t *testing.T) {
	t.Setenv(EnvDataDir, "")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home dir: %v", err)
	}

	got, err := ResolveDataDir("~/denly-test")
	if err != nil {
		t.Fatalf("ResolveDataDir: %v", err)
	}
	if want := filepath.Join(home, "denly-test"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEnsureDataDirIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits do not apply on windows")
	}
	dir := filepath.Join(t.TempDir(), "nested", "denly")

	if err := EnsureDataDir(dir); err != nil {
		t.Fatalf("EnsureDataDir: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("data dir mode = %04o, want 0700", perm)
	}
}

// The data dir holds private keys. A pre-existing loose directory — a
// bind-mounted volume, say — must be tightened, not left as found.
func TestEnsureDataDirTightensExistingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits do not apply on windows")
	}
	dir := filepath.Join(t.TempDir(), "loose")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	if err := EnsureDataDir(dir); err != nil {
		t.Fatalf("EnsureDataDir: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("data dir mode = %04o, want 0700", perm)
	}
}

func TestResolveAddr(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvDataDir, dir)

	tests := []struct {
		name string
		flag string
		env  string
		want string
	}{
		{"default", "", "", DefaultAddr},
		{"env override", "", ":9000", ":9000"},
		{"flag beats env", "127.0.0.1:1234", ":9000", "127.0.0.1:1234"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvAddr, tt.env)
			cfg, err := Resolve("", tt.flag)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if cfg.Addr != tt.want {
				t.Errorf("Addr = %q, want %q", cfg.Addr, tt.want)
			}
		})
	}
}

// A fresh install must not be reachable from the network until the operator
// opts in. This is a deliberate product invariant, not an accident.
func TestDefaultAddrIsLoopback(t *testing.T) {
	if !strings.HasPrefix(DefaultAddr, "127.0.0.1:") {
		t.Errorf("DefaultAddr = %q, want a loopback bind", DefaultAddr)
	}
}

func TestDBPath(t *testing.T) {
	if want := filepath.Join("/x", "denly.db"); DBPath("/x") != want {
		t.Errorf("DBPath = %q, want %q", DBPath("/x"), want)
	}
}
