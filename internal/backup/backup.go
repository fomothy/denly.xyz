// Package backup archives and restores a denly data directory.
//
// The archive is encrypted with a passphrase, not with the identity key. That
// is deliberate: the data directory *contains* the identity key, so encrypting
// to it would make the backup useless in the one situation backups exist for —
// losing the machine and the key with it. A passphrase is something a person
// can carry in their head or a password manager.
//
// Format:
//
//	"DENLYBK1" || salt(16) || nonce(24) || XChaCha20-Poly1305(tar.gz)
//
// The header is authenticated as additional data, so the salt and version
// cannot be swapped without the open failing.
package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"

	"github.com/fomothy/denly.xyz/internal/nostr"
)

// Magic identifies the archive format and its version.
var Magic = []byte("DENLYBK1")

const (
	saltLen = 16

	// scrypt parameters. N=2^17 costs roughly 128 MiB and a fraction of a
	// second — deliberately expensive, because a backup archive is exactly the
	// kind of file that gets copied to cloud storage and attacked offline at
	// leisure.
	scryptN = 1 << 17
	scryptR = 8
	scryptP = 1

	// MinPassphraseLen is enforced because the scrypt cost is the only thing
	// standing between a short passphrase and an offline attacker.
	MinPassphraseLen = 12

	// maxEntrySize bounds a single file during restore, so a malicious archive
	// cannot exhaust memory or disk.
	maxEntrySize = 1 << 30 // 1 GiB
)

var (
	// ErrBadPassphrase is returned when decryption fails, which in practice
	// means the wrong passphrase or a corrupted archive.
	ErrBadPassphrase = errors.New("wrong passphrase, or the archive is damaged")
	// ErrNotAnArchive is returned when the magic header does not match.
	ErrNotAnArchive = errors.New("that file is not a denly backup")
	// ErrUnsafePath is returned when an archive contains a path that would
	// escape the destination directory.
	ErrUnsafePath = errors.New("archive contains an unsafe path")
)

// skipNames are regenerated on start or meaningless elsewhere, so they are not
// worth carrying in a backup.
var skipNames = map[string]bool{
	"denly.db-wal": true,
	"denly.db-shm": true,
	".DS_Store":    true,
}

// Create writes an encrypted archive of dataDir to w.
func Create(dataDir, passphrase string, w io.Writer) error {
	if len(passphrase) < MinPassphraseLen {
		return fmt.Errorf("passphrase must be at least %d characters", MinPassphraseLen)
	}

	var plain bytes.Buffer
	if err := writeTarGz(dataDir, &plain); err != nil {
		return err
	}

	salt, err := nostr.RandomBytes(saltLen)
	if err != nil {
		return err
	}
	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("initialising cipher: %w", err)
	}
	nonce, err := nostr.RandomBytes(aead.NonceSize())
	if err != nil {
		return err
	}

	header := make([]byte, 0, len(Magic)+saltLen+len(nonce))
	header = append(header, Magic...)
	header = append(header, salt...)
	header = append(header, nonce...)

	// The header is the additional data, so a tampered salt or version fails
	// the open rather than silently deriving a different key.
	sealed := aead.Seal(nil, nonce, plain.Bytes(), header)

	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("writing archive header: %w", err)
	}
	if _, err := w.Write(sealed); err != nil {
		return fmt.Errorf("writing archive body: %w", err)
	}
	return nil
}

// Restore decrypts an archive from r and writes its contents into dataDir.
//
// It refuses to overwrite a non-empty directory: restoring on top of a live
// instance is how someone loses the identity they were trying to recover.
func Restore(r io.Reader, dataDir, passphrase string) error {
	raw, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("reading archive: %w", err)
	}

	minLen := len(Magic) + saltLen + chacha20poly1305.NonceSizeX
	if len(raw) < minLen+chacha20poly1305.Overhead {
		return ErrNotAnArchive
	}
	if !bytes.Equal(raw[:len(Magic)], Magic) {
		return ErrNotAnArchive
	}

	salt := raw[len(Magic) : len(Magic)+saltLen]
	nonce := raw[len(Magic)+saltLen : minLen]
	header := raw[:minLen]
	body := raw[minLen:]

	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("initialising cipher: %w", err)
	}
	plain, err := aead.Open(nil, nonce, body, header)
	if err != nil {
		return ErrBadPassphrase
	}

	if err := ensureRestorable(dataDir); err != nil {
		return err
	}
	return extractTarGz(bytes.NewReader(plain), dataDir)
}

// Verify checks that an archive decrypts and its contents parse, without
// writing anything.
//
// A backup nobody has restored is a hope, not a backup — this is what lets
// `denly backup --verify` and CI confirm the archive is actually usable.
func Verify(r io.Reader, passphrase string) ([]string, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading archive: %w", err)
	}

	minLen := len(Magic) + saltLen + chacha20poly1305.NonceSizeX
	if len(raw) < minLen+chacha20poly1305.Overhead || !bytes.Equal(raw[:len(Magic)], Magic) {
		return nil, ErrNotAnArchive
	}

	salt := raw[len(Magic) : len(Magic)+saltLen]
	nonce := raw[len(Magic)+saltLen : minLen]

	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("initialising cipher: %w", err)
	}
	plain, err := aead.Open(nil, nonce, raw[minLen:], raw[:minLen])
	if err != nil {
		return nil, ErrBadPassphrase
	}

	gz, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		return nil, fmt.Errorf("archive is corrupt: %w", err)
	}
	defer func() { _ = gz.Close() }()

	var names []string
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("archive is corrupt: %w", err)
		}
		names = append(names, hdr.Name)
	}
	return names, nil
}

func deriveKey(passphrase string, salt []byte) ([]byte, error) {
	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, chacha20poly1305.KeySize)
	if err != nil {
		return nil, fmt.Errorf("deriving key: %w", err)
	}
	return key, nil
}

func writeTarGz(dataDir string, w io.Writer) error {
	// Open a root scoped to the data directory and read every file through it.
	// filepath.Walk hands back a path that was resolved a moment ago; opening
	// that path directly means a symlink swapped in between the stat and the
	// open would be followed. os.Root refuses to traverse outside its root, so
	// the race stops being exploitable rather than merely unlikely.
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		return fmt.Errorf("opening %s: %w", dataDir, err)
	}
	defer func() { _ = root.Close() }()

	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	err = filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dataDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if skipNames[info.Name()] {
			return nil
		}
		// Symlinks in a data directory would let a crafted backup write
		// outside the destination on restore. Nothing denly creates is a
		// symlink, so refusing them costs nothing.
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("describing %s: %w", rel, err)
		}
		hdr.Name = filepath.ToSlash(rel)

		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("writing header for %s: %w", rel, err)
		}
		if info.IsDir() {
			return nil
		}

		f, err := root.Open(filepath.ToSlash(rel))
		if err != nil {
			return fmt.Errorf("opening %s: %w", rel, err)
		}
		defer func() { _ = f.Close() }()

		if _, err := io.Copy(tw, f); err != nil {
			return fmt.Errorf("archiving %s: %w", rel, err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("building archive: %w", err)
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("finishing archive: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("compressing archive: %w", err)
	}
	return nil
}

func extractTarGz(r io.Reader, dataDir string) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dataDir, err)
	}

	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("archive is corrupt: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("archive is corrupt: %w", err)
		}

		target, err := safeJoin(dataDir, hdr.Name)
		if err != nil {
			return err
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return fmt.Errorf("creating %s: %w", hdr.Name, err)
			}

		case tar.TypeReg:
			if hdr.Size > maxEntrySize {
				return fmt.Errorf("%s is %d bytes, which exceeds the restore limit", hdr.Name, hdr.Size)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return fmt.Errorf("creating parent of %s: %w", hdr.Name, err)
			}
			// Always 0600, ignoring the archived mode. Everything denly writes
			// is owner-only anyway, and honouring a mode from an untrusted
			// archive means trusting an attacker to pick file permissions.
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) //nolint:gosec // target is validated by safeJoin
			if err != nil {
				return fmt.Errorf("creating %s: %w", hdr.Name, err)
			}
			if _, err := io.Copy(f, io.LimitReader(tr, maxEntrySize)); err != nil {
				_ = f.Close()
				return fmt.Errorf("writing %s: %w", hdr.Name, err)
			}
			if err := f.Close(); err != nil {
				return fmt.Errorf("closing %s: %w", hdr.Name, err)
			}

		default:
			// Symlinks, devices, and hard links have no business in a denly
			// data directory and are the classic tar-extraction escape.
			return fmt.Errorf("%w: %s has unsupported type %q", ErrUnsafePath, hdr.Name, hdr.Typeflag)
		}
	}
}

// safeJoin resolves an archive path inside dest, rejecting traversal.
func safeJoin(dest, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("%w: empty name", ErrUnsafePath)
	}
	if filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("%w: %s is absolute", ErrUnsafePath, name)
	}

	cleaned := filepath.Clean(filepath.FromSlash(name))
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("%w: %s escapes the destination", ErrUnsafePath, name)
	}

	target := filepath.Join(dest, cleaned)

	// Belt and braces: confirm the resolved path really is under dest.
	rel, err := filepath.Rel(dest, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("%w: %s escapes the destination", ErrUnsafePath, name)
	}
	return target, nil
}

// ensureRestorable refuses to restore over an existing instance.
func ensureRestorable(dataDir string) error {
	entries, err := os.ReadDir(dataDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("checking %s: %w", dataDir, err)
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") {
			return fmt.Errorf(
				"%s is not empty; restoring would overwrite the identity and data already there. "+
					"Move it aside first, or restore into a new directory with --data-dir", dataDir)
		}
	}
	return nil
}
