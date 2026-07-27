package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fomothy/denly.xyz/internal/auth"
	"github.com/fomothy/denly.xyz/internal/config"
	"github.com/fomothy/denly.xyz/internal/drop"
)

func runDrop(args []string) error {
	fs := flag.NewFlagSet("drop", flag.ContinueOnError)
	var (
		server   = fs.String("server", "", "denly instance to upload to (default: the local one)")
		dataDir  = fs.String("data-dir", "", "data directory, used to find the admin token")
		expiry   = fs.Duration("expires", drop.DefaultTTL, "how long the drop lives")
		burn     = fs.Int("burn-after", 0, "delete after this many downloads (0 = no limit)")
		filename = fs.String("name", "", "filename to record inside the encrypted envelope")
	)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: denly drop <file> [flags]
       cat file | denly drop - [flags]

Encrypts a file locally and uploads only the ciphertext. The key is printed
as part of the link and never sent to the server.

Flags:
`)
		fs.PrintDefaults()
	}
	positional, err := parsePermuted(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		fs.Usage()
		return errors.New("drop needs exactly one file, or - for stdin")
	}

	source := positional[0]
	content, name, err := readDropSource(source, *filename)
	if err != nil {
		return err
	}
	if len(content) == 0 {
		return errors.New("nothing to send: the input was empty")
	}

	// Encrypt before anything touches the network. The envelope carries the
	// filename and content type, so neither reaches the server.
	env := drop.Envelope{
		Filename:    name,
		ContentType: guessContentType(name),
		Content:     content,
	}
	ciphertext, fragmentKey, err := drop.Seal(env)
	if err != nil {
		return err
	}

	base := resolveServer(*server)
	dataDirPath, err := config.ResolveDataDir(*dataDir)
	if err != nil {
		return err
	}

	created, err := uploadDrop(base, dataDirPath, ciphertext, *expiry, *burn)
	if err != nil {
		return err
	}

	link := fmt.Sprintf("%s/d/%s#%s", strings.TrimRight(base, "/"), created.ID, fragmentKey)

	// The link goes to stdout alone so `denly drop x | pbcopy` does the
	// obvious thing; everything else is commentary on stderr.
	fmt.Fprintf(os.Stderr, "Encrypted %s (%s) and uploaded %s of ciphertext.\n",
		name, humanBytes(int64(len(content))), humanBytes(created.SizeBytes))
	if created.ExpiresAt != nil {
		fmt.Fprintf(os.Stderr, "Expires %s.\n", created.ExpiresAt.Format(time.RFC1123))
	}
	if *burn > 0 {
		fmt.Fprintf(os.Stderr, "Burns after %d download(s).\n", *burn)
	}
	fmt.Fprintln(os.Stderr, "The server cannot read it. Anyone with this link can.")
	fmt.Fprintln(os.Stderr)

	fmt.Println(link)
	return nil
}

func readDropSource(source, override string) (content []byte, name string, err error) {
	if source == "-" {
		content, err = io.ReadAll(io.LimitReader(os.Stdin, drop.MaxCiphertext+1))
		if err != nil {
			return nil, "", fmt.Errorf("reading stdin: %w", err)
		}
		name = override
		if name == "" {
			name = "stdin"
		}
		return content, name, nil
	}

	content, err = os.ReadFile(source)
	if err != nil {
		return nil, "", fmt.Errorf("reading %s: %w", source, err)
	}
	name = override
	if name == "" {
		name = filepath.Base(source)
	}
	return content, name, nil
}

func guessContentType(name string) string {
	if ct := mime.TypeByExtension(filepath.Ext(name)); ct != "" {
		return ct
	}
	return "application/octet-stream"
}

// resolveServer defaults to the local instance.
func resolveServer(server string) string {
	if server == "" {
		return "http://" + config.DefaultAddr
	}
	if !strings.HasPrefix(server, "http://") && !strings.HasPrefix(server, "https://") {
		server = "https://" + server
	}
	return strings.TrimRight(server, "/")
}

func uploadDrop(base, dataDir string, ciphertext []byte, ttl time.Duration, burn int) (drop.Drop, error) {
	url := fmt.Sprintf("%s/api/drops?expires=%s&burn_after=%d", base, ttl.String(), burn)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(ciphertext))
	if err != nil {
		return drop.Drop{}, fmt.Errorf("building upload request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	// Uploading is an owner action, so it needs the admin token. A missing
	// token is not fatal here — the server will say so more precisely.
	if token, err := auth.LoadOrCreateToken(dataDir); err == nil {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return drop.Drop{}, fmt.Errorf("uploading to %s: %w (is `denly serve` running?)", base, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return drop.Drop{}, fmt.Errorf("reading upload response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return drop.Drop{}, fmt.Errorf("server refused the drop (HTTP %d): %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var created drop.Drop
	if err := json.Unmarshal(body, &created); err != nil {
		return drop.Drop{}, fmt.Errorf("server returned an unreadable response: %w", err)
	}
	return created, nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
