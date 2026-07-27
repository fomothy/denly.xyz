// Package web holds the frontend, compiled into the binary via go:embed.
//
// Everything the browser needs ships inside the executable: no CDN, no
// external fonts, no runtime asset directory to lose during an upgrade. A
// denly instance on an air-gapped machine or behind Tor renders identically to
// one on the public internet, and no third party learns who visits a page.
package web

import (
	"embed"
	"html/template"
	"io/fs"
)

//go:embed static templates
var files embed.FS

// Static returns the static asset tree, rooted so that "static/style.css" is
// served at "/static/style.css".
func Static() (fs.FS, error) {
	return fs.Sub(files, "static")
}

// Templates parses the embedded HTML templates. Parsing happens once at
// startup; a parse failure is a programming error and should stop the server
// rather than surface as a 500 on first request.
func Templates() (*template.Template, error) {
	return template.ParseFS(files, "templates/*.html")
}
