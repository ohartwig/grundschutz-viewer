// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

package view

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed templates/*.html
var templates embed.FS

// Views lists the page layouts there are.
var Views = []string{"explorer", "register"}

// Render writes the page of one view with the data embedded.
func Render(view string, data *Data) ([]byte, error) {
	tpl, err := templates.ReadFile("templates/" + view + ".html")
	if err != nil {
		return nil, fmt.Errorf("unknown view %q (there are %s)", view, strings.Join(Views, ", "))
	}
	var blob bytes.Buffer
	enc := json.NewEncoder(&blob)
	enc.SetEscapeHTML(true) // the blob sits in a <script>: no "</script>" can end it early
	if err := enc.Encode(data); err != nil {
		return nil, err
	}
	const slot = "/*__DATA__*/null"
	if !bytes.Contains(tpl, []byte(slot)) {
		return nil, fmt.Errorf("view %s has no data slot", view)
	}
	return bytes.Replace(tpl, []byte(slot), bytes.TrimSpace(blob.Bytes()), 1), nil
}
