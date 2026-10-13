// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

package view

import (
	"bytes"
	"regexp"
	"testing"
)

// The templates iterate lists without asking first, so the page data must
// carry an empty list, not null, wherever there is none. Seen in the
// register: a run without trial checks left D.trial null, and the check tab
// threw "D.trial is not iterable".
func TestRenderWritesNoNullLists(t *testing.T) {
	data := &Data{
		Reqs: map[string]*Req{"A.1": {T: "One"}},
		Ext:  map[string]*Ext{},
		ISO:  map[string][]ISO{"A.8.1": nil},
	}
	for _, v := range Views {
		page, err := Render(v, data)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{`"trial":[]`, `"checks":[]`, `"warnings":[]`, `"runs":[]`, `"c":[]`, `"h":[]`, `"A.8.1":[]`} {
			if !bytes.Contains(page, []byte(want)) {
				t.Errorf("%s: no %s in the data", v, want)
			}
		}
		// Only the pointers may be null: a parameter value, a deadline, a POA&M entry.
		for _, m := range regexp.MustCompile(`"([A-Za-z0-9.]+)":null`).FindAllSubmatch(page, -1) {
			if k := string(m[1]); k != "p" && k != "dl" && k != "poam" {
				t.Errorf("%s: %s is null", v, k)
			}
		}
	}
}
