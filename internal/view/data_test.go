// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

package view

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ohartwig/grundschutz-viewer/internal/oscal"
)

// chain writes a small, complete chain the way grundschutz-worksheets does:
// catalog <- profile <- one security plan per run, with results next to it
// and trial results in a subdirectory. Imports go through back-matter with
// the SHA-256 of the file. It returns the root directory.
func chain(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel string, v any) string {
		data, err := json.MarshalIndent(v, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:])
	}
	res := func(uuid, href, sum string) map[string]any {
		return map[string]any{"uuid": uuid, "rlinks": []any{map[string]any{"href": href, "hashes": []any{map[string]any{"algorithm": "SHA-256", "value": sum}}}}}
	}
	ctl := func(id, title, prose string, params ...any) map[string]any {
		return map[string]any{"id": id, "title": title, "params": params,
			"props": []any{map[string]any{"name": "sec_level", "value": "normal-SdT"}, map[string]any{"name": "threats", "value": "G 0.18, G 0.19"}},
			"parts": []any{map[string]any{"name": "statement", "prose": prose, "props": []any{map[string]any{"name": "modal_verb", "value": "MUSS"}}}}}
	}
	catSum := write("lib/catalog.json", map[string]any{"catalog": map[string]any{
		"uuid": "c", "metadata": map[string]any{"title": "Katalog"},
		"groups": []any{map[string]any{"id": "GC", "title": "Governance", "groups": []any{map[string]any{"id": "GC.1", "title": "Grundlagen", "controls": []any{
			ctl("GC.1.1", "ISMS", "GC MUSS ein ISMS {{ insert: param, gc.1.1-prm1 }} verankern.", map[string]any{"id": "gc.1.1-prm1", "label": "nach einem Standard"}),
			ctl("GC.1.2", "Rollen", "GC MUSS Rollen festlegen."),
			ctl("GC.1.3", "Nicht anwendbar", "GC KANN etwas."),
		}}}}},
	}})
	profSum := write("lib/profile.json", map[string]any{"profile": map[string]any{
		"uuid": "p", "metadata": map[string]any{"title": "Profil", "last-modified": "2026-10-01T00:00:00Z", "props": []any{map[string]any{"name": "catalog-commit", "value": "0123456789abcdef"}}},
		"imports": []any{map[string]any{"href": "#cat", "include-controls": []any{map[string]any{"with-ids": []string{"GC.1.1", "GC.1.2"}}}}},
		"modify":  map[string]any{"set-parameters": []any{map[string]any{"param-id": "gc.1.1-prm1", "values": []string{"nach ISO 27001"}}}},
		"back-matter": map[string]any{"resources": []any{res("cat", "catalog.json", catSum),
			map[string]any{"uuid": "na", "description": "gibt es nicht", "props": []any{map[string]any{"name": "control-id", "value": "GC.1.3"}, map[string]any{"name": "tailoring", "value": "not-applicable"}}}}},
	}})
	ssp := func(dir, stamp, st2 string) {
		sspSum := write(dir+"/security-plan.json", map[string]any{"system-security-plan": map[string]any{
			"uuid": "s", "metadata": map[string]any{"title": "Plan", "last-modified": stamp},
			"import-profile": map[string]any{"href": "#prof"},
			"control-implementation": map[string]any{"implemented-requirements": []any{
				map[string]any{"control-id": "GC.1.1", "props": []any{map[string]any{"name": "implementation-status", "value": "implemented"}}},
				map[string]any{"control-id": "GC.1.2", "props": []any{map[string]any{"name": "implementation-status", "value": st2}}},
			}},
			"back-matter": map[string]any{"resources": []any{res("prof", "../../lib/profile.json", profSum)}},
		}})
		apSum := write(dir+"/assessment-plan.json", map[string]any{"assessment-plan": map[string]any{
			"uuid": "a", "metadata": map[string]any{"title": "Prüfplan", "last-modified": stamp},
			"import-ssp": map[string]any{"href": "#ssp"},
			"local-definitions": map[string]any{"activities": []any{map[string]any{"title": "ISMS da", "props": []any{map[string]any{"name": "check", "value": "isms"}, map[string]any{"name": "method", "value": "TEST"}},
				"related-controls": map[string]any{"control-selections": []any{map[string]any{"include-controls": []any{map[string]any{"control-id": "GC.1.1"}}}}}}}},
			"back-matter": map[string]any{"resources": []any{res("ssp", "security-plan.json", sspSum)}},
		}})
		result := func(rel, check, target, state string) {
			write(dir+"/"+rel, map[string]any{"assessment-results": map[string]any{
				"uuid": "r", "metadata": map[string]any{"title": check, "last-modified": stamp},
				"import-ap": map[string]any{"href": "#ap"},
				"results": []any{map[string]any{"title": check, "start": stamp, "end": stamp,
					"props":             []any{map[string]any{"name": "check", "value": check}},
					"reviewed-controls": map[string]any{"control-selections": []any{map[string]any{"include-controls": []any{map[string]any{"control-id": target}}}}},
					"findings":          []any{map[string]any{"title": target, "target": map[string]any{"target-id": target, "status": map[string]any{"state": state}}}}}},
				"back-matter": map[string]any{"resources": []any{res("ap", strings.Repeat("../", strings.Count(rel, "/"))+"assessment-plan.json", apSum)}},
			}})
		}
		state := "satisfied"
		if strings.HasPrefix(stamp, "2026-10-03") {
			state = "not-satisfied"
		}
		result("results-isms.json", "isms", "GC.1.1", state)
		result("trial/results-roles.json", "roles", "GC.1.2", "satisfied")
	}
	ssp("runs/1", "2026-10-02T06:00:00Z", "planned")
	ssp("runs/2", "2026-10-03T06:00:00Z", "partial")
	// Not OSCAL: a check's raw output next to the results.
	write("runs/2/run-isms.json", map[string]any{"check": "isms", "subjects": []any{}})
	return root
}

func build(t *testing.T, paths ...string) *Data {
	t.Helper()
	docs, err := oscal.Load(paths)
	if err != nil {
		t.Fatal(err)
	}
	set := oscal.NewSet(docs)
	set.Offline = true
	data, err := Build(set)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestHistoryFromFoldersOfRuns(t *testing.T) {
	root := chain(t)
	d := build(t, root)

	if len(d.Runs) != 2 {
		t.Fatalf("runs = %d, want 2 (trial results belong to the run above them)", len(d.Runs))
	}
	if got := d.Reqs["GC.1.1"].H; !slices.Equal(got, []string{"Is", "In"}) {
		t.Errorf("GC.1.1 history = %v, want implemented and satisfied, then not satisfied", got)
	}
	if got := d.Reqs["GC.1.2"].H; !slices.Equal(got, []string{"Ls", "Ps"}) {
		t.Errorf("GC.1.2 history = %v, want planned then partial, measured by the trial check", got)
	}
	if d.Runs[1].N != 1 || d.Runs[1].OK || !d.Runs[0].OK {
		t.Errorf("run summaries = %+v", d.Runs)
	}
}

func TestChainResolvesThroughHashes(t *testing.T) {
	d := build(t, chain(t))

	if d.Reqs["GC.1.1"].St != "I" || d.Reqs["GC.1.2"].St != "P" {
		t.Errorf("status taken from an older plan: %q %q", d.Reqs["GC.1.1"].St, d.Reqs["GC.1.2"].St)
	}
	if want := "GC MUSS ein ISMS „nach ISO 27001“ verankern."; d.Reqs["GC.1.1"].Stm != want {
		t.Errorf("statement = %q, want the profile's parameter value", d.Reqs["GC.1.1"].Stm)
	}
	if !slices.Equal(d.Trial, []string{"roles"}) || len(d.Checks) != 1 {
		t.Errorf("checks = %v, trial = %v", d.Checks, d.Trial)
	}
	if d.NA["GC.1.3"] != "gibt es nicht" || d.Ext["GC.1.3"] == nil {
		t.Errorf("not-applicable requirement missing: %v", d.NA)
	}
	for _, s := range d.Sources {
		if s.State != oscal.Verified {
			t.Errorf("import %s -> %s: %s, want verified", s.From, s.Href, s.State)
		}
	}
	if len(d.Warnings) != 0 {
		t.Errorf("warnings: %v", d.Warnings)
	}
}

func TestSingleFilesAndChangedProfile(t *testing.T) {
	root := chain(t)
	// Change the profile after the plan was made: the plan's hash no longer fits.
	p := filepath.Join(root, "lib/profile.json")
	data, _ := os.ReadFile(p)
	if err := os.WriteFile(p, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	d := build(t, filepath.Join(root, "runs/2/security-plan.json"), p, filepath.Join(root, "lib/catalog.json"))

	if len(d.Runs) != 1 || len(d.Order) != 2 {
		t.Fatalf("runs = %d, requirements = %d", len(d.Runs), len(d.Order))
	}
	mismatch := slices.ContainsFunc(d.Sources, func(s Source) bool { return s.Kind == oscal.KindProfile && s.State == oscal.Mismatch })
	if !mismatch || len(d.Warnings) == 0 {
		t.Errorf("a changed profile must show as a mismatch with a warning: %+v %v", d.Sources, d.Warnings)
	}
}

func TestRenderEmbedsData(t *testing.T) {
	d := build(t, chain(t))
	d.Reqs["GC.1.1"].T = "</script><b>"
	for _, v := range Views {
		page, err := Render(v, d)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(page), "/*__DATA__*/") || strings.Contains(string(page), "</script><b>") {
			t.Errorf("%s: data slot left or script closed early", v)
		}
	}
}
