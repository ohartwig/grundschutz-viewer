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
	prop := func(name, value string) map[string]any { return map[string]any{"name": name, "value": value} }
	ssp := func(dir, stamp, st2 string, more ...any) {
		props2 := append([]any{prop("implementation-status", st2)}, more...)
		sspSum := write(dir+"/security-plan.json", map[string]any{"system-security-plan": map[string]any{
			"uuid": "s", "metadata": map[string]any{"title": "Plan", "last-modified": stamp},
			"import-profile": map[string]any{"href": "#prof"},
			"control-implementation": map[string]any{"implemented-requirements": []any{
				map[string]any{"control-id": "GC.1.1", "props": []any{prop("implementation-status", "implemented"), prop("reviewed", "2026-10-01"), prop("reviewed-by", "CISO")}},
				map[string]any{"control-id": "GC.1.2", "props": props2},
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
					"props":             []any{prop("check", check), prop("performed-by", "Pipeline "+check)},
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
		// The POA&M as poam.mjs writes it: GC.1.2 permanently unfulfilled
		// with an approved residual risk is a deviation without an action.
		write(dir+"/poam.json", map[string]any{"plan-of-action-and-milestones": map[string]any{
			"uuid": "m", "metadata": map[string]any{"title": "POA&M", "last-modified": stamp, "props": []any{prop("items-deviation-approved", "1")}},
			"import-ssp": map[string]any{"href": "#ssp"},
			"risks":      []any{map[string]any{"uuid": "r2", "title": "GC.1.2 not fully in place", "status": "deviation-approved"}},
			"poam-items": []any{map[string]any{"title": "GC.1.2 (" + st2 + ")", "props": []any{prop("control-id", "GC.1.2"), prop("nonfulfilment", "permanent")},
				"related-risks": []any{map[string]any{"risk-uuid": "r2"}}}},
			"back-matter": map[string]any{"resources": []any{res("ssp", "security-plan.json", sspSum)}},
		}})
	}
	ssp("runs/1", "2026-10-02T06:00:00Z", "planned")
	ssp("runs/2", "2026-10-03T06:00:00Z", "partial", prop("nonfulfilment", "permanent"), prop("risk-analysis", "R-021"),
		prop("residual-risk-approved", "2026-10-02"), prop("residual-risk-approved-by", "Geschäftsführung"))
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

// BSI-Standard 300-1 (4.1.2): an approved permanent nonfulfilment is a
// decision, not a plan item that lacks its action.
func TestApprovedDeviation(t *testing.T) {
	d := build(t, chain(t))

	r := d.Reqs["GC.1.2"]
	if r.NF != "permanent" || r.Risk != "R-021" || r.Appr != "2026-10-02" || r.ApprBy != "Geschäftsführung" {
		t.Errorf("nonfulfilment not taken from the plan: %+v", r)
	}
	if !r.Dev || r.POAM == nil || !r.POAM.Dev || r.POAM.NA {
		t.Errorf("GC.1.2 must be an approved deviation, not an item without an action: %+v %+v", r, r.POAM)
	}
	if g := d.Reqs["GC.1.1"]; g.Dev || g.NF != "" || g.Rev != "2026-10-01" || g.RevBy != "CISO" {
		t.Errorf("GC.1.1: %+v, want reviewed by the CISO and no deviation", g)
	}
	if d.By["isms"] != "Pipeline isms" || d.By["roles"] != "Pipeline roles" {
		t.Errorf("performed-by per check = %v", d.By)
	}
}

func TestPOAMActionsAndDeviations(t *testing.T) {
	var p oscal.POAM
	if err := json.Unmarshal([]byte(`{
		"risks": [
			{"uuid": "a", "status": "open", "deadline": "2026-11-30T23:59:59Z",
			 "remediations": [{"title": "I-7: Tags schützen", "props": [{"name": "responsible", "value": "Plattform-Team"}]}]},
			{"uuid": "b", "status": "open"},
			{"uuid": "c", "status": "deviation-approved"}
		],
		"poam-items": [
			{"props": [{"name": "control-id", "value": "A.1"}], "related-risks": [{"risk-uuid": "a"}]},
			{"props": [{"name": "control-id", "value": "A.2"}, {"name": "no-action", "value": "true"}], "related-risks": [{"risk-uuid": "b"}]},
			{"props": [{"name": "control-id", "value": "A.3"}, {"name": "nonfulfilment", "value": "permanent"}], "related-risks": [{"risk-uuid": "c"}]}
		]}`), &p); err != nil {
		t.Fatal(err)
	}
	got := poamOf(&p)

	if a := got["A.1"]; a.NA || a.Dev || *a.DL != "2026-11-30" || !slices.Equal(a.A, []Action{{ID: "I-7", X: "Tags schützen", Resp: "Plattform-Team"}}) {
		t.Errorf("A.1 = %+v", a)
	}
	if a := got["A.2"]; !a.NA || a.Dev {
		t.Errorf("A.2 has no action and is no deviation: %+v", a)
	}
	if a := got["A.3"]; a.NA || !a.Dev || len(a.A) != 0 {
		t.Errorf("A.3 is an approved deviation: %+v", a)
	}
}
