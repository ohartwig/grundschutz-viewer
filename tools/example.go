// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

//go:build ignore

// Writes the example of the README: a made-up company, Example GmbH, with a
// small catalog excerpt, a profile and seven nightly runs of the worksheets
// chain (security plan, assessment plan, results of five checks, POA&M), the
// way grundschutz-worksheets and grundschutz-checks write them. The company,
// the plans and the measurements are made up. The requirements are the BSI's:
// tools/example-catalog.json is an excerpt of the Grundschutz++ catalog (CC
// BY-SA 4.0, source commit in its metadata).
//
// Two requirements are left out of the profile as not applicable, and one
// permanent nonfulfilment carries an approved residual risk, so the states of
// BSI-Standard 300-1 are all on the page. Only a SOLLTE can be a deviation
// (4.1.2): the generator stops if a MUSS is permanently unfulfilled.
//
//	go run tools/example.go out/example
package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed example-catalog.json
var catalogJSON []byte

type m = map[string]any

func prop(name, value string) m { return m{"name": name, "value": value} }

var root string

// write stores v as JSON below root and returns its SHA-256.
func write(rel string, v any) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		panic(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func res(uuid, href, sum string) m {
	return m{"uuid": uuid, "rlinks": []any{m{"href": href, "hashes": []any{m{"algorithm": "SHA-256", "value": sum}}}}}
}

type req struct {
	id string
	// state of the plan, how it is measured, and what the example says
	status, check, basis string
	nf, risk             string // permanent: approved deviation
	action, resp, due    string // action of the POA&M
	// measured per run, oldest first: s satisfied, n not satisfied
	found string
}

var reqs = []req{
	{id: "ASST.2.3.2",
		status: "planned", check: "sbom", basis: "Es gibt noch keine automatische SBOM.", nf: "temporary", action: "I-3: SBOM in der Build-Pipeline erzeugen", resp: "Plattform-Team", due: "2026-10-24", found: "nnnnnnn"},
	{id: "BER.5.9",
		status: "implemented", check: "mfa", basis: "Alle Administrationszugänge verlangen einen zweiten Faktor.", found: "snsssss"},
	{id: "DET.5.3",
		status: "implemented", check: "vuln-scan", basis: "Wöchentlicher Scan, Ergebnisse im Ticketsystem.", found: "sssssss"},
	{id: "DET.5.10",
		status: "planned", check: "vuln-scan", basis: "Fristen sind noch nicht überwacht.", nf: "temporary", action: "I-5: Patchfristen im Scan überwachen", resp: "Betrieb", due: "2026-11-15", found: "sssssss"},
	{id: "DEV.2.4",
		status: "partial", check: "repo-access", basis: "Zwei Repositories sind noch für alle Entwickler lesbar.", nf: "temporary", action: "I-4: Lesezugriff auf zwei Repositories entziehen", resp: "Entwicklung", due: "2026-11-30", found: "nsnnsss"},
	{id: "DEV.4.3",
		status: "partial", check: "sbom", basis: "Erfasst sind erst die Hälfte der Anwendungen.", nf: "temporary", action: "I-6: Restliche Anwendungen erfassen", resp: "Entwicklung", due: "2026-10-24", found: "nnnnnnn"},
	{id: "KONF.14.1",
		status: "implemented", check: "tls-endpoints", basis: "Alle öffentlichen Endpunkte sprechen TLS.", found: "sssssss"},
	{id: "KONF.14.1.1",
		status: "implemented", check: "tls-endpoints", basis: "HTTP leitet auf HTTPS um, HSTS ist gesetzt.", found: "nnsnsss"},
	{id: "TEST.4.1",
		status: "partial", check: "repo-access", basis: "Notfalländerungen des Hosters werden nachträglich freigegeben.", nf: "permanent", risk: "R-021", found: "ssnnnnn"},
}

var notApplicable = [][2]string{
	{"ARCH.2.2.5", "Example GmbH betreibt keine OT-Systeme."},
	{"KONF.3.3", "Es gibt keine Mobilgeräte mit SIM-Karte in der Firma."},
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run tools/example.go <dir>")
		os.Exit(2)
	}
	root = os.Args[1]
	if err := os.RemoveAll(root); err != nil {
		panic(err)
	}
	var cat m
	if err := json.Unmarshal(catalogJSON, &cat); err != nil {
		panic(err)
	}
	catSum := write("lib/catalog.json", cat)
	for id, verb := range modals(cat) {
		for _, r := range reqs {
			if r.id == id && r.nf == "permanent" && verb != "SOLLTE" && verb != "KANN" {
				panic(id + " is a " + verb + " and cannot be a permanent nonfulfilment (BSI-Standard 300-1, 4.1.2)")
			}
		}
	}

	var ids []string
	for _, r := range reqs {
		ids = append(ids, r.id)
	}
	naRes := []any{res("cat", "catalog.json", catSum)}
	for _, n := range notApplicable {
		naRes = append(naRes, m{"uuid": "na-" + n[0], "description": n[1],
			"props": []any{prop("control-id", n[0]), prop("tailoring", "not-applicable")}})
	}
	profSum := write("lib/profile.json", m{"profile": m{
		"uuid": "00000000-0000-4000-8000-000000000002",
		"metadata": m{"title": "Profil der Example GmbH", "last-modified": "2026-10-20T00:00:00Z",
			"props": []any{prop("catalog-commit", "a128311c0ffee0123456789abcdef0123456789a")}},
		"imports":     []any{m{"href": "#cat", "include-controls": []any{m{"with-ids": ids}}}},
		"back-matter": m{"resources": naRes},
	}})

	checks := []string{"tls-endpoints", "mfa", "sbom", "vuln-scan", "repo-access"}
	titles := map[string]string{"tls-endpoints": "TLS der öffentlichen Endpunkte", "mfa": "Zweiter Faktor für Administratoren",
		"sbom": "Softwarebestandsliste", "vuln-scan": "Schwachstellenscan und Patchstand", "repo-access": "Zugriff auf Repositories"}

	for n := range 7 {
		day := 21 + n
		stamp := fmt.Sprintf("2026-10-%02dT02:15:00Z", day)
		dir := fmt.Sprintf("runs/%02d", n+1)
		var impl []any
		for _, r := range reqs {
			props := []any{prop("implementation-status", r.status), prop("assessment-state", "measured")}
			if r.nf != "" {
				props = append(props, prop("nonfulfilment", r.nf))
			}
			if r.status == "implemented" {
				props = append(props, prop("reviewed", "2026-10-20"), prop("reviewed-by", "Geschäftsführung"))
			}
			if r.nf == "permanent" {
				props = append(props, prop("risk-analysis", r.risk), prop("residual-risk-approved", "2026-10-22"),
					prop("residual-risk-approved-by", "Geschäftsführung"), prop("reviewed", "2026-10-22"), prop("reviewed-by", "Informationssicherheitsbeauftragte"))
			}
			impl = append(impl, m{"control-id": r.id, "props": props,
				"by-components": []any{m{"description": r.basis, "props": []any{prop("basis", "measured")}}}})
		}
		sspSum := write(dir+"/security-plan.json", m{"system-security-plan": m{
			"uuid":           "00000000-0000-4000-8000-0000000001" + fmt.Sprintf("%02d", n),
			"metadata":       m{"title": "Sicherheitskonzept der Example GmbH", "last-modified": stamp},
			"import-profile": m{"href": "#prof"}, "system-characteristics": m{"system-name": "example/compliance"},
			"control-implementation": m{"implemented-requirements": impl},
			"back-matter":            m{"resources": []any{res("prof", "../../lib/profile.json", profSum)}},
		}})
		var acts []any
		for _, id := range checks {
			var covered []any
			for _, r := range reqs {
				if r.check == id {
					covered = append(covered, m{"control-id": r.id})
				}
			}
			acts = append(acts, m{"title": titles[id], "props": []any{prop("check", id), prop("method", "TEST")},
				"related-controls": m{"control-selections": []any{m{"include-controls": covered}}}})
		}
		apSum := write(dir+"/assessment-plan.json", m{"assessment-plan": m{
			"uuid":       "00000000-0000-4000-8000-0000000002" + fmt.Sprintf("%02d", n),
			"metadata":   m{"title": "Prüfplan der Example GmbH", "last-modified": stamp},
			"import-ssp": m{"href": "#ssp"}, "local-definitions": m{"activities": acts},
			"back-matter": m{"resources": []any{res("ssp", "security-plan.json", sspSum)}},
		}})
		for _, id := range checks {
			var findings, covered []any
			for _, r := range reqs {
				if r.check != id {
					continue
				}
				state := map[byte]string{'s': "satisfied", 'n': "not-satisfied"}[r.found[n]]
				covered = append(covered, m{"control-id": r.id})
				findings = append(findings, m{"title": r.id, "target": m{"target-id": r.id, "status": m{"state": state}}})
			}
			write(fmt.Sprintf("%s/results-%s.json", dir, id), m{"assessment-results": m{
				"uuid":     "00000000-0000-4000-8000-0000000003" + fmt.Sprintf("%02d", n),
				"metadata": m{"title": titles[id], "last-modified": stamp}, "import-ap": m{"href": "#ap"},
				"results": []any{m{"title": titles[id], "start": stamp, "end": stamp,
					"props": []any{prop("check", id), prop("performed-by", "grundschutz-checks, Pipeline-Job"),
						prop("measured-by-repository", "example/compliance"), prop("measured-by-job", fmt.Sprint(1200+n)),
						prop("measured-by-commit", "3f9c2d71"+fmt.Sprintf("%02d", n)+"b4e6a"), prop("catalog-commit", "a128311c0ffee0123456789abcdef0123456789a")},
					"reviewed-controls": m{"control-selections": []any{m{"include-controls": covered}}},
					"findings":          findings}},
				"back-matter": m{"resources": []any{res("ap", "assessment-plan.json", apSum)}},
			}})
		}
		var risks, items []any
		for _, r := range reqs {
			if r.nf == "" {
				continue
			}
			uuid := "00000000-0000-4000-8000-00000000" + fmt.Sprintf("%04d", len(risks)+1)
			risk := m{"uuid": uuid, "title": r.id + " nicht vollständig erfüllt", "status": "open"}
			if r.nf == "permanent" {
				risk["status"] = "deviation-approved"
			} else {
				risk["deadline"] = r.due + "T23:59:59Z"
				risk["remediations"] = []any{m{"title": r.action, "props": []any{prop("responsible", r.resp)}}}
			}
			risks = append(risks, risk)
			items = append(items, m{"title": r.id, "props": []any{prop("control-id", r.id), prop("nonfulfilment", r.nf)},
				"related-risks": []any{m{"risk-uuid": uuid}}})
		}
		write(dir+"/poam.json", m{"plan-of-action-and-milestones": m{
			"uuid":       "00000000-0000-4000-8000-0000000004" + fmt.Sprintf("%02d", n),
			"metadata":   m{"title": "Maßnahmenplan der Example GmbH", "last-modified": stamp},
			"import-ssp": m{"href": "#ssp"}, "risks": risks, "poam-items": items,
			"back-matter": m{"resources": []any{res("ssp", "security-plan.json", sspSum)}},
		}})
	}
}

// modals returns the modal verb of every control of the catalog.
func modals(v any) map[string]string {
	out := map[string]string{}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if id, ok := x["id"].(string); ok {
				for _, p := range list(x["parts"]) {
					for _, pr := range list(p.(map[string]any)["props"]) {
						if pr := pr.(map[string]any); pr["name"] == "modal_verb" {
							out[id], _ = pr["value"].(string)
						}
					}
				}
			}
			for _, c := range x {
				walk(c)
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	walk(v)
	return out
}

func list(v any) []any { l, _ := v.([]any); return l }
