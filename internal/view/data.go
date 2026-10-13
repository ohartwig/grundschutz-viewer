// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

// Package view turns a set of OSCAL documents into the data of the page and
// writes the page.
package view

import (
	"cmp"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/ohartwig/grundschutz-viewer/internal/oscal"
)

// The library the BSI publishes its catalogs and mappings in.
const (
	bsiRaw     = "https://raw.githubusercontent.com/BSI-Bund/Stand-der-Technik-Bibliothek/"
	bsiBlob    = "https://github.com/BSI-Bund/Stand-der-Technik-Bibliothek/blob/"
	bsiCatalog = "control_layer/Grundschutz%2B%2B/Grundschutz%2B%2B-resolved_catalog.json"
	bsiISO     = "control_layer/Mappings/ISO-27001-zu-GSpp/ISO27001-AnnexA-to-GS%2B%2B-mapping_collection.json"
)

// Data is what the page receives. Short keys keep the embedded blob small;
// the templates name them.
type Data struct {
	Run        RunInfo           `json:"run"`
	Catalog    string            `json:"catalog"`    // commit of the BSI library, or the catalog's SHA-256
	CatalogURL string            `json:"catalogUrl"` // where to read it, empty if it is not public
	Profile    string            `json:"profile"`
	Runs       []RunSummary      `json:"runs"`
	Order      []string          `json:"order"`
	Reqs       map[string]*Req   `json:"reqs"`
	Ext        map[string]*Ext   `json:"ext"`
	Checks     []Check           `json:"checks"`
	Trial      []string          `json:"trial"`
	ISO        map[string][]ISO  `json:"iso"`
	NA         map[string]string `json:"na"`
	Params     map[string]string `json:"params"`
	Sources    []Source          `json:"sources"`
	Warnings   []string          `json:"warnings"`
}

type RunInfo struct {
	ID      string `json:"id"`
	Date    string `json:"date"`
	Time    string `json:"time"`
	Project string `json:"project"`
	SHA     string `json:"sha"`
	Job     string `json:"job"`
	Dir     string `json:"dir"`
}

// RunSummary is one point of the history.
type RunSummary struct {
	ID   string `json:"id"`
	D    string `json:"d"`
	T    string `json:"t"`
	OK   bool   `json:"ok"`   // no requirement measured as not satisfied
	Plan bool   `json:"plan"` // the run carries a security plan
	I    int    `json:"i"`
	P    int    `json:"p"`
	L    int    `json:"l"`
	S    int    `json:"s"` // requirements measured satisfied
	N    int    `json:"n"` // requirements measured not satisfied
	Dir  string `json:"dir"`
	Job  string `json:"job"`
	SHA  string `json:"sha"`
}

type Req struct {
	T      string   `json:"t"`
	G      string   `json:"g"`
	GT     string   `json:"gt"`
	S      string   `json:"s"`
	STT    string   `json:"stt"`
	St     string   `json:"st"`
	M      bool     `json:"m"`
	Basis  string   `json:"b"`
	C      []string `json:"c"`
	Stm    string   `json:"stm"`
	MV     string   `json:"mv"`
	Doc    string   `json:"doc"`
	Gdn    string   `json:"gdn"`
	Lvl    string   `json:"lvl"`
	Thr    []string `json:"thr"`
	P      *string  `json:"p"`
	K      []string `json:"k"`
	Req    []string `json:"req"`
	ReqBy  []string `json:"reqBy"`
	Rel    []string `json:"rel"`
	ISO    []ISO    `json:"iso"`
	POAM   *POAM    `json:"poam"`
	H      []string `json:"h"` // per run of Data.Runs: status letter and finding letter, e.g. "In"
	Remark string   `json:"rm,omitempty"`
}

type Ext struct {
	T   string  `json:"t"`
	Stm string  `json:"stm"`
	P   *string `json:"p"`
}

type ISO struct {
	ID  string `json:"id"`
	Rel string `json:"rel"`
}

type POAM struct {
	NA bool     `json:"na"`
	DL *string  `json:"dl"`
	A  []Action `json:"a"`
}

type Action struct {
	ID string `json:"id"`
	X  string `json:"x"`
}

type Check struct {
	ID string   `json:"id"`
	M  string   `json:"m"`
	R  []string `json:"r"`
	T  string   `json:"t"`
}

type Source struct {
	From   string `json:"from"`
	Href   string `json:"href"`
	To     string `json:"to"`
	Kind   string `json:"kind"`
	State  string `json:"state"`
	Remote bool   `json:"remote"`
	N      int    `json:"n"` // how many imports this line stands for
}

func kindRank(k string) int {
	return slices.Index([]string{oscal.KindCatalog, oscal.KindMapping, oscal.KindProfile, oscal.KindSSP, oscal.KindAP}, k)
}

// run is the documents of one measurement: a security plan and what sits
// next to it. Results in subdirectories (trial checks) belong to the run of
// the nearest directory above them that has a security plan.
type run struct {
	dir  string
	ssp  *oscal.Doc
	ap   *oscal.Doc
	poam *oscal.Doc
	ars  []*oscal.Doc
	time string
}

// Build assembles the page data. The newest run with a security plan is the
// state shown; all runs make the history.
func Build(set *oscal.Set) (*Data, error) {
	runs := groupRuns(set)
	data := &Data{Reqs: map[string]*Req{}, Ext: map[string]*Ext{}, ISO: map[string][]ISO{}, NA: map[string]string{}, Params: map[string]string{}}

	var cur *run
	for _, r := range runs {
		if r.ssp != nil {
			cur = r
		}
	}
	if cur == nil && len(runs) > 0 {
		cur = runs[len(runs)-1]
	}

	// The chain: plan -> profile -> catalog. Each step falls back to what the
	// inputs hold when the import does not resolve.
	var profile, catalog *oscal.Doc
	if cur != nil && cur.ssp != nil {
		profile = set.Resolve(cur.ssp, cur.ssp.SSP.ImportProfile.Href, oscal.KindProfile)
	}
	if profile == nil {
		profile = newest(set.OfKind(oscal.KindProfile))
	}
	if profile != nil && len(profile.Profile.Imports) > 0 {
		catalog = set.Resolve(profile, profile.Profile.Imports[0].Href, oscal.KindCatalog)
	}
	if catalog == nil {
		catalog = newest(set.OfKind(oscal.KindCatalog))
	}
	commit := ""
	if profile != nil {
		commit = oscal.Value(profile.Profile.Metadata.Props, "catalog-commit")
		data.Profile = profile.Title()
	}
	if commit == "" && cur != nil {
		for _, ar := range cur.ars {
			if c := resultProp(ar, "catalog-commit"); c != "" {
				commit = c
				break
			}
		}
	}
	if catalog == nil && commit != "" {
		d, err := set.Fetch(bsiRaw+commit+"/"+bsiCatalog, "")
		if err != nil {
			return nil, fmt.Errorf("no catalog among the inputs, and fetching the BSI catalog at %s failed: %w", commit[:min(7, len(commit))], err)
		}
		catalog = d
		data.Warnings = append(data.Warnings, "Kein Profil unter den Eingaben: Katalog über den Commit aus den Ergebnissen geladen, ohne Prüfsumme.")
	}
	if catalog == nil {
		return nil, fmt.Errorf("no catalog: give the profile (or the catalog) the security plan imports, or allow fetching")
	}
	if c := commitOf(catalog.Path); c != "" {
		commit = c
	}
	data.Catalog = cmp.Or(commit, catalog.Sum)
	if strings.HasPrefix(catalog.Path, bsiRaw) {
		data.CatalogURL = bsiBlob + strings.TrimPrefix(catalog.Path, bsiRaw)
	}

	cat := indexCatalog(catalog.Catalog)
	if profile != nil && profile.Profile.Modify != nil {
		for _, sp := range profile.Profile.Modify.SetParameters {
			if len(sp.Values) > 0 {
				data.Params[sp.ParamID] = strings.Join(sp.Values, " / ")
			} else if sp.Label != "" {
				data.Params[sp.ParamID] = sp.Label
			}
		}
	}

	// Which requirements: the plan's, else the profile's, else the catalog's.
	status := map[string]planStatus{}
	switch {
	case cur != nil && cur.ssp != nil:
		status = planOf(cur.ssp)
		for _, ir := range cur.ssp.SSP.ControlImplementation.ImplementedRequirements {
			data.Order = append(data.Order, ir.ControlID)
		}
		for _, r := range cur.ssp.BackMatter().Resources {
			if oscal.Value(r.Props, "tailoring") == "not-applicable" {
				data.NA[oscal.Value(r.Props, "control-id")] = r.Description
			}
		}
	case profile != nil:
		for _, im := range profile.Profile.Imports {
			for _, ic := range im.IncludeControls {
				data.Order = append(data.Order, ic.WithIDs...)
			}
		}
		data.Warnings = append(data.Warnings, "Kein Sicherheitskonzept (SSP) unter den Eingaben: kein Stand je Anforderung.")
	default:
		data.Order = slices.Sorted(maps.Keys(cat.controls))
		data.Warnings = append(data.Warnings, "Weder Sicherheitskonzept noch Profil unter den Eingaben: der ganze Katalog ohne Stand.")
	}
	if profile != nil {
		for _, r := range profile.BackMatter().Resources {
			if oscal.Value(r.Props, "tailoring") == "not-applicable" {
				data.NA[oscal.Value(r.Props, "control-id")] = cmp.Or(data.NA[oscal.Value(r.Props, "control-id")], r.Description)
			}
		}
	}
	data.Order = slices.DeleteFunc(slices.Compact(slices.Clone(data.Order)), func(id string) bool { return cat.controls[id] == nil })

	// Checks: the assessment plan's, and trial checks that only have results.
	var ap *oscal.Doc
	if cur != nil {
		for _, ar := range cur.ars {
			if d := set.Resolve(ar, ar.AR.ImportAP.Href, oscal.KindAP); d != nil {
				ap = d
			} else if cur.ap != nil {
				set.Assume(cur.ap)
				ap = cur.ap
			}
		}
		if ap == nil {
			ap = cur.ap
		}
	}
	covers := map[string][]string{}
	planned := map[string]bool{}
	if ap != nil {
		for _, a := range ap.AP.LocalDefinitions.Activities {
			id := oscal.Value(a.Props, "check")
			if id == "" {
				continue
			}
			c := Check{ID: id, M: oscal.Value(a.Props, "method"), T: a.Title}
			for _, cs := range a.RelatedControls.ControlSelections {
				for _, ic := range cs.IncludeControls {
					c.R = append(c.R, ic.ControlID)
					covers[ic.ControlID] = append(covers[ic.ControlID], id)
				}
			}
			planned[id] = true
			data.Checks = append(data.Checks, c)
		}
	}
	if cur != nil {
		for _, ar := range cur.ars {
			for _, res := range ar.AR.Results {
				id := oscal.Value(res.Props, "check")
				if id == "" || planned[id] {
					continue
				}
				if !slices.Contains(data.Trial, id) {
					data.Trial = append(data.Trial, id)
				}
				for _, cs := range res.ReviewedControls.ControlSelections {
					for _, ic := range cs.IncludeControls {
						if !slices.Contains(covers[ic.ControlID], id) {
							covers[ic.ControlID] = append(covers[ic.ControlID], id)
						}
					}
				}
			}
		}
		if cur.poam != nil && cur.ssp != nil {
			if set.Resolve(cur.poam, cur.poam.POAM.ImportSSP.Href, oscal.KindSSP) == nil {
				set.Assume(cur.ssp)
			}
		}
		if ap != nil && ap.AP.ImportSSP.Href != "" {
			if set.Resolve(ap, ap.AP.ImportSSP.Href, oscal.KindSSP) == nil && cur.ssp != nil {
				set.Assume(cur.ssp)
			}
		}
	}
	slices.Sort(data.Trial)

	// ISO 27001: a mapping among the inputs, else the BSI's at the catalog commit.
	if m := pickMapping(set, cur); m != nil {
		addISO(data, m.Mapping)
	} else if commit != "" && strings.HasPrefix(catalog.Path, bsiRaw) {
		if m, err := set.Fetch(bsiRaw+commit+"/"+bsiISO, ""); err == nil && m.Mapping != nil {
			addISO(data, m.Mapping)
			set.Edges = append(set.Edges, oscal.Edge{From: catalog.Path, Href: m.Path, To: m.Path, Kind: oscal.KindMapping, State: oscal.Unhashed, Remote: true})
		}
	}

	// POA&M of the current run.
	poams := map[string]*POAM{}
	if cur != nil && cur.poam != nil {
		poams = poamOf(cur.poam.POAM)
	}

	// History: plan status and measured state per requirement and run.
	hist := map[string][]string{}
	for _, r := range runs {
		st := map[string]planStatus{}
		if r.ssp != nil {
			st = planOf(r.ssp)
		}
		found := findingsOf(r.ars)
		sum := RunSummary{Plan: r.ssp != nil, Dir: rel(r.dir)}
		sum.D, sum.T = splitTime(r.time)
		sum.ID = runID(r)
		sum.Job, sum.SHA = runJob(r)
		for _, id := range data.Order {
			s, f := "-", "-"
			if ps, ok := st[id]; ok {
				s = ps.letter
			}
			switch found[id] {
			case "satisfied":
				f = "s"
				sum.S++
			case "not-satisfied":
				f = "n"
				sum.N++
			}
			switch s {
			case "I":
				sum.I++
			case "P":
				sum.P++
			case "L":
				sum.L++
			}
			hist[id] = append(hist[id], s+f)
		}
		sum.OK = sum.N == 0
		data.Runs = append(data.Runs, sum)
	}

	inProfile := map[string]bool{}
	for _, id := range data.Order {
		inProfile[id] = true
	}
	for _, id := range data.Order {
		r := cat.req(id, data.Params)
		ps := status[id]
		r.St, r.M, r.Basis, r.Remark = ps.letter, ps.measured, ps.basis, ps.remark
		r.C = slices.Compact(sorted(covers[id]))
		r.POAM = poams[id]
		r.H = hist[id]
		r.ISO = data.isoFor(id)
		data.Reqs[id] = r
	}
	// Catalog entries the page links to but the profile leaves out.
	need := map[string]bool{}
	for _, r := range data.Reqs {
		for _, x := range slices.Concat(r.K, r.Req, r.ReqBy, r.Rel) {
			need[x] = true
		}
		if r.P != nil {
			need[*r.P] = true
		}
	}
	for _, targets := range data.ISO {
		for _, t := range targets {
			need[t.ID] = true
		}
	}
	for id := range data.NA {
		need[id] = true
	}
	for id := range need {
		if inProfile[id] || cat.controls[id] == nil {
			continue
		}
		c := cat.controls[id]
		data.Ext[id] = &Ext{T: c.Title, Stm: statement(c, data.Params), P: cat.parent[id]}
	}
	// Keep only the ISO controls the profile touches.
	for src, targets := range data.ISO {
		if !slices.ContainsFunc(targets, func(t ISO) bool { return inProfile[t.ID] }) {
			delete(data.ISO, src)
		}
	}

	if cur != nil {
		data.Run.Dir = rel(cur.dir)
		data.Run.Date, data.Run.Time = splitTime(cur.time)
		data.Run.ID = runID(cur)
		data.Run.Job, data.Run.SHA = runJob(cur)
		for _, ar := range cur.ars {
			if p := resultProp(ar, "measured-by-repository"); p != "" {
				data.Run.Project = p
				break
			}
		}
		if data.Run.Project == "" && cur.ssp != nil {
			data.Run.Project = cur.ssp.SSP.SystemCharacteristics.SystemName
		}
	}
	// The import checks, folded: many results naming the same plan are one line.
	type key struct{ from, to, kind, state string }
	folded := map[key]*Source{}
	for _, e := range set.Edges {
		k := key{filepath.Dir(e.From), e.To, e.Kind, e.State}
		if src := folded[k]; src != nil {
			src.N++
			continue
		}
		src := &Source{From: rel(e.From), Href: e.Href, To: rel(e.To), Kind: e.Kind, State: e.State, Remote: e.Remote, N: 1}
		folded[k] = src
		switch e.State {
		case oscal.Mismatch:
			data.Warnings = append(data.Warnings, fmt.Sprintf("%s nennt %s mit einer anderen Prüfsumme als die gefundene Datei %s.", src.From, e.Href, src.To))
		case oscal.Missing:
			data.Warnings = append(data.Warnings, fmt.Sprintf("%s importiert %s; nicht gefunden.", src.From, e.Href))
		}
	}
	for _, src := range folded {
		data.Sources = append(data.Sources, *src)
	}
	slices.SortFunc(data.Sources, func(a, b Source) int {
		return cmp.Or(cmp.Compare(kindRank(a.Kind), kindRank(b.Kind)), cmp.Compare(a.From, b.From), cmp.Compare(a.Href, b.Href))
	})
	return data, nil
}

type planStatus struct {
	letter, basis, remark string
	measured              bool
}

func planOf(d *oscal.Doc) map[string]planStatus {
	out := map[string]planStatus{}
	for _, ir := range d.SSP.ControlImplementation.ImplementedRequirements {
		state := oscal.Value(ir.Props, "implementation-status")
		var basis, remark string
		for _, bc := range ir.ByComponents {
			if b := oscal.Value(bc.Props, "basis"); b != "" && basis == "" {
				basis, remark = b, bc.Description
			}
			if state == "" && bc.ImplementationStatus != nil {
				state = bc.ImplementationStatus.State
			}
		}
		letter := map[string]string{"implemented": "I", "partial": "P", "planned": "L"}[state]
		// Measured: the plan's basis says so, or it carries the state of the
		// latest assessment (ssp.mjs writes assessment-state next to a review).
		measured := basis == "measured" || oscal.Value(ir.Props, "assessment-state") != ""
		out[ir.ControlID] = planStatus{letter: cmp.Or(letter, "-"), basis: basis, remark: remark, measured: measured}
	}
	return out
}

// findingsOf returns the measured state per requirement over all results of
// a run; one not-satisfied finding outweighs any satisfied one.
func findingsOf(ars []*oscal.Doc) map[string]string {
	out := map[string]string{}
	for _, ar := range ars {
		for _, res := range ar.AR.Results {
			for _, f := range res.Findings {
				id, st := f.Target.TargetID, f.Target.Status.State
				if out[id] != "not-satisfied" {
					out[id] = st
				}
			}
		}
	}
	return out
}

var actionRe = regexp.MustCompile(`^([A-Z]+-\d+):\s*(.*)$`)

func poamOf(p *oscal.POAM) map[string]*POAM {
	risks := map[string]int{}
	for i, r := range p.Risks {
		risks[r.UUID] = i
	}
	out := map[string]*POAM{}
	for _, it := range p.PoamItems {
		id := oscal.Value(it.Props, "control-id")
		if id == "" {
			continue
		}
		e := out[id]
		if e == nil {
			e = &POAM{A: []Action{}}
			out[id] = e
		}
		for _, rr := range it.RelatedRisks {
			i, ok := risks[rr.RiskUUID]
			if !ok {
				continue
			}
			r := p.Risks[i]
			if len(r.Deadline) >= 10 {
				dl := r.Deadline[:10]
				if e.DL == nil || dl < *e.DL {
					e.DL = &dl
				}
			}
			for _, rem := range r.Remediations {
				a := Action{X: rem.Title}
				if m := actionRe.FindStringSubmatch(rem.Title); m != nil {
					a = Action{ID: m[1], X: m[2]}
				}
				e.A = append(e.A, a)
			}
		}
		e.NA = len(e.A) == 0
	}
	return out
}

func pickMapping(set *oscal.Set, cur *run) *oscal.Doc {
	ms := set.OfKind(oscal.KindMapping)
	if len(ms) == 0 {
		return nil
	}
	if cur != nil {
		for _, ar := range cur.ars {
			want := resultProp(ar, "mapping-sha256")
			for _, m := range ms {
				if m.Sum == want {
					return m
				}
			}
		}
	}
	return newest(ms)
}

func addISO(data *Data, m *oscal.MappingCollection) {
	for _, mp := range m.Mappings {
		for _, mm := range mp.Maps {
			for _, s := range mm.Sources {
				for _, t := range mm.Targets {
					data.ISO[s.IDRef] = append(data.ISO[s.IDRef], ISO{ID: t.IDRef, Rel: mm.Relationship})
				}
			}
		}
	}
}

func (data *Data) isoFor(id string) []ISO {
	out := []ISO{}
	for _, src := range slices.Sorted(maps.Keys(data.ISO)) {
		for _, t := range data.ISO[src] {
			if t.ID == id {
				out = append(out, ISO{ID: src, Rel: t.Rel})
			}
		}
	}
	return out
}

func groupRuns(set *oscal.Set) []*run {
	sspDirs := map[string]bool{}
	for _, d := range set.OfKind(oscal.KindSSP) {
		if d.Dir != "" {
			sspDirs[d.Dir] = true
		}
	}
	home := func(d *oscal.Doc) string {
		for dir := d.Dir; ; {
			if sspDirs[dir] {
				return dir
			}
			up := filepath.Dir(dir)
			if up == dir {
				return d.Dir
			}
			dir = up
		}
	}
	byDir := map[string]*run{}
	get := func(d *oscal.Doc) *run {
		dir := home(d)
		r := byDir[dir]
		if r == nil {
			r = &run{dir: dir}
			byDir[dir] = r
		}
		return r
	}
	for _, d := range set.Docs {
		if d.Dir == "" {
			continue // fetched
		}
		switch d.Kind {
		case oscal.KindSSP:
			get(d).ssp = newest([]*oscal.Doc{get(d).ssp, d})
		case oscal.KindAP:
			get(d).ap = newest([]*oscal.Doc{get(d).ap, d})
		case oscal.KindPOAM:
			get(d).poam = newest([]*oscal.Doc{get(d).poam, d})
		case oscal.KindAR:
			r := get(d)
			r.ars = append(r.ars, d)
		}
	}
	var runs []*run
	for _, r := range byDir {
		for _, ar := range r.ars {
			for _, res := range ar.AR.Results {
				r.time = max(r.time, cmp.Or(res.End, res.Start))
			}
		}
		if r.time == "" {
			for _, d := range []*oscal.Doc{r.ssp, r.poam, r.ap} {
				if d != nil {
					r.time = max(r.time, d.Metadata().LastModified)
				}
			}
		}
		if r.ssp == nil && len(r.ars) == 0 {
			continue
		}
		runs = append(runs, r)
	}
	slices.SortFunc(runs, func(a, b *run) int { return cmp.Or(cmp.Compare(a.time, b.time), cmp.Compare(a.dir, b.dir)) })
	return runs
}

func newest(ds []*oscal.Doc) *oscal.Doc {
	var best *oscal.Doc
	for _, d := range ds {
		if d != nil && (best == nil || d.Metadata().LastModified > best.Metadata().LastModified) {
			best = d
		}
	}
	return best
}

func resultProp(ar *oscal.Doc, name string) string {
	for _, res := range ar.AR.Results {
		if v := oscal.Value(res.Props, name); v != "" {
			return v
		}
	}
	return ""
}

func runJob(r *run) (job, sha string) {
	for _, ar := range r.ars {
		job = cmp.Or(job, resultProp(ar, "measured-by-job"))
		sha = cmp.Or(sha, resultProp(ar, "measured-by-commit"))
	}
	return job, sha[:min(8, len(sha))]
}

// runID names a run for people, by its time.
func runID(r *run) string {
	d, t := splitTime(r.time)
	return strings.TrimSpace(d + " " + t)
}

func splitTime(ts string) (date, clock string) {
	if len(ts) >= 16 {
		return ts[:10], ts[11:16]
	}
	if len(ts) >= 10 {
		return ts[:10], ""
	}
	return ts, ""
}

func commitOf(u string) string {
	rest, ok := strings.CutPrefix(u, bsiRaw)
	if !ok {
		return ""
	}
	c, _, _ := strings.Cut(rest, "/")
	return c
}

func rel(p string) string {
	if p == "" || strings.Contains(p, "://") {
		if u, err := url.PathUnescape(p); err == nil {
			return u
		}
		return p
	}
	if wd, err := os.Getwd(); err == nil {
		if r, err := filepath.Rel(wd, p); err == nil && !strings.HasPrefix(r, "..") {
			return filepath.ToSlash(r)
		}
	}
	return filepath.ToSlash(p)
}
