// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

package oscal

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// The fixtures follow the chain grundschutz-worksheets writes: the security
// plan imports the profile through a back-matter resource whose rlink names
// the file and its SHA-256, and the profile imports the catalog the same way.

func catalogJSON(title string) string {
	return fmt.Sprintf(`{"catalog":{"uuid":"c","metadata":{"title":%q},"groups":[{"id":"G","title":"G","controls":[{"id":"G.1","title":"One"}]}]}}`, title)
}

func profileJSON(catalogHref, catalogSum string) string {
	return fmt.Sprintf(`{"profile":{"uuid":"p","metadata":{"title":"Profile"},
  "imports":[{"href":"#cat","include-controls":[{"with-ids":["G.1"]}]}],
  "back-matter":{"resources":[{"uuid":"cat","rlinks":[{"href":%q%s}]}]}}}`, catalogHref, hashes(catalogSum))
}

func sspJSON(rlinks ...string) string {
	return fmt.Sprintf(`{"system-security-plan":{"uuid":"s","metadata":{"title":"Plan"},
  "import-profile":{"href":"#prof"},
  "back-matter":{"resources":[{"uuid":"prof","rlinks":[%s]}]}}}`, strings.Join(rlinks, ","))
}

func rlink(href, sum string) string { return fmt.Sprintf(`{"href":%q%s}`, href, hashes(sum)) }

func hashes(sum string) string {
	if sum == "" {
		return ""
	}
	return fmt.Sprintf(`,"hashes":[{"algorithm":"SHA-256","value":%q}]`, sum)
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// write puts files into a fresh directory and returns it.
func write(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func load(t *testing.T, paths ...string) *Set {
	t.Helper()
	docs, err := Load(paths)
	if err != nil {
		t.Fatal(err)
	}
	s := NewSet(docs)
	s.Offline, s.Cache = true, ""
	return s
}

func only(t *testing.T, s *Set, kind string) *Doc {
	t.Helper()
	ds := s.OfKind(kind)
	if len(ds) != 1 {
		t.Fatalf("%d documents of kind %s, want 1", len(ds), kind)
	}
	return ds[0]
}

func lastEdge(t *testing.T, s *Set) Edge {
	t.Helper()
	if len(s.Edges) == 0 {
		t.Fatal("no edge recorded")
	}
	return s.Edges[len(s.Edges)-1]
}

func TestLoadSkipsWhatIsNotOSCAL(t *testing.T) {
	dir := write(t, map[string]string{
		"catalog.json":       catalogJSON("Catalog"),
		"run-tls.json":       `{"check":"tls","results":[]}`, // a check's raw output: two keys
		"one-key-other.json": `{"findings":[]}`,              // one key, but no OSCAL model
		"array.json":         `[1,2,3]`,
		"broken.json":        `{"catalog":`,
		"notes.md":           "# not JSON",
		".hidden/plan.json":  sspJSON(),
	})
	s := load(t, dir)
	if len(s.Docs) != 1 || s.Docs[0].Kind != KindCatalog {
		var kinds []string
		for _, d := range s.Docs {
			kinds = append(kinds, filepath.Base(d.Path)+":"+d.Kind)
		}
		t.Fatalf("loaded %v, want only the catalog", kinds)
	}
}

func TestLoadReportsAnOSCALDocumentThatDoesNotParse(t *testing.T) {
	// One key that names a model, with a body of the wrong shape, is an error:
	// a broken plan must not disappear from the page as "not OSCAL".
	dir := write(t, map[string]string{"plan.json": `{"system-security-plan":[]}`})
	if _, err := Load([]string{dir}); err == nil {
		t.Fatal("no error for a security plan that does not parse")
	}
}

func TestLoadReadsAFileOnceThoughNamedTwice(t *testing.T) {
	dir := write(t, map[string]string{"catalog.json": catalogJSON("Catalog")})
	docs, err := Load([]string{dir, filepath.Join(dir, "catalog.json")})
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 1 {
		t.Fatalf("%d documents, want 1", len(docs))
	}
}

func TestResolveNextToTheImporterVerified(t *testing.T) {
	cat := catalogJSON("Catalog")
	prof := profileJSON("catalog.json", sum(cat))
	dir := write(t, map[string]string{
		"catalog.json":       cat,
		"profile.json":       prof,
		"security-plan.json": sspJSON(rlink("profile.json", sum(prof))),
		// The same profile under the same name in another run: the one next to
		// the plan has to win, not the newest of the name.
		"other/profile.json": strings.Replace(prof, `"Profile"`, `"Other"`, 1),
	})
	s := load(t, dir)
	ssp := only(t, s, KindSSP)
	p := s.Resolve(ssp, ssp.SSP.ImportProfile.Href, KindProfile)
	if p == nil || p.Path != filepath.Join(dir, "profile.json") {
		t.Fatalf("resolved to %v, want the profile next to the plan", p)
	}
	if e := lastEdge(t, s); e.State != Verified || e.Href != "profile.json" || e.Remote {
		t.Fatalf("edge %+v, want verified, local", e)
	}
	c := s.Resolve(p, p.Profile.Imports[0].Href, KindCatalog)
	if c == nil || lastEdge(t, s).State != Verified {
		t.Fatalf("catalog %v, edge %+v", c, lastEdge(t, s))
	}
}

func TestResolveByHashWhenTheNameDoesNotMatch(t *testing.T) {
	cat := catalogJSON("Catalog")
	prof := profileJSON("catalog.json", sum(cat))
	dir := write(t, map[string]string{
		"run/security-plan.json":   sspJSON(rlink("profile.json", sum(prof))),
		"shared/tailoring-v3.json": prof, // renamed and moved: only the hash finds it
	})
	s := load(t, dir)
	ssp := only(t, s, KindSSP)
	p := s.Resolve(ssp, ssp.SSP.ImportProfile.Href, KindProfile)
	if p == nil || filepath.Base(p.Path) != "tailoring-v3.json" {
		t.Fatalf("resolved to %v, want the profile found by its SHA-256", p)
	}
	if e := lastEdge(t, s); e.State != Verified {
		t.Fatalf("edge %+v, want verified", e)
	}
}

func TestResolveByFileNameTakesTheNewest(t *testing.T) {
	older := `{"profile":{"uuid":"p1","metadata":{"title":"Old","last-modified":"2026-10-01T00:00:00Z"}}}`
	newer := `{"profile":{"uuid":"p2","metadata":{"title":"New","last-modified":"2026-10-12T00:00:00Z"}}}`
	dir := write(t, map[string]string{
		"plans/security-plan.json": sspJSON(rlink("profile.json", "")),
		"runs/a/profile.json":      older,
		"runs/b/profile.json":      newer,
	})
	s := load(t, dir)
	ssp := only(t, s, KindSSP)
	p := s.Resolve(ssp, ssp.SSP.ImportProfile.Href, KindProfile)
	if p == nil || p.Title() != "New" {
		t.Fatalf("resolved to %v, want the newest profile.json", p)
	}
	if e := lastEdge(t, s); e.State != Unhashed {
		t.Fatalf("edge %+v, want unhashed: the plan names no SHA-256", e)
	}
}

func TestResolveReportsAMismatch(t *testing.T) {
	prof := profileJSON("catalog.json", "")
	named := sum(prof + "\n") // what the plan was written against: other bytes
	dir := write(t, map[string]string{
		"profile.json":       prof,
		"security-plan.json": sspJSON(rlink("profile.json", named)),
	})
	s := load(t, dir)
	ssp := only(t, s, KindSSP)
	p := s.Resolve(ssp, ssp.SSP.ImportProfile.Href, KindProfile)
	if p == nil {
		t.Fatal("a profile found by name must still be shown")
	}
	e := lastEdge(t, s)
	if e.State != Mismatch || e.Sum != named {
		t.Fatalf("edge %+v, want a mismatch against %s", e, named)
	}
}

func TestResolveIgnoresADocumentOfAnotherKind(t *testing.T) {
	// A file of the right name and the right hash, but a catalog where a
	// profile is expected, is not the profile.
	cat := catalogJSON("Catalog")
	dir := write(t, map[string]string{
		"profile.json":       cat,
		"security-plan.json": sspJSON(rlink("profile.json", sum(cat))),
	})
	s := load(t, dir)
	ssp := only(t, s, KindSSP)
	if p := s.Resolve(ssp, ssp.SSP.ImportProfile.Href, KindProfile); p != nil {
		t.Fatalf("resolved to %s, a %s", p.Path, p.Kind)
	}
	if e := lastEdge(t, s); e.State != Missing {
		t.Fatalf("edge %+v, want missing", e)
	}
}

func TestResolveMissing(t *testing.T) {
	dir := write(t, map[string]string{
		"security-plan.json": sspJSON(rlink("profile.json", sum("x"))),
	})
	s := load(t, dir)
	ssp := only(t, s, KindSSP)
	if p := s.Resolve(ssp, ssp.SSP.ImportProfile.Href, KindProfile); p != nil {
		t.Fatalf("resolved to %v", p)
	}
	e := lastEdge(t, s)
	if e.State != Missing || e.To != "" || e.Href != "profile.json" || e.Sum != sum("x") {
		t.Fatalf("edge %+v, want missing with the href and hash it names", e)
	}
	// An href to a back-matter resource that does not exist is missing too.
	if p := s.Resolve(ssp, "#no-such-resource", KindProfile); p != nil {
		t.Fatalf("resolved to %v", p)
	}
	if e := lastEdge(t, s); e.State != Missing {
		t.Fatalf("edge %+v, want missing", e)
	}
}

func TestResolveTriesTheRLinksInOrder(t *testing.T) {
	prof := profileJSON("catalog.json", "")
	dir := write(t, map[string]string{
		"profile.json": prof,
		"security-plan.json": sspJSON(
			rlink("gone/profile-old.json", sum("old")),
			rlink("profile.json", sum(prof)),
		),
	})
	s := load(t, dir)
	ssp := only(t, s, KindSSP)
	if p := s.Resolve(ssp, ssp.SSP.ImportProfile.Href, KindProfile); p == nil {
		t.Fatal("the second rlink was not tried")
	}
	if e := lastEdge(t, s); e.State != Verified || e.Href != "profile.json" {
		t.Fatalf("edge %+v, want verified through the second rlink", e)
	}
}

func TestAssume(t *testing.T) {
	prof := profileJSON("catalog.json", "")
	dir := write(t, map[string]string{
		"a/profile.json":     prof,
		"security-plan.json": sspJSON(rlink("tailoring.json", sum(prof))),
		"other-plan.json":    strings.Replace(sspJSON(rlink("tailoring.json", "")), `"uuid":"s"`, `"uuid":"s2"`, 1),
	})
	s := load(t, dir)
	p := only(t, s, KindProfile)
	for _, ssp := range s.OfKind(KindSSP) {
		if s.Resolve(ssp, ssp.SSP.ImportProfile.Href, KindProfile) == nil {
			s.Assume(p)
		}
	}
	// Found by hash: verified. Named without a hash: taken as the only one.
	states := map[string]string{}
	for _, e := range s.Edges {
		states[filepath.Base(e.From)] = e.State
	}
	if states["security-plan.json"] != Verified || states["other-plan.json"] != Nearby {
		t.Fatalf("states %v", states)
	}
	// Assumed against a SHA-256 that does not match: a mismatch, not nearby.
	s2 := load(t, write(t, map[string]string{
		"security-plan.json": sspJSON(rlink("tailoring.json", sum("x"))),
		"profile.json":       prof,
	}))
	ssp := only(t, s2, KindSSP)
	if s2.Resolve(ssp, ssp.SSP.ImportProfile.Href, KindProfile) != nil {
		t.Fatal("resolved by a name it does not have")
	}
	s2.Assume(only(t, s2, KindProfile))
	if e := lastEdge(t, s2); e.State != Mismatch {
		t.Fatalf("edge %+v, want a mismatch", e)
	}
}

func TestFetchVerifiesAndCaches(t *testing.T) {
	cat := catalogJSON("Fetched")
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/catalog.json" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(cat))
	}))
	defer srv.Close()
	url := srv.URL + "/catalog.json"

	dir := write(t, map[string]string{"profile.json": profileJSON(url, sum(cat))})
	cache := t.TempDir()
	newSet := func(offline bool) *Set {
		docs, err := Load([]string{dir})
		if err != nil {
			t.Fatal(err)
		}
		s := NewSet(docs)
		s.Offline, s.Cache = offline, cache
		return s
	}

	s := newSet(false)
	p := only(t, s, KindProfile)
	c := s.Resolve(p, p.Profile.Imports[0].Href, KindCatalog)
	if c == nil || c.Title() != "Fetched" {
		t.Fatalf("fetched %v", c)
	}
	if e := lastEdge(t, s); e.State != Verified || !e.Remote || e.To != url {
		t.Fatalf("edge %+v, want verified and remote", e)
	}
	if _, err := os.Stat(filepath.Join(cache, sum(cat)+".json")); err != nil {
		t.Fatalf("not cached under its SHA-256: %v", err)
	}

	// Offline, the cache answers and the server is not asked.
	before := hits.Load()
	s = newSet(true)
	p = only(t, s, KindProfile)
	if c := s.Resolve(p, p.Profile.Imports[0].Href, KindCatalog); c == nil {
		t.Fatal("offline: not read from the cache")
	}
	if hits.Load() != before {
		t.Fatal("offline: the server was asked")
	}
}

func TestFetchDoesNotCacheWhatDoesNotMatch(t *testing.T) {
	served := catalogJSON("Changed upstream")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(served))
	}))
	defer srv.Close()
	url := srv.URL + "/catalog.json"
	named := sum(catalogJSON("What the profile was written against"))

	dir := write(t, map[string]string{"profile.json": profileJSON(url, named)})
	docs, err := Load([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	cache := t.TempDir()
	s := NewSet(docs)
	s.Cache = cache
	p := only(t, s, KindProfile)
	if c := s.Resolve(p, p.Profile.Imports[0].Href, KindCatalog); c == nil {
		t.Fatal("a fetched catalog with another hash must still be shown")
	}
	if e := lastEdge(t, s); e.State != Mismatch {
		t.Fatalf("edge %+v, want a mismatch", e)
	}
	if entries, _ := os.ReadDir(cache); len(entries) != 0 {
		t.Fatalf("cached %d files; a catalog that does not match must not be cached", len(entries))
	}
}

func TestFetchOfflineWithoutCacheIsMissing(t *testing.T) {
	dir := write(t, map[string]string{"profile.json": profileJSON("https://example.invalid/catalog.json", sum("x"))})
	s := load(t, dir) // offline, no cache
	p := only(t, s, KindProfile)
	if c := s.Resolve(p, p.Profile.Imports[0].Href, KindCatalog); c != nil {
		t.Fatalf("resolved to %v offline", c)
	}
	if e := lastEdge(t, s); e.State != Missing {
		t.Fatalf("edge %+v, want missing", e)
	}
}
