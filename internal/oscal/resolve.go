package oscal

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Check states of an import, from good to bad.
const (
	Verified = "verified" // found, and the SHA-256 the importing document names matches
	Unhashed = "unhashed" // found, but the importing document names no SHA-256
	Mismatch = "mismatch" // found by name, but the bytes differ from the SHA-256 named
	Nearby   = "nearby"   // not found by its href; the only one of its kind in the same run was taken
	Missing  = "missing"  // not among the inputs and not fetched
)

// Edge records how one import was resolved, for the sources list of the page.
type Edge struct {
	From   string `json:"from"`   // the importing document
	Href   string `json:"href"`   // what it names
	To     string `json:"to"`     // where it was found, empty when missing
	Kind   string `json:"kind"`   // what was expected
	State  string `json:"state"`  // Verified, Unhashed, Mismatch or Missing
	Remote bool   `json:"remote"` // fetched over the network
	Sum    string `json:"sum"`    // the SHA-256 the importer names, if any
}

// Set holds the loaded documents and resolves imports between them.
type Set struct {
	Docs    []*Doc
	Offline bool   // never fetch
	Cache   string // directory for fetched files, empty for none
	Edges   []Edge

	byPath map[string]*Doc
	byHash map[string]*Doc
	client *http.Client
}

func NewSet(docs []*Doc) *Set {
	s := &Set{byPath: map[string]*Doc{}, byHash: map[string]*Doc{}, client: &http.Client{Timeout: 60 * time.Second}}
	for _, d := range docs {
		s.add(d)
	}
	if dir, err := os.UserCacheDir(); err == nil {
		s.Cache = filepath.Join(dir, "grundschutz-viewer")
	}
	return s
}

func (s *Set) add(d *Doc) {
	s.Docs = append(s.Docs, d)
	s.byPath[d.Path] = d
	if _, ok := s.byHash[d.Sum]; !ok {
		s.byHash[d.Sum] = d
	}
}

// OfKind returns the loaded documents of one kind.
func (s *Set) OfKind(kind string) []*Doc {
	var out []*Doc
	for _, d := range s.Docs {
		if d.Kind == kind {
			out = append(out, d)
		}
	}
	return out
}

// Resolve follows an import href of from to a document of the expected kind.
// An href of the form #uuid goes through the back-matter resource with that
// uuid; its rlinks are tried in order, each with its SHA-256 if it names one.
// A document is looked up by its path next to the importer, then by hash
// among all inputs, then by file name, and last fetched if the href is a URL.
// It returns nil when nothing was found; the edge is recorded either way.
func (s *Set) Resolve(from *Doc, href, kind string) *Doc {
	type cand struct{ href, sum string }
	var cands []cand
	if id, ok := strings.CutPrefix(href, "#"); ok {
		for _, r := range from.BackMatter().Resources {
			if r.UUID != id {
				continue
			}
			for _, l := range r.RLinks {
				c := cand{href: l.Href}
				for _, h := range l.Hashes {
					if strings.EqualFold(h.Algorithm, "SHA-256") {
						c.sum = strings.ToLower(h.Value)
					}
				}
				cands = append(cands, c)
			}
		}
	} else if href != "" {
		cands = append(cands, cand{href: href})
	}
	edge := Edge{From: from.Path, Href: href, Kind: kind, State: Missing}
	if len(cands) > 0 {
		edge.Href, edge.Sum = cands[0].href, cands[0].sum
	}
	for _, c := range cands {
		d, remote := s.find(from, c.href, c.sum, kind)
		if d == nil {
			continue
		}
		edge.Href, edge.To, edge.Remote = c.href, d.Path, remote
		switch {
		case c.sum == "":
			edge.State = Unhashed
		case c.sum == d.Sum:
			edge.State = Verified
		default:
			edge.State = Mismatch
		}
		s.Edges = append(s.Edges, edge)
		return d
	}
	s.Edges = append(s.Edges, edge)
	return nil
}

// Assume marks the last recorded edge, which did not resolve, as resolved to
// d: the caller took the only candidate it had. If the importer named a
// SHA-256, d is checked against it all the same.
func (s *Set) Assume(d *Doc) {
	if len(s.Edges) == 0 {
		return
	}
	e := &s.Edges[len(s.Edges)-1]
	e.To, e.State = d.Path, Nearby
	if e.Sum != "" {
		e.State = map[bool]string{true: Verified, false: Mismatch}[e.Sum == d.Sum]
	}
}

func (s *Set) find(from *Doc, href, sum, kind string) (*Doc, bool) {
	url := strings.Contains(href, "://")
	if !url && from.Dir != "" {
		if d := s.byPath[filepath.Join(from.Dir, filepath.FromSlash(href))]; d != nil && d.Kind == kind {
			return d, false
		}
	}
	if d := s.byHash[sum]; sum != "" && d != nil && d.Kind == kind {
		return d, false
	}
	if url {
		if d := s.byPath[href]; d != nil {
			return d, true
		}
	}
	// By file name: the newest of that name and kind, so a folder of runs
	// where every run carries its own copy still resolves.
	base := filepath.Base(filepath.FromSlash(href))
	if url {
		base = ""
	}
	var best *Doc
	for _, d := range s.Docs {
		if d.Kind == kind && base != "" && filepath.Base(d.Path) == base {
			if best == nil || d.Metadata().LastModified > best.Metadata().LastModified {
				best = d
			}
		}
	}
	if best != nil {
		return best, false
	}
	if url {
		d, err := s.fetch(href, sum)
		if err == nil && d != nil && d.Kind == kind {
			return d, true
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "fetch %s: %v\n", href, err)
		}
	}
	return nil, false
}

// Fetch loads a URL as an extra document, through the cache when the
// expected SHA-256 is known. It is used for imports and for the mapping.
func (s *Set) Fetch(url, sum string) (*Doc, error) {
	if d := s.byPath[url]; d != nil {
		return d, nil
	}
	return s.fetch(url, sum)
}

// fetch reads a URL through the cache. A file is cached under its SHA-256
// when the importer names one, else under the hash of its URL: the library's
// URLs name a commit and do not change. Offline, only the cache is read.
func (s *Set) fetch(url, sum string) (*Doc, error) {
	var cached string
	if s.Cache != "" {
		key := sum
		if key == "" {
			u := sha256.Sum256([]byte(url))
			key = "url-" + hex.EncodeToString(u[:])
		}
		cached = filepath.Join(s.Cache, key+".json")
		if data, err := os.ReadFile(cached); err == nil {
			return s.parseFetched(url, data)
		}
	}
	if s.Offline {
		return nil, fmt.Errorf("offline and not in the cache")
	}
	resp, err := s.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	got := sha256.Sum256(data)
	if cached != "" && (sum == "" || hex.EncodeToString(got[:]) == sum) {
		if err := os.MkdirAll(s.Cache, 0o755); err == nil {
			_ = os.WriteFile(cached, data, 0o644)
		}
	}
	return s.parseFetched(url, data)
}

func (s *Set) parseFetched(url string, data []byte) (*Doc, error) {
	d, err := Parse(url, data)
	if err != nil || d == nil {
		return nil, err
	}
	s.add(d)
	return d, nil
}
