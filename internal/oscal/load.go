package oscal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Kinds of document, by the root key of their JSON.
const (
	KindCatalog = "catalog"
	KindProfile = "profile"
	KindSSP     = "system-security-plan"
	KindAP      = "assessment-plan"
	KindAR      = "assessment-results"
	KindPOAM    = "plan-of-action-and-milestones"
	KindMapping = "mapping-collection"
)

// Doc is one OSCAL document, read from disk or fetched from a URL.
type Doc struct {
	Path string // absolute path, or the URL it was fetched from
	Dir  string // directory imports are resolved against; empty for a URL
	Sum  string // SHA-256 of the bytes, lower-case hex
	Kind string

	Catalog *Catalog
	Profile *Profile
	SSP     *SSP
	AP      *AssessmentPlan
	AR      *AssessmentResults
	POAM    *POAM
	Mapping *MappingCollection
}

// BackMatter returns the back-matter of whatever kind the document is.
func (d *Doc) BackMatter() BackMatter {
	switch {
	case d.Catalog != nil:
		return d.Catalog.BackMatter
	case d.Profile != nil:
		return d.Profile.BackMatter
	case d.SSP != nil:
		return d.SSP.BackMatter
	case d.AP != nil:
		return d.AP.BackMatter
	case d.AR != nil:
		return d.AR.BackMatter
	case d.POAM != nil:
		return d.POAM.BackMatter
	case d.Mapping != nil:
		return d.Mapping.BackMatter
	}
	return BackMatter{}
}

// Title returns the metadata title.
func (d *Doc) Title() string { return d.Metadata().Title }

// Metadata returns the metadata of whatever kind the document is.
func (d *Doc) Metadata() Metadata {
	switch {
	case d.Catalog != nil:
		return d.Catalog.Metadata
	case d.Profile != nil:
		return d.Profile.Metadata
	case d.SSP != nil:
		return d.SSP.Metadata
	case d.AP != nil:
		return d.AP.Metadata
	case d.AR != nil:
		return d.AR.Metadata
	case d.POAM != nil:
		return d.POAM.Metadata
	case d.Mapping != nil:
		return d.Mapping.Metadata
	}
	return Metadata{}
}

// Parse reads one document. It returns nil and no error for JSON that is not
// one of the OSCAL models the viewer knows, such as a check's raw output.
func Parse(path string, data []byte) (*Doc, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil || len(root) != 1 {
		return nil, nil // an OSCAL document is an object with exactly one key
	}
	sum := sha256.Sum256(data)
	d := &Doc{Path: path, Sum: hex.EncodeToString(sum[:])}
	if !strings.Contains(path, "://") {
		d.Dir = filepath.Dir(path)
	}
	var target any
	for kind, raw := range root {
		switch kind {
		case KindCatalog:
			d.Catalog = new(Catalog)
			target = d.Catalog
		case KindProfile:
			d.Profile = new(Profile)
			target = d.Profile
		case KindSSP:
			d.SSP = new(SSP)
			target = d.SSP
		case KindAP:
			d.AP = new(AssessmentPlan)
			target = d.AP
		case KindAR:
			d.AR = new(AssessmentResults)
			target = d.AR
		case KindPOAM:
			d.POAM = new(POAM)
			target = d.POAM
		case KindMapping:
			d.Mapping = new(MappingCollection)
			target = d.Mapping
		default:
			continue
		}
		d.Kind = kind
		if err := json.Unmarshal(raw, target); err != nil {
			return nil, fmt.Errorf("%s: %s: %w", path, kind, err)
		}
		return d, nil
	}
	return nil, nil
}

// Load reads every OSCAL document in the given files and directories.
// Directories are walked with all their subdirectories; files that are not
// JSON or not OSCAL are skipped.
func Load(paths []string) ([]*Doc, error) {
	var docs []*Doc
	seen := map[string]bool{}
	read := func(path string) error {
		abs, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if seen[abs] {
			return nil
		}
		seen[abs] = true
		data, err := os.ReadFile(abs)
		if err != nil {
			return err
		}
		d, err := Parse(abs, data)
		if err != nil {
			return err
		}
		if d != nil {
			docs = append(docs, d)
		}
		return nil
	}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			if err := read(p); err != nil {
				return nil, err
			}
			continue
		}
		err = filepath.WalkDir(p, func(path string, e fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if e.IsDir() {
				if path != p && strings.HasPrefix(e.Name(), ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.EqualFold(filepath.Ext(path), ".json") {
				return nil
			}
			return read(path)
		})
		if err != nil {
			return nil, err
		}
	}
	return docs, nil
}
