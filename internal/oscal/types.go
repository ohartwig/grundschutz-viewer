// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

// Package oscal reads the parts of OSCAL documents the viewer shows: the
// catalog, the profile, the security plan, the assessment plan, assessment
// results, the POA&M and mapping collections. Fields the viewer does not use
// are left out; unknown fields are ignored.
package oscal

type Prop struct {
	Name  string `json:"name"`
	NS    string `json:"ns"`
	Value string `json:"value"`
}

// Value returns the value of the first property with the given name.
func Value(ps []Prop, name string) string {
	for _, p := range ps {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

type Link struct {
	Href string `json:"href"`
	Rel  string `json:"rel"`
}

type Part struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Prose string `json:"prose"`
	Props []Prop `json:"props"`
	Parts []Part `json:"parts"`
}

type Param struct {
	ID     string   `json:"id"`
	Label  string   `json:"label"`
	Values []string `json:"values"`
}

type Control struct {
	ID       string    `json:"id"`
	Title    string    `json:"title"`
	Params   []Param   `json:"params"`
	Props    []Prop    `json:"props"`
	Parts    []Part    `json:"parts"`
	Links    []Link    `json:"links"`
	Controls []Control `json:"controls"`
}

type Group struct {
	ID       string    `json:"id"`
	Title    string    `json:"title"`
	Groups   []Group   `json:"groups"`
	Controls []Control `json:"controls"`
}

type Hash struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type RLink struct {
	Href   string `json:"href"`
	Hashes []Hash `json:"hashes"`
}

type Resource struct {
	UUID        string  `json:"uuid"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Props       []Prop  `json:"props"`
	RLinks      []RLink `json:"rlinks"`
}

type BackMatter struct {
	Resources []Resource `json:"resources"`
}

type Metadata struct {
	Title        string `json:"title"`
	LastModified string `json:"last-modified"`
	Version      string `json:"version"`
	Props        []Prop `json:"props"`
}

type Import struct {
	Href string `json:"href"`
}

type ControlSelection struct {
	IncludeControls []struct {
		ControlID string `json:"control-id"`
	} `json:"include-controls"`
}

type Catalog struct {
	UUID       string     `json:"uuid"`
	Metadata   Metadata   `json:"metadata"`
	Groups     []Group    `json:"groups"`
	Controls   []Control  `json:"controls"`
	BackMatter BackMatter `json:"back-matter"`
}

type Profile struct {
	UUID     string   `json:"uuid"`
	Metadata Metadata `json:"metadata"`
	Imports  []struct {
		Href            string `json:"href"`
		IncludeControls []struct {
			WithIDs []string `json:"with-ids"`
		} `json:"include-controls"`
	} `json:"imports"`
	Modify *struct {
		SetParameters []struct {
			ParamID string   `json:"param-id"`
			Label   string   `json:"label"`
			Values  []string `json:"values"`
		} `json:"set-parameters"`
	} `json:"modify"`
	BackMatter BackMatter `json:"back-matter"`
}

type SSP struct {
	UUID                  string   `json:"uuid"`
	Metadata              Metadata `json:"metadata"`
	ImportProfile         Import   `json:"import-profile"`
	SystemCharacteristics struct {
		SystemName string `json:"system-name"`
	} `json:"system-characteristics"`
	ControlImplementation struct {
		ImplementedRequirements []struct {
			ControlID    string `json:"control-id"`
			Props        []Prop `json:"props"`
			ByComponents []struct {
				Description          string `json:"description"`
				Props                []Prop `json:"props"`
				ImplementationStatus *struct {
					State string `json:"state"`
				} `json:"implementation-status"`
			} `json:"by-components"`
		} `json:"implemented-requirements"`
	} `json:"control-implementation"`
	BackMatter BackMatter `json:"back-matter"`
}

type AssessmentPlan struct {
	UUID             string   `json:"uuid"`
	Metadata         Metadata `json:"metadata"`
	ImportSSP        Import   `json:"import-ssp"`
	LocalDefinitions struct {
		Activities []struct {
			Title           string `json:"title"`
			Props           []Prop `json:"props"`
			RelatedControls struct {
				ControlSelections []ControlSelection `json:"control-selections"`
			} `json:"related-controls"`
		} `json:"activities"`
	} `json:"local-definitions"`
	BackMatter BackMatter `json:"back-matter"`
}

type Finding struct {
	Title  string `json:"title"`
	Target struct {
		TargetID string `json:"target-id"`
		Status   struct {
			State string `json:"state"`
		} `json:"status"`
	} `json:"target"`
}

type AssessmentResults struct {
	UUID     string   `json:"uuid"`
	Metadata Metadata `json:"metadata"`
	ImportAP Import   `json:"import-ap"`
	Results  []struct {
		Title            string `json:"title"`
		Start            string `json:"start"`
		End              string `json:"end"`
		Props            []Prop `json:"props"`
		ReviewedControls struct {
			ControlSelections []ControlSelection `json:"control-selections"`
		} `json:"reviewed-controls"`
		Findings []Finding `json:"findings"`
	} `json:"results"`
	BackMatter BackMatter `json:"back-matter"`
}

type POAM struct {
	UUID      string   `json:"uuid"`
	Metadata  Metadata `json:"metadata"`
	ImportSSP Import   `json:"import-ssp"`
	Risks     []struct {
		UUID         string `json:"uuid"`
		Title        string `json:"title"`
		Deadline     string `json:"deadline"`
		Remediations []struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			Lifecycle   string `json:"lifecycle"`
		} `json:"remediations"`
	} `json:"risks"`
	PoamItems []struct {
		Title        string `json:"title"`
		Props        []Prop `json:"props"`
		RelatedRisks []struct {
			RiskUUID string `json:"risk-uuid"`
		} `json:"related-risks"`
	} `json:"poam-items"`
	BackMatter BackMatter `json:"back-matter"`
}

type MappingCollection struct {
	UUID     string   `json:"uuid"`
	Metadata Metadata `json:"metadata"`
	Mappings []struct {
		Maps []struct {
			Relationship string `json:"relationship"`
			Sources      []struct {
				IDRef string `json:"id-ref"`
			} `json:"sources"`
			Targets []struct {
				IDRef string `json:"id-ref"`
			} `json:"targets"`
		} `json:"maps"`
	} `json:"mappings"`
	BackMatter BackMatter `json:"back-matter"`
}
