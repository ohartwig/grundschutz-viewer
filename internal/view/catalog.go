// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

package view

import (
	"regexp"
	"slices"
	"strings"

	"github.com/ohartwig/grundschutz-viewer/internal/oscal"
)

type catIndex struct {
	controls map[string]*oscal.Control
	parent   map[string]*string
	group    map[string][2]*oscal.Group // practice and its subgroup
	reqBy    map[string][]string
	relBack  map[string][]string
}

func indexCatalog(c *oscal.Catalog) *catIndex {
	x := &catIndex{controls: map[string]*oscal.Control{}, parent: map[string]*string{}, group: map[string][2]*oscal.Group{}, reqBy: map[string][]string{}, relBack: map[string][]string{}}
	var walk func(cs []oscal.Control, parent *string, g [2]*oscal.Group)
	walk = func(cs []oscal.Control, parent *string, g [2]*oscal.Group) {
		for i := range cs {
			c := &cs[i]
			x.controls[c.ID] = c
			x.parent[c.ID] = parent
			x.group[c.ID] = g
			walk(c.Controls, &c.ID, g)
		}
	}
	var groups func(gs []oscal.Group, top *oscal.Group)
	groups = func(gs []oscal.Group, top *oscal.Group) {
		for i := range gs {
			g := &gs[i]
			pair := [2]*oscal.Group{g, nil}
			if top != nil {
				pair = [2]*oscal.Group{top, g}
			}
			walk(g.Controls, nil, pair)
			groups(g.Groups, pair[0])
		}
	}
	groups(c.Groups, nil)
	walk(c.Controls, nil, [2]*oscal.Group{})
	for id, c := range x.controls {
		for _, t := range links(c, "required") {
			x.reqBy[t] = append(x.reqBy[t], id)
		}
		for _, t := range links(c, "related") {
			x.relBack[t] = append(x.relBack[t], id)
		}
	}
	return x
}

func links(c *oscal.Control, rel string) []string {
	out := []string{}
	for _, l := range c.Links {
		if l.Rel == rel {
			out = append(out, strings.TrimPrefix(l.Href, "#"))
		}
	}
	return out
}

func partProp(c *oscal.Control, part, name string) string {
	for _, p := range c.Parts {
		if p.Name == part {
			return oscal.Value(p.Props, name)
		}
	}
	return ""
}

func prose(c *oscal.Control, part string) string {
	for _, p := range c.Parts {
		if p.Name == part {
			return p.Prose
		}
	}
	return ""
}

var insertRe = regexp.MustCompile(`\{\{\s*insert:\s*param,\s*([\w.-]+)\s*\}\}`)

// statement is the requirement's text with its parameters filled in: the
// profile's value where it sets one, else the catalog's label or default.
func statement(c *oscal.Control, set map[string]string) string {
	own := map[string]string{}
	for _, p := range c.Params {
		own[p.ID] = p.Label
		if own[p.ID] == "" {
			own[p.ID] = strings.Join(p.Values, " / ")
		}
	}
	return insertRe.ReplaceAllStringFunc(prose(c, "statement"), func(m string) string {
		id := insertRe.FindStringSubmatch(m)[1]
		v, ok := set[id]
		if !ok {
			v = own[id]
		}
		if v == "" {
			v = id
		}
		return "„" + v + "“"
	})
}

func (x *catIndex) req(id string, params map[string]string) *Req {
	c := x.controls[id]
	g := x.group[id]
	r := &Req{
		T:     c.Title,
		Stm:   statement(c, params),
		MV:    partProp(c, "statement", "modal_verb"),
		Doc:   partProp(c, "statement", "documentation"),
		Gdn:   prose(c, "guidance"),
		Lvl:   oscal.Value(c.Props, "sec_level"),
		Thr:   []string{},
		P:     x.parent[id],
		K:     []string{},
		Req:   links(c, "required"),
		ReqBy: sorted(x.reqBy[id]),
		C:     []string{},
	}
	if g[0] != nil {
		r.G, r.GT = g[0].ID, g[0].Title
	}
	if g[1] != nil {
		r.S, r.STT = g[1].ID, g[1].Title
	}
	for t := range strings.SplitSeq(oscal.Value(c.Props, "threats"), ",") {
		if t = strings.TrimSpace(t); t != "" {
			r.Thr = append(r.Thr, t)
		}
	}
	for _, k := range c.Controls {
		r.K = append(r.K, k.ID)
	}
	r.Rel = slices.Compact(sorted(append(links(c, "related"), x.relBack[id]...)))
	return r
}

// sorted returns a sorted copy, never nil: the page reads .length of every list.
func sorted(s []string) []string {
	out := append([]string{}, s...)
	slices.Sort(out)
	return out
}
