// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

// Command grundschutz-viewer writes one HTML page from OSCAL documents: the
// security plan, the assessment plan, assessment results and the POA&M that
// grundschutz-worksheets produces, with the profile and catalog they import.
// Give it files, directories, or both; directories are read with all their
// subdirectories, so a folder with one subfolder per run becomes a history.
//
//	grundschutz-viewer -o grundschutz.html runs/
//	grundschutz-viewer -view register security-plan.json results-*.json
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ohartwig/grundschutz-viewer/internal/oscal"
	"github.com/ohartwig/grundschutz-viewer/internal/view"
)

func main() {
	out := flag.String("o", "grundschutz.html", "the page to write, - for stdout")
	layout := flag.String("view", "explorer", "layout: "+strings.Join(view.Views, " or "))
	offline := flag.Bool("offline", false, "never fetch an import over the network")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: grundschutz-viewer [flags] [file or directory ...]\n\nWithout arguments the current directory is read.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if err := run(*out, *layout, *offline, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "grundschutz-viewer:", err)
		os.Exit(1)
	}
}

func run(out, layout string, offline bool, paths []string) error {
	if len(paths) == 0 {
		paths = []string{"."}
	}
	docs, err := oscal.Load(paths)
	if err != nil {
		return err
	}
	if len(docs) == 0 {
		return fmt.Errorf("no OSCAL documents in %s", strings.Join(paths, ", "))
	}
	set := oscal.NewSet(docs)
	set.Offline = offline
	data, err := view.Build(set)
	if err != nil {
		return err
	}
	page, err := view.Render(layout, data)
	if err != nil {
		return err
	}
	for _, w := range data.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	fmt.Fprintf(os.Stderr, "%d documents, %d runs, %d requirements\n", len(docs), len(data.Runs), len(data.Order))
	if out == "-" {
		_, err = os.Stdout.Write(page)
		return err
	}
	return os.WriteFile(out, page, 0o644)
}
