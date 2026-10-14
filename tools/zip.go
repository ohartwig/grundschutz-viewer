// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

//go:build ignore

// Packs files into a ZIP, flat, and keeps the executable bit.
//
// The golang image the release builds run in has no zip, and a package
// install for it would be a second package channel in a pipeline that
// otherwise needs only Go. The bit has to travel: a binary that arrives
// without +x does not start.
//
//	go run tools/zip.go target.zip file [file ...]
package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: go run tools/zip.go target.zip file [file ...]")
		os.Exit(2)
	}
	target, err := os.Create(os.Args[1])
	if err != nil {
		fail(err)
	}
	w := zip.NewWriter(target)
	for _, name := range os.Args[2:] {
		if err := add(w, name); err != nil {
			fail(err)
		}
	}
	if err := w.Close(); err != nil {
		fail(err)
	}
	if err := target.Close(); err != nil {
		fail(err)
	}
}

func add(w *zip.Writer, name string) error {
	info, err := os.Stat(name)
	if err != nil {
		return err
	}
	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = filepath.Base(name)
	header.Method = zip.Deflate
	header.SetMode(info.Mode())
	part, err := w.CreateHeader(header)
	if err != nil {
		return err
	}
	source, err := os.Open(name)
	if err != nil {
		return err
	}
	defer source.Close()
	_, err = io.Copy(part, source)
	return err
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "zip:", err)
	os.Exit(1)
}
