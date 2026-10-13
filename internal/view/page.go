// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

package view

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

//go:embed templates/*.html
var templates embed.FS

// Views lists the page layouts there are.
var Views = []string{"explorer", "register"}

// Render writes the page of one view with the data embedded.
func Render(view string, data *Data) ([]byte, error) {
	tpl, err := templates.ReadFile("templates/" + view + ".html")
	if err != nil {
		return nil, fmt.Errorf("unknown view %q (there are %s)", view, strings.Join(Views, ", "))
	}
	noNullLists(reflect.ValueOf(data))
	var blob bytes.Buffer
	enc := json.NewEncoder(&blob)
	enc.SetEscapeHTML(true) // the blob sits in a <script>: no "</script>" can end it early
	if err := enc.Encode(data); err != nil {
		return nil, err
	}
	const slot = "/*__DATA__*/null"
	if !bytes.Contains(tpl, []byte(slot)) {
		return nil, fmt.Errorf("view %s has no data slot", view)
	}
	return bytes.Replace(tpl, []byte(slot), bytes.TrimSpace(blob.Bytes()), 1), nil
}

// noNullLists replaces every nil slice and map in v with an empty one. encoding/json
// writes a nil slice as null, and the templates iterate lists without asking
// first: a run without trial checks broke the register's check tab. A nil
// pointer stays null on purpose; the templates read it as "not given".
func noNullLists(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			noNullLists(v.Elem())
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				noNullLists(v.Field(i))
			}
		}
	case reflect.Slice:
		if v.IsNil() {
			if v.CanSet() {
				v.Set(reflect.MakeSlice(v.Type(), 0, 0))
			}
			return
		}
		for i := range v.Len() {
			noNullLists(v.Index(i))
		}
	case reflect.Map:
		if v.IsNil() {
			if v.CanSet() {
				v.Set(reflect.MakeMap(v.Type()))
			}
			return
		}
		for _, k := range v.MapKeys() {
			e := v.MapIndex(k)
			switch {
			case e.Kind() == reflect.Slice && e.IsNil():
				v.SetMapIndex(k, reflect.MakeSlice(e.Type(), 0, 0))
			case e.Kind() == reflect.Pointer:
				noNullLists(e)
			case e.Kind() == reflect.Slice:
				for i := range e.Len() {
					noNullLists(e.Index(i))
				}
			}
		}
	}
}
