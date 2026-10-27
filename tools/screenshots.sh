#!/bin/sh
# SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
# SPDX-License-Identifier: MIT
#
# Rebuilds the screenshots in docs/ from the example of tools/example.go:
# writes the example chain, renders both views and captures them with
# headless Chrome at 1440x900, twice the pixels.
#
#   sh tools/screenshots.sh
#
# CHROME overrides the browser; the default is Chrome on macOS.
set -eu
cd "$(dirname "$0")/.."

CHROME=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
out=out/screenshots
rm -rf "$out"
mkdir -p "$out" docs

go run tools/example.go "$out/example"
go build -o "$out/grundschutz-viewer" ./cmd/grundschutz-viewer
"$out/grundschutz-viewer" -offline -view explorer -o "$out/explorer.html" "$out/example"
"$out/grundschutz-viewer" -offline -view register -o "$out/register.html" "$out/example"

shot() { # page fragment image
	"$CHROME" --headless --disable-gpu --hide-scrollbars --force-device-scale-factor=2 \
		--window-size=1440,900 --virtual-time-budget=5000 \
		--screenshot="$PWD/docs/$3" "file://$PWD/$out/$1#$2" >/dev/null 2>&1
}

shot explorer.html "" explorer-overview.png
shot explorer.html TEST.4.1 explorer-requirement.png
shot register.html "" register.png
