#!/bin/sh
# Builds the release binaries into $1 (default dist): dist/<os>/<arch>/relay for the image, and
# dist/assets/relay_<os>_<arch> with checksums.txt for the release. With RELAY_VERSION set, fails
# unless every binary reports that version.
set -eu

out=${1:-dist}
targets=${RELAY_TARGETS:-"linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"}

export CGO_ENABLED=0 GOFIPS140=certified GOFLAGS=-mod=readonly
rm -rf "$out"
mkdir -p "$out/assets"

for target in $targets; do
	goos=${target%/*}
	goarch=${target#*/}
	ext=
	if [ "$goos" = windows ]; then ext=.exe; fi
	bin="$out/$target/relay$ext"
	GOOS=$goos GOARCH=$goarch go build -trimpath -buildvcs=true -o "$bin" ./cmd/relay

	info=$(go version -m "$bin")
	if ! printf '%s\n' "$info" | grep -Eq '^[[:space:]]+build[[:space:]]+GOFIPS140=v[0-9]'; then
		echo "$bin: not built with a certified FIPS 140-3 module" >&2
		exit 1
	fi
	if [ -n "${RELAY_VERSION:-}" ] && ! printf '%s\n' "$info" | grep -Eq "^[[:space:]]+mod[[:space:]]+github.com/parallelworks/relay[[:space:]]+v${RELAY_VERSION}[[:space:]]"; then
		echo "$bin: version is not v$RELAY_VERSION" >&2
		exit 1
	fi
	cp "$bin" "$out/assets/relay_${goos}_${goarch}$ext"
done

go version -m "$bin" | sed -n 's/^[[:space:]]*build[[:space:]]*GOFIPS140=//p' > "$out/fips140.txt"
(cd "$out/assets" && sha256sum relay_* > checksums.txt)
