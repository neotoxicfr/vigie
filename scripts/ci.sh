#!/usr/bin/env bash
# CI locale, mêmes contrôles que .github/workflows/ci.yml : format, vet, tests, vulnérabilités, build statique.
set -euo pipefail
cd "$(dirname "$0")/.."

unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
	echo "gofmt à appliquer :" >&2
	echo "$unformatted" >&2
	exit 1
fi
go vet ./...
go test -race ./...
govulncheck ./...
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/vigie ./cmd/vigie
echo "ci ok"
