#!/usr/bin/env bash
# CI locale, mêmes contrôles que .github/workflows/ci.yml : format, vet, staticcheck, tests, vulnérabilités
# (govulncheck, osv-scanner), build statique. Versions des outils figées.
set -euo pipefail
cd "$(dirname "$0")/.."

unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
	echo "gofmt à appliquer :" >&2
	echo "$unformatted" >&2
	exit 1
fi
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@2026.2.2 ./...
go test -race ./...
govulncheck ./...
go run github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.7.1 scan source -r .
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/vigie ./cmd/vigie
echo "ci ok"
