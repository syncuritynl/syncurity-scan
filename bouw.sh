#!/usr/bin/env bash
# Bouwt de scandienst voor Linux op ARM64 (statisch, zonder C).
# Weigert te bouwen met werk dat niet is vastgelegd, of als govulncheck iets vindt.
# Uitkomst: ./syncurity-keuring-<versie> en de sha256 ervan.
set -euo pipefail
cd "$(dirname "$0")"
[ -z "$(git status --porcelain)" ] || { echo "niet vastgelegd werk: eerst committen" >&2; exit 1; }
# De versie is altijd de commit (12 tekens), los van tags: die staat onder elk
# rapport met een link naar de code, en is nodig om het programma na te bouwen.
VERSIE=$(git rev-parse --short=12 HEAD)
go vet ./...
go test ./...
"${GOVULNCHECK:-$HOME/go/bin/govulncheck}" ./...
UIT="syncurity-keuring-$VERSIE"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w -X main.versie=$VERSIE" -o "$UIT" ./cmd/dienst
sha256sum "$UIT"
