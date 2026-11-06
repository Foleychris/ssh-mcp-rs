#!/usr/bin/env bash
# Helpers for the scheduled Dependabot release (.github/workflows/release.yml).
#
#   merge   Merge open Dependabot PRs that change Cargo.lock and nothing else
#           (semver-compatible updates, what `cargo update` would do) once
#           every check on them has passed. Anything else is left for review:
#           Cargo.toml changes (major versions), workflow/action updates.
#   decide  Print release=true|false (for $GITHUB_OUTPUT): release only if
#           Dependabot updates landed since the last tag and nothing else
#           since then changes the published crate.
#   bump    Bump the patch version in Cargo.toml (and Cargo.lock); print it.
#
# Needs: git with full history and tags, gh (GH_TOKEN), jq, cargo.
set -euo pipefail

# Paths whose changes alter the published crate.
CODE_PATHS='^(src/|tests/|Cargo\.toml$|Cargo\.lock$|build\.rs$)'
DEPENDABOT='dependabot[bot]'

merge() {
  local n files checks mergeable
  for n in $(gh pr list --author "app/dependabot" --state open --json number --jq '.[].number'); do
    files=$(gh pr view "$n" --json files --jq '[.files[].path] | join(" ")')
    if [ "$files" != "Cargo.lock" ]; then
      echo "#$n changes $files, not just Cargo.lock: left for review"
      continue
    fi
    mergeable=$(gh pr view "$n" --json mergeable --jq .mergeable)
    # Every check run must have succeeded (or been skipped/neutral); none pending.
    checks=$(gh pr view "$n" --json statusCheckRollup --jq '
      [.statusCheckRollup[] | (if .__typename == "CheckRun" then .conclusion else .state end)] as $c
      | if ($c | length) == 0 then "none"
        elif all($c[]; . == "SUCCESS" or . == "SKIPPED" or . == "NEUTRAL") then "green"
        else "not-green" end')
    if [ "$mergeable" != MERGEABLE ] || [ "$checks" != green ]; then
      echo "#$n not merged: mergeable=$mergeable checks=$checks"
      continue
    fi
    gh pr merge "$n" --squash --delete-branch
    echo "#$n merged"
  done
}

decide() {
  local last code deps h a
  last=$(git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*')
  deps=$(git log "$last"..HEAD --format=%an | grep -cxF "$DEPENDABOT" || true)
  code=""
  while read -r h a; do
    [ -z "$h" ] && continue
    [ "$a" = "$DEPENDABOT" ] && continue
    if git diff-tree --no-commit-id --name-only -r "$h" | grep -qE "$CODE_PATHS"; then
      code="$code ${h:0:7}"
    fi
  done < <(git log "$last"..HEAD --format='%H %an')
  if [ -n "$code" ]; then
    echo "::notice::Not releasing: commits since $last change the crate and aren't Dependabot's:$code. Release by hand." >&2
    echo release=false
  elif [ "$deps" -eq 0 ]; then
    echo "No Dependabot updates since $last; nothing to release." >&2
    echo release=false
  else
    echo "$deps Dependabot update(s) since $last: releasing." >&2
    echo release=true
  fi
}

bump() {
  local cur ma mi pa new
  cur=$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')
  IFS=. read -r ma mi pa <<<"$cur"
  [[ "$pa" =~ ^[0-9]+$ ]] || { echo "can't bump version $cur" >&2; exit 1; }
  new="$ma.$mi.$((pa + 1))"
  sed -i "0,/^version = \"$cur\"/s//version = \"$new\"/" Cargo.toml
  cargo update --workspace --quiet
  echo "$new"
}

case "${1:-}" in
  merge) merge ;;
  decide) decide ;;
  bump) bump ;;
  *) echo "usage: $0 merge|decide|bump" >&2; exit 2 ;;
esac
