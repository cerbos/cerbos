#!/usr/bin/env bash
#
# Copyright 2021-2025 Zenauth Ltd.

set -o errexit
set -o nounset
set -o pipefail

pull_request_number="$1"
pull_request_title="$2"

add_label() {
  local label="$1"
  gh pr edit "$pull_request_number" --add-label "$label"
}

conventional_commits_pattern="^([^(:!]+)([(]([^)]+)[)])?!?: "

if [[ "$pull_request_title" =~ $conventional_commits_pattern ]]; then
  type="${BASH_REMATCH[1]}"
  scope="${BASH_REMATCH[3]}"
else
  echo "Pull request title doesn't match Conventional Commits specification" >&2
  exit 1
fi

case "$type" in
  chore)
    add_label chore
    ;;

  docs)
    add_label documentation
    ;;

  enhancement)
    add_label enhancement
    ;;

  feat)
    add_label feature
    ;;

  fix)
    add_label bug
    ;;
esac

case "$scope" in
  ci)
    add_label ci
    ;;

  release)
    add_label release
    ;;

  test)
    add_label testing
    ;;
esac
