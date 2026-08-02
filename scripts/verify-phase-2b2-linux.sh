#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="${1:-$(pwd)}"

required_files=(
    "apps/bootstrapper-linux/Install-CyrpWazuhFromEnrollmentFile.sh"
    "apps/bootstrapper-linux/Test-CyrpWazuhAgent.sh"
)

for relative_path in "${required_files[@]}"; do
    full_path="$PROJECT_ROOT/$relative_path"

    [[ -f "$full_path" ]] || {
        printf 'Missing file: %s\n' "$relative_path" >&2
        exit 1
    }

    bash -n "$full_path"
    printf 'Bash syntax: %s\n' "$relative_path"
done

printf '\nCYRP Phase 2B.2-Linux Bash verification completed.\n'
