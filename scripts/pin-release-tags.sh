#!/usr/bin/env bash
#
# pin-release-tags.sh — Pin all rossoctl-built image tags to a release version.
#
# Updates image tags across both charts/rossoctl/ and charts/rossoctl-deps/ so
# that a tagged release checkout always pulls the correct images when installed
# from source (via the setup-rossoctl.sh installers).
#
# Usage:
#   ./scripts/pin-release-tags.sh v0.6.0-rc.6
#   ./scripts/pin-release-tags.sh v0.7.0-alpha.2 --dry-run
#   ./scripts/pin-release-tags.sh v0.6.0 --verify-images
#
# This script is idempotent — running it multiple times with the same version
# produces the same result.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

ROSSOCTL_VALUES="$REPO_ROOT/charts/rossoctl/values.yaml"
ROSSOCTL_DEPS_VALUES="$REPO_ROOT/charts/rossoctl-deps/values.yaml"
# Only rossoctl Chart.yaml is versioned here; rossoctl-deps is a dependency chart
# whose version is managed independently via its own release cadence.
ROSSOCTL_CHART="$REPO_ROOT/charts/rossoctl/Chart.yaml"

DRY_RUN=false
VERIFY_IMAGES=false

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $(basename "$0") VERSION [OPTIONS]

Pin all rossoctl-built container image tags to VERSION across both Helm charts.

Arguments:
  VERSION             The release version tag (e.g., v0.6.0-rc.6, v0.7.0-alpha.1)

Options:
  --dry-run              Show what would change without modifying files
  --verify-images        Check that images exist in ghcr.io before pinning
  --chart-version V      Override Chart.yaml version (default: derived from VERSION)
  --skip-chart-version   Do NOT update Chart.yaml version/appVersion
  -h, --help             Show this help message

Images pinned:
  Every ghcr.io/rossoctl/rossoctl/* image found in charts/rossoctl/values.yaml
  and charts/rossoctl-deps/values.yaml is pinned (the set is derived from the
  values files, so new rossoctl images are covered automatically). Run with
  --dry-run to see the exact list for the current tree.

EOF
    exit 0
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------

VERSION=""
CHART_VERSION=""
SKIP_CHART_VERSION=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)             DRY_RUN=true; shift ;;
        --verify-images)       VERIFY_IMAGES=true; shift ;;
        --chart-version)       CHART_VERSION="$2"; shift 2 ;;
        --skip-chart-version)  SKIP_CHART_VERSION=true; shift ;;
        -h|--help)             usage ;;
        -*)                    echo "Unknown option: $1" >&2; usage ;;
        *)
            if [[ -z "$VERSION" ]]; then
                VERSION="$1"
            else
                echo "Unexpected argument: $1" >&2; usage
            fi
            shift
            ;;
    esac
done

if [[ -z "$VERSION" ]]; then
    echo "error: VERSION argument is required" >&2
    echo "" >&2
    usage
fi

# Validate version format (must start with v and contain at least major.minor.patch)
if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
    echo "error: VERSION must match vX.Y.Z[-prerelease] (got: $VERSION)" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Check prerequisites
# ---------------------------------------------------------------------------

if ! command -v yq >/dev/null 2>&1; then
    echo "error: yq is required but not installed" >&2
    echo "  Install: brew install yq  (or see https://github.com/mikefarah/yq)" >&2
    exit 2
fi

if [[ ! -f "$ROSSOCTL_VALUES" ]]; then
    echo "error: $ROSSOCTL_VALUES not found (run from repo root)" >&2
    exit 1
fi

if [[ ! -f "$ROSSOCTL_DEPS_VALUES" ]]; then
    echo "error: $ROSSOCTL_DEPS_VALUES not found (run from repo root)" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Image registry and paths
# ---------------------------------------------------------------------------

REGISTRY="ghcr.io/rossoctl/rossoctl"

# The set of pinnable images is derived dynamically from the chart values so
# that ANY ghcr.io/rossoctl/rossoctl/* image is pinned automatically — a
# hardcoded key list silently skipped new images (phoenix-oauth-secret and the
# charts/rossoctl copy of spiffe-idp-setup were left stale; rossoctl/rossoctl#2401).
#
# For every string value matching the registry, we pin its sibling `tag`. This
# handles both layouts in the values files by replacing the last path segment
# with "tag":
#   flat:    image: <ref>            + tag: <ver>   -> <parent>.tag
#   nested:  image: { repository: <ref>, tag: <ver> } -> <parent>.image.tag
# Format of each derived entry: "values-file|yq-path|image-name"
#
# By design, any layout OTHER than these two aborts the run (fail-loud, never a
# silent skip): an image carrying an inline tag with no sibling `tag:` key yields
# a `.tag` path that doesn't exist and the pin loop exits with an error; likewise
# a values key containing a literal "." breaks the `join(".")` path. Both are
# absent from these charts today — if one is introduced, extend this deriver
# rather than let it half-pin the tree.
derive_expr='.. | select((tag == "!!str") and (. == "'"$REGISTRY"'/*"))
    | (path | .[-1] = "tag" | join("."))
    + "|" + (. | sub("^'"$REGISTRY"'/"; "") | sub(":.*$"; ""))'

PINNABLE_IMAGES=()
for values_file in "$ROSSOCTL_VALUES" "$ROSSOCTL_DEPS_VALUES"; do
    while IFS= read -r derived; do
        [[ -z "$derived" ]] && continue
        PINNABLE_IMAGES+=("$values_file|.$derived")
    done < <(yq eval "$derive_expr" "$values_file")
done

if [[ ${#PINNABLE_IMAGES[@]} -eq 0 ]]; then
    echo "error: no $REGISTRY/* images found in chart values — image derivation failed" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; NC=$'\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; NC=''
fi

# ---------------------------------------------------------------------------
# Surgical in-place value replacement
#
# `yq -i` rewrites (and reformats) the whole document — it drops blank lines and
# re-indents sequences, which turned a 9-tag pin into ~100 lines of churn. To keep
# the diff to only the version lines, we locate each target node's line with
# `yq '... | line'` (read-only) and rewrite just that line's value with sed. The
# line count never changes (same-line value swap), so line numbers stay valid
# across successive edits within a file.
# ---------------------------------------------------------------------------

# Detect GNU vs BSD/macOS sed once: GNU accepts `--version`; BSD needs `-i ''`.
if sed --version >/dev/null 2>&1; then
    sed_i() { sed -i "$@"; }
else
    sed_i() { sed -i '' "$@"; }
fi

# pin_scalar FILE YQ_PATH VALUE — rewrite only the value of the scalar at YQ_PATH
# to VALUE, in place, touching just that one line (no document reflow).
#
# yq's `line` operator is used as an anchor, but its offset is not uniform (0 for
# top-level keys like Chart.yaml's .version, but -1 for nested keys in
# values.yaml), so we resolve the exact line by matching YQ_PATH's trailing key
# within a one-line window of the anchor. The post-write assertion at the call
# site re-reads via yq and fails loudly if the substitution missed.
pin_scalar() {
    local file="$1" yq_path="$2" value="$3"
    local key="${yq_path##*.}"
    local anchor cand target=""
    anchor=$(yq eval "$yq_path | line" "$file")
    if [[ -z "$anchor" || "$anchor" == "0" ]]; then
        echo "error: could not locate $yq_path in ${file#$REPO_ROOT/}" >&2
        exit 1
    fi
    for cand in "$anchor" $((anchor + 1)); do
        if sed -n "${cand}p" "$file" | grep -qE "^[[:space:]]*${key}:"; then
            target="$cand"; break
        fi
    done
    if [[ -z "$target" ]]; then
        echo "error: could not resolve '$key:' line near $anchor in ${file#$REPO_ROOT/}" >&2
        exit 1
    fi
    # Replace only the scalar value, preserving the key, its existing quoting,
    # and any trailing comment. A blunt `s#: .*#: value#` would silently unquote
    # (e.g. Chart.yaml's quoted appVersion) and strip trailing comments — changes
    # the post-write assertion can't catch, since it compares the parsed value.
    # Groups: 1=indent+key+colon+space, 2=open quote (or empty), 3=close quote,
    # 4=trailing whitespace+comment; the value between 2 and 3 is rewritten.
    sed_i -E "${target}s|^([[:space:]]*[^:]+:[[:space:]]*)(['\"]?)[^#[:space:]'\"]*(['\"]?)([[:space:]]*(#.*)?)\$|\1\2${value}\3\4|" "$file"
}

# ---------------------------------------------------------------------------
# Verify images exist (optional)
# ---------------------------------------------------------------------------

if [[ "$VERIFY_IMAGES" == "true" ]]; then
    if ! command -v docker >/dev/null 2>&1; then
        echo "error: --verify-images requires docker" >&2
        exit 2
    fi

    echo "Verifying images exist in registry..."
    all_found=true

    for entry in "${PINNABLE_IMAGES[@]}"; do
        IFS='|' read -r _ _ image_name <<< "$entry"
        full_ref="$REGISTRY/$image_name:$VERSION"

        if docker manifest inspect "$full_ref" >/dev/null 2>&1; then
            printf '%s[OK]%s   %s\n' "$GREEN" "$NC" "$full_ref"
        else
            printf '%s[MISS]%s %s\n' "$RED" "$NC" "$full_ref"
            all_found=false
        fi
    done

    if [[ "$all_found" != "true" ]]; then
        echo ""
        echo "${RED}error: Some images are missing. Build and push them before pinning.${NC}" >&2
        exit 1
    fi

    echo ""
fi

# ---------------------------------------------------------------------------
# Pin image tags
# ---------------------------------------------------------------------------

echo "Pinning image tags to ${VERSION}..."
echo ""

for entry in "${PINNABLE_IMAGES[@]}"; do
    IFS='|' read -r target_file yq_path image_name <<< "$entry"

    # Get current value (yq returns literal "null" for missing paths)
    current=$(yq eval "$yq_path // \"\"" "$target_file")
    rel_path="${target_file#$REPO_ROOT/}"

    if [[ -z "$current" ]]; then
        echo "error: yq path $yq_path not found in $rel_path" >&2
        exit 1
    fi

    if [[ "$current" == "$VERSION" ]]; then
        printf '%s[SKIP]%s %s (%s) — already %s\n' "$GREEN" "$NC" "$image_name" "$rel_path" "$VERSION"
        continue
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        printf '%s[DRY]%s  %s (%s): %s → %s\n' "$YELLOW" "$NC" "$image_name" "$rel_path" "$current" "$VERSION"
    else
        pin_scalar "$target_file" "$yq_path" "$VERSION"
        got=$(yq eval "$yq_path" "$target_file")
        [[ "$got" == "$VERSION" ]] || { echo "error: pin verify failed for $yq_path in $rel_path (got '$got')" >&2; exit 1; }
        printf '%s[PIN]%s  %s (%s): %s → %s\n' "$GREEN" "$NC" "$image_name" "$rel_path" "$current" "$VERSION"
    fi
done

# ---------------------------------------------------------------------------
# Pin Chart.yaml version
#
# By default, Chart.yaml version and appVersion are set to match VERSION
# (strip 'v' prefix). Use --chart-version to override, or --skip-chart-version
# to leave Chart.yaml untouched.
# ---------------------------------------------------------------------------

if [[ "$SKIP_CHART_VERSION" != "true" ]]; then
    # Default to VERSION if --chart-version was not explicitly passed
    if [[ -z "$CHART_VERSION" ]]; then
        CHART_VERSION="$VERSION"
    fi

    echo ""
    echo "Updating Chart.yaml version..."

    # Strip 'v' prefix for chart version
    chart_ver="${CHART_VERSION#v}"

    if [[ "$DRY_RUN" == "true" ]]; then
        current_chart_ver=$(yq eval '.version' "$ROSSOCTL_CHART")
        printf '%s[DRY]%s  Chart.yaml version: %s → %s\n' "$YELLOW" "$NC" "$current_chart_ver" "$chart_ver"
        printf '%s[DRY]%s  Chart.yaml appVersion: → %s\n' "$YELLOW" "$NC" "$chart_ver"
    else
        pin_scalar "$ROSSOCTL_CHART" '.version' "$chart_ver"
        pin_scalar "$ROSSOCTL_CHART" '.appVersion' "$chart_ver"
        got_v=$(yq eval '.version' "$ROSSOCTL_CHART")
        got_av=$(yq eval '.appVersion' "$ROSSOCTL_CHART")
        [[ "$got_v" == "$chart_ver" && "$got_av" == "$chart_ver" ]] || { echo "error: Chart.yaml version pin verify failed (version='$got_v' appVersion='$got_av')" >&2; exit 1; }
        printf '%s[PIN]%s  Chart.yaml version + appVersion → %s\n' "$GREEN" "$NC" "$chart_ver"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
if [[ "$DRY_RUN" == "true" ]]; then
    echo "${YELLOW}Dry run complete — no files were modified.${NC}"
    echo "Remove --dry-run to apply changes."
else
    echo "${GREEN}All image tags pinned to ${VERSION}.${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Review changes:  git diff charts/"
    echo "  2. Run validation:  bash scripts/check-release-pins.sh"
    echo "  3. Commit:          git add charts/ && git commit -s -m \"chore(release): pin image tags for ${VERSION}\""
fi
