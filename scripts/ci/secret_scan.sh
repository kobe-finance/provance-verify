#!/bin/bash
# =============================================================================
# Secret scan (git grep, no extra tooling)
#
# Fails when a tracked file contains a credential-shaped string or when an
# env/key file other than .env.example is tracked. With a base ref (CI passes
# the pull request base or the previous push), it also scans every line added
# in BASE..HEAD, so a secret that was committed and then deleted in the same
# change is still caught.
#
#   bash scripts/ci/secret_scan.sh               # tracked files at HEAD
#   bash scripts/ci/secret_scan.sh origin/main   # plus lines added since origin/main
#
# Patterns cover the providers Provance uses (Stripe, Anthropic, OpenAI,
# Z.ai-style sk- keys, Resend, GitHub, AWS, Google, Slack) and private keys.
# Test fixtures use obviously fake values that do not match these shapes.
#
# The same script runs in provance-api, provance-web, provance-sdks and
# provance-shared (HYG-001); change it in all four.
# =============================================================================

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

PATTERNS="$(mktemp)"
trap 'rm -f "$PATTERNS"' EXIT
cat > "$PATTERNS" <<'EOF'
-----BEGIN ([A-Z]+ )?PRIVATE KEY-----
AKIA[0-9A-Z]{16}
(sk|rk)_live_[0-9a-zA-Z]{10,}
(sk|rk)_test_[0-9a-zA-Z]{24,}
whsec_[0-9a-zA-Z]{24,}
sk-ant-[a-zA-Z0-9_-]{20,}
sk-proj-[a-zA-Z0-9_-]{20,}
sk-[a-zA-Z0-9]{40,}
gh[pousr]_[0-9a-zA-Z]{36}
github_pat_[0-9a-zA-Z_]{40,}
xox[abprs]-[0-9a-zA-Z-]{10,}
AIza[0-9A-Za-z_-]{35}
re_[0-9a-zA-Z]{8}_[0-9a-zA-Z]{20,}
EOF

status=0

echo "Scanning tracked files..."
if git grep -nIE -f "$PATTERNS" -- . ':!scripts/ci/secret_scan.sh'; then
    echo "::error::Credential-shaped string in a tracked file (above)." >&2
    status=1
fi

tracked_env="$(git ls-files | grep -E '(^|/)\.env(\..+)?$' | grep -vE '(^|/)\.env\.example$' || true)"
# Key stores and PEM files. A .pem that holds only certificates (public data,
# e.g. a test TSA's chain in provance-verify's fixtures) is allowed; one with
# any other block, or none, is reported.
tracked_keys=""
while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    if [[ "$f" == *.pem ]] && grep -q -- '-----BEGIN CERTIFICATE-----' "$f" \
        && ! grep -E -- '-----BEGIN ' "$f" | grep -qv -- '-----BEGIN CERTIFICATE-----'; then
        continue
    fi
    tracked_keys+="$f"$'\n'
done < <(git ls-files | grep -E '\.(pem|key|p12|pfx|jks)$' || true)
tracked_keys="${tracked_keys%$'\n'}"
if [[ -n "$tracked_env$tracked_keys" ]]; then
    echo "::error::Env or key files are tracked (only .env.example may be):" >&2
    printf '%s\n' $tracked_env $tracked_keys >&2
    status=1
fi

base="${1:-}"
if [[ -n "$base" ]] && git rev-parse --verify --quiet "$base^{commit}" > /dev/null; then
    echo "Scanning lines added in $base..HEAD..."
    added="$(git log -p --no-color --format= "$base..HEAD" -- . ':!scripts/ci/secret_scan.sh' \
        | grep -E '^\+' | grep -vE '^\+\+\+ ' || true)"
    if [[ -n "$added" ]] && grep -nE -f "$PATTERNS" <<< "$added"; then
        echo "::error::Credential-shaped string added in $base..HEAD (above). Rotate it and rewrite the branch." >&2
        status=1
    fi
elif [[ -n "$base" ]]; then
    echo "Base $base not available; scanned tracked files only."
fi

if [[ $status -eq 0 ]]; then
    echo "Secret scan passed."
fi
exit $status
