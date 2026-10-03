#!/usr/bin/env bash
# Independent safety regressions. Every caller sentinel and injected tool is
# itself disposable; this suite never points the smoke test at personal state.
set -euo pipefail
umask 077

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# Keep Unix socket paths short enough for gpg-agent, including the nested test
# allocation. /tmp is only the parent; mktemp owns the new private directory.
SAFETY_ROOT=$(mktemp -d /tmp/trove-safety.XXXXXXXX)
trap 'rm -rf -- "$SAFETY_ROOT"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
SMOKE_REAL_GPG=$(command -v gpg)
export SMOKE_REAL_GPG

scenarios=(success gpg-failure openssl-failure HUP INT TERM allocation-failure)
# Optional exact cases are for focused diagnostics. The integration entry point
# supplies no arguments and always executes the full acceptance set.
if [[ $# -gt 0 ]]; then scenarios=("$@"); fi
for scenario in "${scenarios[@]}"; do
  case "$scenario" in
    success|gpg-failure|openssl-failure|HUP|INT|TERM|allocation-failure) ;;
    *) echo "Unknown safety scenario: $scenario" >&2; exit 1 ;;
  esac
  case_root="$SAFETY_ROOT/$scenario"
  # Include spaces to catch accidental splitting in allocation and cleanup.
  mkdir -p "$case_root/caller/store/secrets/nested" "$case_root/caller/store/users" \
    "$case_root/caller/legacy-gpg" "$case_root/caller/personal" \
    "$case_root/tools" "$case_root/allocated space"
  printf 'keep encrypted content\n' > "$case_root/caller/store/secrets/nested/secret.enc"
  printf 'keep registration\n' > "$case_root/caller/store/users/alice.pub"
  printf 'keep legacy keys\n' > "$case_root/caller/legacy-gpg/sentinel"
  printf 'keep personal identity\n' > "$case_root/caller/personal/sentinel"
  printf 'keep unrelated temporary file\n' > "$case_root/allocated space/keep"
  cp -R "$case_root/caller" "$case_root/expected"

  # Check actual allocated permissions and each gpg home at execution time.
  # A forced failure or signal arrives after allocation, exercising cleanup.
  cat > "$case_root/tools/gpg" <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
args=("$@")
home_path=""
while [[ $# -gt 0 ]]; do
  if [[ $1 == --homedir ]]; then home_path=$2; break; fi
  shift
done
case "$home_path" in
  "$TMPDIR"/trove-smoke.*/private|"$TMPDIR"/trove-smoke.*/public) ;;
  *) echo 'GPG escaped the allocated home' >&2; exit 91 ;;
esac
root_path=${home_path%/*}
for directory in "$root_path" "$root_path/private" "$root_path/public" "$root_path/data"; do
  mode=$(stat -f '%Lp' "$directory" 2>/dev/null || stat -c '%a' "$directory")
  [[ $mode == 700 ]] || { echo 'Test directory is not owner-only' >&2; exit 92; }
done
while IFS= read -r file; do
  mode=$(stat -f '%Lp' "$file" 2>/dev/null || stat -c '%a' "$file")
  [[ $mode == 600 ]] || { echo 'Test file is not owner-only' >&2; exit 93; }
done < <(find "$root_path/data" -type f)
printf 'checked\n' >> "$SMOKE_CHECKS"
case "$SMOKE_SCENARIO" in
  gpg-failure) exit 42 ;;
  # Isolate the OpenSSL failure path without requiring a preceding live agent.
  openssl-failure) exit 0 ;;
  HUP|INT|TERM) kill -s "$SMOKE_SCENARIO" "$PPID"; exit 0 ;;
esac
exec "$SMOKE_REAL_GPG" "${args[@]}"
WRAPPER
  chmod 700 "$case_root/tools/gpg"
  if [[ $scenario == openssl-failure ]]; then
    printf '#!/usr/bin/env bash\nexit 43\n' > "$case_root/tools/openssl"
    chmod 700 "$case_root/tools/openssl"
  elif [[ $scenario == allocation-failure ]]; then
    printf '#!/usr/bin/env bash\nexit 44\n' > "$case_root/tools/mktemp"
    chmod 700 "$case_root/tools/mktemp"
  fi

  status=0
  TMPDIR="$case_root/allocated space" PATH="$case_root/tools:$PATH" \
    SMOKE_SCENARIO="$scenario" SMOKE_CHECKS="$case_root/checks" \
    GNUPGHOME="$case_root/caller/personal" \
    make -C "$REPO_ROOT" test-crypto PM_USER=smoke-test \
    STORE_DIR="$case_root/caller/store" \
    USERS_DIR="$case_root/caller/store/users" \
    SECRETS_DIR="$case_root/caller/store/secrets" \
    GNUPGHOME="$case_root/caller/legacy-gpg" \
    > "$case_root/output" 2>&1 || status=$?
  diff -r "$case_root/expected" "$case_root/caller"
  [[ -z $(find "$case_root/allocated space" -maxdepth 1 -name 'trove-smoke.*' -print) ]] || \
    { echo "Allocated smoke root remained after $scenario" >&2; exit 1; }
  [[ $(cat "$case_root/allocated space/keep") == 'keep unrelated temporary file' ]]
  if [[ $scenario == success ]]; then
    [[ $status == 0 ]] || { cat "$case_root/output" >&2; exit 1; }
    grep -q 'binary round-trip matches byte-for-byte' "$case_root/output"
    [[ $(wc -l < "$case_root/checks") -ge 7 ]]
  else
    [[ $status != 0 ]] || { echo "$scenario incorrectly reported success" >&2; exit 1; }
    if [[ $scenario != allocation-failure ]]; then [[ -s "$case_root/checks" ]]; fi
    case "$scenario" in
      gpg-failure) expected_status=42 ;;
      openssl-failure) expected_status=43 ;;
      HUP) expected_status=129 ;;
      INT) expected_status=130 ;;
      TERM) expected_status=143 ;;
      allocation-failure) expected_status=44 ;;
    esac
    grep -q "Error $expected_status" "$case_root/output" || \
      { echo "$scenario did not preserve the expected failure status" >&2; cat "$case_root/output" >&2; exit 1; }
    if grep -q 'GPG escaped\|not owner-only' "$case_root/output"; then
      cat "$case_root/output" >&2; exit 1
    fi
  fi
  echo "  Smoke safety: $scenario preserves caller files and bounds cleanup"
done
