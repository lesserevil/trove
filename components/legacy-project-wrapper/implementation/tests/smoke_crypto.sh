#!/usr/bin/env bash
# Contributor-only legacy interoperability harness. All state belongs to one
# allocation; caller store/keyring settings never select setup or cleanup paths.
set -euo pipefail
umask 077

SMOKE_ROOT=""
cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [[ -n "$SMOKE_ROOT" ]]; then
    if command -v gpgconf >/dev/null 2>&1; then
      gpgconf --homedir "$SMOKE_ROOT/private" --kill gpg-agent >/dev/null 2>&1 || true
      gpgconf --homedir "$SMOKE_ROOT/public" --kill gpg-agent >/dev/null 2>&1 || true
    fi
    rm -rf -- "$SMOKE_ROOT"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

SMOKE_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/trove-smoke.XXXXXXXX")
mkdir "$SMOKE_ROOT/private" "$SMOKE_ROOT/public" "$SMOKE_ROOT/data"
export GNUPGHOME="$SMOKE_ROOT/private"

echo '=== Trove isolated crypto smoke test ==='
gpg --batch --yes --homedir "$SMOKE_ROOT/private" \
  --pinentry-mode loopback --passphrase '' \
  --quick-generate-key 'trove-smoke@test.local' default default never
gpg --batch --yes --homedir "$SMOKE_ROOT/private" --armor \
  --export 'trove-smoke@test.local' > "$SMOKE_ROOT/data/user.pub"
gpg --batch --yes --homedir "$SMOKE_ROOT/public" \
  --import "$SMOKE_ROOT/data/user.pub"

printf 'test secret content 12345\n' > "$SMOKE_ROOT/data/text"
openssl rand 10240 > "$SMOKE_ROOT/data/binary"
for kind in text binary; do
  key=$(openssl rand -hex 32)
  iv=$(openssl rand -hex 16)
  printf '%s\n' "$iv" > "$SMOKE_ROOT/data/$kind.enc"
  openssl enc -aes-256-cbc -nosalt -K "$key" -iv "$iv" \
    -in "$SMOKE_ROOT/data/$kind" >> "$SMOKE_ROOT/data/$kind.enc"
  printf '%s\n' "$key" | gpg --batch --yes --trust-model always \
    --homedir "$SMOKE_ROOT/public" \
    --recipient-file "$SMOKE_ROOT/data/user.pub" --encrypt --armor \
    --output "$SMOKE_ROOT/data/$kind.key.enc"
  recovered_key=$(gpg --batch --yes --quiet --homedir "$SMOKE_ROOT/private" \
    --pinentry-mode loopback --passphrase '' \
    --decrypt "$SMOKE_ROOT/data/$kind.key.enc")
  recovered_iv=$(head -1 "$SMOKE_ROOT/data/$kind.enc")
  tail -n +2 "$SMOKE_ROOT/data/$kind.enc" | \
    openssl enc -aes-256-cbc -d -nosalt -K "$recovered_key" -iv "$recovered_iv" \
    > "$SMOKE_ROOT/data/$kind.recovered"
  cmp "$SMOKE_ROOT/data/$kind" "$SMOKE_ROOT/data/$kind.recovered"
  echo "  PASS: $kind round-trip matches byte-for-byte"
done
echo '=== Crypto smoke test complete ==='
