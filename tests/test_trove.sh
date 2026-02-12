#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

# ---------------------------------------------------------------------------
# 1. Init creates directory structure
# ---------------------------------------------------------------------------
test_init_creates_structure() {
  begin_test "init creates directory structure"
  setup_test_env
  local ok=true

  assert_dir_exists "$TEST_STORE_DIR/users" || ok=false
  assert_dir_exists "$TEST_STORE_DIR/secrets" || ok=false
  assert_dir_exists "$TEST_STORE_DIR/.gnupg" || ok=false

  local perms
  perms=$(stat -f '%Lp' "$TEST_STORE_DIR/.gnupg" 2>/dev/null || stat -c '%a' "$TEST_STORE_DIR/.gnupg" 2>/dev/null)
  assert_eq "700" "$perms" ".gnupg should have mode 700" || ok=false

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 2. Add user registers public key
# ---------------------------------------------------------------------------
test_add_user() {
  begin_test "add-user registers public key"
  setup_test_env
  local ok=true

  run_make add-user NAME="alice" KEY="$TEST_TMPDIR/alice.pub" >/dev/null 2>&1 || { fail_test "add-user exited non-zero"; ok=false; }
  assert_file_exists "$TEST_STORE_DIR/users/alice.pub" || ok=false

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 3. Create + read round-trip (text)
# ---------------------------------------------------------------------------
test_create_read_text() {
  begin_test "create + read round-trip (text)"
  setup_test_env
  local ok=true

  run_make add-user NAME="alice" KEY="$TEST_TMPDIR/alice.pub" >/dev/null 2>&1
  echo "my secret password 123" > "$TEST_TMPDIR/secret.txt"
  run_as alice create-secret NAME="mysecret" FILE="$TEST_TMPDIR/secret.txt" >/dev/null 2>&1 || { fail_test "create-secret failed"; ok=false; }

  if $ok; then
    local recovered
    recovered=$(run_as alice read-secret NAME="mysecret" 2>/dev/null)
    assert_eq "my secret password 123" "$recovered" "decrypted text should match original" || ok=false
  fi

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 4. Create + read round-trip (binary)
# ---------------------------------------------------------------------------
test_create_read_binary() {
  begin_test "create + read round-trip (binary)"
  setup_test_env
  local ok=true

  run_make add-user NAME="alice" KEY="$TEST_TMPDIR/alice.pub" >/dev/null 2>&1
  dd if=/dev/urandom of="$TEST_TMPDIR/binary.dat" bs=1024 count=10 2>/dev/null
  local orig_sha
  orig_sha=$(shasum -a 256 "$TEST_TMPDIR/binary.dat" | awk '{print $1}')

  run_as alice create-secret NAME="bindata" FILE="$TEST_TMPDIR/binary.dat" >/dev/null 2>&1 || { fail_test "create-secret failed"; ok=false; }

  if $ok; then
    run_as alice read-secret NAME="bindata" 2>/dev/null > "$TEST_TMPDIR/recovered.dat"
    local recv_sha
    recv_sha=$(shasum -a 256 "$TEST_TMPDIR/recovered.dat" | awk '{print $1}')
    assert_eq "$orig_sha" "$recv_sha" "SHA-256 of binary round-trip should match" || ok=false
  fi

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 5. Create duplicate secret fails
# ---------------------------------------------------------------------------
test_create_duplicate_fails() {
  begin_test "create duplicate secret fails"
  setup_test_env
  local ok=true

  run_make add-user NAME="alice" KEY="$TEST_TMPDIR/alice.pub" >/dev/null 2>&1
  echo "first" > "$TEST_TMPDIR/s1.txt"
  echo "second" > "$TEST_TMPDIR/s2.txt"
  run_as alice create-secret NAME="dup" FILE="$TEST_TMPDIR/s1.txt" >/dev/null 2>&1

  local exit_code=0
  run_as alice create-secret NAME="dup" FILE="$TEST_TMPDIR/s2.txt" >/dev/null 2>&1 || exit_code=$?
  assert_ne "0" "$exit_code" "duplicate create should fail" || ok=false

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 6. Grant access enables second user
# ---------------------------------------------------------------------------
test_grant_access() {
  begin_test "grant access enables second user"
  setup_test_env
  local ok=true

  run_make add-user NAME="alice" KEY="$TEST_TMPDIR/alice.pub" >/dev/null 2>&1
  run_make add-user NAME="bob" KEY="$TEST_TMPDIR/bob.pub" >/dev/null 2>&1
  echo "shared secret" > "$TEST_TMPDIR/shared.txt"
  run_as alice create-secret NAME="shared" FILE="$TEST_TMPDIR/shared.txt" >/dev/null 2>&1

  run_as alice grant-access NAME="shared" USER="bob" >/dev/null 2>&1 || { fail_test "grant-access failed"; ok=false; }

  if $ok; then
    local bob_read
    bob_read=$(run_as bob read-secret NAME="shared" 2>/dev/null)
    assert_eq "shared secret" "$bob_read" "bob should read the shared secret" || ok=false
  fi

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 7. Revoke access removes key file
# ---------------------------------------------------------------------------
test_revoke_removes_key() {
  begin_test "revoke access removes key file"
  setup_test_env
  local ok=true

  run_make add-user NAME="alice" KEY="$TEST_TMPDIR/alice.pub" >/dev/null 2>&1
  run_make add-user NAME="bob" KEY="$TEST_TMPDIR/bob.pub" >/dev/null 2>&1
  echo "data" > "$TEST_TMPDIR/d.txt"
  run_as alice create-secret NAME="revtest" FILE="$TEST_TMPDIR/d.txt" >/dev/null 2>&1
  run_as alice grant-access NAME="revtest" USER="bob" >/dev/null 2>&1

  assert_file_exists "$TEST_STORE_DIR/secrets/revtest/bob.key.enc" || ok=false

  run_make revoke-access NAME="revtest" USER="bob" >/dev/null 2>&1 || { fail_test "revoke-access failed"; ok=false; }
  assert_file_not_exists "$TEST_STORE_DIR/secrets/revtest/bob.key.enc" || ok=false

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 8. After revoke, user cannot read
# ---------------------------------------------------------------------------
test_revoke_denies_read() {
  begin_test "after revoke, user cannot read"
  setup_test_env
  local ok=true

  run_make add-user NAME="alice" KEY="$TEST_TMPDIR/alice.pub" >/dev/null 2>&1
  run_make add-user NAME="bob" KEY="$TEST_TMPDIR/bob.pub" >/dev/null 2>&1
  echo "restricted" > "$TEST_TMPDIR/r.txt"
  run_as alice create-secret NAME="restricted" FILE="$TEST_TMPDIR/r.txt" >/dev/null 2>&1
  run_as alice grant-access NAME="restricted" USER="bob" >/dev/null 2>&1
  run_make revoke-access NAME="restricted" USER="bob" >/dev/null 2>&1

  local exit_code=0
  run_as bob read-secret NAME="restricted" >/dev/null 2>&1 || exit_code=$?
  assert_ne "0" "$exit_code" "read after revoke should fail" || ok=false

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 9. List secrets shows entries with counts
# ---------------------------------------------------------------------------
test_list_secrets() {
  begin_test "list-secrets shows entries with user counts"
  setup_test_env
  local ok=true

  run_make add-user NAME="alice" KEY="$TEST_TMPDIR/alice.pub" >/dev/null 2>&1
  run_make add-user NAME="bob" KEY="$TEST_TMPDIR/bob.pub" >/dev/null 2>&1
  echo "a" > "$TEST_TMPDIR/a.txt"
  echo "b" > "$TEST_TMPDIR/b.txt"
  run_as alice create-secret NAME="alpha" FILE="$TEST_TMPDIR/a.txt" >/dev/null 2>&1
  run_as alice create-secret NAME="beta" FILE="$TEST_TMPDIR/b.txt" >/dev/null 2>&1
  run_as alice grant-access NAME="alpha" USER="bob" >/dev/null 2>&1

  local output
  output=$(run_make list-secrets 2>/dev/null)
  assert_output_contains "alpha" "$output" "should list alpha" || ok=false
  assert_output_contains "beta" "$output" "should list beta" || ok=false
  assert_output_contains "2 users" "$output" "alpha should show 2 users" || ok=false
  assert_output_contains "1 users" "$output" "beta should show 1 user" || ok=false

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 10. List users shows registered users
# ---------------------------------------------------------------------------
test_list_users() {
  begin_test "list-users shows registered users"
  setup_test_env
  local ok=true

  run_make add-user NAME="alice" KEY="$TEST_TMPDIR/alice.pub" >/dev/null 2>&1
  run_make add-user NAME="bob" KEY="$TEST_TMPDIR/bob.pub" >/dev/null 2>&1

  local output
  output=$(run_make list-users 2>/dev/null)
  assert_output_contains "alice" "$output" || ok=false
  assert_output_contains "bob" "$output" || ok=false

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 11. Delete secret removes directory
# ---------------------------------------------------------------------------
test_delete_secret() {
  begin_test "delete-secret removes directory"
  setup_test_env
  local ok=true

  run_make add-user NAME="alice" KEY="$TEST_TMPDIR/alice.pub" >/dev/null 2>&1
  echo "delete me" > "$TEST_TMPDIR/del.txt"
  run_as alice create-secret NAME="todelete" FILE="$TEST_TMPDIR/del.txt" >/dev/null 2>&1
  assert_dir_exists "$TEST_STORE_DIR/secrets/todelete" || ok=false

  run_make delete-secret NAME="todelete" >/dev/null 2>&1 || { fail_test "delete-secret failed"; ok=false; }
  assert_dir_not_exists "$TEST_STORE_DIR/secrets/todelete" || ok=false

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 12. Path traversal in NAME rejected
# ---------------------------------------------------------------------------
test_path_traversal_rejected() {
  begin_test "path traversal in NAME rejected"
  setup_test_env
  local ok=true

  run_make add-user NAME="alice" KEY="$TEST_TMPDIR/alice.pub" >/dev/null 2>&1
  echo "evil" > "$TEST_TMPDIR/evil.txt"

  local exit_code=0
  run_as alice create-secret NAME="../evil" FILE="$TEST_TMPDIR/evil.txt" >/dev/null 2>&1 || exit_code=$?
  assert_ne "0" "$exit_code" "path traversal (../) should be rejected" || ok=false

  exit_code=0
  run_as alice create-secret NAME="/absolute/path" FILE="$TEST_TMPDIR/evil.txt" >/dev/null 2>&1 || exit_code=$?
  assert_ne "0" "$exit_code" "absolute path (/) should be rejected" || ok=false

  exit_code=0
  run_as alice create-secret NAME="../../escape" FILE="$TEST_TMPDIR/evil.txt" >/dev/null 2>&1 || exit_code=$?
  assert_ne "0" "$exit_code" "multi-level path traversal should be rejected" || ok=false

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 13. Missing parameters rejected
# ---------------------------------------------------------------------------
test_missing_params_rejected() {
  begin_test "missing parameters rejected"
  setup_test_env
  local ok=true

  local exit_code=0
  run_make create-secret NAME="" FILE="/dev/null" >/dev/null 2>&1 || exit_code=$?
  assert_ne "0" "$exit_code" "empty NAME should fail" || ok=false

  exit_code=0
  run_make create-secret FILE="/dev/null" >/dev/null 2>&1 || exit_code=$?
  assert_ne "0" "$exit_code" "missing NAME should fail" || ok=false

  exit_code=0
  run_make add-user NAME="" KEY="/dev/null" >/dev/null 2>&1 || exit_code=$?
  assert_ne "0" "$exit_code" "add-user with empty NAME should fail" || ok=false

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 14. Read nonexistent secret fails
# ---------------------------------------------------------------------------
test_read_nonexistent_fails() {
  begin_test "read nonexistent secret fails"
  setup_test_env
  local ok=true

  run_make add-user NAME="alice" KEY="$TEST_TMPDIR/alice.pub" >/dev/null 2>&1

  local exit_code=0
  run_as alice read-secret NAME="ghost" >/dev/null 2>&1 || exit_code=$?
  assert_ne "0" "$exit_code" "reading nonexistent secret should fail" || ok=false

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 15. Grant from user without access fails
# ---------------------------------------------------------------------------
test_grant_without_access_fails() {
  begin_test "grant from user without access fails"
  setup_test_env
  local ok=true

  run_make add-user NAME="alice" KEY="$TEST_TMPDIR/alice.pub" >/dev/null 2>&1
  run_make add-user NAME="bob" KEY="$TEST_TMPDIR/bob.pub" >/dev/null 2>&1
  run_make add-user NAME="carol" KEY="$TEST_TMPDIR/carol.pub" >/dev/null 2>&1
  echo "data" > "$TEST_TMPDIR/x.txt"
  run_as alice create-secret NAME="exclusive" FILE="$TEST_TMPDIR/x.txt" >/dev/null 2>&1

  local exit_code=0
  run_as bob grant-access NAME="exclusive" USER="carol" >/dev/null 2>&1 || exit_code=$?
  assert_ne "0" "$exit_code" "bob (no access) should not be able to grant to carol" || ok=false

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 16. Empty store — list returns empty, no errors
# ---------------------------------------------------------------------------
test_empty_store_lists() {
  begin_test "empty store - list returns empty, no errors"
  setup_test_env
  local ok=true

  local secrets_out
  secrets_out=$(run_make list-secrets 2>/dev/null)
  assert_output_contains "No secrets found" "$secrets_out" "empty secrets list should say 'No secrets found'" || ok=false

  local users_out
  users_out=$(run_make list-users 2>/dev/null)
  assert_output_contains "No users found" "$users_out" "empty users list should say 'No users found'" || ok=false

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 17. check-deps validates tools
# ---------------------------------------------------------------------------
test_check_deps() {
  begin_test "check-deps validates tools and reports status"
  setup_test_env
  local ok=true

  local output
  output=$(run_make check-deps 2>&1) || true
  assert_output_contains "GPG" "$output" "check-deps should report GPG status" || ok=false
  assert_output_contains "OpenSSL" "$output" "check-deps should report OpenSSL status" || ok=false

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 18. Delete nonexistent secret fails
# ---------------------------------------------------------------------------
test_delete_nonexistent_fails() {
  begin_test "delete nonexistent secret fails"
  setup_test_env
  local ok=true

  local exit_code=0
  run_make delete-secret NAME="nope" >/dev/null 2>&1 || exit_code=$?
  assert_ne "0" "$exit_code" "deleting nonexistent secret should fail" || ok=false

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 19. Revoke from user without access fails
# ---------------------------------------------------------------------------
test_revoke_nonexistent_access_fails() {
  begin_test "revoke from user without access fails"
  setup_test_env
  local ok=true

  run_make add-user NAME="alice" KEY="$TEST_TMPDIR/alice.pub" >/dev/null 2>&1
  echo "data" > "$TEST_TMPDIR/z.txt"
  run_as alice create-secret NAME="onlyalice" FILE="$TEST_TMPDIR/z.txt" >/dev/null 2>&1

  local exit_code=0
  run_make revoke-access NAME="onlyalice" USER="bob" >/dev/null 2>&1 || exit_code=$?
  assert_ne "0" "$exit_code" "revoking access from user who has none should fail" || ok=false

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 20. Grant to already-granted user fails
# ---------------------------------------------------------------------------
test_grant_duplicate_fails() {
  begin_test "grant to already-granted user fails"
  setup_test_env
  local ok=true

  run_make add-user NAME="alice" KEY="$TEST_TMPDIR/alice.pub" >/dev/null 2>&1
  run_make add-user NAME="bob" KEY="$TEST_TMPDIR/bob.pub" >/dev/null 2>&1
  echo "data" > "$TEST_TMPDIR/g.txt"
  run_as alice create-secret NAME="granted" FILE="$TEST_TMPDIR/g.txt" >/dev/null 2>&1
  run_as alice grant-access NAME="granted" USER="bob" >/dev/null 2>&1

  local exit_code=0
  run_as alice grant-access NAME="granted" USER="bob" >/dev/null 2>&1 || exit_code=$?
  assert_ne "0" "$exit_code" "granting access twice should fail" || ok=false

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 21. Update secret changes content (text)
# ---------------------------------------------------------------------------
test_update_secret_text() {
  begin_test "update-secret changes content (text)"
  setup_test_env
  local ok=true

  run_make add-user NAME="alice" KEY="$TEST_TMPDIR/alice.pub" >/dev/null 2>&1
  echo "original value" > "$TEST_TMPDIR/v1.txt"
  run_as alice create-secret NAME="updatable" FILE="$TEST_TMPDIR/v1.txt" >/dev/null 2>&1

  echo "updated value" > "$TEST_TMPDIR/v2.txt"
  run_as alice update-secret NAME="updatable" FILE="$TEST_TMPDIR/v2.txt" >/dev/null 2>&1 || { fail_test "update-secret failed"; ok=false; }

  if $ok; then
    local recovered
    recovered=$(run_as alice read-secret NAME="updatable" 2>/dev/null)
    assert_eq "updated value" "$recovered" "decrypted text should match updated content" || ok=false
  fi

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 22. Update secret preserves access for other users
# ---------------------------------------------------------------------------
test_update_secret_preserves_access() {
  begin_test "update-secret preserves access for other users"
  setup_test_env
  local ok=true

  run_make add-user NAME="alice" KEY="$TEST_TMPDIR/alice.pub" >/dev/null 2>&1
  run_make add-user NAME="bob" KEY="$TEST_TMPDIR/bob.pub" >/dev/null 2>&1
  echo "v1" > "$TEST_TMPDIR/v1.txt"
  run_as alice create-secret NAME="shared" FILE="$TEST_TMPDIR/v1.txt" >/dev/null 2>&1
  run_as alice grant-access NAME="shared" USER="bob" >/dev/null 2>&1

  echo "v2" > "$TEST_TMPDIR/v2.txt"
  run_as alice update-secret NAME="shared" FILE="$TEST_TMPDIR/v2.txt" >/dev/null 2>&1 || { fail_test "update-secret failed"; ok=false; }

  if $ok; then
    local bob_read
    bob_read=$(run_as bob read-secret NAME="shared" 2>/dev/null)
    assert_eq "v2" "$bob_read" "bob should read the updated secret" || ok=false
  fi

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 23. Update secret works with binary content
# ---------------------------------------------------------------------------
test_update_secret_binary() {
  begin_test "update-secret works with binary content"
  setup_test_env
  local ok=true

  run_make add-user NAME="alice" KEY="$TEST_TMPDIR/alice.pub" >/dev/null 2>&1
  dd if=/dev/urandom of="$TEST_TMPDIR/bin1.dat" bs=1024 count=5 2>/dev/null
  run_as alice create-secret NAME="binup" FILE="$TEST_TMPDIR/bin1.dat" >/dev/null 2>&1

  dd if=/dev/urandom of="$TEST_TMPDIR/bin2.dat" bs=1024 count=8 2>/dev/null
  local expected_sha
  expected_sha=$(shasum -a 256 "$TEST_TMPDIR/bin2.dat" | awk '{print $1}')

  run_as alice update-secret NAME="binup" FILE="$TEST_TMPDIR/bin2.dat" >/dev/null 2>&1 || { fail_test "update-secret failed"; ok=false; }

  if $ok; then
    run_as alice read-secret NAME="binup" 2>/dev/null > "$TEST_TMPDIR/recovered.dat"
    local actual_sha
    actual_sha=$(shasum -a 256 "$TEST_TMPDIR/recovered.dat" | awk '{print $1}')
    assert_eq "$expected_sha" "$actual_sha" "SHA-256 of updated binary should match" || ok=false
  fi

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 24. Update nonexistent secret fails
# ---------------------------------------------------------------------------
test_update_nonexistent_fails() {
  begin_test "update nonexistent secret fails"
  setup_test_env
  local ok=true

  run_make add-user NAME="alice" KEY="$TEST_TMPDIR/alice.pub" >/dev/null 2>&1
  echo "data" > "$TEST_TMPDIR/data.txt"

  local exit_code=0
  run_as alice update-secret NAME="ghost" FILE="$TEST_TMPDIR/data.txt" >/dev/null 2>&1 || exit_code=$?
  assert_ne "0" "$exit_code" "updating nonexistent secret should fail" || ok=false

  $ok && pass_test
  teardown_test_env
}

# ---------------------------------------------------------------------------
# 25. Update secret without access fails
# ---------------------------------------------------------------------------
test_update_without_access_fails() {
  begin_test "update secret without access fails"
  setup_test_env
  local ok=true

  run_make add-user NAME="alice" KEY="$TEST_TMPDIR/alice.pub" >/dev/null 2>&1
  run_make add-user NAME="bob" KEY="$TEST_TMPDIR/bob.pub" >/dev/null 2>&1
  echo "original" > "$TEST_TMPDIR/orig.txt"
  run_as alice create-secret NAME="restricted" FILE="$TEST_TMPDIR/orig.txt" >/dev/null 2>&1

  echo "hacked" > "$TEST_TMPDIR/hack.txt"
  local exit_code=0
  run_as bob update-secret NAME="restricted" FILE="$TEST_TMPDIR/hack.txt" >/dev/null 2>&1 || exit_code=$?
  assert_ne "0" "$exit_code" "user without access should not be able to update" || ok=false

  # Verify original content is unchanged
  if $ok; then
    local recovered
    recovered=$(run_as alice read-secret NAME="restricted" 2>/dev/null)
    assert_eq "original" "$recovered" "original content should be unchanged after failed update" || ok=false
  fi

  $ok && pass_test
  teardown_test_env
}

# ===========================================================================
# Run all tests
# ===========================================================================
echo ""
echo "${BOLD}Trove Integration Test Suite${RESET}"
echo "${BOLD}========================================${RESET}"
echo ""

test_init_creates_structure
test_add_user
test_create_read_text
test_create_read_binary
test_create_duplicate_fails
test_grant_access
test_revoke_removes_key
test_revoke_denies_read
test_list_secrets
test_list_users
test_delete_secret
test_path_traversal_rejected
test_missing_params_rejected
test_read_nonexistent_fails
test_grant_without_access_fails
test_empty_store_lists
test_check_deps
test_delete_nonexistent_fails
test_revoke_nonexistent_access_fails
test_grant_duplicate_fails
test_update_secret_text
test_update_secret_preserves_access
test_update_secret_binary
test_update_nonexistent_fails
test_update_without_access_fails

print_summary

[[ $TESTS_FAILED -eq 0 ]]
