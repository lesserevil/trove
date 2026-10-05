#!/usr/bin/env bash
# tests/helpers.sh — Test helper functions for Trove integration tests
# Provides isolated GPG environments, assertions, and cleanup utilities.
set -euo pipefail

# ---------------------------------------------------------------------------
# Globals (set by setup_test_env, read by tests and teardown)
# ---------------------------------------------------------------------------
TEST_TMPDIR=""
TEST_GNUPGHOME=""
TEST_STORE_DIR=""
TEST_FAKE_HOME=""
TROVE_ROOT=""
REAL_HOME=""

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_RUN=0
CURRENT_TEST=""

# ---------------------------------------------------------------------------
# Colors (disabled if not a tty)
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
  GREEN=$'\033[0;32m'
  RED=$'\033[0;31m'
  YELLOW=$'\033[0;33m'
  BOLD=$'\033[1m'
  RESET=$'\033[0m'
else
  GREEN="" RED="" YELLOW="" BOLD="" RESET=""
fi

# ---------------------------------------------------------------------------
# Setup / Teardown
# ---------------------------------------------------------------------------

setup_test_env() {
  TROVE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  REAL_HOME="$HOME"

  TEST_TMPDIR="$(mktemp -d)"
  TEST_STORE_DIR="$(mktemp -d)"
  TEST_FAKE_HOME="$(mktemp -d)"

  # Place the test GPG keyring directly inside TEST_FAKE_HOME/.gnupg (not a symlink).
  # GPG refuses to use a symlinked homedir, so read-secret (which calls gpg with
  # `unset GNUPGHOME; HOME=$TEST_FAKE_HOME`) must find a real directory here.
  TEST_GNUPGHOME="$TEST_FAKE_HOME/.gnupg"
  mkdir -p "$TEST_GNUPGHOME"
  chmod 700 "$TEST_GNUPGHOME"

  run_make init >/dev/null 2>&1

  local users=("alice@test.local" "bob@test.local" "carol@test.local")
  for user_email in "${users[@]}"; do
    local name="${user_email%%@*}"
    gpg --batch --yes --homedir "$TEST_GNUPGHOME" --pinentry-mode loopback --passphrase "" \
      --quick-generate-key "$user_email" default default never 2>/dev/null

    gpg --batch --yes --homedir "$TEST_GNUPGHOME" --armor \
      --export "$user_email" > "$TEST_TMPDIR/${name}.pub"
  done
}

teardown_test_env() {
  [[ -n "$TEST_TMPDIR" && -d "$TEST_TMPDIR" ]] && rm -rf "$TEST_TMPDIR"
  [[ -n "$TEST_GNUPGHOME" && -d "$TEST_GNUPGHOME" ]] && rm -rf "$TEST_GNUPGHOME"
  [[ -n "$TEST_STORE_DIR" && -d "$TEST_STORE_DIR" ]] && rm -rf "$TEST_STORE_DIR"
  [[ -n "$TEST_FAKE_HOME" && -d "$TEST_FAKE_HOME" ]] && rm -rf "$TEST_FAKE_HOME"

  TEST_TMPDIR=""
  TEST_GNUPGHOME=""
  TEST_STORE_DIR=""
  TEST_FAKE_HOME=""
}

# ---------------------------------------------------------------------------
# Test Runner Helpers
# ---------------------------------------------------------------------------

begin_test() {
  CURRENT_TEST="$1"
  TESTS_RUN=$((TESTS_RUN + 1))
}

pass_test() {
  TESTS_PASSED=$((TESTS_PASSED + 1))
  echo "  ${GREEN}PASS${RESET}: $CURRENT_TEST"
}

fail_test() {
  local msg="${1:-}"
  TESTS_FAILED=$((TESTS_FAILED + 1))
  echo "  ${RED}FAIL${RESET}: $CURRENT_TEST"
  [[ -n "$msg" ]] && echo "        $msg"
}

print_summary() {
  echo ""
  echo "${BOLD}========================================${RESET}"
  echo "${BOLD} Test Summary${RESET}"
  echo "${BOLD}========================================${RESET}"
  echo " Total:  $TESTS_RUN"
  echo " ${GREEN}Passed: $TESTS_PASSED${RESET}"
  if [[ $TESTS_FAILED -gt 0 ]]; then
    echo " ${RED}Failed: $TESTS_FAILED${RESET}"
  else
    echo " Failed: 0"
  fi
  echo "${BOLD}========================================${RESET}"
  echo ""
  echo "$TESTS_PASSED passed, $TESTS_FAILED failed"
}

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

assert_eq() {
  local expected="$1"
  local actual="$2"
  local msg="${3:-expected '$expected', got '$actual'}"
  if [[ "$expected" = "$actual" ]]; then
    return 0
  else
    fail_test "$msg"
    return 1
  fi
}

assert_ne() {
  local unexpected="$1"
  local actual="$2"
  local msg="${3:-expected NOT '$unexpected', but got it}"
  if [[ "$unexpected" != "$actual" ]]; then
    return 0
  else
    fail_test "$msg"
    return 1
  fi
}

assert_file_exists() {
  local filepath="$1"
  local msg="${2:-file should exist: $filepath}"
  if [[ -f "$filepath" ]]; then
    return 0
  else
    fail_test "$msg"
    return 1
  fi
}

assert_file_not_exists() {
  local filepath="$1"
  local msg="${2:-file should NOT exist: $filepath}"
  if [[ ! -f "$filepath" ]]; then
    return 0
  else
    fail_test "$msg"
    return 1
  fi
}

assert_dir_exists() {
  local dirpath="$1"
  local msg="${2:-directory should exist: $dirpath}"
  if [[ -d "$dirpath" ]]; then
    return 0
  else
    fail_test "$msg"
    return 1
  fi
}

assert_dir_not_exists() {
  local dirpath="$1"
  local msg="${2:-directory should NOT exist: $dirpath}"
  if [[ ! -d "$dirpath" ]]; then
    return 0
  else
    fail_test "$msg"
    return 1
  fi
}

assert_exit_code() {
  local expected_code="$1"
  shift
  local actual_code=0
  "$@" >/dev/null 2>&1 || actual_code=$?
  if [[ "$expected_code" -eq "$actual_code" ]]; then
    return 0
  else
    fail_test "expected exit code $expected_code, got $actual_code (cmd: $*)"
    return 1
  fi
}

assert_output_contains() {
  local expected="$1"
  local actual="$2"
  local msg="${3:-output should contain '$expected'}"
  if echo "$actual" | grep -qF "$expected"; then
    return 0
  else
    fail_test "$msg"
    return 1
  fi
}

assert_output_not_contains() {
  local unexpected="$1"
  local actual="$2"
  local msg="${3:-output should NOT contain '$unexpected'}"
  if ! echo "$actual" | grep -qF "$unexpected"; then
    return 0
  else
    fail_test "$msg"
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Make Runner — runs a make target against the isolated test store
# ---------------------------------------------------------------------------

run_make() {
  make --no-print-directory -C "$TROVE_ROOT" "$@" \
    STORE_DIR="$TEST_STORE_DIR" \
    GNUPGHOME="$TEST_STORE_DIR/.gnupg"
}

run_as() {
  local user="$1"
  shift
  make --no-print-directory -C "$TROVE_ROOT" "$@" \
    STORE_DIR="$TEST_STORE_DIR" \
    GNUPGHOME="$TEST_STORE_DIR/.gnupg" \
    PERSONAL_GNUPGHOME="$TEST_GNUPGHOME" \
    PM_USER="$user"
}
