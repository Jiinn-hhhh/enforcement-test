#!/usr/bin/env bash
# Enforces: F-01, F-02, F-03, F-04
set -euo pipefail

INPUT=$(cat)

TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name' 2>/dev/null) || {
  echo "BLOCKED: Hook parse error (jq failed). Denying by default. [FAIL-SAFE]" >&2
  exit 2
}

# Only act on Bash
if [[ "$TOOL_NAME" != "Bash" ]]; then
  exit 0
fi

COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command')

# Only activate if command starts with git commit
if ! echo "$COMMAND" | grep -qE '^\s*git\s+commit\b'; then
  exit 0
fi

# Extract commit message from -m flag (handles both single and double quotes)
# Try double-quoted message first, then single-quoted
COMMIT_MSG=""
if echo "$COMMAND" | grep -qE '\-m\s+"'; then
  COMMIT_MSG=$(echo "$COMMAND" | sed -n 's/.*-m[[:space:]]*"\([^"]*\)".*/\1/p')
elif echo "$COMMAND" | grep -qE "\-m\s+'"; then
  COMMIT_MSG=$(echo "$COMMAND" | sed -n "s/.*-m[[:space:]]*'\([^']*\)'.*/\1/p")
fi

# Handle --file / -F: extract file path and read its content for validation
if [[ -z "$COMMIT_MSG" ]]; then
  MSG_FILE=""
  if echo "$COMMAND" | grep -qE '\-\-file\s+'; then
    MSG_FILE=$(echo "$COMMAND" | sed -n 's/.*--file[[:space:]]*\([^[:space:]]*\).*/\1/p')
  elif echo "$COMMAND" | grep -qE '\-F\s+'; then
    MSG_FILE=$(echo "$COMMAND" | sed -n 's/.*-F[[:space:]]*\([^[:space:]]*\).*/\1/p')
  fi
  if [[ -n "$MSG_FILE" && -f "$MSG_FILE" ]]; then
    COMMIT_MSG=$(cat "$MSG_FILE" 2>/dev/null || true)
  fi
fi

# If still no message (heredoc, interactive, or multiline that sed couldn't parse),
# do a raw-command fallback check for obvious violations before allowing through.
# Pre-commit commitizen hook and CI enforcement-check are the backstops for edge cases.
if [[ -z "$COMMIT_MSG" ]]; then
  # Fallback: check raw command for forbidden patterns (defense-in-depth)
  if echo "$COMMAND" | grep -qiE 'co-authored-by:'; then
    echo "BLOCKED: Commit message must not contain 'Co-Authored-By:' attribution. Disclose AI use with '(w/ Claude)' in the message instead. [F-03]" >&2
    exit 2
  fi
  if echo "$COMMAND" | grep -qiE '(Generated with Claude|Generated with \[Claude)'; then
    echo "BLOCKED: Commit message must not contain 'Generated with Claude' boilerplate. Disclose AI use with '(w/ Claude)' in the subject line instead. [F-03]" >&2
    exit 2
  fi
  exit 0
fi

# F-01: Must start with a valid conventional commit prefix
VALID_PREFIXES="^(feat|fix|docs|refactor|test|chore|style|perf|ci|build|revert)(\([^)]+\))?!?:"
if ! echo "$COMMIT_MSG" | grep -qE "$VALID_PREFIXES"; then
  echo "BLOCKED: Commit message must start with a valid prefix (feat:, fix:, docs:, refactor:, test:, chore:, style:, perf:, ci:, build:, revert:). [F-01]" >&2
  exit 2
fi

# F-03: Must NOT contain "Co-Authored-By:" (AI attribution hidden in co-author)
if echo "$COMMIT_MSG" | grep -qiE 'co-authored-by:'; then
  echo "BLOCKED: Commit message must not contain 'Co-Authored-By:' attribution. Disclose AI use with '(w/ Claude)' in the message instead. [F-03]" >&2
  exit 2
fi

# F-03: Must NOT contain AI-generation boilerplate strings
if echo "$COMMIT_MSG" | grep -qiE '(Generated with Claude|Generated with \[Claude)'; then
  echo "BLOCKED: Commit message must not contain 'Generated with Claude' boilerplate. Disclose AI use with '(w/ Claude)' in the subject line instead. [F-03]" >&2
  exit 2
fi

# F-02: Should contain "(w/ Claude)" — warn but do not block
if ! echo "$COMMIT_MSG" | grep -qF '(w/ Claude)'; then
  echo "WARNING: Commit message does not contain '(w/ Claude)'. AI-assisted commits should disclose this per policy F-02." >&2
  # exit 0 — this is a warning, not a block
fi

exit 0
