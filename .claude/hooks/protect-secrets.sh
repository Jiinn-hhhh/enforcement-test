#!/usr/bin/env bash
# Enforces: S-01, S-02, S-03, S-06
set -euo pipefail

INPUT=$(cat)

# Fail-safe: if jq is missing or input is malformed, deny by default
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name' 2>/dev/null) || {
  echo "BLOCKED: Hook parse error (jq failed). Denying by default. [FAIL-SAFE]" >&2
  exit 2
}
if [[ -z "$TOOL_NAME" || "$TOOL_NAME" == "null" ]]; then
  echo "BLOCKED: Hook could not determine tool name. Denying by default. [FAIL-SAFE]" >&2
  exit 2
fi

# Handle Read, Write, Edit, MultiEdit (file_path check) and Bash (command check)
case "$TOOL_NAME" in
  Read|Write|Edit|MultiEdit) ;;
  Bash)
    # For Bash, check if the command references sensitive files
    COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command')
    COMMAND_LOWER=$(echo "$COMMAND" | tr '[:upper:]' '[:lower:]')

    # ── Phase 1: Broad .env reference detection (catches indirect access) ──
    # Matches: .env, .env.prod, .env.local, '.env.prod', ".env.prod"
    # Does NOT match: environment, .envrc, event, dotenv (no leading dot)
    # No whitelist gating — compound commands like "pip install x && cat .env" are caught
    if echo "$COMMAND_LOWER" | grep -qE '\.env(\s|$|\.|'"'"'|"|/)'; then
      echo "BLOCKED: Command references .env file. Use proper configuration management. [S-01]" >&2
      exit 2
    fi

    # ── Phase 2: Broad secrets/key/pem reference detection ──
    # secrets/ directory reference anywhere in command
    if echo "$COMMAND_LOWER" | grep -qE '(^|[[:space:];|&(])([^[:space:]]*secrets/|[^[:space:]]*\.pem\b|[^[:space:]]*\.key\b)'; then
      echo "BLOCKED: Command references sensitive file (secrets/key/pem). [S-02]" >&2
      exit 2
    fi
    # Simpler fallback: any mention of /secrets/ path segment
    if echo "$COMMAND_LOWER" | grep -qE '/secrets/'; then
      echo "BLOCKED: Command references secrets directory. [S-02]" >&2
      exit 2
    fi

    # ── Phase 3: Language runtime + sensitive file pattern detection ──
    # Catches: python3 -c "open('.env.prod')", node -e "fs.readFileSync('secrets/x')", etc.
    if echo "$COMMAND_LOWER" | grep -qE '(python3?|node|ruby|perl|php)\s+(-c|-e)\s'; then
      if echo "$COMMAND_LOWER" | grep -qE '(\.env|secrets|\.key|\.pem|\.secret|password|credential)'; then
        echo "BLOCKED: Scripting language with inline code references sensitive file. [S-01/S-02]" >&2
        exit 2
      fi
    fi

    # ── Phase 4: Legacy verb-specific checks (kept for defense-in-depth) ──
    # Check for commands that read/copy/output sensitive files
    if echo "$COMMAND_LOWER" | grep -qE '(cat|head|tail|less|more|source|grep|rg|awk|sed|\.)\s+[^\s]*\.env'; then
      echo "BLOCKED: Bash command reads .env file. Use proper configuration management. [S-01]" >&2
      exit 2
    fi
    # cp/mv with .env as SOURCE
    if echo "$COMMAND_LOWER" | grep -qE '(cp|mv)\s+[^\s]*\.env'; then
      echo "BLOCKED: Bash command copies/moves .env file. [S-01]" >&2
      exit 2
    fi
    if echo "$COMMAND_LOWER" | grep -qE '(cat|head|tail|less|more|cp|mv|grep|rg|awk|sed)\s+[^\s]*(\.pem|\.key|/secrets/)'; then
      echo "BLOCKED: Bash command accesses sensitive file (key/secret). [S-02]" >&2
      exit 2
    fi
    # find with -exec targeting sensitive paths
    if echo "$COMMAND_LOWER" | grep -qE 'find\s.*\.(env|pem|key)' ; then
      echo "BLOCKED: Bash find command targets sensitive file patterns. [S-01/S-02]" >&2
      exit 2
    fi
    # Encoding tools that could exfiltrate sensitive files
    if echo "$COMMAND_LOWER" | grep -qE '(base64|xxd|od|strings|hexdump)\s+[^\s]*(\.env|/secrets/|\.key|\.pem)'; then
      echo "BLOCKED: Encoding/dump command targets sensitive file. [S-01/S-02]" >&2
      exit 2
    fi
    exit 0
    ;;
  *) exit 0 ;;
esac

FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path')

# Normalize to lowercase for case-insensitive matching
FILE_PATH_LOWER=$(echo "$FILE_PATH" | tr '[:upper:]' '[:lower:]')

# Pattern matching against sensitive file patterns
block() {
  echo "BLOCKED: Access to sensitive file '${FILE_PATH}' is prohibited. [S-01/S-02]" >&2
  exit 2
}

# .env files — matches .env, .env.local, .env.prod, .env.staging etc.
# Does NOT match environment.py, events/, etc.
BASENAME=$(basename "$FILE_PATH_LOWER")
if echo "$BASENAME" | grep -qE '^\.env($|\.)'; then
  block
fi

# *.pem
if echo "$FILE_PATH_LOWER" | grep -qE '\.pem$'; then
  block
fi

# *.key
if echo "$FILE_PATH_LOWER" | grep -qE '\.key$'; then
  block
fi

# *secrets/* — any path segment named "secrets"
if echo "$FILE_PATH_LOWER" | grep -qE '(^|/)secrets/'; then
  block
fi

# *.secret* — any file containing "secret" in the name/extension
if echo "$FILE_PATH_LOWER" | grep -qE '(^|\.|/)[^/]*secret[^/]*$'; then
  block
fi

exit 0
