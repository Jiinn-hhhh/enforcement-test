#!/usr/bin/env bash
# Enforces: B-01, B-02, B-03, B-04, E-01, E-02
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

block() {
  local branch="${1:-unknown}"
  echo "BLOCKED: Direct push/commit to protected branch '${branch}' is prohibited. Use PR workflow. [B-01/B-02]" >&2
  exit 2
}

# Check for any force push flag regardless of branch
if echo "$COMMAND" | grep -qE 'git\s+push\b' && echo "$COMMAND" | grep -qE '(\s--force\b|\s-f\b|\s--force-with-lease\b)'; then
  block "protected (force push)"
fi

# Check for direct push to protected remote branches
# Matches patterns like: git push origin prod, git push origin/prod, git push origin stg, git push --set-upstream origin main, etc.
PROTECTED_BRANCHES="prod|stg|staging|main"

if echo "$COMMAND" | grep -qE 'git\s+push\b'; then
  # Extract all words after 'git push' and check if any match a protected branch
  # Match: git push <remote> <branch>, git push <remote> <local>:<remote>, HEAD:<branch>
  if echo "$COMMAND" | grep -qE "git\s+push\b[^|;]*\s(origin\s+)?(${PROTECTED_BRANCHES})\b"; then
    MATCHED_BRANCH=$(echo "$COMMAND" | grep -oE "(${PROTECTED_BRANCHES})" | head -1)
    block "$MATCHED_BRANCH"
  fi

  # Match HEAD:branch syntax
  if echo "$COMMAND" | grep -qE "HEAD:(${PROTECTED_BRANCHES})\b"; then
    MATCHED_BRANCH=$(echo "$COMMAND" | grep -oE "HEAD:(${PROTECTED_BRANCHES})" | grep -oE "(${PROTECTED_BRANCHES})" | head -1)
    block "$MATCHED_BRANCH"
  fi

  # Match refs/heads/branch syntax
  if echo "$COMMAND" | grep -qE "refs/heads/(${PROTECTED_BRANCHES})\b"; then
    MATCHED_BRANCH=$(echo "$COMMAND" | grep -oE "refs/heads/(${PROTECTED_BRANCHES})" | grep -oE "(${PROTECTED_BRANCHES})" | head -1)
    block "$MATCHED_BRANCH"
  fi
fi

# Check for git commit while on a protected branch
if echo "$COMMAND" | grep -qE 'git\s+commit\b'; then
  # Attempt to get current branch; if git is not available or not in a repo, skip
  CURRENT_BRANCH=""
  if CURRENT_BRANCH=$(git branch --show-current 2>/dev/null); then
    if echo "$CURRENT_BRANCH" | grep -qE "^(${PROTECTED_BRANCHES})$"; then
      block "$CURRENT_BRANCH"
    fi
  fi
fi

exit 0
