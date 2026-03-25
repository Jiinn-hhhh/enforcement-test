#!/usr/bin/env bash
# Enforces: I-01, I-02, I-03, E-03, E-05
set -euo pipefail

INPUT=$(cat)

TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name' 2>/dev/null) || {
  echo "BLOCKED: Hook parse error (jq failed). Denying by default. [FAIL-SAFE]" >&2
  exit 2
}

block_file() {
  local path="$1"
  echo "BLOCKED: Modification of infrastructure file '${path}' is prohibited. [I-02/I-03]" >&2
  exit 2
}

block_cmd() {
  local reason="$1"
  echo "BLOCKED: Dangerous infrastructure command detected — ${reason}. [E-03/E-05]" >&2
  exit 2
}

# --- Write / Edit: check file paths ---
if [[ "$TOOL_NAME" == "Write" || "$TOOL_NAME" == "Edit" || "$TOOL_NAME" == "MultiEdit" ]]; then
  FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path')
  FILE_PATH_NORM=$(echo "$FILE_PATH" | sed 's|^\./||')  # strip leading ./

  # .github/workflows/* and .github/actions/*
  if echo "$FILE_PATH_NORM" | grep -qE '(^|/).github/(workflows|actions)/'; then
    block_file "$FILE_PATH"
  fi

  # deploy/*
  if echo "$FILE_PATH_NORM" | grep -qE '(^|/)deploy/'; then
    block_file "$FILE_PATH"
  fi

  # terraform/* or *.tf or *.tfvars
  if echo "$FILE_PATH_NORM" | grep -qE '(^|/)terraform/' || \
     echo "$FILE_PATH_NORM" | grep -qE '\.tf$' || \
     echo "$FILE_PATH_NORM" | grep -qE '\.tfvars$'; then
    block_file "$FILE_PATH"
  fi

  # docker-compose.yml and docker-compose.*.yml
  if echo "$FILE_PATH_NORM" | grep -qE '(^|/)docker-compose(\.[^/]+)?\.yml$'; then
    block_file "$FILE_PATH"
  fi

  # Dockerfile and Dockerfile.*
  if echo "$FILE_PATH_NORM" | grep -qE '(^|/)Dockerfile(\.[^/]+)?$'; then
    block_file "$FILE_PATH"
  fi

  # .claude/settings.json and .claude/settings.local.json
  if echo "$FILE_PATH_NORM" | grep -qE '(^|/)\.claude/settings(\.local)?\.json$'; then
    block_file "$FILE_PATH"
  fi

  # infra/, k8s/, helm/ directories
  if echo "$FILE_PATH_NORM" | grep -qE '(^|/)(infra|k8s|helm)/'; then
    block_file "$FILE_PATH"
  fi
fi

# --- Bash: check dangerous commands ---
if [[ "$TOOL_NAME" == "Bash" ]]; then
  COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command')

  # terraform apply / destroy / import
  if echo "$COMMAND" | grep -qE '\bterraform\s+(apply|destroy|import)\b'; then
    SUBCMD=$(echo "$COMMAND" | grep -oE 'terraform\s+(apply|destroy|import)' | head -1)
    block_cmd "$SUBCMD"
  fi

  # aws with --profile prod
  if echo "$COMMAND" | grep -qE '\baws\b' && echo "$COMMAND" | grep -qE '\-\-profile\s+prod\b'; then
    block_cmd "aws --profile prod"
  fi

  # gcloud commands
  if echo "$COMMAND" | grep -qE '(^|\s|\||\;)gcloud\s'; then
    block_cmd "gcloud CLI"
  fi

  # az commands (Azure CLI)
  if echo "$COMMAND" | grep -qE '(^|\s|\||\;|\&)az\s'; then
    block_cmd "az (Azure CLI)"
  fi

  # docker push
  if echo "$COMMAND" | grep -qE '\bdocker\s+push\b'; then
    block_cmd "docker push"
  fi

  # kubectl — block all mutating subcommands (allow only get, describe, logs, version)
  if echo "$COMMAND" | grep -qE '\bkubectl\b'; then
    # Allow read-only subcommands
    if ! echo "$COMMAND" | grep -qE '\bkubectl\s+(get|describe|logs|version|cluster-info|api-resources|explain)\b'; then
      SUBCMD=$(echo "$COMMAND" | grep -oE 'kubectl\s+\w+' | head -1)
      block_cmd "$SUBCMD"
    fi
  fi

  # helm install / upgrade
  if echo "$COMMAND" | grep -qE '\bhelm\s+(install|upgrade)\b'; then
    SUBCMD=$(echo "$COMMAND" | grep -oE 'helm\s+(install|upgrade)' | head -1)
    block_cmd "$SUBCMD"
  fi

  # gh workflow run (E-06: prevent triggering deploy workflows)
  if echo "$COMMAND" | grep -qE '\bgh\s+workflow\s+run\b'; then
    block_cmd "gh workflow run"
  fi
fi

exit 0
