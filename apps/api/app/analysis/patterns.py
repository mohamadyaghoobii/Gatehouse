from __future__ import annotations

import re

SECRET_NAME_RE = re.compile(
    r"(?<![a-z0-9])(password|passwd|secret|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token)(?![a-z0-9])",
    re.I,
)
GENERIC_TOKEN_NAME_RE = re.compile(r"(?<![a-z0-9])(token|credential)(?![a-z0-9])", re.I)

SECRET_VALUE_RE = re.compile(
    r"(ghp_[A-Za-z0-9]{30,}"
    r"|github_pat_[A-Za-z0-9_]{40,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|AIza[0-9A-Za-z_\-]{30,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})"
)

# value assigned to a secret-looking key, e.g. DEPLOY_TOKEN: hardcoded-token-value
HARDCODED_SECRET_RE = re.compile(
    r"(?P<key>[A-Za-z0-9_]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)[A-Za-z0-9_]*)"
    r"\s*[:=]\s*"
    r"(?P<value>['\"]?[^\s'\"\$\{\}#]{6,}['\"]?)",
    re.I,
)

REMOTE_EXEC_RE = re.compile(
    r"(curl|wget)\s+[^\n|;&]*\|\s*(sudo\s+)?(ba)?sh"
    r"|(ba)?sh\s+<\s*\(\s*(curl|wget)"
    r"|iwr\s+[^\n|]*\|\s*iex",
    re.I,
)

PINNED_SHA_RE = re.compile(r"@[0-9a-f]{40}$", re.I)
MUTABLE_REF_RE = re.compile(r"@(main|master|dev|develop|latest|v?\d+(\.\d+){0,2})$", re.I)

CHMOD_777_RE = re.compile(r"chmod\s+(-[A-Za-z]+\s+)?777", re.I)
DOCKER_PASSWORD_RE = re.compile(r"docker\s+login\b[^\n]*(-p|--password)\b", re.I)
SET_X_RE = re.compile(r"set\s+-[a-wyz]*x|set\s+\+x", re.I)
SUDO_RE = re.compile(r"(?<![\w/])sudo\s", re.I)
ECHO_SECRET_RE = re.compile(r"echo\s+[^\n]*\$\{?\{?\s*(secrets\.|[A-Za-z0-9_]*(token|password|secret|key))", re.I)

DEPLOY_NAME_RE = re.compile(r"(deploy|release|publish|promote|rollout|ship|prod)", re.I)
DEPLOY_COMMAND_RE = re.compile(
    r"(kubectl\s+apply|kubectl\s+rollout|helm\s+(install|upgrade)|terraform\s+apply"
    r"|serverless\s+deploy|aws\s+(s3|ecs|lambda|cloudformation)|gcloud\s+app\s+deploy"
    r"|ssh\s+|scp\s+|rsync\s+|docker\s+push|npm\s+publish)",
    re.I,
)
PROD_REF_RE = re.compile(r"(prod|production)", re.I)

DOCKER_BUILD_ARG_SECRET_RE = re.compile(
    r"docker\s+build[^\n]*--build-arg\s+[A-Za-z0-9_]*(token|password|secret|key)",
    re.I,
)
ENV_ARTIFACT_RE = re.compile(r"(\.env(\.[a-z]+)?|kubeconfig|\.kube/config|id_rsa|\.pem|credentials)", re.I)
