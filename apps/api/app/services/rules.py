RULES = [
    {
        "id": "GH-PERM-WRITE-ALL",
        "title": "Workflow grants broad write permissions",
        "category": "Permissions",
        "severity": "high",
        "description": "GitHub Actions permissions are set to write-all or grant broad write access."
    },
    {
        "id": "SCM-UNPINNED-ACTION",
        "title": "Action or dependency is not pinned",
        "category": "Supply Chain",
        "severity": "medium",
        "description": "A workflow action uses a branch, mutable tag, or floating reference instead of a commit SHA."
    },
    {
        "id": "SCRIPT-REMOTE-EXEC",
        "title": "Remote script execution pattern",
        "category": "Build Safety",
        "severity": "high",
        "description": "The pipeline downloads a remote script and executes it directly."
    },
    {
        "id": "SECRET-IN-PIPELINE",
        "title": "Secret-like value exposed in pipeline configuration",
        "category": "Secrets",
        "severity": "critical",
        "description": "A variable, argument, or step contains a name or value that looks sensitive."
    },
    {
        "id": "GITLAB-PRIVILEGED-DIND",
        "title": "Privileged Docker-in-Docker usage",
        "category": "Runner Hardening",
        "severity": "high",
        "description": "The pipeline appears to use Docker-in-Docker or privileged container execution."
    },
    {
        "id": "JENKINS-UNGUARDED-SH",
        "title": "Jenkins shell step needs review",
        "category": "Build Safety",
        "severity": "medium",
        "description": "A Jenkins shell command contains high-risk patterns that should be gated."
    },
    {
        "id": "MISSING-TIMEOUT",
        "title": "Pipeline job does not define a timeout",
        "category": "Reliability",
        "severity": "low",
        "description": "Jobs without timeouts can hang and consume runner capacity."
    },
    {
        "id": "MISSING-APPROVAL-GATE",
        "title": "Deployment job has no visible approval gate",
        "category": "Release Safety",
        "severity": "medium",
        "description": "Deployment-like jobs should use environments, approvals, manual gates, or protected branches."
    }
]
