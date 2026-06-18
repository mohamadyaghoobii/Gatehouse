import pytest

from app.parsers import parse_pipeline
from app.parsers.detect import detect_provider

GITHUB = """name: ci
on:
  push:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
"""

GITLAB = """stages:
  - build
build-job:
  stage: build
  image: node:20
  script:
    - npm ci
    - npm run build
"""

JENKINS = """pipeline {
  agent any
  stages {
    stage('Build') { steps { sh 'make build' } }
    stage('Deploy') { steps { sh './deploy.sh' } }
  }
}
"""


def test_detect_github():
    assert detect_provider(GITHUB) == "github_actions"


def test_detect_gitlab():
    assert detect_provider(GITLAB) == "gitlab_ci"


def test_detect_jenkins():
    assert detect_provider(JENKINS) == "jenkins"


def test_github_on_key_is_not_boolean():
    parsed = parse_pipeline(GITHUB)
    assert parsed.triggers == ["push"]
    assert parsed.name == "ci"


def test_github_jobs_and_steps():
    parsed = parse_pipeline(GITHUB)
    assert len(parsed.jobs) == 1
    job = parsed.jobs[0]
    assert job.name == "build"
    assert job.runner == "ubuntu-latest"
    assert len(job.steps) == 2
    assert job.steps[0].uses == "actions/checkout@v4"
    assert job.line is not None


def test_gitlab_jobs_and_stages():
    parsed = parse_pipeline(GITLAB)
    assert parsed.stages == ["build"]
    assert [job.name for job in parsed.jobs] == ["build-job"]
    assert parsed.jobs[0].steps  # script lines became steps


def test_jenkins_stages():
    parsed = parse_pipeline(JENKINS)
    names = [job.name for job in parsed.jobs]
    assert names == ["Build", "Deploy"]


def test_empty_content_raises():
    with pytest.raises(ValueError):
        parse_pipeline("   ")
