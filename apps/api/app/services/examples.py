from app.schemas import ExampleInfo

EXAMPLES = {
    "github-actions-risky": ExampleInfo(
        id="github-actions-risky",
        title="Risky GitHub Actions deployment",
        platform="github_actions",
        description="Broad permissions, unpinned actions, remote script execution, and missing deployment gate.",
        content='''name: risky-release
on:
  push:
    branches: [main]
permissions: write-all
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: docker/login-action@v2
        with:
          username: admin
          password: super-secret-password
      - name: Install deploy tool
        run: curl -fsSL https://example.com/install.sh | bash
      - name: Deploy
        run: kubectl apply -f k8s/
'''
    ),
    "github-actions-hardened": ExampleInfo(
        id="github-actions-hardened",
        title="Hardened GitHub Actions deployment",
        platform="github_actions",
        description="Read-only defaults, scoped write permission, pinned-style examples, timeout, and protected environment.",
        content='''name: hardened-release
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@f43a0e5ff2bd294095638e18286ca9a3d1956744
      - name: Test
        run: npm ci && npm test
  deploy:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    environment:
      name: production
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@f43a0e5ff2bd294095638e18286ca9a3d1956744
      - name: Deploy
        run: ./scripts/deploy.sh
'''
    ),
    "gitlab-risky": ExampleInfo(
        id="gitlab-risky",
        title="Risky GitLab CI container deploy",
        platform="gitlab_ci",
        description="Docker-in-Docker, secret-like variables, and automated deploy behavior.",
        content='''image: docker:latest
services:
  - docker:dind
variables:
  DEPLOY_TOKEN: hardcoded-token-value
stages:
  - build
  - deploy
build-image:
  stage: build
  script:
    - docker login -u admin -p $DEPLOY_TOKEN registry.example.com
    - docker build -t app:latest .
deploy-prod:
  stage: deploy
  script:
    - curl https://example.com/deploy.sh | sh
'''
    ),
    "jenkins-risky": ExampleInfo(
        id="jenkins-risky",
        title="Risky Jenkinsfile deployment",
        platform="jenkins",
        description="Remote script execution and weak secret handling patterns.",
        content='''pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh 'curl https://example.com/install.sh | bash'
      }
    }
    stage('Deploy') {
      steps {
        sh 'DEPLOY_PASSWORD=hunter2 ./deploy.sh'
      }
    }
  }
}
'''
    )
}


def list_examples() -> list[ExampleInfo]:
    return list(EXAMPLES.values())


def get_example(example_id: str) -> ExampleInfo | None:
    return EXAMPLES.get(example_id)
