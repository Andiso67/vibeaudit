"""Tests del CICDScanner (GitHub Actions y GitLab CI)."""

import pytest

from vibeaudit.models import Severity
from vibeaudit.scanners.cicd import CICDScanner

WORKFLOW_PR_TARGET = """name: PR Check

on:
  pull_request_target:
    types: [opened]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
"""

WORKFLOW_PR_TARGET_PERMISSIONS = """name: PR Check

on:
  pull_request_target:

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""

WORKFLOW_UNPINNED = """name: CI

on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: thirdparty/action@v2
      - uses: another/action@main
      - uses: pinned/action@8f6a8f9c1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d
"""

WORKFLOW_SECRET_IN_RUN = """name: Deploy

on: push

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo ${{ secrets.DEPLOY_KEY }} > key.pem
      - run: |
          curl -H "Authorization: Bearer ${{ secrets.API_TOKEN }}" https://api.example.com
"""

GITLAB_CI = """stages:
  - deploy

deploy:
  stage: deploy
  script:
    - echo "Deploying..."
    - curl -H "Job-Token: $CI_JOB_TOKEN" https://api.example.com/deploy
"""


class TestFindCiFiles:
    def test_detecta_github_workflows_y_gitlab(self, tmp_path):
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text(WORKFLOW_PR_TARGET)
        (workflows / "deploy.yaml").write_text(WORKFLOW_UNPINNED)
        (workflows / "ignore.txt").write_text("no")
        (tmp_path / ".gitlab-ci.yml").write_text(GITLAB_CI)

        files = CICDScanner(tmp_path)._find_ci_files()
        assert len(files) == 3
        assert all(str(workflows) in f for f in files if ".github" in f)

    def test_sin_pipelines_devuelve_vacio(self, tmp_path):
        (tmp_path / "README.md").write_text("hola")
        assert CICDScanner(tmp_path)._find_ci_files() == []

    def test_no_escanea_workflows_anidados(self, tmp_path):
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        assert CICDScanner(tmp_path)._find_ci_files() == []


class TestGithubWorkflow:
    def test_pr_target_sin_permissions(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text(WORKFLOW_PR_TARGET)

        findings = CICDScanner(tmp_path).scan()
        rules = {f.rule for f in findings}
        assert "cicd-github-pr-target-no-permissions" in rules
        pr_finding = next(
            f for f in findings if f.rule == "cicd-github-pr-target-no-permissions"
        )
        assert pr_finding.severity == Severity.HIGH
        assert pr_finding.line == 4
        assert pr_finding.file == ".github/workflows/ci.yml"

    def test_pr_target_con_permissions_no_hallazgo(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text(WORKFLOW_PR_TARGET_PERMISSIONS)

        findings = CICDScanner(tmp_path).scan()
        assert all(
            f.rule != "cicd-github-pr-target-no-permissions" for f in findings
        )

    def test_acciones_sin_pin_a_sha(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text(WORKFLOW_UNPINNED)

        findings = CICDScanner(tmp_path).scan()
        not_pinned = [f for f in findings if f.rule == "cicd-github-action-not-pinned"]
        assert len(not_pinned) == 2
        assert {f.line for f in not_pinned} == {10, 11}
        assert all(f.severity == Severity.MEDIUM for f in not_pinned)
        assert not_pinned[0].snippet and "thirdparty/action@v2" in not_pinned[0].snippet

    def test_secretos_en_run(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text(WORKFLOW_SECRET_IN_RUN)

        findings = CICDScanner(tmp_path).scan()
        secrets_in_run = [f for f in findings if f.rule == "cicd-github-secret-in-run"]
        assert len(secrets_in_run) == 2
        assert secrets_in_run[0].severity == Severity.HIGH
        assert secrets_in_run[0].line == 10


class TestGitlabCi:
    def test_token_en_script(self, tmp_path):
        (tmp_path / ".gitlab-ci.yml").write_text(GITLAB_CI)

        findings = CICDScanner(tmp_path).scan()
        assert len(findings) == 1
        assert findings[0].rule == "cicd-gitlab-token-in-script"
        assert findings[0].severity == Severity.MEDIUM
        assert "$CI_JOB_TOKEN" in findings[0].snippet

    def test_gitlab_sin_token_sin_hallazgos(self, tmp_path):
        (tmp_path / ".gitlab-ci.yml").write_text(
            "build:\n  script:\n    - echo \"Compilando\"\n"
        )
        assert CICDScanner(tmp_path).scan() == []

    def test_gitlab_token_de_otro_job_no_contamina(self, tmp_path):
        (tmp_path / ".gitlab-ci.yml").write_text(
            "job1:\n"
            "  script:\n"
            "    - echo \"sin token\"\n"
            "\n"
            "job2:\n"
            "  script:\n"
            "    - curl -H \"Job-Token: $CI_JOB_TOKEN\" https://x/api\n"
        )
        findings = CICDScanner(tmp_path).scan()
        assert len(findings) == 1
        assert findings[0].line == 6

    def test_gitlab_token_en_before_script(self, tmp_path):
        (tmp_path / ".gitlab-ci.yml").write_text(
            "deploy:\n"
            "  before_script:\n"
            "    - docker login -u x -p $CI_REGISTRY_PASSWORD\n"
        )
        findings = CICDScanner(tmp_path).scan()
        assert len(findings) == 1
        assert findings[0].rule == "cicd-gitlab-token-in-script"
        assert "$CI_REGISTRY_PASSWORD" in findings[0].snippet

    def test_gitlab_token_en_after_script(self, tmp_path):
        (tmp_path / ".gitlab-ci.yml").write_text(
            "build:\n"
            "  script:\n"
            "    - echo ok\n"
            "  after_script:\n"
            "    - echo $CI_JOB_TOKEN\n"
        )
        findings = CICDScanner(tmp_path).scan()
        assert len(findings) == 1
        assert findings[0].line == 4

    def test_workflow_vacio_sin_hallazgos(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("name: Empty\non: push\n")
        assert CICDScanner(tmp_path).scan() == []

    def test_on_con_comillas_detecta_pr_target(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("name: Q\n\"on\": pull_request_target\n")
        findings = CICDScanner(tmp_path).scan()
        assert any(
            f.rule == "cicd-github-pr-target-no-permissions" for f in findings
        )

    def test_permissions_comentado_no_es_valido(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text(
            "name: C\non: pull_request_target\n# permissions:\n#   contents: read\n"
        )
        findings = CICDScanner(tmp_path).scan()
        assert any(
            f.rule == "cicd-github-pr-target-no-permissions" for f in findings
        )

    def test_comentarios_y_vars_no_generan_hallazgos(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text(
            "name: C\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - name: x\n"
            "      # - uses: evil/action@v1\n"
            "      # - run: echo ${{ secrets.FOO }}\n"
            "      - run: echo ${{ vars.NOT_A_SECRET }}\n"
        )
        assert CICDScanner(tmp_path).scan() == []

    def test_uses_docker_y_local_no_generan_hallazgos(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text(
            "name: D\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - uses: docker://alpine:3.18\n"
            "      - uses: ./local-action\n"
        )
        assert CICDScanner(tmp_path).scan() == []

    def test_script_que_genera_uses_no_genera_hallazgo(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text(
            "name: G\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: |\n"
            "          echo 'uses: evil/action@v1' > template.txt\n"
            "          uses: not-a-real-line\n"
        )
        assert CICDScanner(tmp_path).scan() == []

    def test_secreto_comentado_en_run_no_genera_hallazgo(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text(
            "name: R\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: |\n"
            "          echo \"hi\"\n"
            "          # echo ${{ secrets.COMMENTED }}\n"
        )
        assert CICDScanner(tmp_path).scan() == []

    def test_token_comentado_gitlab_no_genera_hallazgo(self, tmp_path):
        (tmp_path / ".gitlab-ci.yml").write_text(
            "build:\n  script:\n    - echo \"ok\"\n"
            "    # - curl -H \"Job-Token: $CI_JOB_TOKEN\" https://x\n"
        )
        assert CICDScanner(tmp_path).scan() == []

    def test_secreto_real_y_commentado_en_mismo_run(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text(
            "name: M\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: |\n"
            "          # echo ${{ secrets.COMMENTED }}\n"
            "          echo ${{ secrets.REAL }}\n"
        )
        findings = CICDScanner(tmp_path).scan()
        assert len(findings) == 1
        assert findings[0].rule == "cicd-github-secret-in-run"

    def test_runs_consecutivos_no_contaminan(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text(
            "name: MR\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo \"safe\"\n"
            "      - run: |\n          echo ${{ secrets.ONE }}\n"
            "      - run: |\n          echo ${{ secrets.TWO }}\n"
        )
        findings = CICDScanner(tmp_path).scan()
        secrets_in_run = [f for f in findings if f.rule == "cicd-github-secret-in-run"]
        assert len(secrets_in_run) == 2
        assert {f.line for f in secrets_in_run} == {8, 10}

    def test_secreto_inline_en_run(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text(
            "name: I\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo ${{ secrets.INLINE }}\n"
            "      - uses: evil/action@v1\n"
        )
        findings = CICDScanner(tmp_path).scan()
        rules = {f.rule for f in findings}
        assert "cicd-github-secret-in-run" in rules
        assert "cicd-github-action-not-pinned" in rules


    def test_pr_target_comentado_no_dispara_hallazgo(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text(
            "name: C\non:\n"
            "  # pull_request_target es peligroso, no usarlo\n"
            "  push:\n"
            "jobs:\n  j:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo safe\n"
        )
        findings = CICDScanner(tmp_path).scan()
        assert all(f.rule != "cicd-github-pr-target-no-permissions" for f in findings)

    def test_pr_target_con_blank_dentro_de_on(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text(
            "name: B\non:\n"
            "\n"
            "  pull_request_target:\n"
            "\n"
            "  push:\n"
            "jobs:\n  j:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo safe\n"
        )
        findings = CICDScanner(tmp_path).scan()
        assert any(
            f.rule == "cicd-github-pr-target-no-permissions" for f in findings
        )

    def test_workflow_con_bom_utf8(self, tmp_path):
        workflow = tmp_path / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        content = (
            "name: BOM\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - uses: thirdparty/action@v2\n"
        )
        workflow.write_bytes(b"\xef\xbb\xbf" + content.encode("utf-8"))
        findings = CICDScanner(tmp_path).scan()
        assert any(f.rule == "cicd-github-action-not-pinned" for f in findings)


class TestHelpers:
    def test_find_pr_target_en_linea_1(self):
        lines = WORKFLOW_PR_TARGET.splitlines()
        line = CICDScanner._find_pull_request_target(lines)
        assert line == 4

    def test_find_pr_target_ausente(self):
        lines = "name: CI\non: push\njobs: {}\n".splitlines()
        assert CICDScanner._find_pull_request_target(lines) is None

    def test_has_permissions_true_false(self):
        assert CICDScanner._has_permissions(["permissions: read-all"]) is True
        assert CICDScanner._has_permissions(["  permissions: read"]) is True
        assert CICDScanner._has_permissions(["on: push"]) is False

    @pytest.mark.parametrize(
        "ref,expected",
        [
            ("actions/checkout@v4", "skip"),
            ("actions/checkout@8f6a8f9c1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d", "skip"),
            ("thirdparty/action@v2", "finding"),
            ("pinned/action@8f6a8f9c1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d", "skip"),
        ],
    )
    def test_shas_validos(self, ref, expected, tmp_path):
        workflow = tmp_path / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text(f"name: CI\non: push\njobs:\n  j:\n    steps:\n      - uses: {ref}\n")

        findings = CICDScanner(tmp_path).scan()
        if expected == "finding":
            assert any(
                f.rule == "cicd-github-action-not-pinned" for f in findings
            )
        else:
            assert all(
                f.rule != "cicd-github-action-not-pinned" for f in findings
            )
