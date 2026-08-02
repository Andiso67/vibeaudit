"""Tests del motor LLM (auditoría por checklists). Sin red: clientes con MockTransport."""

import json

import httpx
import pytest

from vibeaudit.llm import (
    LLMAuditor,
    LLMClient,
    LLMConfig,
    LLMUnavailableError,
    STARTER_CHECKLIST,
)
from vibeaudit.models import (
    AuditReport,
    Metrics,
    ProjectMetadata,
    Severity,
    Vulnerability,
)


def make_report(**kwargs):
    return AuditReport(
        project=ProjectMetadata(name="demo", languages=["python"]),
        vulnerabilities=[
            Vulnerability(rule="r1", file="app.py", line=1, severity=Severity.HIGH)
        ],
        iac_issues=[],
        cicd_issues=[],
        custom_issues=[],
        secrets=[],
        metrics=Metrics(lines_of_code=10, test_files=1),
        **kwargs,
    )


class FakeLLMResponse:
    def __init__(self, content):
        self._content = content

    @property
    def text(self):
        return self._content

    def json(self):
        return {"choices": [{"message": {"content": self._content}}]}


class FakeLLMClient:
    """Cliente LLM falso que devuelve un JSON predefinido."""

    def __init__(self, content="", fail=None):
        self.content = content
        self.fail = fail
        self.last_messages = None

    def chat(self, messages):
        self.last_messages = messages
        if self.fail:
            raise self.fail
        return self.content


VALID_RESPONSE = json.dumps(
    {
        "findings": [
            {
                "title": "Secretos en el código",
                "severity": "CRITICAL",
                "checklistRef": "12-factor.config",
                "evidence": "Secretos filtrados detectados por gitleaks.",
                "recommendation": "Mover los secretos a un gestor (Vault/SSM).",
                "relatedFiles": ["app.py"],
            },
            {
                "title": "Consulta SQL concatenada",
                "severity": "HIGH",
                "severity_extra": "ignorado",
                "checklistRef": "owasp.injection",
                "evidence": "SAST r1 en app.py:1.",
                "recommendation": "Usar parámetros.",
            },
        ]
    }
)


class TestLLMClient:
    def make_client(self, handler):
        transport = httpx.MockTransport(handler)
        return LLMClient(
            config=LLMConfig(base_url="http://ollama:11434/v1", model="llama3.1"),
            transport=transport,
        )

    def test_chat_envia_request_correcto(self):
        captured = {}

        def handler(request):
            captured["url"] = str(request.url)
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

        client = self.make_client(handler)
        text = client.chat([{"role": "user", "content": "hola"}])

        assert text == "ok"
        assert captured["url"] == "http://ollama:11434/v1/chat/completions"
        assert captured["body"]["model"] == "llama3.1"
        assert captured["body"]["messages"][0]["content"] == "hola"

    def test_chat_con_api_key_envia_header(self):
        def handler(request):
            assert request.headers["Authorization"] == "Bearer secret-key"
            return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

        client = LLMClient(
            config=LLMConfig(base_url="http://x/v1", model="m", api_key="secret-key"),
            transport=httpx.MockTransport(handler),
        )
        assert client.chat([{"role": "user", "content": "x"}]) == "ok"

    def test_chat_sin_api_key_no_envia_header(self):
        def handler(request):
            assert "Authorization" not in request.headers
            return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

        client = LLMClient(
            config=LLMConfig(base_url="http://x/v1", model="m"),
            transport=httpx.MockTransport(handler),
        )
        assert client.chat([{"role": "user", "content": "x"}]) == "ok"

    def test_chat_error_conexion_lanza_unavailable(self):
        def handler(request):
            raise httpx.ConnectError("connection refused")

        client = self.make_client(handler)
        with pytest.raises(LLMUnavailableError):
            client.chat([{"role": "user", "content": "x"}])

    def test_chat_401_lanza_unavailable(self):
        client = self.make_client(lambda request: httpx.Response(401))
        with pytest.raises(LLMUnavailableError):
            client.chat([{"role": "user", "content": "x"}])

    def test_chat_500_lanza_unavailable(self):
        client = self.make_client(lambda request: httpx.Response(500, text="boom"))
        with pytest.raises(LLMUnavailableError):
            client.chat([{"role": "user", "content": "x"}])

    def test_chat_respuesta_sin_choices_lanza_unavailable(self):
        client = self.make_client(lambda request: httpx.Response(200, json={}))
        with pytest.raises(LLMUnavailableError):
            client.chat([{"role": "user", "content": "x"}])


class TestLLMAuditorParse:
    def make_auditor(self):
        return LLMAuditor(make_report())

    def test_parse_json_valido(self):
        findings = self.make_auditor().parse_response(VALID_RESPONSE)

        assert len(findings) == 2
        assert findings[0].title == "Secretos en el código"
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].checklist_ref == "12-factor.config"
        assert findings[0].related_files == ["app.py"]

    def test_parse_json_con_fence_markdown(self):
        findings = self.make_auditor().parse_response(
            "Claro:\n```json\n" + VALID_RESPONSE + "\n```\nFin"
        )
        assert len(findings) == 2

    def test_parse_json_embebido_en_texto(self):
        findings = self.make_auditor().parse_response(
            "Aquí va el análisis: " + VALID_RESPONSE + " Espero que sirva."
        )
        assert len(findings) == 2

    def test_parse_sin_json_devuelve_vacio(self):
        assert self.make_auditor().parse_response("no encontré problemas") == []

    def test_parse_json_sin_findings_devuelve_vacio(self):
        assert self.make_auditor().parse_response('{"otra": "cosa"}') == []

    def test_parse_items_invalidos_se_ignoran(self):
        raw = json.dumps(
            {
                "findings": [
                    {"title": "ok", "severity": "HIGH"},
                    {"title": "", "severity": "HIGH"},
                    {"not_title": "x"},
                    "texto",
                ]
            }
        )
        findings = self.make_auditor().parse_response(raw)
        assert len(findings) == 1
        assert findings[0].title == "ok"

    def test_parse_checklist_ref_con_corchetes_se_normaliza(self):
        raw = json.dumps(
            {
                "findings": [
                    {
                        "title": "Configuración",
                        "severity": "INFO",
                        "checklistRef": "[12-factor.config]",
                    }
                ]
            }
        )
        findings = self.make_auditor().parse_response(raw)
        assert findings[0].checklist_ref == "12-factor.config"

    def test_parse_severity_invalida_se_ignora(self):
        raw = json.dumps({"findings": [{"title": "x", "severity": "URGENTE"}]})
        assert self.make_auditor().parse_response(raw) == []


class TestLLMAuditorAudit:
    def test_audit_devuelve_hallazgos_del_cliente(self):
        client = FakeLLMClient(content=VALID_RESPONSE)
        auditor = LLMAuditor(make_report(), client=client)

        findings = auditor.audit()

        assert len(findings) == 2
        assert findings[0].checklist_ref == "12-factor.config"

    def test_build_messages_incluye_reporte_y_checklist(self):
        client = FakeLLMClient(content=VALID_RESPONSE)
        auditor = LLMAuditor(make_report(), client=client)

        messages = auditor.build_messages()

        assert len(messages) == 2
        assert messages[0]["role"] == "system"
        assert "JSON" in messages[0]["content"]
        user = messages[1]["content"]
        assert "demo" in user
        assert "python" in user
        assert "12-factor.config" in user
        assert "r1 HIGH app.py:1" in user
        assert "Vulnerabilidades por severidad" in user

    def test_audit_checklist_default_no_vacio(self):
        auditor = LLMAuditor(make_report(), client=FakeLLMClient(content="{}"))
        assert len(auditor.checklist) > 0
        assert auditor.checklist == STARTER_CHECKLIST

    def test_audit_con_checklist_custom(self):
        from vibeaudit.llm import ChecklistItem

        custom = [ChecklistItem(id="x.1", title="T", description="D")]
        client = FakeLLMClient(content=VALID_RESPONSE)
        auditor = LLMAuditor(make_report(), client=client, checklist=custom)

        auditor.audit()
        assert "x.1" in client.last_messages[1]["content"]

    def test_audit_fallo_cliente_se_propaga(self):
        client = FakeLLMClient(fail=LLMUnavailableError("caido"))
        auditor = LLMAuditor(make_report(), client=client)
        with pytest.raises(LLMUnavailableError):
            auditor.audit()


class TestLLMEnReporte:
    def test_to_json_incluye_llm_findings_camelcase(self, tmp_path):
        from vibeaudit.reporter import AuditReporter

        reporter = AuditReporter(
            project=ProjectMetadata(name="demo"),
            vulnerabilities=[],
            secrets=[],
            iac_issues=[],
            cicd_issues=[],
            repo_path=tmp_path,
        )
        report = reporter.build()
        from vibeaudit.models import LLMFinding

        report.llm_findings = [
            LLMFinding(
                title="Secretos en código",
                severity=Severity.CRITICAL,
                checklist_ref="12-factor.config",
                evidence="ev",
                related_files=["a.py"],
            )
        ]

        data = json.loads(reporter.to_json())
        assert len(data["llmFindings"]) == 1
        assert data["llmFindings"][0]["checklistRef"] == "12-factor.config"
        assert data["llmFindings"][0]["relatedFiles"] == ["a.py"]

    def test_save_html_incluye_seccion_llm(self, tmp_path):
        from vibeaudit.llm import LLMAuditor, LLMConfig
        from vibeaudit.reporter import AuditReporter

        report = make_report()
        client = LLMClient(
            config=LLMConfig(base_url="http://x/v1", model="m"),
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"choices": [{"message": {"content": VALID_RESPONSE}}]})
            ),
        )
        findings = LLMAuditor(report, client=client).audit()
        reporter = AuditReporter(
            project=report.project,
            vulnerabilities=report.vulnerabilities,
            secrets=[],
            iac_issues=[],
            cicd_issues=[],
            llm_findings=findings,
            repo_path=tmp_path,
        )
        out = tmp_path / "r.html"
        reporter.save_html(out)
        content = out.read_text()

        assert "Auditoría LLM (checklists)" in content
        assert "Secretos en el código" in content
        assert "12-factor.config" in content
        assert "Recomendación:" in content

    def test_save_markdown_incluye_seccion_llm(self, tmp_path):
        from vibeaudit.reporter import AuditReporter
        from vibeaudit.models import LLMFinding

        reporter = AuditReporter(
            project=ProjectMetadata(name="demo"),
            vulnerabilities=[],
            secrets=[],
            iac_issues=[],
            cicd_issues=[],
            repo_path=tmp_path,
        )
        report = reporter.build()
        report.llm_findings = [
            LLMFinding(
                title="Secretos en código",
                severity=Severity.CRITICAL,
                checklist_ref="12-factor.config",
                evidence="evidencia",
                recommendation="recomendación",
            )
        ]
        out = tmp_path / "r.md"
        reporter.save_markdown(out)
        content = out.read_text()

        assert "## Auditoría LLM (checklists)" in content
        assert "`12-factor.config`" in content
        assert "**Recomendación:** recomendación" in content

    def test_print_summary_incluye_llm_en_total(self, tmp_path, capsys):
        import re

        from vibeaudit.models import LLMFinding
        from vibeaudit.reporter import AuditReporter

        reporter = AuditReporter(
            project=ProjectMetadata(name="demo"),
            vulnerabilities=[
                Vulnerability(rule="r1", file="a.py", line=1, severity=Severity.HIGH)
            ],
            secrets=[],
            iac_issues=[],
            cicd_issues=[],
            repo_path=tmp_path,
        )
        report = reporter.build()
        report.llm_findings = [LLMFinding(title="t", severity=Severity.HIGH)]
        reporter.print_summary()
        output = capsys.readouterr().out

        def count_of(row_name):
            for line in output.splitlines():
                if row_name in line:
                    return int(re.search(r"\d+", line.split(row_name)[1]).group())
            raise AssertionError(f"Fila no encontrada: {row_name}")

        assert count_of("Hallazgos LLM") == 1
        assert count_of("Total de hallazgos") == 2

        severity_count = None
        in_severity = False
        for line in output.splitlines():
            if "Severidad" in line and "Cantidad" in line:
                in_severity = True
                continue
            if in_severity and "HIGH" in line:
                severity_count = int(re.search(r"\d+", line).group())
                break
        assert severity_count == 2, (
            "La tabla por severidad debe incluir los hallazgos LLM (1 SAST + 1 LLM)"
        )
