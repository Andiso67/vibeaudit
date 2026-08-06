"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";

import {
  SEVERITY_COLORS,
  Badge,
  IssueTable,
  CloudTable,
  CloudResourcesTable,
  DepsTable,
  LlmTable,
  RecurrentTable,
} from "../../../../components/tablas";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

const STATUS_LABEL = {
  queued: "En cola",
  running: "En curso",
  done: "Finalizado",
  error: "Error",
};

function formatFecha(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("es-ES", { dateStyle: "short", timeStyle: "short" });
}

function formatElapsed(seconds) {
  if (seconds == null) return "—";
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m}m ${s}s`;
}

export default function DetalleAnalisis() {
  const params = useParams();
  const id = params.id;
  const [data, setData] = useState(null);
  const [artefactos, setArtefactos] = useState([]);
  const [cargando, setCargando] = useState(true);
  const [apiError, setApiError] = useState("");

  useEffect(() => {
    let detenido = false;
    setCargando(true);
    Promise.all([
      fetch(`${API}/api/analyses/${id}`),
      fetch(`${API}/api/analyses/${id}/artifacts`).then((r) =>
        r.ok ? r.json() : { files: [] }
      ),
    ])
      .then(async ([resp, arts]) => {
        if (resp.status === 404) throw new Error("análisis no encontrado");
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const body = await resp.json();
        if (!detenido) {
          setData(body);
          setArtefactos(arts.files || []);
          setApiError("");
        }
      })
      .catch((err) => {
        if (!detenido) setApiError(`No se pudo cargar el análisis: ${err.message}`);
      })
      .finally(() => {
        if (!detenido) setCargando(false);
      });
    return () => {
      detenido = true;
    };
  }, [id]);

  const descargarJSON = useCallback(async () => {
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${id}-audit-report.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [data, id]);

  if (cargando) {
    return (
      <main className="container">
        <header className="brand">
          <img
            src="/improven-logo.png"
            alt="Improven"
            width="171"
            height="36"
            style={{ objectFit: "contain" }}
          />
          <h1>Detalle de análisis</h1>
        </header>
        <p className="muted">Cargando…</p>
      </main>
    );
  }

  if (apiError || !data) {
    return (
      <main className="container">
        <header className="brand">
          <img
            src="/improven-logo.png"
            alt="Improven"
            width="171"
            height="36"
            style={{ objectFit: "contain" }}
          />
          <h1>Detalle de análisis</h1>
        </header>
        <p className="error-banner">{apiError}</p>
        <p>
          <a href="/consola">← Volver a la consola</a>
        </p>
      </main>
    );
  }

  const { summary = {}, report = null } = data;
  const request = data.request || {};
  const sections = report
    ? [
        ["Vulnerabilidades (SAST)", <IssueTable key="sast" items={report.vulnerabilities} />],
        ["Secretos filtrados", <IssueTable key="sec" items={report.secrets} />],
        ["Problemas de IaC", <IssueTable key="iac" items={report.iacIssues} />],
        ["Riesgos de CI/CD", <IssueTable key="cicd" items={report.cicdIssues} />],
        ["Reglas custom", <IssueTable key="cust" items={report.customIssues} />],
        ["Seguridad en la nube", <CloudTable key="cloud" items={report.cloudIssues} />],
        [
          "Recursos de nube analizados",
          <CloudResourcesTable key="cloudres" items={report.cloudResources} />,
        ],
        ["Auditoría LLM (checklists)", <LlmTable key="llm" items={report.llmFindings} />],
        [
          "Hallazgos recurrentes (memoria)",
          <RecurrentTable key="rec" items={report.recurrentFindings} />,
        ],
        [
          "Dependencias con CVEs",
          <DepsTable key="deps" items={report.metrics?.dependencyVulnerabilities} />,
        ],
      ]
    : [];

  return (
    <main className="container">
      <header className="brand">
        <img
          src="/improven-logo.png"
          alt="Improven"
          width="171"
          height="36"
          style={{ objectFit: "contain" }}
        />
        <h1>Detalle de análisis</h1>
      </header>
      <p>
        <a href="/consola">← Volver a la consola</a>
      </p>
      <div className="project-card">
        <div className="job-head">
          <span className="job-id">
            Análisis <code>{id}</code>
            {request.label ? <span className="chip">{request.label}</span> : null}
          </span>
          <span className="badge" style={{ background: "#16a34a" }}>
            {STATUS_LABEL[data.status] || data.status}
          </span>
        </div>
        <ul className="mini-counts">
          <li>Repo: <code>{data.repo || "—"}</code></li>
          <li>Rama: {data.branch || "—"}</li>
          <li>Commit: <code>{data.commit_hash || "—"}</code></li>
          <li>Inicio: {formatFecha(data.started_at)}</li>
          <li>Fin: {formatFecha(data.finished_at)}</li>
          <li>Duración: {formatElapsed(data.duration_seconds)}</li>
        </ul>
        {data.error ? <p className="error-banner">{data.error}</p> : null}
        <div className="checks">
          <button type="button" className="primary" onClick={descargarJSON}>
            Descargar reporte JSON
          </button>
          <a className="primary-link" href={`${API}/api/analyses/${id}`} target="_blank" rel="noreferrer">
            Ver JSON
          </a>
        </div>
        {artefactos.length > 0 ? (
          <div>
            <h3>Artefactos guardados</h3>
            <ul className="mini-counts">
              {artefactos.map((f) => (
                <li key={f}>
                  <a
                    href={`${API}/api/analyses/${id}/artifacts/${f}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    {f}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </div>
      <section>
        <h2>Resumen</h2>
        <div className="cards">
          <div className="card">
            <div className="label">Hallazgos</div>
            <div className="num">{summary.total ?? 0}</div>
          </div>
          {Object.entries(summary.by_severity || {}).map(([sev, n]) => (
            <div className="card" key={sev} style={{ borderColor: SEVERITY_COLORS[sev] }}>
              <div className="label">{sev}</div>
              <div className="num" style={{ color: SEVERITY_COLORS[sev] }}>
                {n}
              </div>
            </div>
          ))}
        </div>
        {Object.keys(summary.by_type || {}).length > 0 ? (
          <ul className="mini-counts">
            {Object.entries(summary.by_type).map(([tipo, n]) => (
              <li key={tipo}>
                {tipo}: <strong>{n}</strong>
              </li>
            ))}
          </ul>
        ) : null}
      </section>
      {report ? (
        sections.map(([title, table]) => (
          <section key={title}>
            <h2>{title}</h2>
            {table}
          </section>
        ))
      ) : (
        <p className="muted">
          Este análisis no tiene reporte completo (p. ej. quedó en cola o falló
          antes de terminar). Solo hay metadatos.
        </p>
      )}
    </main>
  );
}
