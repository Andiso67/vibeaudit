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

const ENTREGABLES = [
  ["informe-ejecutivo.pdf", "Informe ejecutivo (PDF)"],
  ["informe-ejecutivo.html", "Informe ejecutivo (HTML)"],
  ["informe-central.html", "Informe maestro"],
  ["informe-central.md", "Informe maestro (MD)"],
  ["roadmap.md", "Roadmap"],
  ["backlog.csv", "Backlog CSV"],
  ["backlog.json", "Backlog JSON"],
  ["c4-context.mmd", "C4 contexto"],
  ["c4-container.mmd", "C4 contenedores"],
];

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

function severityCounts(report) {
  const counts = {};
  const items = [
    report?.vulnerabilities,
    report?.secrets,
    report?.iacIssues,
    report?.cicdIssues,
    report?.customIssues,
    report?.cloudIssues,
    report?.llmFindings,
    report?.recurrentFindings,
    report?.metrics?.dependencyVulnerabilities,
  ];
  for (const group of items) {
    for (const item of group || []) {
      if (item && item.severity) {
        const sev = String(item.severity).toUpperCase();
        counts[sev] = (counts[sev] || 0) + 1;
      }
    }
  }
  return counts;
}

function riskSemaphore(report) {
  const counts = severityCounts(report);
  if ((counts.CRITICAL || 0) + (counts.HIGH || 0) > 0) {
    return { level: "red", label: "Riesgo alto" };
  }
  if (counts.MEDIUM > 0) return { level: "amber", label: "Riesgo medio" };
  return { level: "green", label: "Riesgo bajo" };
}

function ProjectHeader({ report }) {
  const project = report?.project || {};
  const details = [
    project.repositoryUrl ? ["Repositorio", project.repositoryUrl] : null,
    project.defaultBranch ? ["Rama", project.defaultBranch] : null,
    project.commitHash ? ["Commit", String(project.commitHash).slice(0, 12)] : null,
  ].filter(Boolean);
  const tags = [
    ...(project.languages || []).map((l) => `Lenguaje: ${l}`),
    ...(project.frameworks || []).map((f) => `Framework: ${f}`),
  ];
  return (
    <div className="project-card">
      <div className="project-name">{project.name || "Proyecto sin nombre"}</div>
      {project.repositoryUrl ? (
        <div className="project-repo">
          <a href={project.repositoryUrl} target="_blank" rel="noreferrer">
            {project.repositoryUrl}
          </a>
        </div>
      ) : null}
      {details.length > 0 || tags.length > 0 || project.iacFiles?.length ? (
        <div className="project-details">
          {details.map(([label, value]) => (
            <span className="chip" key={label}>
              <strong>{label}:</strong> {value}
            </span>
          ))}
          {tags.map((t) => (
            <span className="chip" key={t}>
              {t}
            </span>
          ))}
          {project.iacFiles?.length ? (
            <div className="iac-list">
              <strong>Archivos analizados:</strong>
              <ul>
                {project.iacFiles.map((f) => (
                  <li key={f}>
                    <code>{f}</code>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function SummaryCards({ report }) {
  const totals = [
    ["SAST", report?.vulnerabilities?.length ?? 0],
    ["Secretos", report?.secrets?.length ?? 0],
    ["IaC", report?.iacIssues?.length ?? 0],
    ["CI/CD", report?.cicdIssues?.length ?? 0],
    ["Reglas custom", report?.customIssues?.length ?? 0],
    ["Nube", report?.cloudIssues?.length ?? 0],
    ["LLM", report?.llmFindings?.length ?? 0],
    ["Checklists", report?.checklists?.length ?? 0],
    ["Recurrentes", report?.recurrentFindings?.length ?? 0],
    ["Deps con CVEs", report?.metrics?.dependencyVulnerabilities?.length ?? 0],
  ];
  const grand = totals.reduce((sum, [, n]) => sum + n, 0);
  return (
    <div className="cards">
      {totals.map(([label, num]) => (
        <div className="card" key={label}>
          <div className="label">{label}</div>
          <div className="num">{num}</div>
        </div>
      ))}
      <div className="card total">
        <div className="label">Total hallazgos</div>
        <div className="num">{grand}</div>
      </div>
    </div>
  );
}

function EvolutionPanel({ filas }) {
  if (!filas || filas.length < 2) {
    return (
      <p className="muted">
        {filas?.length === 1
          ? "Solo hay un análisis guardado de este repositorio; se necesita al menos 2 para mostrar la evolución."
          : "No hay análisis previos de este repositorio en la base de datos."}
      </p>
    );
  }
  return (
    <table>
      <thead>
        <tr>
          <th>Fecha</th>
          <th>Commit</th>
          <th>Total</th>
          <th>CRITICAL</th>
          <th>HIGH</th>
          <th>MEDIUM</th>
          <th>LOW</th>
          <th>Duración</th>
        </tr>
      </thead>
      <tbody>
        {filas.map((fila) => {
          const bySev = fila.summary?.by_severity || {};
          return (
            <tr key={fila.id}>
              <td>{formatFecha(fila.started_at)}</td>
              <td>
                <code>{(fila.commit_hash || "").slice(0, 12)}</code>
              </td>
              <td>{fila.summary?.total ?? 0}</td>
              <td>{bySev.CRITICAL ?? 0}</td>
              <td>{bySev.HIGH ?? 0}</td>
              <td>{bySev.MEDIUM ?? 0}</td>
              <td>{bySev.LOW ?? 0}</td>
              <td>{formatElapsed(fila.duration_seconds)}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

export default function DetalleAnalisis() {
  const params = useParams();
  const id = params.id;
  const [data, setData] = useState(null);
  const [artefactos, setArtefactos] = useState([]);
  const [evolucion, setEvolucion] = useState(null);
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
        if (detenido) return;
        setData(body);
        setArtefactos(arts.files || []);
        setApiError("");
        if (body.repo) {
          fetch(
            `${API}/api/analyses?limit=100&status=done&repo=${encodeURIComponent(body.repo)}`
          )
            .then((r) => (r.ok ? r.json() : { items: [] }))
            .then((d) => {
              if (detenido) return;
              const filas = (d.items || [])
                .filter((i) => i.repo === body.repo)
                .sort(
                  (a, b) => new Date(a.started_at) - new Date(b.started_at)
                );
              setEvolucion(filas);
            })
            .catch(() => {});
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
  const sem = report ? riskSemaphore(report) : null;
  const counts = report ? severityCounts(report) : {};
  const metrics = report?.metrics || {};
  const entregables = ENTREGABLES.filter(([file]) => artefactos.includes(`deliverables/${file}`));
  const secciones = report
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
            {data.name ? (
              <span style={{ marginRight: "0.5rem" }}>{data.name}</span>
            ) : null}
            Análisis <code>{id}</code>
            {request.label ? <span className="chip">{request.label}</span> : null}
          </span>
          <span className="badge" style={{ background: "#16a34a" }}>
            {STATUS_LABEL[data.status] || data.status}
          </span>
        </div>
        <ul className="mini-counts">
          <li>Nombre: {data.name || "—"}</li>
          <li>Repo: <code>{data.repo || "—"}</code></li>
          <li>Rama: {data.branch || "—"}</li>
          <li>Commit: <code>{data.commit_hash || "—"}</code></li>
          <li>Inicio: {formatFecha(data.started_at)}</li>
          <li>Fin: {formatFecha(data.finished_at)}</li>
          <li>Duración: {formatElapsed(data.duration_seconds)}</li>
        </ul>
        {data.error ? <p className="error-banner">{data.error}</p> : null}
      </div>
      {report ? (
        <>
          <ProjectHeader report={report} />
          {sem ? (
            <div className={`semaphore ${sem.level}`}>
              <span className="dot" />
              {sem.label}
            </div>
          ) : null}
          <SummaryCards report={report} />
          <h2>Severidades</h2>
          <ul>
            {Object.entries(counts)
              .filter(([, n]) => n > 0)
              .map(([sev, n]) => (
                <li key={sev}>
                  <strong style={{ color: SEVERITY_COLORS[sev] || undefined }}>{sev}:</strong> {n}
                </li>
              ))}
          </ul>
          <h2>Métricas</h2>
          <ul>
            <li>
              Líneas de código: {(metrics.linesOfCode ?? 0).toLocaleString()}
            </li>
            <li>Archivos de test: {metrics.testFiles ?? 0}</li>
            <li>
              Dependencias con CVEs:{" "}
              {(metrics.dependenciesWithCves || []).join(", ") || "ninguna"}
            </li>
          </ul>
        </>
      ) : null}
      <div className="checks">
        <button type="button" className="primary" onClick={descargarJSON}>
          Descargar reporte JSON
        </button>
        <a className="primary-link" href={`${API}/api/analyses/${id}`} target="_blank" rel="noreferrer">
          Ver JSON
        </a>
      </div>
      {entregables.length > 0 ? (
        <section>
          <h2>Informes y entregables</h2>
          <ul>
            {entregables.map(([file, nombre]) => (
              <li key={file}>
                <a
                  href={`${API}/api/analyses/${id}/artifacts/deliverables/${file}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  {nombre}
                </a>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      {artefactos.length > 0 ? (
        <section>
          <h2>Artefactos guardados</h2>
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
        </section>
      ) : null}
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
      </section>
      <section>
        <h2>Evolución (historial de este repositorio)</h2>
        <EvolutionPanel filas={evolucion} />
      </section>
      {report ? (
        secciones.map(([title, table]) => (
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
