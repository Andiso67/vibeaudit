import fs from "node:fs";
import path from "node:path";

import {
  SEVERITY_COLORS,
  SEVERITY_ORDER,
  Badge,
  IssueTable,
  CloudResourcesTable,
  CloudTable,
  DepsTable,
  LlmTable,
  RecurrentTable,
} from "../components/tablas";

export const dynamic = "force-dynamic";

function loadReport() {
  const candidates = [
    process.env.VIBEAUDIT_REPORT,
    path.join(process.cwd(), "public", "audit-report.json"),
  ];
  for (const candidate of candidates) {
    if (!candidate) continue;
    try {
      const raw = fs.readFileSync(candidate, "utf-8");
      const data = JSON.parse(raw);
      if (data && typeof data === "object" && data.project) return { data, source: candidate };
    } catch {
      continue;
    }
  }
  return null;
}

function loadHistory() {
  const candidates = [
    process.env.VIBEAUDIT_HISTORY,
    path.join(process.cwd(), "public", "audit-history.json"),
  ];
  for (const candidate of candidates) {
    if (!candidate) continue;
    try {
      const raw = fs.readFileSync(candidate, "utf-8");
      const data = JSON.parse(raw);
      if (data && typeof data === "object" && data.snapshots) return data;
    } catch {
      continue;
    }
  }
  return null;
}

function riskSemaphore(report) {
  const counts = severityCounts(report);
  if (counts.CRITICAL + counts.HIGH > 0) return { level: "red", label: "Riesgo alto" };
  if (counts.MEDIUM > 0) return { level: "amber", label: "Riesgo medio" };
  return { level: "green", label: "Riesgo bajo" };
}

function severityCounts(report) {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0]));
  const items = [
    report.vulnerabilities,
    report.secrets,
    report.iacIssues,
    report.cicdIssues,
    report.customIssues,
    report.cloudIssues,
    report.llmFindings,
    report.recurrentFindings,
    report.metrics?.dependencyVulnerabilities,
  ];
  for (const group of items) {
    for (const item of group || []) {
      if (item && item.severity && counts[item.severity] !== undefined) {
        counts[item.severity] += 1;
      }
    }
  }
  return counts;
}

function ProjectHeader({ project }) {
  const details = [
    project?.repositoryUrl ? ["Repositorio", project.repositoryUrl] : null,
    project?.defaultBranch ? ["Rama", project.defaultBranch] : null,
    project?.commitHash ? ["Commit", project.commitHash.slice(0, 12)] : null,
  ].filter(Boolean);
  const tags = [
    ...(project?.languages || []).map((l) => `Lenguaje: ${l}`),
    ...(project?.frameworks || []).map((f) => `Framework: ${f}`),
  ];
  return (
    <div className="project-card">
      <div className="project-name">{project?.name || "Proyecto sin nombre"}</div>
      {project?.repositoryUrl ? (
        <div className="project-repo">
          <a href={project.repositoryUrl} target="_blank" rel="noreferrer">
            {project.repositoryUrl}
          </a>
        </div>
      ) : null}
      {details.length > 0 || tags.length > 0 || project?.iacFiles?.length ? (
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
          {project?.iacFiles?.length ? (
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

function EvolutionPanel({ history }) {
  if (!history || !history.snapshots || history.snapshots.length < 2) {
    return <p>Se necesitan al menos 2 escaneos guardados para mostrar la evolución.</p>;
  }
  return (
    <>
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
            <th>LOC</th>
          </tr>
        </thead>
        <tbody>
          {history.snapshots.map((snap) => (
            <tr key={snap.id}>
              <td>{snap.timestamp}</td>
              <td>
                <code>{(snap.commit || "").slice(0, 12)}</code>
              </td>
              <td>{snap.summary.total}</td>
              <td>{snap.summary.perSeverity.CRITICAL}</td>
              <td>{snap.summary.perSeverity.HIGH}</td>
              <td>{snap.summary.perSeverity.MEDIUM}</td>
              <td>{snap.summary.perSeverity.LOW}</td>
              <td>(snap.summary.linesOfCode ?? 0).toLocaleString()</td>
            </tr>
          ))}
        </tbody>
      </table>
      {history.deltas && history.deltas.length > 0 ? (
        <>
          <h3>Deltas entre escaneos</h3>
          <ul>
            {history.deltas.map((d, i) => (
              <li key={i}>
                <code>{(d.from?.commit || "").slice(0, 12)}</code> →{" "}
                <code>{(d.to?.commit || "").slice(0, 12)}</code>:{" "}
                <strong>{d.new}</strong> nuevos, <strong>{d.resolved}</strong>{" "}
                resueltos, <strong>{d.persistent}</strong> persistentes.
              </li>
            ))}
          </ul>
        </>
      ) : null}
      {history.alerts && history.alerts.length > 0 ? (
        <>
          <h3>Alertas de recurrencia</h3>
          <p>
            Hallazgos que persisten entre escaneos y/o se repiten: merecen un fix
            definitivo.
          </p>
          <table>
            <thead>
              <tr>
                <th>Nivel</th>
                <th>Score</th>
                <th>Snapshots</th>
                <th>Ocurrencias</th>
                <th>Regla</th>
                <th>Archivo</th>
              </tr>
            </thead>
            <tbody>
              {history.alerts.map((a) => (
                <tr key={a.key}>
                  <td>{a.level}</td>
                  <td>{a.score}</td>
                  <td>{a.snapshots}</td>
                  <td>{a.occurrences}</td>
                  <td>
                    <code>{a.rule}</code>
                  </td>
                  <td>{a.file || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      ) : null}
    </>
  );
}

function SummaryCards({ report }) {
  const totals = [
    ["SAST", report.vulnerabilities?.length ?? 0],
    ["Secretos", report.secrets?.length ?? 0],
    ["IaC", report.iacIssues?.length ?? 0],
    ["CI/CD", report.cicdIssues?.length ?? 0],
    ["Reglas custom", report.customIssues?.length ?? 0],
    ["Nube", report.cloudIssues?.length ?? 0],
    ["LLM", report.llmFindings?.length ?? 0],
    ["Checklists", report.checklists?.length ?? 0],
    ["Recurrentes", report.recurrentFindings?.length ?? 0],
    ["Deps con CVEs", report.metrics?.dependencyVulnerabilities?.length ?? 0],
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


export default function Page() {
  const loaded = loadReport();
  const history = loadHistory();
  if (!loaded) {
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
          <h1>VibeAudit — Dashboard de cliente</h1>
        </header>
        <p>
          No se encontró el JSON maestro. Cópialo a{" "}
          <code>public/audit-report.json</code> dentro de{" "}
          <code>dashboard/</code> o define la variable{" "}
          <code>VIBEAUDIT_REPORT</code> apuntando al reporte JSON.
        </p>
      </main>
    );
  }

  const { data: report, source } = loaded;
  const sem = riskSemaphore(report);
  const counts = severityCounts(report);

  const sections = [
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
  ];

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
        <h1>VibeAudit — Dashboard de cliente</h1>
      </header>
      <p>
        <a href="/consola">Consola de análisis →</a> (pedir nuevos análisis y
        consultar el histórico guardado)
      </p>
      <ProjectHeader project={report.project} />
      <div className={`semaphore ${sem.level}`}>
        <span className="dot" />
        {sem.label}
      </div>
      <SummaryCards report={report} />
      <h2>Severidades</h2>
      <ul>
        {SEVERITY_ORDER.filter((s) => counts[s] > 0).map((s) => (
          <li key={s}>
            <strong>{s}:</strong> {counts[s]}
          </li>
        ))}
      </ul>
      <h2>Métricas</h2>
      <ul>
        <li>
          Líneas de código: {(report.metrics?.linesOfCode ?? 0).toLocaleString()}
        </li>
        <li>Archivos de test: {report.metrics?.testFiles ?? 0}</li>
        <li>
          Dependencias con CVEs:{" "}
          {(report.metrics?.dependenciesWithCves || []).join(", ") || "ninguna"}
        </li>
      </ul>
      <section>
        <h2>Evolución (historial)</h2>
        <EvolutionPanel history={history} />
      </section>
      <section>
        <h2>Informes y entregables</h2>
        <ul>
          <li>
            <a href="/deliverables/informe-central.html">Informe maestro</a>{" "}
            (informe central con C4, roadmap y backlog)
          </li>
          <li>
            <a href="/deliverables/informe-ejecutivo.html">
              Informe ejecutivo
            </a>{" "}
            (<a href="/deliverables/informe-ejecutivo.pdf">PDF</a>) — resumen
            para stakeholders
          </li>
          <li>
            <a href="/deliverables/remediaciones.md">Remediaciones</a>{" "}
            (diffs propuestos:{" "}
            <a href="/deliverables/remediaciones.patch">patch</a>,{" "}
            <a href="/deliverables/remediaciones.json">json</a>)
          </li>
          <li>
            <a href="/deliverables/ranking-riesgo.html">
              Ranking multi-repo
            </a>{" "}
            (<a href="/deliverables/ranking-riesgo.csv">csv</a>)
          </li>
          <li>
            <a href="/deliverables/c4-context.mmd">C4 contexto</a> ·{" "}
            <a href="/deliverables/c4-container.mmd">C4 contenedores</a>
          </li>
          <li>
            <a href="/deliverables/roadmap.md">Roadmap</a> ·{" "}
            <a href="/deliverables/backlog.csv">Backlog CSV</a> ·{" "}
            <a href="/deliverables/backlog.json">Backlog JSON</a>
          </li>
          <li>
            Reporte maestro: <a href="/audit-report.json">audit-report.json</a>{" "}
            · Evolución: <a href="/audit-history.json">audit-history.json</a>
          </li>
        </ul>
      </section>
      {sections.map(([title, table]) => (
        <section key={title}>
          <h2>{title}</h2>
          {table}
        </section>
      ))}
      <p id="meta">Fuente: {source}</p>
    </main>
  );
}
