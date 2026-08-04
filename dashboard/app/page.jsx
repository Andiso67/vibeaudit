import fs from "node:fs";
import path from "node:path";

export const dynamic = "force-dynamic";

const SEVERITY_COLORS = {
  CRITICAL: "#dc2626",
  HIGH: "#ea580c",
  MEDIUM: "#d97706",
  LOW: "#16a34a",
  INFO: "#2563eb",
};

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

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

function Badge({ severity }) {
  return (
    <span
      className="badge"
      style={{ background: SEVERITY_COLORS[severity] || "#6b7280" }}
    >
      {severity}
    </span>
  );
}

function IssueTable({ items }) {
  if (!items || items.length === 0) {
    return <p>No se encontraron hallazgos.</p>;
  }
  return (
    <table>
      <thead>
        <tr>
          <th>Regla</th>
          <th>Archivo</th>
          <th>Severidad</th>
          <th>Detalle</th>
        </tr>
      </thead>
      <tbody>
        {items.map((item, i) => (
          <tr key={i}>
            <td>
              <code>{item.rule || item.type}</code>
            </td>
            <td>
              {item.file}:{item.line}
            </td>
            <td>
              <Badge severity={item.severity} />
            </td>
            <td>{item.snippet ? <pre>{item.snippet}</pre> : ""}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function CloudResourcesTable({ items }) {
  if (!items || items.length === 0) {
    return <p>No se analizaron recursos de nube en este reporte.</p>;
  }
  return (
    <table>
      <thead>
        <tr>
          <th>Proveedor</th>
          <th>Tipo</th>
          <th>Recurso</th>
          <th>Región</th>
          <th>Estado</th>
        </tr>
      </thead>
      <tbody>
        {items.map((item, i) => (
          <tr key={i}>
            <td>{item.provider}</td>
            <td>{item.resource_type}</td>
            <td>
              <code>{item.resource}</code>
            </td>
            <td>{item.region || "—"}</td>
            <td>
              <Badge severity={item.status === "issue" ? "HIGH" : "INFO"} />
              {item.status === "issue" ? "con hallazgo" : "analizado (ok)"}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function CloudTable({ items }) {
  if (!items || items.length === 0) {
    return <p>No se encontraron hallazgos.</p>;
  }
  return (
    <table>
      <thead>
        <tr>
          <th>Regla</th>
          <th>Proveedor</th>
          <th>Recurso</th>
          <th>Severidad</th>
          <th>Detalle</th>
        </tr>
      </thead>
      <tbody>
        {items.map((item, i) => (
          <tr key={i}>
            <td>
              <code>{item.rule}</code>
            </td>
            <td>{item.provider}</td>
            <td>
              <code>{item.resource}</code>
            </td>
            <td>
              <Badge severity={item.severity} />
            </td>
            <td>
              {item.description}
              {item.recommendation ? (
                <>
                  {" "}
                  <strong>Recomendación:</strong> {item.recommendation}
                </>
              ) : null}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function DepsTable({ items }) {
  if (!items || items.length === 0) {
    return <p>No se encontraron hallazgos.</p>;
  }
  return (
    <table>
      <thead>
        <tr>
          <th>Paquete</th>
          <th>Ecosistema</th>
          <th>Severidad</th>
          <th>Detalle</th>
        </tr>
      </thead>
      <tbody>
        {items.map((item, i) => (
          <tr key={i}>
            <td>
              <code>
                {item.name}@{item.version}
              </code>
            </td>
            <td>{item.ecosystem}</td>
            <td>
              <Badge severity={item.severity} />
            </td>
            <td>
              {item.fixedVersion ? (
                <>
                  corregida en <code>{item.fixedVersion}</code>
                </>
              ) : (
                "sin fix"
              )}
              {item.cveIds?.length ? ` — ${item.cveIds.join(", ")}` : ""}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function LlmTable({ items }) {
  if (!items || items.length === 0) {
    return <p>No se encontraron hallazgos.</p>;
  }
  return (
    <table>
      <thead>
        <tr>
          <th>Hallazgo</th>
          <th>Checklist</th>
          <th>Severidad</th>
          <th>Detalle</th>
        </tr>
      </thead>
      <tbody>
        {items.map((item, i) => (
          <tr key={i}>
            <td>{item.title}</td>
            <td>{item.checklistRef || "—"}</td>
            <td>
              <Badge severity={item.severity} />
            </td>
            <td>
              {item.evidence}
              {item.recommendation ? (
                <>
                  {" "}
                  <strong>Recomendación:</strong> {item.recommendation}
                </>
              ) : null}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function RecurrentTable({ items }) {
  if (!items || items.length === 0) {
    return <p>No se encontraron hallazgos.</p>;
  }
  return (
    <table>
      <thead>
        <tr>
          <th>Regla</th>
          <th>Ocurrencias</th>
          <th>Severidad</th>
          <th>Sugerencia</th>
        </tr>
      </thead>
      <tbody>
        {items.map((item, i) => (
          <tr key={i}>
            <td>
              <code>{item.rule}</code>
            </td>
            <td>{item.occurrences}</td>
            <td>
              <Badge severity={item.severity} />
            </td>
            <td>{item.suggestion || "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function Page() {
  const loaded = loadReport();
  if (!loaded) {
    return (
      <main className="container">
        <h1>VibeAudit — Dashboard de cliente</h1>
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
      <h1>VibeAudit — Dashboard de cliente</h1>
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
