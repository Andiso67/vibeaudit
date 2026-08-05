export const SEVERITY_COLORS = {
  CRITICAL: "#dc2626",
  HIGH: "#ea580c",
  MEDIUM: "#d97706",
  LOW: "#16a34a",
  INFO: "#2563eb",
};

export const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export function Badge({ severity }) {
  return (
    <span
      className="badge"
      style={{ background: SEVERITY_COLORS[severity] || "#6b7280" }}
    >
      {severity}
    </span>
  );
}

export function IssueTable({ items }) {
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

export function CloudResourcesTable({ items }) {
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

export function CloudTable({ items }) {
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

export function DepsTable({ items }) {
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

export function LlmTable({ items }) {
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

export function RecurrentTable({ items }) {
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

export function countHallazgos(report) {
  const groups = [
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
  return groups.reduce((sum, g) => sum + (g?.length || 0), 0);
}
