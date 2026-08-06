"use client";

import { useCallback, useEffect, useRef, useState } from "react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

const STATUS_STYLE = {
  queued: "#6b7280",
  running: "#2563eb",
  done: "#16a34a",
  error: "#dc2626",
};

const STATUS_LABEL = {
  queued: "En cola",
  running: "En curso",
  done: "Finalizado",
  error: "Error",
};

const SEVERITY_COLORS = {
  CRITICAL: "#dc2626",
  HIGH: "#ea580c",
  MEDIUM: "#d97706",
  LOW: "#16a34a",
  INFO: "#2563eb",
};

function formatElapsed(seconds) {
  if (seconds == null) return "—";
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m}m ${s}s`;
}

function formatFecha(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("es-ES", { dateStyle: "short", timeStyle: "short" });
}

function countHallazgos(report) {
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

function SeguimientoJob({ jobId, repo, onCerrar }) {
  const [status, setStatus] = useState("queued");
  const [step, setStep] = useState("En cola");
  const [error, setError] = useState("");
  const [report, setReport] = useState(null);
  const [segundos, setSegundos] = useState(0);
  const [historial, setHistorial] = useState(null);
  const startedAt = useRef(Date.now());
  const cardRef = useRef(null);

  useEffect(() => {
    cardRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);

  useEffect(() => {
    if (!repo) return;
    let detenido = false;
    const params = new URLSearchParams({ limit: "100", status: "done" });
    params.set("repo", repo);
    fetch(`${API}/api/analyses?${params}`)
      .then((r) => (r.ok ? r.json() : { items: [] }))
      .then((d) => {
        if (detenido) return;
        const duraciones = (d.items || [])
          .map((i) => i.duration_seconds)
          .filter((v) => v != null && v > 0);
        if (duraciones.length) {
          setHistorial({
            media:
              duraciones.reduce((a, b) => a + b, 0) / duraciones.length,
            n: duraciones.length,
          });
        }
      })
      .catch(() => {});
    return () => {
      detenido = true;
    };
  }, [repo]);

  useEffect(() => {
    if (status !== "running" && status !== "queued") return;
    const timer = setInterval(() => {
      setSegundos(Math.round((Date.now() - startedAt.current) / 1000));
    }, 1000);
    return () => clearInterval(timer);
  }, [status]);

  useEffect(() => {
    let detenido = false;
    const poll = async () => {
      try {
        const resp = await fetch(`${API}/api/scan/${jobId}`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        if (detenido) return;
        setStatus(data.status);
        setStep(data.step || "");
        if (data.status === "done" && data.report) setReport(data.report);
        if (data.status === "error") setStep(data.error || "Error en el análisis");
      } catch (err) {
        if (!detenido) setError(`No se pudo consultar la API: ${err.message}`);
      }
    };
    poll();
    const timer = setInterval(poll, 2000);
    return () => {
      detenido = true;
      clearInterval(timer);
    };
  }, [jobId]);

  const enCurso = status === "queued" || status === "running";
  const restante =
    historial != null && enCurso
      ? Math.max(0, Math.round(historial.media - segundos))
      : null;
  const progreso =
    historial != null && enCurso
      ? Math.min(100, Math.round((segundos / historial.media) * 100))
      : null;
  if (error) {
    return (
      <div className="project-card" ref={cardRef}>
        <p className="error-banner">{error}</p>
        <button type="button" className="primary" onClick={onCerrar}>
          Cerrar
        </button>
      </div>
    );
  }

  return (
    <div className="project-card" ref={cardRef}>
      <div className="job-head">
        <span className="job-id">
          Análisis <code>{jobId}</code>
        </span>
        <span
          className="badge"
          style={{ background: STATUS_STYLE[status] || "#6b7280" }}
        >
          {STATUS_LABEL[status] || status}
        </span>
      </div>
      {enCurso ? (
        <>
          <div className="job-clock">
            <span className="spinner" aria-hidden="true" />
            <span className="clock">{formatElapsed(segundos)}</span>
            <span className="muted">{step || "Iniciando…"}</span>
          </div>
          {progreso != null ? (
            <div className="progress-track">
              <div
                className="progress-fill"
                style={{ width: `${progreso}%` }}
              />
            </div>
          ) : null}
          <p className="muted">
            {restante != null && restante > 0 ? (
              <>
                Tiempo restante estimado:{" "}
                <strong>{formatElapsed(restante)}</strong> según los{" "}
                {historial.n} análisis anteriores de este repositorio
              </>
            ) : historial != null ? (
              <>
                Duración media de análisis anteriores:{" "}
                {formatElapsed(Math.round(historial.media))}. El análisis está
                en marcha, esto puede tardar unos minutos más.
              </>
            ) : (
              "Primer análisis de este repositorio: sin estimación, pero suele tardar entre 1 y 5 minutos."
            )}
          </p>
        </>
      ) : null}
      {status === "error" ? <p className="error-banner">{step}</p> : null}
      {status === "done" ? (
        <>
          <p className="ok-banner">
            Análisis finalizado en {formatElapsed(segundos)} —{" "}
            <strong>{countHallazgos(report)} hallazgos</strong> en total.
          </p>
          {report ? (
            <ul className="mini-counts">
              <li>SAST: {report.vulnerabilities?.length ?? 0}</li>
              <li>Secretos: {report.secrets?.length ?? 0}</li>
              <li>IaC: {report.iacIssues?.length ?? 0}</li>
              <li>CI/CD: {report.cicdIssues?.length ?? 0}</li>
              <li>Nube: {report.cloudIssues?.length ?? 0}</li>
              <li>LLM: {report.llmFindings?.length ?? 0}</li>
              <li>
                Deps con CVEs: {report.metrics?.dependencyVulnerabilities?.length ?? 0}
              </li>
            </ul>
          ) : null}
          <p className="muted">
            Guardado en la base de datos.{" "}
            <a href={`/consola/analisis/${jobId}`}>Vista de detalle</a>
            {" · "}Reporte JSON:{" "}
            <a href={`${API}/api/analyses/${jobId}`} target="_blank" rel="noreferrer">
              /api/analyses/{jobId}
            </a>
          </p>
        </>
      ) : null}
      {!enCurso ? (
        <button type="button" className="primary" onClick={onCerrar}>
          Cerrar
        </button>
      ) : null}
    </div>
  );
}

function NuevoAnalisis({ onSeguir }) {
  const [repo, setRepo] = useState("");
  const [branch, setBranch] = useState("");
  const [depth, setDepth] = useState("");
  const [label, setLabel] = useState("");
  const [llm, setLlm] = useState(false);
  const [cloud, setCloud] = useState(false);
  const [avanzado, setAvanzado] = useState(false);
  const [memory, setMemory] = useState("");
  const [sonarJson, setSonarJson] = useState(false);
  const [deliverables, setDeliverables] = useState(false);
  const [enviando, setEnviando] = useState(false);
  const [apiError, setApiError] = useState("");

  const enviar = async (e) => {
    e.preventDefault();
    setApiError("");
    setEnviando(true);
    const body = {
      repo: repo.trim() || null,
      branch: branch.trim() || null,
      depth: depth ? Number(depth) : 1,
      label: label.trim() || null,
      llm,
      cloud,
      memory: avanzado && memory.trim() ? memory.trim() : null,
      sonar_json: avanzado && sonarJson ? "sonar-issues.json" : null,
      deliverables: avanzado && deliverables ? "deliverables" : null,
    };
    try {
      const resp = await fetch(`${API}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await resp.json();
      if (!resp.ok) {
        setApiError(
          `La API rechazó el análisis (${resp.status}): ${
            data.detail || JSON.stringify(data)
          }`
        );
        setEnviando(false);
        return;
      }
      onSeguir(data.job_id, repo.trim() || null);
      setEnviando(false);
    } catch (err) {
      setApiError(
        `No se pudo contactar la API en ${API}. Comprueba la variable ` +
          `NEXT_PUBLIC_API_URL del dashboard. (${err.message})`
      );
      setEnviando(false);
    }
  };

  return (
    <section>
      <h2>Nuevo análisis</h2>
      <form className="form" onSubmit={enviar}>
        <label className="field">
          <span>Repositorio (URL git o directorio local/remoto con los ficheros)</span>
          <input
            type="text"
            value={repo}
            onChange={(e) => setRepo(e.target.value)}
            placeholder="https://github.com/org/repo · /ruta/al/directorio · /Volumes/nfs/repo"
          />
          <small className="muted">
            Si empieza por http(s)://, ssh://, git:// o git@ se clona; cualquier
            otra ruta se escanea en el servidor (debe ser accesible por la API).
          </small>
        </label>
        <div className="grid-3">
          <label className="field">
            <span>Rama (opcional)</span>
            <input
              type="text"
              value={branch}
              onChange={(e) => setBranch(e.target.value)}
              placeholder="main"
            />
          </label>
          <label className="field">
            <span>Profundidad de clon (opcional)</span>
            <input
              type="number"
              min="1"
              value={depth}
              onChange={(e) => setDepth(e.target.value)}
              placeholder="1 = clon superficial"
            />
          </label>
          <label className="field">
            <span>Etiqueta (opcional)</span>
            <input
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="p. ej. sprint-12"
            />
          </label>
        </div>
        <div className="checks">
          <label>
            <input type="checkbox" checked={llm} onChange={(e) => setLlm(e.target.checked)} />
            Auditoría LLM (checklists)
          </label>
          <label>
            <input type="checkbox" checked={cloud} onChange={(e) => setCloud(e.target.checked)} />
            Escaneo de nube (AWS/Azure/GCP)
          </label>
        </div>
        <button
          type="button"
          className="link-btn"
          onClick={() => setAvanzado(!avanzado)}
        >
          {avanzado ? "Ocultar opciones avanzadas" : "Opciones avanzadas"}
        </button>
        {avanzado ? (
          <div className="advanced">
            <label className="field">
              <span>Memoria de recurrencias (directorio o URL Qdrant)</span>
              <input
                type="text"
                value={memory}
                onChange={(e) => setMemory(e.target.value)}
                placeholder="/data/memoria o http://qdrant:6333"
              />
            </label>
            <div className="checks">
              <label>
                <input
                  type="checkbox"
                  checked={sonarJson}
                  onChange={(e) => setSonarJson(e.target.checked)}
                />
                Exportar issues a SonarQube
              </label>
              <label>
                <input
                  type="checkbox"
                  checked={deliverables}
                  onChange={(e) => setDeliverables(e.target.checked)}
                />
                Generar entregables de cliente
              </label>
            </div>
          </div>
        ) : null}
        <button type="submit" className="primary" disabled={enviando}>
          {enviando ? "Enviando…" : "Iniciar análisis"}
        </button>
        {apiError ? <p className="error-banner">{apiError}</p> : null}
      </form>
    </section>
  );
}

function ListadoAnalisis({ onSeguir }) {
  const [filtroRepo, setFiltroRepo] = useState("");
  const [sugerencias, setSugerencias] = useState([]);
  const [filtroEstado, setFiltroEstado] = useState("");
  const [desde, setDesde] = useState("");
  const [hasta, setHasta] = useState("");
  const [limit, setLimit] = useState(10);
  const [pagina, setPagina] = useState(0);
  const [data, setData] = useState(null);
  const [cargando, setCargando] = useState(false);
  const [apiError, setApiError] = useState("");
  const [seleccion, setSeleccion] = useState({});
  const [borrando, setBorrando] = useState(false);

  useEffect(() => {
    fetch(`${API}/api/repos`)
      .then((r) => (r.ok ? r.json() : { repos: [] }))
      .then((d) => setSugerencias(d.repos || []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    let detenido = false;
    const params = new URLSearchParams({ limit: String(limit), offset: String(pagina * limit) });
    if (filtroRepo.trim()) params.set("repo", filtroRepo.trim());
    if (filtroEstado) params.set("status", filtroEstado);
    if (desde) params.set("since", `${desde}T00:00:00Z`);
    if (hasta) params.set("until", `${hasta}T23:59:59Z`);
    setCargando(true);
    fetch(`${API}/api/analyses?${params}`)
      .then(async (resp) => {
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const body = await resp.json();
        if (detenido) return;
        setData(body);
        setApiError("");
      })
      .catch((err) => {
        if (!detenido) setApiError(`No se pudo cargar el listado: ${err.message}`);
      })
      .finally(() => {
        if (!detenido) setCargando(false);
      });
    return () => {
      detenido = true;
    };
  }, [filtroRepo, filtroEstado, desde, hasta, limit, pagina]);

  const reescanear = useCallback(
    async (item) => {
      const req = item.request || {};
      const body = {
        repo_url: req.repo_url || null,
        local_path: req.local_path || null,
        branch: item.branch || null,
        label: item.repo ? `re-scan ${item.repo}` : null,
      };
      try {
        const resp = await fetch(`${API}/api/scan`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        const data = await resp.json();
        if (!resp.ok) {
          window.alert(`No se pudo re-escanear (${resp.status}): ${data.detail || ""}`);
          return;
        }
        onSeguir(data.job_id, item.repo || null);
      } catch (err) {
        window.alert(`No se pudo contactar la API: ${err.message}`);
      }
    },
    [onSeguir]
  );

  const descargarJSON = useCallback(async (id) => {
    try {
      const resp = await fetch(`${API}/api/analyses/${id}`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${id}-audit-report.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      window.alert(`No se pudo descargar el reporte: ${err.message}`);
    }
  }, []);

  const borrarAnalisis = useCallback(
    async (ids, descripcion) => {
      if (!window.confirm(`¿Borrar ${descripcion}? Esta acción no se puede deshacer.`)) {
        return;
      }
      setBorrando(true);
      try {
        const resp = await fetch(`${API}/api/analyses`, {
          method: "DELETE",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ids }),
        });
        const body = await resp.json().catch(() => ({}));
        if (!resp.ok) {
          window.alert(`No se pudo borrar (${resp.status}): ${body.detail || ""}`);
          return;
        }
        const idsSet = new Set(ids);
        setSeleccion((prev) => {
          const next = { ...prev };
          ids.forEach((id) => delete next[id]);
          return next;
        });
        setPagina((p) => {
          const visibles = data?.items || [];
          const cuantos = visibles.filter((i) => idsSet.has(i.id)).length;
          if (cuantos === visibles.length && p > 0) return p - 1;
          return p;
        });
        setData((prev) =>
          prev
            ? {
                ...prev,
                total: Math.max(0, prev.total - ids.length),
                items: prev.items.filter((i) => !idsSet.has(i.id)),
              }
            : prev
        );
      } catch (err) {
        window.alert(`No se pudo contactar la API: ${err.message}`);
      } finally {
        setBorrando(false);
      }
    },
    [data]
  );

  const toggleSeleccion = useCallback((id) => {
    setSeleccion((prev) => ({ ...prev, [id]: !prev[id] }));
  }, []);

  const seleccionTodos = useCallback(() => {
    setSeleccion((prev) => {
      const ids = (data?.items || []).map((i) => i.id);
      const todosSeleccionados = ids.length > 0 && ids.every((id) => prev[id]);
      const next = { ...prev };
      ids.forEach((id) => {
        if (todosSeleccionados) delete next[id];
        else next[id] = true;
      });
      return next;
    });
  }, [data]);

  const idsSeleccionados = Object.entries(seleccion)
    .filter(([, v]) => v)
    .map(([id]) => id);

  const totalPaginas = data ? Math.max(1, Math.ceil(data.total / limit)) : 1;

  return (
    <section>
      <h2>Análisis guardados</h2>
      <div className="filtros">
        <label className="field">
          <span>Repositorio</span>
          <input
            type="text"
            list="repos"
            value={filtroRepo}
            onChange={(e) => {
              setFiltroRepo(e.target.value);
              setPagina(0);
            }}
            placeholder="Filtrar por subcadena…"
          />
          <datalist id="repos">
            {sugerencias.map((r) => (
              <option key={r} value={r} />
            ))}
          </datalist>
        </label>
        <label className="field">
          <span>Estado</span>
          <select
            value={filtroEstado}
            onChange={(e) => {
              setFiltroEstado(e.target.value);
              setPagina(0);
            }}
          >
            <option value="">Todos</option>
            <option value="queued">En cola</option>
            <option value="running">En curso</option>
            <option value="done">Finalizado</option>
            <option value="error">Error</option>
          </select>
        </label>
        <label className="field">
          <span>Desde</span>
          <input
            type="date"
            value={desde}
            onChange={(e) => {
              setDesde(e.target.value);
              setPagina(0);
            }}
          />
        </label>
        <label className="field">
          <span>Hasta</span>
          <input
            type="date"
            value={hasta}
            onChange={(e) => {
              setHasta(e.target.value);
              setPagina(0);
            }}
          />
        </label>
        <label className="field">
          <span>Por página</span>
          <select
            value={limit}
            onChange={(e) => {
              setLimit(Number(e.target.value));
              setPagina(0);
            }}
          >
            <option value={5}>5</option>
            <option value={10}>10</option>
            <option value={25}>25</option>
            <option value={50}>50</option>
          </select>
        </label>
      </div>
      {apiError ? <p className="error-banner">{apiError}</p> : null}
      {cargando ? <p className="muted">Cargando…</p> : null}
      {data && !cargando ? (
        data.items.length === 0 ? (
          <p>No hay análisis que coincidan con los filtros.</p>
        ) : (
          <>
            {idsSeleccionados.length > 0 ? (
              <div className="sel-bar">
                <span>
                  <strong>{idsSeleccionados.length}</strong> seleccionado
                  {idsSeleccionados.length > 1 ? "s" : ""}
                </span>
                <button
                  type="button"
                  className="danger"
                  onClick={() =>
                    borrarAnalisis(idsSeleccionados, `${idsSeleccionados.length} análisis seleccionados`)
                  }
                  disabled={borrando}
                >
                  {borrando ? "Borrando…" : "Borrar seleccionados"}
                </button>
                <button
                  type="button"
                  className="link-btn"
                  onClick={() => setSeleccion({})}
                >
                  Limpiar selección
                </button>
              </div>
            ) : null}
            <table>
              <thead>
                <tr>
                  <th>
                    <input
                      type="checkbox"
                      aria-label="Seleccionar todos"
                      checked={
                        (data?.items || []).length > 0 &&
                        (data?.items || []).every((i) => seleccion[i])
                      }
                      onChange={seleccionTodos}
                    />
                  </th>
                  <th>Repo</th>
                  <th>Rama</th>
                  <th>Commit</th>
                  <th>Inicio</th>
                  <th>Duración</th>
                  <th>Estado</th>
                  <th>Hallazgos</th>
                  <th>Acciones</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((item) => {
                  const summary = item.summary || {};
                  const label = item.request?.label;
                  return (
                    <tr key={item.id} className={seleccion[item.id] ? "sel-row" : ""}>
                      <td>
                        <input
                          type="checkbox"
                          aria-label={`Seleccionar ${item.id}`}
                          checked={!!seleccion[item.id]}
                          onChange={() => toggleSeleccion(item.id)}
                        />
                      </td>
                      <td>
                        <code>{item.repo || "—"}</code>
                        {label ? <div className="chip">{label}</div> : null}
                      </td>
                      <td>{item.branch || "—"}</td>
                      <td>
                        {item.commit_hash ? (
                          <code>{item.commit_hash.slice(0, 10)}</code>
                        ) : (
                          "—"
                        )}
                      </td>
                      <td>{formatFecha(item.started_at)}</td>
                      <td>{formatElapsed(item.duration_seconds)}</td>
                      <td>
                        <span
                          className="badge"
                          style={{ background: STATUS_STYLE[item.status] || "#6b7280" }}
                        >
                          {STATUS_LABEL[item.status] || item.status}
                        </span>
                      </td>
                      <td>
                        <strong>{summary.total ?? 0}</strong>{" "}
                        {Object.entries(summary.by_severity || {}).map(
                          ([sev, n]) =>
                            n > 0 ? (
                              <span
                                key={sev}
                                className="sev-chip"
                                style={{
                                  color: SEVERITY_COLORS[sev] || "#6b7280",
                                  borderColor: SEVERITY_COLORS[sev] || "#6b7280",
                                }}
                              >
                                {sev}: {n}
                              </span>
                            ) : null
                        )}
                      </td>
                      <td>
                        <span className="acciones">
                          <a href={`/consola/analisis/${item.id}`}>Ver</a>
                          <button
                            type="button"
                            className="link-btn"
                            onClick={() => reescanear(item)}
                            disabled={!item.request?.repo_url && !item.request?.local_path}
                          >
                            Re-escanear
                          </button>
                          <button
                            type="button"
                            className="link-btn"
                            onClick={() => descargarJSON(item.id)}
                            disabled={!item.has_report}
                          >
                            Descargar JSON
                          </button>
                          <button
                            type="button"
                            className="link-btn danger-link"
                            onClick={() => borrarAnalisis([item.id], "este análisis")}
                            disabled={borrando}
                          >
                            Borrar
                          </button>
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <div className="paginacion">
              <button
                type="button"
                className="link-btn"
                onClick={() => setPagina(Math.max(0, pagina - 1))}
                disabled={pagina === 0}
              >
                ← Anterior
              </button>
              <span className="muted">
                Página {pagina + 1} de {totalPaginas} · {data.total} análisis
              </span>
              <button
                type="button"
                className="link-btn"
                onClick={() => setPagina(Math.min(totalPaginas - 1, pagina + 1))}
                disabled={pagina >= totalPaginas - 1}
              >
                Siguiente →
              </button>
            </div>
          </>
        )
      ) : null}
    </section>
  );
}

export default function Consola() {
  const [tracking, setTracking] = useState(null);
  const [apiVersion, setApiVersion] = useState("");

  useEffect(() => {
    fetch(`${API}/api/health`)
      .then((r) => (r.ok ? r.json() : {}))
      .then((d) => setApiVersion(d.version || ""))
      .catch(() => {});
  }, []);

  const cerrarSeguimiento = useCallback(() => setTracking(null), []);
  const seguir = useCallback((jobId, repo) => setTracking({ jobId, repo }), []);

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
        <h1>VibeAudit — Consola</h1>
      </header>
      <p>
        <a href="/">← Volver al dashboard de cliente</a>
      </p>
      {tracking ? (
        <SeguimientoJob
          jobId={tracking.jobId}
          repo={tracking.repo}
          onCerrar={cerrarSeguimiento}
        />
      ) : null}
      <NuevoAnalisis onSeguir={seguir} />
      <ListadoAnalisis onSeguir={seguir} />
      <footer className="footer">
        <span>VibeAudit v0.2.0 · Consola de análisis</span>
        <span>{apiVersion ? `API v${apiVersion}` : ""}</span>
        <span>© {new Date().getFullYear()} andiso67</span>
        <span>Pre-auditoría de seguridad con VibeAudit para Improven</span>
      </footer>
    </main>
  );
}
