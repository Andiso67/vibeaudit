# Propuestas de remediación — bojuboard-main

Generadas por vibeaudit el 2026-08-05. **Ninguna acción se aplica automáticamente**:
cada una requiere aprobación explícita del operador.

## 1. Crítica — Actualizar Next.js (CVE-2025-29927)
- **Hallazgo**: `next@14.2.15` → CVE-2025-29927 "Authorization Bypass in Next.js Middleware" (CVSS 9.1), más 27 CVEs HIGH (SSRF, DoS, request smuggling).
- **Acción propuesta**: `npm install next@14.2.25` (o migrar a Next 15).
- **Riesgo del cambio**: bajo; parche de seguridad menor. Requiere re-test del login/middleware.
- **Estado**: PENDIENTE DE APROBACIÓN

## 2. Alta — Actualizar xlsx (prototype pollution + ReDoS)
- **Hallazgo**: `xlsx@0.18.5` → CVE-2023-30533 (prototype pollution) y CVE-2024-22363 (ReDoS).
- **Acción propuesta**: `npm install xlsx@0.19.3` o migrar a `exceljs`.
- **Riesgo del cambio**: medio; revisar API de hojas de cálculo usada en `bojucontratos/analyze`.
- **Estado**: PENDIENTE DE APROBACIÓN

## 3. Media — Deps transitivas (ajv, minimatch, brace-expansion, fast-uri, postcss, lodash...)
- **Hallazgo**: 44 HIGH / 1 CRITICAL en el árbol transitivo.
- **Acción propuesta**: `npm audit fix` + revisar `npm audit` (bloquear las que requieran breaking change).
- **Riesgo del cambio**: bajo (resuelve el árbol sin tocar código).
- **Estado**: PENDIENTE DE APROBACIÓN

## 4. Media — console.log en producción (53)
- **Hallazgo**: regla custom `vibe-js-console-log`, p.ej. `src/app/api/bojucalendar/user-role/route.ts`, `src/app/api/bojucontratos/analyze/route.ts`.
- **Acción propuesta**: sustituir por logger estructurado o eliminar en rutas API.
- **Riesgo del cambio**: bajo.
- **Estado**: PENDIENTE DE APROBACIÓN

## 5. Media — Non-null assertions (20)
- **Hallazgo**: `vibe-ts-non-null-assertion` (`!`).
- **Acción propuesta**: revisar y reemplazar por guards (son puntos probables de crash en runtime).
- **Riesgo del cambio**: bajo.
- **Estado**: PENDIENTE DE APROBACIÓN

## 6. Baja — TODO/FIXME pendientes (9)
- **Acción propuesta**: triaje manual en sesión de revisión.
- **Estado**: PENDIENTE DE APROBACIÓN

---
**Aprobación**: responde con los números de las propuestas que apruebas
(ej. "apruebo 1 y 2") para generar el plan de ejecución. Nada se aplica sin tu visto bueno.
