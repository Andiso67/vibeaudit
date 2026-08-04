# Roadmap de remediación — golf-tracker

**Repositorio:** https://github.com/Andiso67/golf-tracker.git

**Total de hallazgos considerados:** 83

## Fase 1

Remediación inmediata (0-2 semanas): riesgos graves o explotables.

| ID | Tipo | Regla | Archivo | Severidad |
|---|---|---|---|---|
| `sast-dockerfile.security.missing-user.missing-user` | sast | `dockerfile.security.missing-user.missing-user` | Dockerfile:29 | **HIGH** |
| `sast-javascript.lang.security.detect-child-process.detect-child-process` | sast | `javascript.lang.security.detect-child-process.detect-child-process` | scripts/scrape-rfeg.js:22 | **HIGH** |
| `iac-CKV_DOCKER_2` | iac | `CKV_DOCKER_2` | Dockerfile:1 | **HIGH** |
| `iac-CKV_DOCKER_3` | iac | `CKV_DOCKER_3` | Dockerfile:1 | **HIGH** |
| `custom-vibeaudit.rules.vibe-eval` | custom | `vibeaudit.rules.vibe-eval` | scripts/extract-data.js:71 | **HIGH** |
| `custom-vibeaudit.rules.vibe-eval` | custom | `vibeaudit.rules.vibe-eval` | scripts/extract-data.js:77 | **HIGH** |
| `cloud-aws-ec2-security-group-open` | cloud | `aws-ec2-security-group-open` | sg-0b173d608eadc8fa3: | **HIGH** |
| `deps-brace-expansion@1.1.15` | deps | `brace-expansion@1.1.15` |  | **HIGH** |
| `deps-brace-expansion@1.1.15` | deps | `brace-expansion@1.1.15` |  | **HIGH** |
| `deps-brace-expansion@1.1.15` | deps | `brace-expansion@1.1.15` |  | **HIGH** |
| `deps-fast-uri@3.1.2` | deps | `fast-uri@3.1.2` |  | **HIGH** |
| `deps-fast-uri@3.1.2` | deps | `fast-uri@3.1.2` |  | **HIGH** |
| `deps-fast-uri@3.1.2` | deps | `fast-uri@3.1.2` |  | **HIGH** |
| `deps-js-yaml@4.2.0` | deps | `js-yaml@4.2.0` |  | **HIGH** |
| `deps-next@16.2.9` | deps | `next@16.2.9` |  | **HIGH** |
| `deps-next@16.2.9` | deps | `next@16.2.9` |  | **HIGH** |
| `deps-next@16.2.9` | deps | `next@16.2.9` |  | **HIGH** |
| `deps-next@16.2.9` | deps | `next@16.2.9` |  | **HIGH** |
| `deps-next@16.2.9` | deps | `next@16.2.9` |  | **HIGH** |
| `deps-next@16.2.9` | deps | `next@16.2.9` |  | **HIGH** |
| `deps-next@16.2.9` | deps | `next@16.2.9` |  | **HIGH** |
| `deps-next@16.2.9` | deps | `next@16.2.9` |  | **HIGH** |
| `deps-next@16.2.9` | deps | `next@16.2.9` |  | **HIGH** |
| `deps-postcss@8.4.31` | deps | `postcss@8.4.31` |  | **HIGH** |
| `deps-postcss@8.4.31` | deps | `postcss@8.4.31` |  | **HIGH** |
| `deps-postcss@8.4.31` | deps | `postcss@8.4.31` |  | **HIGH** |
| `deps-sharp@0.34.5` | deps | `sharp@0.34.5` |  | **HIGH** |
| `deps-valibot@1.2.0` | deps | `valibot@1.2.0` |  | **HIGH** |

## Fase 2

Remediación a corto plazo (2-6 semanas): endurecer y reducir superficie.

| ID | Tipo | Regla | Archivo | Severidad |
|---|---|---|---|---|
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | prisma/seed.ts:33 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | prisma/seed.ts:53 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | prisma/seed.ts:61 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | prisma/seed.ts:75 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | prisma/seed.ts:106 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | prisma/seed.ts:131 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | prisma/seed.ts:158 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | prisma/seed.ts:217 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | prisma/seed.ts:230 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | prisma/seed.ts:232 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/extract-data.js:61 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/extract-data.js:79 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/extract-data.js:84 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/extract-data.js:85 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/extract-data.js:90 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/extract-data.js:95 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/extract-data.js:100 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/extract-data.js:109 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/extract-data.js:112 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/extract-data.js:115 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/scrape-rfeg.js:138 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/scrape-rfeg.js:140 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/scrape-rfeg.js:142 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/scrape-rfeg.js:144 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/scrape-rfeg.js:148 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/scrape-rfeg.js:160 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/scrape-rfeg.js:170 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/scrape-rfeg.js:203 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/scrape-rfeg.js:205 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/scrape-rfeg.js:222 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/scrape-rfeg.js:223 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/scrape-rfeg.js:224 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/scrape-rfeg.js:225 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/seed.ts:10 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/seed.ts:11 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/seed.ts:16 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/seed.ts:42 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/seed.ts:56 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/seed.ts:74 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/seed.ts:128 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/seed.ts:174 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/seed.ts:176 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | scripts/seed.ts:177 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | src/app/api/auth/forgot-password/route.ts:31 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-js-console-log` | custom | `vibeaudit.rules.vibe-js-console-log` | src/app/api/auth/register/route.ts:45 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-ts-non-null-assertion` | custom | `vibeaudit.rules.vibe-ts-non-null-assertion` | src/store/useStore.ts:138 | **MEDIUM** |
| `custom-vibeaudit.rules.vibe-ts-non-null-assertion` | custom | `vibeaudit.rules.vibe-ts-non-null-assertion` | src/store/useStore.ts:389 | **MEDIUM** |
| `deps-@hono/node-server@1.19.11` | deps | `@hono/node-server@1.19.11` |  | **MEDIUM** |
| `deps-@hono/node-server@1.19.11` | deps | `@hono/node-server@1.19.11` |  | **MEDIUM** |
| `deps-hono@4.12.26` | deps | `hono@4.12.26` |  | **MEDIUM** |
| `deps-hono@4.12.26` | deps | `hono@4.12.26` |  | **MEDIUM** |
| `deps-hono@4.12.26` | deps | `hono@4.12.26` |  | **MEDIUM** |
| `deps-hono@4.12.26` | deps | `hono@4.12.26` |  | **MEDIUM** |
| `deps-postcss@8.4.31` | deps | `postcss@8.4.31` |  | **MEDIUM** |

## Fase 3

Mejora continua (más de 6 semanas): higiene y deuda técnica.

| ID | Tipo | Regla | Archivo | Severidad |
|---|---|---|---|---|
| `custom-vibeaudit.rules.vibe-todo-fixme` | custom | `vibeaudit.rules.vibe-todo-fixme` | Prueba.md:208 | **LOW** |
