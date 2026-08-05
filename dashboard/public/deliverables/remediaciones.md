# Informe de remediación (diffs propuestos)

_Generado por VibeAudit 2026-08-05 11:14 UTC. Solo informativo: nada se aplica automáticamente._

Total: 158 propuestas — 53 con diff, 66 solo comando, 39 revisión manual.

### 1. [LOW] vibe-todo-fixme — `docs/00_AGENTS.md:162` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 2. [LOW] vibe-todo-fixme — `docs/00_AGENTS.md:170` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 3. [LOW] vibe-todo-fixme — `docs/01_ARCHITECTURE.md:160` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 4. [LOW] vibe-todo-fixme — `docs/02_MODULES.md:528` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 5. [LOW] vibe-todo-fixme — `migrations/017_empresas_grupo.sql:37` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 6. [MEDIUM] vibe-js-console-log — `src/app/api/bojucalendar/user-role/route.ts:30` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucalendar/user-role/route.ts b/src/app/api/bojucalendar/user-role/route.ts
--- a/src/app/api/bojucalendar/user-role/route.ts+++ b/src/app/api/bojucalendar/user-role/route.ts@@ -27,7 +27,6 @@       );     } -    console.log('✅ Perfil obtenido correctamente');     return NextResponse.json({ rol: profile.rol, tecnico_id: profile.tecnico_id ?? null });        } catch (error) {
```


### 7. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/analyze/route.ts:15` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/analyze/route.ts b/src/app/api/bojucontratos/analyze/route.ts
--- a/src/app/api/bojucontratos/analyze/route.ts+++ b/src/app/api/bojucontratos/analyze/route.ts@@ -12,7 +12,6 @@   const auth = await requireRole(['admin']);   if (!auth.ok) return auth.response; -  console.log('========================================');   console.log('BOJUCONTRATOS: API /analyze iniciada');   console.log('========================================');   
```


### 8. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/analyze/route.ts:16` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/analyze/route.ts b/src/app/api/bojucontratos/analyze/route.ts
--- a/src/app/api/bojucontratos/analyze/route.ts+++ b/src/app/api/bojucontratos/analyze/route.ts@@ -13,7 +13,6 @@   if (!auth.ok) return auth.response;    console.log('========================================');-  console.log('BOJUCONTRATOS: API /analyze iniciada');   console.log('========================================');      try {
```


### 9. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/analyze/route.ts:17` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/analyze/route.ts b/src/app/api/bojucontratos/analyze/route.ts
--- a/src/app/api/bojucontratos/analyze/route.ts+++ b/src/app/api/bojucontratos/analyze/route.ts@@ -14,7 +14,6 @@    console.log('========================================');   console.log('BOJUCONTRATOS: API /analyze iniciada');-  console.log('========================================');      try {     const body = await request.json();
```


### 10. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/analyze/route.ts:21` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/analyze/route.ts b/src/app/api/bojucontratos/analyze/route.ts
--- a/src/app/api/bojucontratos/analyze/route.ts+++ b/src/app/api/bojucontratos/analyze/route.ts@@ -18,7 +18,6 @@      try {     const body = await request.json();-    console.log('BOJUCONTRATOS: Body parseado correctamente');      const { contractPdfBase64 } = body; 
```


### 11. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/analyze/route.ts:33` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/analyze/route.ts b/src/app/api/bojucontratos/analyze/route.ts
--- a/src/app/api/bojucontratos/analyze/route.ts+++ b/src/app/api/bojucontratos/analyze/route.ts@@ -30,7 +30,6 @@       );     } -    console.log('BOJUCONTRATOS: PDF recibido (base64)');      // Validar tamaño     let pdfBuffer;
```


### 12. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/analyze/route.ts:58` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/analyze/route.ts b/src/app/api/bojucontratos/analyze/route.ts
--- a/src/app/api/bojucontratos/analyze/route.ts+++ b/src/app/api/bojucontratos/analyze/route.ts@@ -55,7 +55,6 @@       );     } -    console.log('BOJUCONTRATOS: Tamaño validado OK');      // Extraer texto     console.log('BOJUCONTRATOS: Iniciando extracción de texto...');
```


### 13. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/analyze/route.ts:61` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/analyze/route.ts b/src/app/api/bojucontratos/analyze/route.ts
--- a/src/app/api/bojucontratos/analyze/route.ts+++ b/src/app/api/bojucontratos/analyze/route.ts@@ -58,7 +58,6 @@     console.log('BOJUCONTRATOS: Tamaño validado OK');      // Extraer texto-    console.log('BOJUCONTRATOS: Iniciando extracción de texto...');     let extractedText;     try {       extractedText = await extractTextFromPdf(contractPdfBase64);
```


### 14. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/analyze/route.ts:88` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/analyze/route.ts b/src/app/api/bojucontratos/analyze/route.ts
--- a/src/app/api/bojucontratos/analyze/route.ts+++ b/src/app/api/bojucontratos/analyze/route.ts@@ -85,7 +85,6 @@       );     } -    console.log('BOJUCONTRATOS: Texto validado OK');      // Analizar con GPT     console.log('BOJUCONTRATOS: Iniciando análisis con GPT...');
```


### 15. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/analyze/route.ts:91` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/analyze/route.ts b/src/app/api/bojucontratos/analyze/route.ts
--- a/src/app/api/bojucontratos/analyze/route.ts+++ b/src/app/api/bojucontratos/analyze/route.ts@@ -88,7 +88,6 @@     console.log('BOJUCONTRATOS: Texto validado OK');      // Analizar con GPT-    console.log('BOJUCONTRATOS: Iniciando análisis con GPT...');     let analysis;     try {       analysis = await analyzeContract(extractedText);
```


### 16. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/analyze/route.ts:95` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/analyze/route.ts b/src/app/api/bojucontratos/analyze/route.ts
--- a/src/app/api/bojucontratos/analyze/route.ts+++ b/src/app/api/bojucontratos/analyze/route.ts@@ -92,7 +92,6 @@     let analysis;     try {       analysis = await analyzeContract(extractedText);-      console.log('BOJUCONTRATOS: Análisis GPT completado OK');     } catch (error) {       console.error('ERROR BOJUCONTRATOS: Error en análisis GPT:', error);       return NextResponse.json(
```


### 17. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/analyze/route.ts:107` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/analyze/route.ts b/src/app/api/bojucontratos/analyze/route.ts
--- a/src/app/api/bojucontratos/analyze/route.ts+++ b/src/app/api/bojucontratos/analyze/route.ts@@ -104,7 +104,6 @@       );     } -    console.log('========================================');     console.log('BOJUCONTRATOS: API completada con éxito');     console.log('========================================'); 
```


### 18. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/analyze/route.ts:108` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/analyze/route.ts b/src/app/api/bojucontratos/analyze/route.ts
--- a/src/app/api/bojucontratos/analyze/route.ts+++ b/src/app/api/bojucontratos/analyze/route.ts@@ -105,7 +105,6 @@     }      console.log('========================================');-    console.log('BOJUCONTRATOS: API completada con éxito');     console.log('========================================');      return NextResponse.json({
```


### 19. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/analyze/route.ts:109` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/analyze/route.ts b/src/app/api/bojucontratos/analyze/route.ts
--- a/src/app/api/bojucontratos/analyze/route.ts+++ b/src/app/api/bojucontratos/analyze/route.ts@@ -106,7 +106,6 @@      console.log('========================================');     console.log('BOJUCONTRATOS: API completada con éxito');-    console.log('========================================');      return NextResponse.json({       success: true,
```


### 20. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/obras/route.ts:12` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/obras/route.ts b/src/app/api/bojucontratos/obras/route.ts
--- a/src/app/api/bojucontratos/obras/route.ts+++ b/src/app/api/bojucontratos/obras/route.ts@@ -9,7 +9,6 @@   if (!auth.ok) return auth.response;    try {-    console.log('BOJUCONTRATOS: Cargando obras...');          const supabase = createServerClient(); 
```


### 21. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/save-result/route.ts:15` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/save-result/route.ts b/src/app/api/bojucontratos/save-result/route.ts
--- a/src/app/api/bojucontratos/save-result/route.ts+++ b/src/app/api/bojucontratos/save-result/route.ts@@ -12,7 +12,6 @@   const auth = await requireRole(['admin']);   if (!auth.ok) return auth.response; -  console.log('========================================');   console.log('BOJUCONTRATOS: API /save-result iniciada');   console.log('========================================');   
```


### 22. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/save-result/route.ts:16` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/save-result/route.ts b/src/app/api/bojucontratos/save-result/route.ts
--- a/src/app/api/bojucontratos/save-result/route.ts+++ b/src/app/api/bojucontratos/save-result/route.ts@@ -13,7 +13,6 @@   if (!auth.ok) return auth.response;    console.log('========================================');-  console.log('BOJUCONTRATOS: API /save-result iniciada');   console.log('========================================');      try {
```


### 23. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/save-result/route.ts:17` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/save-result/route.ts b/src/app/api/bojucontratos/save-result/route.ts
--- a/src/app/api/bojucontratos/save-result/route.ts+++ b/src/app/api/bojucontratos/save-result/route.ts@@ -14,7 +14,6 @@    console.log('========================================');   console.log('BOJUCONTRATOS: API /save-result iniciada');-  console.log('========================================');      try {     const body = await request.json();
```


### 24. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/save-result/route.ts:21` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/save-result/route.ts b/src/app/api/bojucontratos/save-result/route.ts
--- a/src/app/api/bojucontratos/save-result/route.ts+++ b/src/app/api/bojucontratos/save-result/route.ts@@ -18,7 +18,6 @@      try {     const body = await request.json();-    console.log('BOJUCONTRATOS: Body parseado correctamente');      const { analysis, obraId, obraName } = body; 
```


### 25. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/save-result/route.ts:33` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/save-result/route.ts b/src/app/api/bojucontratos/save-result/route.ts
--- a/src/app/api/bojucontratos/save-result/route.ts+++ b/src/app/api/bojucontratos/save-result/route.ts@@ -30,7 +30,6 @@       );     } -    console.log('BOJUCONTRATOS: Generando PDF resumen...');          // Generar PDF     let pdfBuffer: Buffer;
```


### 26. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/save-result/route.ts:39` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/save-result/route.ts b/src/app/api/bojucontratos/save-result/route.ts
--- a/src/app/api/bojucontratos/save-result/route.ts+++ b/src/app/api/bojucontratos/save-result/route.ts@@ -36,7 +36,6 @@     let pdfBuffer: Buffer;     try {       pdfBuffer = await generateSummaryPdf(analysis as ContractAnalysis, obraName);-      console.log('BOJUCONTRATOS: PDF generado OK');     } catch (error) {       console.error('ERROR BOJUCONTRATOS: Error generando PDF:', error);       return NextResponse.json(
```


### 27. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/save-result/route.ts:52` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/save-result/route.ts b/src/app/api/bojucontratos/save-result/route.ts
--- a/src/app/api/bojucontratos/save-result/route.ts+++ b/src/app/api/bojucontratos/save-result/route.ts@@ -49,7 +49,6 @@     const supabase = createServerClient();      // Obtener versión actual-    console.log('BOJUCONTRATOS: Obteniendo versión actual...');     const { data: existingReviews, error: versionError } = await supabase       .schema('api')       .from('contract_reviews')
```


### 28. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/save-result/route.ts:79` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/save-result/route.ts b/src/app/api/bojucontratos/save-result/route.ts
--- a/src/app/api/bojucontratos/save-result/route.ts+++ b/src/app/api/bojucontratos/save-result/route.ts@@ -76,7 +76,6 @@     const fileName = `${obraId}_v${nextVersion}_${Date.now()}.pdf`;     const filePath = `summaries/${fileName}`; -    console.log('BOJUCONTRATOS: Subiendo PDF a Storage...');     const { error: uploadError } = await supabase.storage       .from('boju-contracts')       .upload(filePath, pdfBuffer, {
```


### 29. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/save-result/route.ts:95` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/save-result/route.ts b/src/app/api/bojucontratos/save-result/route.ts
--- a/src/app/api/bojucontratos/save-result/route.ts+++ b/src/app/api/bojucontratos/save-result/route.ts@@ -92,7 +92,6 @@       );     } -    console.log('BOJUCONTRATOS: PDF subido OK');      // Obtener URL pública     const { data: urlData } = supabase.storage
```


### 30. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/save-result/route.ts:106` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/save-result/route.ts b/src/app/api/bojucontratos/save-result/route.ts
--- a/src/app/api/bojucontratos/save-result/route.ts+++ b/src/app/api/bojucontratos/save-result/route.ts@@ -103,7 +103,6 @@     console.log('BOJUCONTRATOS: URL pública:', pdfUrl);      // Guardar en base de datos-    console.log('BOJUCONTRATOS: Guardando en base de datos...');     const { data: reviewData, error: insertError } = await supabase       .schema('api')       .from('contract_reviews')
```


### 31. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/save-result/route.ts:129` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/save-result/route.ts b/src/app/api/bojucontratos/save-result/route.ts
--- a/src/app/api/bojucontratos/save-result/route.ts+++ b/src/app/api/bojucontratos/save-result/route.ts@@ -126,7 +126,6 @@       );     } -    console.log('========================================');     console.log('BOJUCONTRATOS: Guardado completado con éxito');     console.log('========================================'); 
```


### 32. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/save-result/route.ts:130` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/save-result/route.ts b/src/app/api/bojucontratos/save-result/route.ts
--- a/src/app/api/bojucontratos/save-result/route.ts+++ b/src/app/api/bojucontratos/save-result/route.ts@@ -127,7 +127,6 @@     }      console.log('========================================');-    console.log('BOJUCONTRATOS: Guardado completado con éxito');     console.log('========================================');      return NextResponse.json({
```


### 33. [MEDIUM] vibe-js-console-log — `src/app/api/bojucontratos/save-result/route.ts:131` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/api/bojucontratos/save-result/route.ts b/src/app/api/bojucontratos/save-result/route.ts
--- a/src/app/api/bojucontratos/save-result/route.ts+++ b/src/app/api/bojucontratos/save-result/route.ts@@ -128,7 +128,6 @@      console.log('========================================');     console.log('BOJUCONTRATOS: Guardado completado con éxito');-    console.log('========================================');      return NextResponse.json({       success: true,
```


### 34. [LOW] vibe-todo-fixme — `src/app/api/bojuinformes/validar/route.ts:188` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 35. [LOW] vibe-todo-fixme — `src/app/api/bojupartes/tecnico/route.ts:88` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 36. [MEDIUM] vibe-ts-non-null-assertion — `src/app/bojualmacen/historial/page.tsx:67` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 37. [MEDIUM] vibe-ts-non-null-assertion — `src/app/bojualmacen/historial/page.tsx:67` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 38. [MEDIUM] vibe-ts-non-null-assertion — `src/app/bojualmacen/movimiento/page.tsx:200` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 39. [MEDIUM] vibe-ts-non-null-assertion — `src/app/bojuboard/BojuBoardMobile.tsx:150` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 40. [MEDIUM] vibe-ts-non-null-assertion — `src/app/bojuboard/BojuBoardMobile.tsx:153` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 41. [MEDIUM] vibe-ts-non-null-assertion — `src/app/bojuboard/BojuBoardMobile.tsx:158` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 42. [MEDIUM] vibe-ts-non-null-assertion — `src/app/bojuboard/BojuBoardMobile.tsx:165` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 43. [MEDIUM] vibe-ts-non-null-assertion — `src/app/bojuboard/BojuBoardMobile.tsx:165` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 44. [MEDIUM] vibe-ts-non-null-assertion — `src/app/bojuboard/BojuBoardMobile.tsx:319` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 45. [MEDIUM] vibe-ts-non-null-assertion — `src/app/bojuboard/BojuBoardMobile.tsx:336` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 46. [MEDIUM] vibe-ts-non-null-assertion — `src/app/bojuboard/BojuBoardMobile.tsx:341` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 47. [MEDIUM] vibe-ts-non-null-assertion — `src/app/bojuboard/BojuBoardMobile.tsx:350` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 48. [MEDIUM] vibe-ts-non-null-assertion — `src/app/bojuboard/BojuBoardMobile.tsx:375` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 49. [MEDIUM] vibe-ts-non-null-assertion — `src/app/bojuboard/BojuBoardMobile.tsx:385` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 50. [MEDIUM] vibe-ts-non-null-assertion — `src/app/bojuboard/BojuBoardMobile.tsx:421` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 51. [MEDIUM] vibe-ts-non-null-assertion — `src/app/bojuboard/BojuBoardMobile.tsx:431` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 52. [MEDIUM] vibe-js-console-log — `src/app/bojuboard/BojuBoardWeekly.tsx:236` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojuboard/BojuBoardWeekly.tsx b/src/app/bojuboard/BojuBoardWeekly.tsx
--- a/src/app/bojuboard/BojuBoardWeekly.tsx+++ b/src/app/bojuboard/BojuBoardWeekly.tsx@@ -233,7 +233,6 @@         return;       } -      console.log('✅ Obra actualizada exitosamente');        // 🤖 ACTUALIZAR asignaciones automáticas       // 1. Eliminar asignaciones automáticas existentes de esta obra
```


### 53. [MEDIUM] vibe-js-console-log — `src/app/bojuboard/BojuBoardWeekly.tsx:256` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojuboard/BojuBoardWeekly.tsx b/src/app/bojuboard/BojuBoardWeekly.tsx
--- a/src/app/bojuboard/BojuBoardWeekly.tsx+++ b/src/app/bojuboard/BojuBoardWeekly.tsx@@ -253,7 +253,6 @@                  for (let fecha = new Date(fechaInicio); fecha <= fechaFin; fecha.setDate(fecha.getDate() + 1)) {           const diaSemana = fecha.getDay();-          console.log(`Día: ${fecha.toISOString().split('T')[0]}, diaSemana: ${diaSemana}`);           if (diaSemana >= 1 && diaSemana <= 5) {             const fechaStr = fecha.getFullYear() + '-' + String(fecha.getMonth() + 1).padStart(2, '0') + '-' + String(fecha.getDate()).padStart(2, '0');             
```


### 54. [MEDIUM] vibe-js-console-log — `src/app/bojuboard/BojuBoardWeekly.tsx:347` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojuboard/BojuBoardWeekly.tsx b/src/app/bojuboard/BojuBoardWeekly.tsx
--- a/src/app/bojuboard/BojuBoardWeekly.tsx+++ b/src/app/bojuboard/BojuBoardWeekly.tsx@@ -344,7 +344,6 @@         return;       } -      console.log('✅ Obra eliminada exitosamente');              // 3. Recargar datos para actualizar la vista       if (onReloadData) {
```


### 55. [MEDIUM] vibe-js-console-log — `src/app/bojuboard/BojuBoardWeekly.tsx:351` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojuboard/BojuBoardWeekly.tsx b/src/app/bojuboard/BojuBoardWeekly.tsx
--- a/src/app/bojuboard/BojuBoardWeekly.tsx+++ b/src/app/bojuboard/BojuBoardWeekly.tsx@@ -348,7 +348,6 @@              // 3. Recargar datos para actualizar la vista       if (onReloadData) {-        console.log('🔄 Recargando datos...');         onReloadData();       }       
```


### 56. [MEDIUM] vibe-js-console-log — `src/app/bojuboard/BojuBoardWeekly.tsx:398` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojuboard/BojuBoardWeekly.tsx b/src/app/bojuboard/BojuBoardWeekly.tsx
--- a/src/app/bojuboard/BojuBoardWeekly.tsx+++ b/src/app/bojuboard/BojuBoardWeekly.tsx@@ -395,7 +395,6 @@         return;       } -      console.log('✅ Obra creada exitosamente');        // 🤖 GENERAR Y GUARDAR asignaciones automáticas       if (nuevaObra.tecnico1 || nuevaObra.tecnico2) {
```


### 57. [MEDIUM] vibe-js-console-log — `src/app/bojuboard/BojuBoardWeekly.tsx:408` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojuboard/BojuBoardWeekly.tsx b/src/app/bojuboard/BojuBoardWeekly.tsx
--- a/src/app/bojuboard/BojuBoardWeekly.tsx+++ b/src/app/bojuboard/BojuBoardWeekly.tsx@@ -405,7 +405,6 @@                  for (let fecha = new Date(fechaInicio); fecha <= fechaFin; fecha.setDate(fecha.getDate() + 1)) {           const diaSemana = fecha.getDay();-          console.log(`Día: ${fecha.toISOString().split('T')[0]}, diaSemana: ${diaSemana}`);           if (diaSemana >= 1 && diaSemana <= 5) {             const fechaStr = fecha.getFullYear() + '-' + String(fecha.getMonth() + 1).padStart(2, '0') + '-' + String(fecha.getDate()).padStart(2, '0');             
```


### 58. [MEDIUM] vibe-js-console-log — `src/app/bojuboard/BojuBoardWeekly.tsx:500` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojuboard/BojuBoardWeekly.tsx b/src/app/bojuboard/BojuBoardWeekly.tsx
--- a/src/app/bojuboard/BojuBoardWeekly.tsx+++ b/src/app/bojuboard/BojuBoardWeekly.tsx@@ -497,7 +497,6 @@         return;       } -      console.log('✅ Operario creado exitosamente');              // Limpiar formulario       setNombreOperario('');
```


### 59. [MEDIUM] vibe-js-console-log — `src/app/bojuboard/BojuBoardWeekly.tsx:548` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojuboard/BojuBoardWeekly.tsx b/src/app/bojuboard/BojuBoardWeekly.tsx
--- a/src/app/bojuboard/BojuBoardWeekly.tsx+++ b/src/app/bojuboard/BojuBoardWeekly.tsx@@ -545,7 +545,6 @@         return;       } -      console.log('✅ Técnico creado exitosamente');              // Limpiar formulario       setNombreTecnico('');
```


### 60. [MEDIUM] vibe-js-console-log — `src/app/bojuboard/BojuBoardWeekly.tsx:584` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojuboard/BojuBoardWeekly.tsx b/src/app/bojuboard/BojuBoardWeekly.tsx
--- a/src/app/bojuboard/BojuBoardWeekly.tsx+++ b/src/app/bojuboard/BojuBoardWeekly.tsx@@ -581,7 +581,6 @@     );      if (!asignacionAEliminar || !asignacionAEliminar.id) {-      console.log('⚠️ No se encontró la asignación para eliminar');       return;     } 
```


### 61. [MEDIUM] vibe-js-console-log — `src/app/bojuboard/BojuBoardWeekly.tsx:600` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojuboard/BojuBoardWeekly.tsx b/src/app/bojuboard/BojuBoardWeekly.tsx
--- a/src/app/bojuboard/BojuBoardWeekly.tsx+++ b/src/app/bojuboard/BojuBoardWeekly.tsx@@ -597,7 +597,6 @@       ? operarios.find(o => o.id === personaId)?.nombre        : tecnicos.find(t => t.id === personaId)?.nombre;     -    console.log(`✅ ${personaNombre} eliminado correctamente sin recargar`);    } catch (error) {     console.error('💥 Error general eliminando asignación:', error);
```


### 62. [MEDIUM] vibe-js-console-log — `src/app/bojuboard/BojuBoardWeekly.tsx:678` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojuboard/BojuBoardWeekly.tsx b/src/app/bojuboard/BojuBoardWeekly.tsx
--- a/src/app/bojuboard/BojuBoardWeekly.tsx+++ b/src/app/bojuboard/BojuBoardWeekly.tsx@@ -675,7 +675,6 @@       onReloadData();     }     -    console.log(`Obra ${draggedObra.nombre} asignada al día ${fechaStr}`);        } catch (error) {     console.error('Error en drag & drop:', error);
```


### 63. [MEDIUM] vibe-js-console-log — `src/app/bojuboard/BojuBoardWeekly.tsx:746` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojuboard/BojuBoardWeekly.tsx b/src/app/bojuboard/BojuBoardWeekly.tsx
--- a/src/app/bojuboard/BojuBoardWeekly.tsx+++ b/src/app/bojuboard/BojuBoardWeekly.tsx@@ -743,7 +743,6 @@         return;       } -      console.log(`✅ ${draggedOperario?.nombre || draggedTecnico?.nombre} asignado correctamente`);      } catch (error) {       console.error('ERROR GENERAL en drag & drop:', error);
```


### 64. [MEDIUM] vibe-js-console-log — `src/app/bojuboard/BojuBoardWeekly.tsx:779` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojuboard/BojuBoardWeekly.tsx b/src/app/bojuboard/BojuBoardWeekly.tsx
--- a/src/app/bojuboard/BojuBoardWeekly.tsx+++ b/src/app/bojuboard/BojuBoardWeekly.tsx@@ -776,7 +776,6 @@         // BUSCAR OBRA POR UUID STRING         const obra = obras.find(o => String(o.id) === String(obraId));         if (!obra) {-          console.log(`⚠️ No se encontró obra con ID: ${obraId}`);           return null;         }         
```


### 65. [MEDIUM] vibe-js-console-log — `src/app/bojuboard/BojuBoardWeekly.tsx:791` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojuboard/BojuBoardWeekly.tsx b/src/app/bojuboard/BojuBoardWeekly.tsx
--- a/src/app/bojuboard/BojuBoardWeekly.tsx+++ b/src/app/bojuboard/BojuBoardWeekly.tsx@@ -788,7 +788,6 @@           .map(asig => {             const operario = operarios.find(op => String(op.id) === String(asig.persona_id));             if (!operario) {-              console.log(`⚠️ No se encontró operario con ID: ${asig.persona_id}`);             }             return operario;           })
```


### 66. [MEDIUM] vibe-js-console-log — `src/app/bojuboard/BojuBoardWeekly.tsx:803` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojuboard/BojuBoardWeekly.tsx b/src/app/bojuboard/BojuBoardWeekly.tsx
--- a/src/app/bojuboard/BojuBoardWeekly.tsx+++ b/src/app/bojuboard/BojuBoardWeekly.tsx@@ -800,7 +800,6 @@           .map(asig => {             const tecnico = tecnicos.find(tec => String(tec.id) === String(asig.persona_id));             if (!tecnico) {-              console.log(`⚠️ No se encontró técnico con ID: ${asig.persona_id}`);             }             return tecnico;           })
```


### 67. [LOW] vibe-todo-fixme — `src/app/bojuboard/BojuBoardWeekly.tsx:817` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 68. [MEDIUM] vibe-js-console-log — `src/app/bojuboard/page.tsx:75` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojuboard/page.tsx b/src/app/bojuboard/page.tsx
--- a/src/app/bojuboard/page.tsx+++ b/src/app/bojuboard/page.tsx@@ -72,7 +72,6 @@ const cargarDatos = useCallback(async (forzar = false) => {   try {     setLoading(true);-    console.log('🔄 Cargando datos...' + (forzar ? ' (FORZADO)' : ''));          // LIMPIAR estado local primero     if (forzar) {
```


### 69. [MEDIUM] vibe-js-console-log — `src/app/bojuboard/page.tsx:99` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojuboard/page.tsx b/src/app/bojuboard/page.tsx
--- a/src/app/bojuboard/page.tsx+++ b/src/app/bojuboard/page.tsx@@ -96,7 +96,6 @@     if (asignacionesResult.data) setAsignaciones(asignacionesResult.data);          if (forzar) {-      console.log('✅ Recarga FORZADA completada');       console.log('📊 Asignaciones cargadas:', asignacionesResult.data?.length);     } 
```


### 70. [MEDIUM] vibe-js-console-log — `src/app/bojuboard/page.tsx:148` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojuboard/page.tsx b/src/app/bojuboard/page.tsx
--- a/src/app/bojuboard/page.tsx+++ b/src/app/bojuboard/page.tsx@@ -145,7 +145,6 @@       // 2. Actualizar estado local de forma inmutable       setAsignaciones(prev => [...prev, data]);       -      console.log('✅ Asignación actualizada correctamente');       return { success: true, data: data as Asignacion };      } catch (error) {
```


### 71. [MEDIUM] vibe-js-console-log — `src/app/bojuboard/page.tsx:172` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojuboard/page.tsx b/src/app/bojuboard/page.tsx
--- a/src/app/bojuboard/page.tsx+++ b/src/app/bojuboard/page.tsx@@ -169,7 +169,6 @@     // 2. Actualizar estado local inmediatamente     setAsignaciones(prev => prev.filter(asig => asig.id !== asignacionId));     -    console.log('✅ Asignación eliminada correctamente');     return { success: true };    } catch (error) {
```


### 72. [LOW] vibe-todo-fixme — `src/app/bojucalendar/page.tsx:760` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 73. [MEDIUM] vibe-js-console-log — `src/app/bojucontratos/services/gptAnalyzer.ts:14` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojucontratos/services/gptAnalyzer.ts b/src/app/bojucontratos/services/gptAnalyzer.ts
--- a/src/app/bojucontratos/services/gptAnalyzer.ts+++ b/src/app/bojucontratos/services/gptAnalyzer.ts@@ -11,7 +11,6 @@   });    try {-    console.log('BOJUCONTRATOS: Iniciando análisis con GPT...');      if (contractText.length < 100) {       const error = new Error('El texto del contrato es demasiado corto para analizar');
```


### 74. [MEDIUM] vibe-js-console-log — `src/app/bojucontratos/services/gptAnalyzer.ts:22` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojucontratos/services/gptAnalyzer.ts b/src/app/bojucontratos/services/gptAnalyzer.ts
--- a/src/app/bojucontratos/services/gptAnalyzer.ts+++ b/src/app/bojucontratos/services/gptAnalyzer.ts@@ -19,7 +19,6 @@       throw error;     } -    console.log('BOJUCONTRATOS: Llamando a OpenAI API...');          const response = await openai.chat.completions.create({       model: BOJUCONTRATOS_CONFIG.openai.model,
```


### 75. [MEDIUM] vibe-js-console-log — `src/app/bojucontratos/services/gptAnalyzer.ts:52` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojucontratos/services/gptAnalyzer.ts b/src/app/bojucontratos/services/gptAnalyzer.ts
--- a/src/app/bojucontratos/services/gptAnalyzer.ts+++ b/src/app/bojucontratos/services/gptAnalyzer.ts@@ -49,7 +49,6 @@       throw error;     } -    console.log('BOJUCONTRATOS: Respuesta de GPT recibida, parseando...');      const analysis = parseGptResponse(gptOutput);     validateAnalysis(analysis);
```


### 76. [MEDIUM] vibe-js-console-log — `src/app/bojucontratos/services/gptAnalyzer.ts:57` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojucontratos/services/gptAnalyzer.ts b/src/app/bojucontratos/services/gptAnalyzer.ts
--- a/src/app/bojucontratos/services/gptAnalyzer.ts+++ b/src/app/bojucontratos/services/gptAnalyzer.ts@@ -54,7 +54,6 @@     const analysis = parseGptResponse(gptOutput);     validateAnalysis(analysis); -    console.log('BOJUCONTRATOS: Análisis completado exitosamente');      return analysis;   } catch (error) {
```


### 77. [MEDIUM] vibe-js-console-log — `src/app/bojucontratos/services/pdfExtractor.ts:5` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojucontratos/services/pdfExtractor.ts b/src/app/bojucontratos/services/pdfExtractor.ts
--- a/src/app/bojucontratos/services/pdfExtractor.ts+++ b/src/app/bojucontratos/services/pdfExtractor.ts@@ -2,7 +2,6 @@  export async function extractTextFromPdf(pdfBase64: string): Promise<string> {   try {-    console.log('BOJUCONTRATOS: Iniciando extracción con pdf2json...');          const PDFParser = require('pdf2json');     const pdfParser = new PDFParser();
```


### 78. [MEDIUM] vibe-js-console-log — `src/app/bojucontratos/services/pdfGenerator.ts:12` (con diff propuesto)

- Nota: Eliminar el console.log o sustituirlo por logging estructurado.

```diff
diff --git a/src/app/bojucontratos/services/pdfGenerator.ts b/src/app/bojucontratos/services/pdfGenerator.ts
--- a/src/app/bojucontratos/services/pdfGenerator.ts+++ b/src/app/bojucontratos/services/pdfGenerator.ts@@ -9,7 +9,6 @@   obraName: string ): Promise<Buffer> {   try {-    console.log('BOJUCONTRATOS: Generando PDF resumen...');      const pdfDoc = await PDFDocument.create();     const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
```


### 79. [MEDIUM] vibe-ts-non-null-assertion — `src/app/bojumanager/vision-empresa/page.tsx:222` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 80. [MEDIUM] vibe-ts-non-null-assertion — `src/app/bojumanager/vision-empresa/page.tsx:223` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 81. [MEDIUM] vibe-ts-non-null-assertion — `src/app/bojumanager/vision-empresa/page.tsx:224` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 82. [MEDIUM] vibe-ts-non-null-assertion — `src/app/bojumanager/vision-empresa/page.tsx:225` (revisión manual)

- Nota: Revisión manual: requiere criterio de implementación.


### 83. [LOW] @babel/core — `package.json` (solo comando)

- Nota: CVE-2026-49356

- Comando: `npm install @babel/core@7.29.6 && npm audit fix`


### 84. [HIGH] @babel/plugin-transform-modules-systemjs — `package.json` (solo comando)

- Nota: CVE-2026-44728

- Comando: `npm install @babel/plugin-transform-modules-systemjs@7.29.4 && npm audit fix`


### 85. [HIGH] ajv — `package.json` (solo comando)

- Nota: CVE-2025-69873

- Comando: `npm install ajv@6.14.0 && npm audit fix`


### 86. [HIGH] brace-expansion — `package.json` (solo comando)

- Nota: CVE-2026-13149

- Comando: `npm install brace-expansion@2.1.2 && npm audit fix`


### 87. [MEDIUM] brace-expansion — `package.json` (solo comando)

- Nota: CVE-2026-33750

- Comando: `npm install brace-expansion@2.0.3 && npm audit fix`


### 88. [HIGH] brace-expansion — `package.json` (solo comando)

- Nota: CVE-2026-14257

- Comando: `npm install brace-expansion@2.1.3 && npm audit fix`


### 89. [HIGH] brace-expansion — `package.json` (solo comando)

- Nota: CVE-2026-69152

- Comando: `npm install brace-expansion@2.1.4 && npm audit fix`


### 90. [HIGH] fast-uri — `package.json` (solo comando)

- Nota: CVE-2026-13676

- Comando: `npm install fast-uri@3.1.3 && npm audit fix`


### 91. [HIGH] fast-uri — `package.json` (solo comando)

- Nota: CVE-2026-18446

- Comando: `npm install fast-uri@3.1.5 && npm audit fix`


### 92. [HIGH] fast-uri — `package.json` (solo comando)

- Nota: CVE-2026-6321

- Comando: `npm install fast-uri@3.1.1 && npm audit fix`


### 93. [HIGH] fast-uri — `package.json` (solo comando)

- Nota: CVE-2026-16221

- Comando: `npm install fast-uri@3.1.4 && npm audit fix`


### 94. [HIGH] fast-uri — `package.json` (solo comando)

- Nota: CVE-2026-6322

- Comando: `npm install fast-uri@3.1.2 && npm audit fix`


### 95. [HIGH] flatted — `package.json` (solo comando)

- Nota: CVE-2026-32141

- Comando: `npm install flatted@3.4.0 && npm audit fix`


### 96. [HIGH] flatted — `package.json` (solo comando)

- Nota: CVE-2026-33228

- Comando: `npm install flatted@3.4.2 && npm audit fix`


### 97. [HIGH] js-yaml — `package.json` (solo comando)

- Nota: CVE-2026-59869

- Comando: `npm install js-yaml@4.3.0 && npm audit fix`


### 98. [MEDIUM] js-yaml — `package.json` (solo comando)

- Nota: CVE-2026-53550

- Comando: `npm install js-yaml@4.2.0 && npm audit fix`


### 99. [MEDIUM] lodash — `package.json` (solo comando)

- Nota: CVE-2025-13465; CVE-2026-2950

- Comando: `npm install lodash@4.18.0 && npm audit fix`


### 100. [HIGH] lodash — `package.json` (solo comando)

- Nota: CVE-2021-23337; CVE-2026-4800

- Comando: `npm install lodash@4.18.0 && npm audit fix`


### 101. [HIGH] minimatch — `package.json` (solo comando)

- Nota: CVE-2026-27904

- Comando: `npm install minimatch@9.0.7 && npm audit fix`


### 102. [HIGH] minimatch — `package.json` (solo comando)

- Nota: CVE-2026-26996

- Comando: `npm install minimatch@9.0.6 && npm audit fix`


### 103. [HIGH] minimatch — `package.json` (solo comando)

- Nota: CVE-2026-27903

- Comando: `npm install minimatch@9.0.7 && npm audit fix`


### 104. [HIGH] next — `package.json` (solo comando)

- Nota: CVE-2026-44573

- Comando: `npm install next@15.5.16 && npm audit fix`


### 105. [LOW] next — `package.json` (solo comando)

- Nota: CVE-2026-44572

- Comando: `npm install next@15.5.16 && npm audit fix`


### 106. [LOW] next — `package.json` (solo comando)

- Nota: CVE-2025-48068

- Comando: `npm install next@14.2.30 && npm audit fix`


### 107. [HIGH] next — `package.json` (solo comando)

- Nota: CVE-2026-27980

- Comando: `npm install next@15.5.14 && npm audit fix`


### 108. [MEDIUM] next — `package.json` (solo comando)

- Nota: CVE-2025-57822

- Comando: `npm install next@14.2.32 && npm audit fix`


### 109. [HIGH] next — `package.json` (solo comando)

- Nota: CVE-2026-64647

- Comando: `npm install next@15.5.21 && npm audit fix`


### 110. [HIGH] next — `package.json` (solo comando)

- Nota: CVE-2026-64646

- Comando: `npm install next@15.5.21 && npm audit fix`


### 111. [HIGH] next — `package.json` (solo comando)

- Comando: `npm install next@14.2.35 && npm audit fix`


### 112. [HIGH] next — `package.json` (solo comando)

- Nota: CVE-2026-64648

- Comando: `npm install next@15.5.21 && npm audit fix`


### 113. [MEDIUM] next — `package.json` (solo comando)

- Nota: CVE-2024-56332

- Comando: `npm install next@14.2.21 && npm audit fix`


### 114. [HIGH] next — `package.json` (solo comando)

- Nota: CVE-2026-64649

- Comando: `npm install next@15.5.21 && npm audit fix`


### 115. [HIGH] next — `package.json` (solo comando)

- Comando: `npm install next@15.5.16 && npm audit fix`


### 116. [HIGH] next — `package.json` (solo comando)

- Nota: CVE-2026-64643

- Comando: `npm install next@15.5.21 && npm audit fix`


### 117. [MEDIUM] next — `package.json` (solo comando)

- Nota: CVE-2025-59471

- Comando: `npm install next@15.5.10 && npm audit fix`


### 118. [HIGH] next — `package.json` (solo comando)

- Nota: CVE-2026-44578

- Comando: `npm install next@15.5.16 && npm audit fix`


### 119. [CRITICAL] next — `package.json` (solo comando)

- Nota: CVE-2025-29927

- Comando: `npm install next@14.2.25 && npm audit fix`


### 120. [MEDIUM] next — `package.json` (solo comando)

- Nota: CVE-2026-44581

- Comando: `npm install next@15.5.16 && npm audit fix`


### 121. [MEDIUM] next — `package.json` (solo comando)

- Nota: CVE-2025-57752

- Comando: `npm install next@14.2.31 && npm audit fix`


### 122. [HIGH] next — `package.json` (solo comando)

- Nota: CVE-2026-29057

- Comando: `npm install next@15.5.13 && npm audit fix`


### 123. [MEDIUM] next — `package.json` (solo comando)

- Nota: CVE-2026-44580

- Comando: `npm install next@15.5.16 && npm audit fix`


### 124. [HIGH] next — `package.json` (solo comando)

- Comando: `npm install next@15.0.8 && npm audit fix`


### 125. [MEDIUM] next — `package.json` (solo comando)

- Nota: CVE-2026-44577

- Comando: `npm install next@15.5.16 && npm audit fix`


### 126. [HIGH] next — `package.json` (solo comando)

- Nota: CVE-2026-64641

- Comando: `npm install next@15.5.21 && npm audit fix`


### 127. [HIGH] next — `package.json` (solo comando)

- Comando: `npm install next@14.2.34 && npm audit fix`


### 128. [HIGH] next — `package.json` (solo comando)

- Nota: CVE-2026-64645

- Comando: `npm install next@15.5.21 && npm audit fix`


### 129. [HIGH] next — `package.json` (solo comando)

- Comando: `npm install next@15.5.15 && npm audit fix`


### 130. [LOW] next — `package.json` (solo comando)

- Nota: CVE-2025-32421

- Comando: `npm install next@14.2.24 && npm audit fix`


### 131. [LOW] next — `package.json` (solo comando)

- Nota: CVE-2026-44582

- Comando: `npm install next@15.5.16 && npm audit fix`


### 132. [MEDIUM] next — `package.json` (solo comando)

- Nota: CVE-2026-44576

- Comando: `npm install next@15.5.16 && npm audit fix`


### 133. [MEDIUM] next — `package.json` (solo comando)

- Nota: CVE-2025-55173

- Comando: `npm install next@14.2.31 && npm audit fix`


### 134. [MEDIUM] picomatch — `package.json` (solo comando)

- Nota: CVE-2026-33672

- Comando: `npm install picomatch@2.3.2 && npm audit fix`


### 135. [HIGH] picomatch — `package.json` (solo comando)

- Nota: CVE-2026-33671

- Comando: `npm install picomatch@2.3.2 && npm audit fix`


### 136. [HIGH] postcss — `package.json` (solo comando)

- Nota: CVE-2026-45623

- Comando: `npm install postcss@8.5.12 && npm audit fix`


### 137. [HIGH] postcss — `package.json` (solo comando)

- Nota: CVE-2026-69153

- Comando: `npm install postcss@8.5.23 && npm audit fix`


### 138. [MEDIUM] postcss — `package.json` (solo comando)

- Nota: CVE-2026-41305

- Comando: `npm install postcss@8.5.10 && npm audit fix`


### 139. [HIGH] postcss — `package.json` (solo comando)

- Comando: `npm install postcss@8.5.18 && npm audit fix`


### 140. [HIGH] rollup — `package.json` (solo comando)

- Nota: CVE-2026-27606

- Comando: `npm install rollup@2.80.0 && npm audit fix`


### 141. [HIGH] serialize-javascript — `package.json` (solo comando)

- Comando: `npm install serialize-javascript@7.0.3 && npm audit fix`


### 142. [MEDIUM] serialize-javascript — `package.json` (solo comando)

- Nota: CVE-2026-34043

- Comando: `npm install serialize-javascript@7.0.5 && npm audit fix`


### 143. [HIGH] tmp — `package.json` (solo comando)

- Nota: CVE-2026-44705

- Comando: `npm install tmp@0.2.6 && npm audit fix`


### 144. [HIGH] uuid — `package.json` (solo comando)

- Nota: CVE-2026-41907; CVE-2026-41988

- Comando: `npm install uuid@11.1.1 && npm audit fix`


### 145. [MEDIUM] ws — `package.json` (solo comando)

- Nota: CVE-2026-45736

- Comando: `npm install ws@8.20.1 && npm audit fix`


### 146. [HIGH] ws — `package.json` (solo comando)

- Nota: CVE-2026-48779

- Comando: `npm install ws@8.21.0 && npm audit fix`


### 147. [HIGH] xlsx — `package.json` (solo comando)

- Nota: CVE-2023-30533

- Comando: `npm install xlsx@latest && npm audit fix`


### 148. [HIGH] xlsx — `package.json` (solo comando)

- Nota: CVE-2024-22363

- Comando: `npm install xlsx@latest && npm audit fix`


### 149. [CRITICAL] owasp.vulnerable-deps — `package.json` (revisión manual)

- Nota: Dependencia vulnerable


### 150. [HIGH] owasp.vulnerable-deps — `package.json` (revisión manual)

- Nota: Dependencia vulnerable


### 151. [HIGH] owasp.vulnerable-deps — `package.json` (revisión manual)

- Nota: Dependencia vulnerable


### 152. [MEDIUM] owasp.vulnerable-deps — `package.json` (revisión manual)

- Nota: Dependencia vulnerable


### 153. [MEDIUM] owasp.vulnerable-deps — `package.json` (revisión manual)

- Nota: Dependencia vulnerable


### 154. [MEDIUM] owasp.vulnerable-deps — `package.json` (revisión manual)

- Nota: Dependencia vulnerable


### 155. [LOW] owasp.vulnerable-deps — `package.json` (revisión manual)

- Nota: Dependencia vulnerable


### 156. [LOW] owasp.vulnerable-deps — `package.json` (revisión manual)

- Nota: Dependencia vulnerable


### 157. [MEDIUM] owasp.injection — `src/app/api/bojucalendar/user-role/route.ts:30` (revisión manual)

- Nota: Console.log en producción


### 158. [LOW] 12-factor.config — `docs/00_AGENTS.md:162` (revisión manual)

- Nota: Secretos hardcodeados en el código

