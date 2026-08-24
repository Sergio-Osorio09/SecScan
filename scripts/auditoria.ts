/**
 * Mide el ruido del motor sobre codigo real y bien escrito.
 *
 * No mide si detecta: eso ya lo cubren las pruebas. Mide lo contrario — cuantas
 * veces molesta a proyectos que hacen las cosas bien. Separa el codigo de la
 * libreria de sus pruebas, porque una suite de pruebas contiene a proposito
 * patrones inseguros y mezclarlas falsearia la cifra.
 */
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { extname, join, relative } from 'node:path';
import { analizar } from './src/engine/analizar';
import type { Hallazgo } from './src/engine/tipos';

const RAIZ = process.argv[2];
const EXTENSIONES = new Set(['.py', '.js', '.mjs', '.cjs', '.ts', '.java']);

/** Nada de dependencias, artefactos ni codigo minificado: solo fuente escrita a mano. */
const EXCLUIDOS =
  /node_modules|[/\\](dist|build|coverage|vendor|\.git|__pycache__|site-packages)[/\\]|\.min\.|\.map$/;

const ES_PRUEBA = /(^|[/\\])(tests?|__tests__|spec|e2e|examples?|benchmark)[/\\]|(test_|_test|\.test\.|\.spec\.)/i;

function* archivos(directorio: string): Generator<string> {
  for (const entrada of readdirSync(directorio)) {
    const ruta = join(directorio, entrada);
    if (EXCLUIDOS.test(ruta)) continue;
    if (statSync(ruta).isDirectory()) yield* archivos(ruta);
    else if (EXTENSIONES.has(extname(entrada))) yield ruta;
  }
}

interface Fila {
  proyecto: string;
  grupo: 'libreria' | 'pruebas';
  archivo: string;
  hallazgo: Hallazgo;
}

const filas: Fila[] = [];
const totales: Record<string, { archivos: number; lineas: number }> = {};

for (const proyecto of readdirSync(RAIZ)) {
  const base = join(RAIZ, proyecto);
  if (!statSync(base).isDirectory()) continue;

  for (const grupo of ['libreria', 'pruebas'] as const) {
    totales[`${proyecto}/${grupo}`] = { archivos: 0, lineas: 0 };
  }

  for (const ruta of archivos(base)) {
    const relativa = relative(base, ruta);
    const grupo = ES_PRUEBA.test(relativa) ? 'pruebas' : 'libreria';
    const codigo = readFileSync(ruta, 'utf8');
    const clave = `${proyecto}/${grupo}`;
    totales[clave].archivos += 1;
    totales[clave].lineas += codigo.split('\n').length;
    for (const hallazgo of analizar(codigo, { maxHallazgos: 10_000 }).hallazgos) {
      filas.push({ proyecto, grupo, archivo: relativa, hallazgo });
    }
  }
}

const porGrupo = (grupo: string) => filas.filter((f) => `${f.proyecto}/${f.grupo}` === grupo).length;

console.log('proyecto            | grupo    | archivos |  lineas | hallazgos | por 1000 lineas');
console.log('--------------------|----------|----------|---------|-----------|----------------');
for (const [clave, { archivos: n, lineas }] of Object.entries(totales)) {
  if (n === 0) continue;
  const total = porGrupo(clave);
  const [proyecto, grupo] = clave.split('/');
  console.log(
    `${proyecto.padEnd(19)} | ${grupo.padEnd(8)} | ${String(n).padStart(8)} | ${String(lineas).padStart(7)} | ${String(total).padStart(9)} | ${(total / (lineas / 1000)).toFixed(2)}`,
  );
}

console.log('\n=== por regla (solo codigo de libreria) ===');
const porRegla = new Map<string, Fila[]>();
for (const fila of filas.filter((f) => f.grupo === 'libreria')) {
  const lista = porRegla.get(fila.hallazgo.reglaId) ?? [];
  lista.push(fila);
  porRegla.set(fila.hallazgo.reglaId, lista);
}
for (const [regla, lista] of [...porRegla.entries()].sort((a, b) => b[1].length - a[1].length)) {
  console.log(`${String(lista.length).padStart(4)}  ${regla}`);
}

writeFileSync(
  process.argv[3] ?? 'auditoria.json',
  JSON.stringify(
    filas.map((f) => ({
      proyecto: f.proyecto,
      grupo: f.grupo,
      archivo: f.archivo,
      regla: f.hallazgo.reglaId,
      linea: f.hallazgo.linea,
      severidad: f.hallazgo.severidad,
      fragmento: f.hallazgo.fragmento,
    })),
    null,
    1,
  ),
  'utf8',
);
console.log(`\n${filas.length} hallazgos guardados para revisarlos uno a uno.`);
