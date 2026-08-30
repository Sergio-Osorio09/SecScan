import { execFileSync } from 'node:child_process';
import { transformSync } from 'esbuild';
import { describe, expect, it } from 'vitest';
import { CATALOGO_DE_REGLAS } from '../reglas';

/**
 * Los fragmentos de "cómo se arregla" son el ejemplo de buenas prácticas que
 * lee el usuario, y estaban escritos a mano sin comprobar nunca. Publicar un
 * ejemplo con un paréntesis de menos sería peor que no darlo: aquí se
 * verifica que cada uno es sintácticamente válido en su lenguaje.
 *
 * Python y Bash se comprueban con el intérprete del sistema. Si no está
 * disponible —un portátil sin Python, por ejemplo— la prueba se salta en lugar
 * de fallar: la máquina de integración continua sí los tiene y ahí se ejecutan
 * siempre.
 */

const hay = (programa: string, argumentos: string[]) => {
  try {
    execFileSync(programa, argumentos, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
};

const HAY_PYTHON = hay('python', ['--version']) || hay('python3', ['--version']);
const PYTHON = hay('python', ['--version']) ? 'python' : 'python3';
const HAY_BASH = hay('bash', ['--version']);

const porLenguaje = (lenguaje: string) =>
  CATALOGO_DE_REGLAS.filter((regla) => regla.ficha.fix.lenguaje === lenguaje).map((regla) => ({
    id: regla.id,
    codigo: regla.ficha.fix.codigo,
  }));

describe('los ejemplos de solución son código válido', () => {
  it('el catálogo entero trae un fragmento con contenido', () => {
    for (const regla of CATALOGO_DE_REGLAS) {
      expect(regla.ficha.fix.codigo.trim().length, regla.id).toBeGreaterThan(20);
    }
  });

  const enJavaScript = porLenguaje('javascript');
  it.each(enJavaScript)('JavaScript · $id', ({ codigo }) => {
    expect(() => transformSync(codigo, { loader: 'js' })).not.toThrow();
  });

  const enPython = porLenguaje('python');
  it.skipIf(!HAY_PYTHON).each(enPython)('Python · $id', ({ codigo }) => {
    // `ast.parse` falla con un error de sintaxis y no ejecuta nada del fragmento.
    expect(() =>
      execFileSync(PYTHON, ['-c', 'import ast,sys; ast.parse(sys.stdin.read())'], {
        input: codigo,
        stdio: ['pipe', 'ignore', 'pipe'],
      }),
    ).not.toThrow();
  });

  const enBash = porLenguaje('bash');
  it.skipIf(!HAY_BASH).each(enBash)('Bash · $id', ({ codigo }) => {
    // -n solo analiza la sintaxis: no ejecuta ninguna orden.
    expect(() =>
      execFileSync('bash', ['-n'], { input: codigo, stdio: ['pipe', 'ignore', 'pipe'] }),
    ).not.toThrow();
  });
});
