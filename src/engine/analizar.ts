import { detectarLenguaje, lineaDeOffset, prepararCodigo } from './preprocesar';
import { CATALOGO_DE_REGLAS } from './reglas';
import { ORDEN_SEVERIDAD } from './tipos';
import type { Hallazgo, Regla, ResultadoAnalisis, ResumenSeveridad } from './tipos';

export interface OpcionesDeAnalisis {
  /** Reglas a aplicar. Por defecto, el catalogo completo. */
  reglas?: Regla[];
  /** Tope de hallazgos, para que un archivo enorme no bloquee la interfaz. */
  maxHallazgos?: number;
}

const MAX_HALLAZGOS_POR_DEFECTO = 300;

function resumir(hallazgos: Hallazgo[]): ResumenSeveridad {
  const resumen: ResumenSeveridad = { critica: 0, alta: 0, media: 0, baja: 0, total: 0 };
  for (const hallazgo of hallazgos) {
    resumen[hallazgo.severidad] += 1;
    resumen.total += 1;
  }
  return resumen;
}

/**
 * Analiza un fragmento de codigo y devuelve los hallazgos.
 *
 * Es una funcion pura: mismo texto, mismo resultado. No toca la red, no toca
 * el disco y no guarda nada — el codigo del usuario no sale de su navegador.
 */
export function analizar(codigo: string, opciones: OpcionesDeAnalisis = {}): ResultadoAnalisis {
  const inicio = typeof performance !== 'undefined' ? performance.now() : Date.now();
  const reglas = opciones.reglas ?? CATALOGO_DE_REGLAS;
  const maxHallazgos = opciones.maxHallazgos ?? MAX_HALLAZGOS_POR_DEFECTO;

  const preparado = prepararCodigo(codigo);
  const hallazgos: Hallazgo[] = [];
  // Un mismo problema en la misma linea se reporta una sola vez.
  const yaVistos = new Set<string>();

  for (const regla of reglas) {
    // Copia del patron: `lastIndex` es estado mutable y las reglas se comparten.
    const patron = new RegExp(regla.patron.source, regla.patron.flags);
    const ignorarEnCadenas = regla.ignorarEnCadenas ?? true;
    let coincidencia: RegExpExecArray | null;

    while ((coincidencia = patron.exec(preparado.limpio)) !== null) {
      // Un patron que puede coincidir con la cadena vacia colgaria el bucle.
      if (coincidencia[0] === '') {
        patron.lastIndex += 1;
        continue;
      }

      const offset = coincidencia.index;
      if (ignorarEnCadenas && preparado.enCadena[offset]) continue;

      const linea = lineaDeOffset(preparado.iniciosDeLinea, offset);
      const textoLinea = preparado.lineas[linea - 1] ?? '';

      if (regla.ignorarSiLinea?.some((guarda) => guarda.test(textoLinea))) continue;
      if (regla.ignorarSiCoincide?.some((guarda) => guarda.test(coincidencia![0]))) continue;

      const clave = `${regla.id}:${linea}`;
      if (yaVistos.has(clave)) continue;
      yaVistos.add(clave);

      const columna = offset - preparado.iniciosDeLinea[linea - 1] + 1;
      hallazgos.push({
        id: `${regla.id}:${linea}:${columna}`,
        reglaId: regla.id,
        titulo: regla.titulo,
        severidad: regla.severidad,
        owasp: regla.owasp,
        cwe: regla.cwe,
        linea,
        columna,
        fragmento: textoLinea.trim(),
        ficha: regla.ficha,
      });

      if (hallazgos.length >= maxHallazgos) break;
    }
    if (hallazgos.length >= maxHallazgos) break;
  }

  hallazgos.sort(
    (a, b) => ORDEN_SEVERIDAD[a.severidad] - ORDEN_SEVERIDAD[b.severidad] || a.linea - b.linea,
  );

  const fin = typeof performance !== 'undefined' ? performance.now() : Date.now();

  return {
    hallazgos,
    resumen: resumir(hallazgos),
    lenguaje: detectarLenguaje(codigo),
    lineasAnalizadas: codigo.trim() ? preparado.lineas.length : 0,
    duracionMs: Math.max(0, Math.round((fin - inicio) * 100) / 100),
  };
}
