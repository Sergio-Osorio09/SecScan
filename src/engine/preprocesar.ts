import type { Lenguaje } from './tipos';

/**
 * Preparacion del codigo antes de aplicar las reglas.
 *
 * Un `split('\n')` ingenuo no basta: hace falta saber que trozos son
 * comentarios (para ignorarlos) y cuales son cadenas de texto (para decidir,
 * regla por regla, si la coincidencia cuenta). Y hay que hacerlo con un
 * recorrido consciente del estado, porque `"http://ejemplo.com"` contiene `//`
 * y no es un comentario, y `# hola` dentro de un string tampoco lo es.
 */
export interface CodigoPreparado {
  original: string;
  /** Mismo texto con el contenido de los comentarios reemplazado por espacios. */
  limpio: string;
  /** `true` en cada indice que cae dentro de una cadena de texto. */
  enCadena: boolean[];
  /** Offset donde arranca cada linea (indice 0 = linea 1). */
  iniciosDeLinea: number[];
  lineas: string[];
}

type Estado =
  | { tipo: 'normal' }
  | { tipo: 'cadena'; cierre: string; multilinea: boolean }
  | { tipo: 'comentarioLinea' }
  | { tipo: 'comentarioBloque' };

const COMILLAS_TRIPLES = ["'''", '"""'];

export function prepararCodigo(codigo: string): CodigoPreparado {
  const n = codigo.length;
  const limpio: string[] = new Array(n);
  const enCadena: boolean[] = new Array(n).fill(false);
  let estado: Estado = { tipo: 'normal' };
  let i = 0;

  const copiar = (indice: number) => {
    limpio[indice] = codigo[indice];
  };
  const borrar = (indice: number) => {
    // Se conservan los saltos de linea para que los offsets sigan cuadrando.
    limpio[indice] = codigo[indice] === '\n' ? '\n' : ' ';
  };

  while (i < n) {
    const c = codigo[i];
    const par = codigo.slice(i, i + 2);
    const triple = codigo.slice(i, i + 3);

    if (estado.tipo === 'comentarioLinea') {
      if (c === '\n') estado = { tipo: 'normal' };
      borrar(i);
      i += 1;
      continue;
    }

    if (estado.tipo === 'comentarioBloque') {
      if (par === '*/') {
        borrar(i);
        borrar(i + 1);
        estado = { tipo: 'normal' };
        i += 2;
        continue;
      }
      borrar(i);
      i += 1;
      continue;
    }

    if (estado.tipo === 'cadena') {
      // Escape: el siguiente caracter no puede cerrar la cadena.
      if (c === '\\' && i + 1 < n) {
        enCadena[i] = true;
        enCadena[i + 1] = true;
        copiar(i);
        copiar(i + 1);
        i += 2;
        continue;
      }
      if (estado.cierre.length === 3 && triple === estado.cierre) {
        copiar(i);
        copiar(i + 1);
        copiar(i + 2);
        i += 3;
        estado = { tipo: 'normal' };
        continue;
      }
      if (estado.cierre.length === 1 && c === estado.cierre) {
        copiar(i);
        i += 1;
        estado = { tipo: 'normal' };
        continue;
      }
      // Una cadena de comilla simple no sobrevive a un salto de linea: si lo
      // hay, lo mas probable es que fuera un apostrofe suelto y no un string.
      if (c === '\n' && !estado.multilinea) {
        copiar(i);
        i += 1;
        estado = { tipo: 'normal' };
        continue;
      }
      enCadena[i] = true;
      copiar(i);
      i += 1;
      continue;
    }

    // Estado normal
    if (COMILLAS_TRIPLES.includes(triple)) {
      estado = { tipo: 'cadena', cierre: triple, multilinea: true };
      copiar(i);
      copiar(i + 1);
      copiar(i + 2);
      i += 3;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      estado = { tipo: 'cadena', cierre: c, multilinea: c === '`' };
      copiar(i);
      i += 1;
      continue;
    }
    if (c === '#' || par === '//') {
      estado = { tipo: 'comentarioLinea' };
      borrar(i);
      i += 1;
      continue;
    }
    if (par === '/*') {
      estado = { tipo: 'comentarioBloque' };
      borrar(i);
      borrar(i + 1);
      i += 2;
      continue;
    }
    copiar(i);
    i += 1;
  }

  const textoLimpio = limpio.join('');
  const lineas = codigo.split('\n');
  const iniciosDeLinea: number[] = [0];
  for (let k = 0; k < lineas.length - 1; k += 1) {
    iniciosDeLinea.push(iniciosDeLinea[k] + lineas[k].length + 1);
  }

  return { original: codigo, limpio: textoLimpio, enCadena, iniciosDeLinea, lineas };
}

/** Traduce un offset absoluto a numero de linea (base 1) mediante busqueda binaria. */
export function lineaDeOffset(iniciosDeLinea: number[], offset: number): number {
  let bajo = 0;
  let alto = iniciosDeLinea.length - 1;
  while (bajo < alto) {
    const medio = Math.ceil((bajo + alto) / 2);
    if (iniciosDeLinea[medio] <= offset) bajo = medio;
    else alto = medio - 1;
  }
  return bajo + 1;
}

const SENALES_PYTHON = [
  /^\s*def\s+\w+\s*\(/m,
  /^\s*(?:def|class)\s+\w+[^\n]*:\s*$/m,
  /^\s*from\s+[\w.]+\s+import\s+/m,
  /^\s*import\s+\w+\s*$/m,
  /\bself\./,
  /\bprint\s*\(.*\)\s*$/m,
  /\b(True|False|None)\b/,
  /\bos\.(system|environ|getenv)\b/,
  /\bhashlib\./,
  /^\s*(if|for|while|else|elif|try|except)\b.*:\s*$/m,
  /\bf["'][^"'\n]*\{/,
];

const SENALES_JS = [
  /\b(const|let|var)\s+\w+\s*=/,
  /=>/,
  /\bfunction\s*\w*\s*\(/,
  /\bdocument\.(getElementById|querySelector|write)\b/,
  /\brequire\s*\(\s*["']/,
  /\bconsole\.log\s*\(/,
  /\b(null|undefined)\b/,
  /;\s*$/m,
  /\bexport\s+(default|const|function)\b/,
  /`[^`]*\$\{/,
];

/**
 * Java comparte con JavaScript el punto y coma, las llaves y `null`, asi que
 * se buscan las senales que solo tiene Java: la declaracion de paquete, los
 * modificadores de acceso delante de un metodo, los tipos con generico y las
 * anotaciones. Sin esto, todo archivo .java acabaria etiquetado como .js.
 */
const SENALES_JAVA = [
  /^\s*package\s+[\w.]+\s*;/m,
  /^\s*import\s+(?:static\s+)?(?:java|javax|org|com)[\w.]*\s*;/m,
  /\b(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?(?:void|int|long|double|boolean|char|String|[A-Z]\w*)\s+\w+\s*\(/,
  /\b(?:public|abstract|final)\s+class\s+\w+/,
  /\bSystem\.(?:out|err)\.print/,
  /\bString\[\]\s+\w+/,
  /\bnew\s+[A-Z]\w*\s*<[^>]*>\s*\(/,
  /@(?:Override|SuppressWarnings|Deprecated|FunctionalInterface)\b/,
  /\bthrows\s+[A-Z]\w*/,
  /\bimplements\s+[A-Z]\w*/,
];

const SENALES: Record<Exclude<Lenguaje, 'generico'>, RegExp[]> = {
  python: SENALES_PYTHON,
  javascript: SENALES_JS,
  java: SENALES_JAVA,
};

/**
 * Deteccion de lenguaje por senales. Es cosmetica — sirve para la pestana del
 * archivo y la barra de estado. Las reglas se aplican siempre todas, para que
 * una deteccion equivocada nunca esconda un hallazgo.
 *
 * Gana el lenguaje con mas senales, siempre que reuna al menos dos y saque
 * ventaja al segundo. Si hay empate, se prefiere no inventar: `generico`.
 */
export function detectarLenguaje(codigo: string): Lenguaje {
  if (!codigo.trim()) return 'generico';

  const puntuaciones = (Object.entries(SENALES) as [Lenguaje, RegExp[]][])
    .map(([lenguaje, senales]) => ({
      lenguaje,
      puntos: senales.filter((senal) => senal.test(codigo)).length,
    }))
    .sort((a, b) => b.puntos - a.puntos);

  const [mejor, segundo] = puntuaciones;
  return mejor.puntos >= 2 && mejor.puntos > segundo.puntos ? mejor.lenguaje : 'generico';
}

export const ETIQUETA_LENGUAJE: Record<Lenguaje, string> = {
  python: 'Python',
  javascript: 'JavaScript',
  java: 'Java',
  generico: 'texto plano',
};

export const EXTENSION_LENGUAJE: Record<Lenguaje, string> = {
  python: 'codigo.py',
  javascript: 'codigo.js',
  java: 'Codigo.java',
  generico: 'codigo.txt',
};
