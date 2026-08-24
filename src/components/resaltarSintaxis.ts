/**
 * Resaltado de sintaxis del editor.
 *
 * No pretende ser un analizador de lenguajes: es el mismo truco que usa
 * cualquier editor ligero — una pasada de expresiones regulares que reconoce
 * comentarios, cadenas, numeros, palabras clave, tipos y llamadas a funcion.
 * Los colores salen de los tokens `--sx-*`, que reproducen el tema por defecto
 * de Xcode.
 *
 * Invariante que sostiene todo: concatenar los tokens devuelve exactamente el
 * texto original. Si se pierde un solo caracter, la capa de color deja de
 * cuadrar con el textarea que tiene encima.
 */

export type TipoToken =
  | 'comentario'
  | 'cadena'
  | 'numero'
  | 'clave'
  | 'tipo'
  | 'funcion'
  | 'decorador'
  | 'texto';

export interface TokenSintaxis {
  texto: string;
  tipo: TipoToken;
}

/** Union de palabras reservadas de Python y JavaScript: el editor acepta ambos. */
const PALABRAS_CLAVE = [
  // Python
  'and', 'as', 'assert', 'class', 'def', 'del', 'elif', 'except', 'finally', 'from', 'global',
  'import', 'in', 'is', 'lambda', 'nonlocal', 'not', 'or', 'pass', 'raise', 'with', 'yield',
  'True', 'False', 'None', 'self', 'cls',
  // JavaScript
  'async', 'await', 'break', 'case', 'catch', 'const', 'continue', 'default', 'delete', 'do',
  'else', 'export', 'extends', 'for', 'function', 'get', 'if', 'instanceof', 'let', 'new', 'of',
  'return', 'set', 'static', 'super', 'switch', 'this', 'throw', 'try', 'typeof', 'undefined',
  'null', 'true', 'false', 'var', 'void', 'while',
  // Java: solo las que no comparte con los anteriores. Se dejan fuera los tipos
  // primitivos (`int`, `char`...) porque en Python son funciones de conversion
  // y quedarian coloreadas como si fueran palabras reservadas.
  'public', 'private', 'protected', 'final', 'implements', 'interface', 'package', 'throws',
  'abstract', 'synchronized', 'enum',
].join('|');

const PATRON = new RegExp(
  [
    // Comentarios de bloque y de linea (# de Python, // de JavaScript)
    String.raw`(?<comentario>\/\*[\s\S]*?(?:\*\/|$)|(?:#|\/\/)[^\n]*)`,
    // Cadenas: triples, plantillas, dobles y simples. El cierre es opcional
    // para que el color no se rompa mientras se escribe.
    String.raw`(?<cadena>"""[\s\S]*?(?:"""|$)|'''[\s\S]*?(?:'''|$)|\x60(?:\\[\s\S]|[^\\\x60])*\x60?|"(?:\\.|[^"\\\n])*"?|'(?:\\.|[^'\\\n])*'?)`,
    // Decoradores de Python y anotaciones
    String.raw`(?<decorador>@[A-Za-z_]\w*)`,
    // Numeros, incluidos hexadecimales y separadores por guion bajo
    String.raw`(?<numero>\b\d[\w.]*\b)`,
    String.raw`(?<clave>\b(?:${PALABRAS_CLAVE})\b)`,
    // Convencion universal: los tipos empiezan en mayuscula
    String.raw`(?<tipo>\b[A-Z][A-Za-z0-9_]*\b)`,
    // Un identificador seguido de parentesis es una llamada
    String.raw`(?<funcion>\b[A-Za-z_]\w*(?=\s*\())`,
  ].join('|'),
  'g',
);

/** A partir de este tamano se deja de colorear: no merece la pena bloquear el teclado. */
const LIMITE_CARACTERES = 80_000;

export function resaltarSintaxis(codigo: string): TokenSintaxis[] {
  if (!codigo) return [];
  if (codigo.length > LIMITE_CARACTERES) return [{ texto: codigo, tipo: 'texto' }];

  const tokens: TokenSintaxis[] = [];
  let cursor = 0;

  for (const coincidencia of codigo.matchAll(PATRON)) {
    const inicio = coincidencia.index ?? 0;
    if (inicio > cursor) tokens.push({ texto: codigo.slice(cursor, inicio), tipo: 'texto' });

    const grupos = coincidencia.groups ?? {};
    const tipo = (Object.keys(grupos).find((nombre) => grupos[nombre] !== undefined) ??
      'texto') as TipoToken;
    tokens.push({ texto: coincidencia[0], tipo });
    cursor = inicio + coincidencia[0].length;
  }

  if (cursor < codigo.length) tokens.push({ texto: codigo.slice(cursor), tipo: 'texto' });
  return tokens;
}
