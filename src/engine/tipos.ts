/**
 * Modelo de datos del motor de analisis.
 *
 * Una `Regla` describe QUE se busca y COMO se explica. Un `Hallazgo` es una
 * regla que efectivamente coincidio en un punto concreto del codigo.
 */

export type Severidad = 'critica' | 'alta' | 'media' | 'baja';

export type Lenguaje = 'python' | 'javascript' | 'java' | 'generico';

/** Orden de mayor a menor gravedad; se usa para ordenar la lista de hallazgos. */
export const ORDEN_SEVERIDAD: Record<Severidad, number> = {
  critica: 0,
  alta: 1,
  media: 2,
  baja: 3,
};

export const ETIQUETA_SEVERIDAD: Record<Severidad, string> = {
  critica: 'Critica',
  alta: 'Alta',
  media: 'Media',
  baja: 'Baja',
};

/** Referencia a una categoria del OWASP Top 10 (edicion 2021). */
export interface CategoriaOwasp {
  id: string;
  nombre: string;
}

/** Referencia a una debilidad del catalogo CWE de MITRE. */
export interface ReferenciaCwe {
  id: string;
  nombre: string;
}

/**
 * Las tres fichas educativas: el corazon del producto.
 * Cada hallazgo tiene que ensenar algo, no solo senalar el error.
 */
export interface FichaEducativa {
  /** Que encontramos: descripcion del problema en lenguaje llano. */
  queEncontramos: string;
  /** Como te atacarian: el ataque concreto, contado de forma humana. */
  comoTeAtacarian: string;
  /** Como se arregla: la solucion explicada. */
  comoSeArregla: string;
  /** Snippet corregido que acompana a la explicacion anterior. */
  fix: {
    lenguaje: 'python' | 'javascript' | 'bash' | 'text';
    codigo: string;
  };
}

export interface Regla {
  id: string;
  titulo: string;
  severidad: Severidad;
  owasp: CategoriaOwasp;
  cwe: ReferenciaCwe;
  /**
   * Patron o patrones. Deben llevar la bandera `g`: se buscan todas las
   * coincidencias. Se admite una lista para poder mezclar banderas — por
   * ejemplo, una parte que distinga mayusculas y otra que no.
   */
  patron: RegExp | RegExp[];
  /**
   * Guardas negativas evaluadas sobre la LINEA COMPLETA donde cayo la coincidencia.
   * Existen para no gritarle a codigo que ya es correcto
   * (por ejemplo `password = os.getenv("DB_PASS")`).
   */
  ignorarSiLinea?: RegExp[];
  /** Guardas negativas evaluadas sobre el TEXTO COINCIDENTE. */
  ignorarSiCoincide?: RegExp[];
  /**
   * Por defecto una coincidencia que empieza dentro de una cadena de texto se
   * descarta (evita detectar `eval(` escrito dentro de un string). Las reglas
   * cuyo objetivo ES el contenido de la cadena — una clave de AWS, una URL —
   * ponen esto en `false`.
   */
  ignorarEnCadenas?: boolean;
  /**
   * Las cadenas de tres comillas suelen ser documentacion, y la documentacion
   * esta llena de ejemplos deliberadamente malos: `DEBUG = True`, URLs http://,
   * claves de juguete. Por defecto no se reportan; una regla puede pedir lo
   * contrario poniendo esto en `false`.
   */
  ignorarEnDocumentacion?: boolean;
  ficha: FichaEducativa;
}

export interface Hallazgo {
  /** Identificador unico del hallazgo (`reglaId:linea:columna`). */
  id: string;
  reglaId: string;
  titulo: string;
  severidad: Severidad;
  owasp: CategoriaOwasp;
  cwe: ReferenciaCwe;
  /** Numero de linea, empezando en 1. */
  linea: number;
  /** Numero de columna, empezando en 1. */
  columna: number;
  /** La linea de codigo exacta, sin indentacion sobrante. */
  fragmento: string;
  ficha: FichaEducativa;
}

export interface ResumenSeveridad {
  critica: number;
  alta: number;
  media: number;
  baja: number;
  total: number;
}

export interface ResultadoAnalisis {
  hallazgos: Hallazgo[];
  resumen: ResumenSeveridad;
  /** Lenguaje detectado. Es informativo: las reglas se aplican siempre todas. */
  lenguaje: Lenguaje;
  lineasAnalizadas: number;
  /** Duracion del analisis en milisegundos (para la barra de estado). */
  duracionMs: number;
}
