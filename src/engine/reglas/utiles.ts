import type { CategoriaOwasp, ReferenciaCwe } from '../tipos';

/**
 * Une varias alternativas en un unico patron. Escribir cada caso en su propia
 * linea es mucho mas legible (y revisable) que una regex kilometrica.
 */
export function unir(partes: string[], flags = 'g'): RegExp {
  return new RegExp(partes.join('|'), flags);
}

/** Categorías del OWASP Top 10 — edición 2021. */
export const OWASP = {
  A01: { id: 'A01:2021', nombre: 'Pérdida de control de acceso' },
  A02: { id: 'A02:2021', nombre: 'Fallos criptográficos' },
  A03: { id: 'A03:2021', nombre: 'Inyección' },
  A05: { id: 'A05:2021', nombre: 'Configuración de seguridad defectuosa' },
  A07: { id: 'A07:2021', nombre: 'Fallos de identificación y autenticación' },
  A08: { id: 'A08:2021', nombre: 'Fallos de integridad de software y datos' },
} satisfies Record<string, CategoriaOwasp>;

/** Debilidades del catalogo CWE de MITRE. */
export const CWE = {
  CREDENCIALES_EMBEBIDAS: { id: 'CWE-798', nombre: 'Uso de credenciales embebidas en el código' },
  SQL: { id: 'CWE-89', nombre: 'Neutralización incorrecta de elementos en una sentencia SQL' },
  COMANDOS: {
    id: 'CWE-78',
    nombre: 'Neutralización incorrecta de elementos en un comando del sistema',
  },
  EVAL: { id: 'CWE-95', nombre: 'Inyección de código evaluado dinámicamente' },
  XSS: { id: 'CWE-79', nombre: 'Neutralización incorrecta de entrada al generar una página web' },
  DESERIALIZACION: { id: 'CWE-502', nombre: 'Deserialización de datos no confiables' },
  HASH_DEBIL: { id: 'CWE-327', nombre: 'Uso de un algoritmo criptográfico roto o arriesgado' },
  CERTIFICADO: { id: 'CWE-295', nombre: 'Validación incorrecta de certificados' },
  TEXTO_PLANO: { id: 'CWE-319', nombre: 'Transmisión de información sensible en texto plano' },
  DEPURACION: { id: 'CWE-489', nombre: 'Código de depuración activo en producción' },
  RUTA: { id: 'CWE-22', nombre: 'Recorrido de directorios al construir una ruta de archivo' },
  XXE: { id: 'CWE-611', nombre: 'Procesamiento de entidades externas en documentos XML' },
  FIRMA: { id: 'CWE-347', nombre: 'Verificación incorrecta de una firma criptográfica' },
  PLANTILLA: {
    id: 'CWE-1336',
    nombre: 'Neutralización incorrecta de la sintaxis de plantillas del servidor',
  },
  CORS: { id: 'CWE-942', nombre: 'Política de origen cruzado demasiado permisiva' },
  CSRF: { id: 'CWE-352', nombre: 'Falsificación de peticiones en sitios cruzados' },
  COOKIE: { id: 'CWE-614', nombre: 'Cookie sensible sin los atributos de seguridad' },
  ALEATORIEDAD: {
    id: 'CWE-338',
    nombre: 'Generador pseudoaleatorio criptográficamente débil',
  },
  REDIRECCION: { id: 'CWE-601', nombre: 'Redirección hacia un destino no confiable' },
} satisfies Record<string, ReferenciaCwe>;

/** Comilla invertida escrita como escape, para no pelear con las plantillas de JS. */
export const BT = '\\x60';
