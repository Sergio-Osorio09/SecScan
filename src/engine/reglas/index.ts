import type { Regla } from '../tipos';
import { reglasDeAcceso } from './acceso';
import { reglasDeConfiguracion } from './configuracion';
import { reglasDeCriptografia } from './criptografia';
import { reglasDeIntegridad } from './integridad';
import { reglasDeInyeccion } from './inyeccion';
import { reglasDeSecretos } from './secretos';

/**
 * Catalogo completo, agrupado por categoria del OWASP Top 10.
 * Anadir una regla nueva es anadir un objeto a uno de estos archivos.
 */
export const CATALOGO_DE_REGLAS: Regla[] = [
  ...reglasDeSecretos, // A07 — credenciales y autenticacion
  ...reglasDeInyeccion, // A03 — inyeccion
  ...reglasDeAcceso, // A01 — control de acceso
  ...reglasDeIntegridad, // A08 — integridad
  ...reglasDeCriptografia, // A02 — fallos criptograficos
  ...reglasDeConfiguracion, // A05 — configuracion
];

export const REGLAS_POR_ID: ReadonlyMap<string, Regla> = new Map(
  CATALOGO_DE_REGLAS.map((regla) => [regla.id, regla]),
);

export * from './secretos';
export * from './inyeccion';
export * from './acceso';
export * from './integridad';
export * from './criptografia';
export * from './configuracion';
