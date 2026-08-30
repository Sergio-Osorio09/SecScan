import type { ResumenSeveridad as Resumen, Severidad } from '../engine/tipos';
import estilos from './ResumenSeveridad.module.css';

const PLURAL: Record<Severidad, [string, string]> = {
  critica: ['Crítica', 'Críticas'],
  alta: ['Alta', 'Altas'],
  media: ['Media', 'Medias'],
  baja: ['Baja', 'Bajas'],
};

const ORDEN: Severidad[] = ['critica', 'alta', 'media', 'baja'];

interface Props {
  resumen: Resumen;
  /** Severidad por la que se está filtrando, o `null` si se ven todas. */
  filtro: Severidad | null;
  onFiltrar: (severidad: Severidad | null) => void;
}

/**
 * Los chips del resumen hacen de filtro: pulsar uno deja solo esa severidad y
 * volver a pulsarlo lo quita. Con trece hallazgos ya cuesta encontrar las
 * críticas, y con trescientos es la unica forma de moverse.
 */
export function ResumenSeveridad({ resumen, filtro, onFiltrar }: Props) {
  const presentes = ORDEN.filter((severidad) => resumen[severidad] > 0);
  if (presentes.length === 0) return null;

  return (
    <div className={estilos.resumen} role="group" aria-label="Filtrar por severidad">
      {presentes.map((severidad) => {
        const cantidad = resumen[severidad];
        const [singular, plural] = PLURAL[severidad];
        const activo = filtro === severidad;
        return (
          <button
            key={severidad}
            type="button"
            className={activo ? `${estilos.chip} ${estilos.activo}` : estilos.chip}
            data-severidad={severidad}
            aria-pressed={activo}
            title={activo ? 'Quitar el filtro' : `Ver solo las de severidad ${singular}`}
            onClick={() => onFiltrar(activo ? null : severidad)}
          >
            <span className={estilos.punto} aria-hidden="true" />
            <strong>{cantidad}</strong> {cantidad === 1 ? singular : plural}
          </button>
        );
      })}

      {filtro !== null && (
        <button type="button" className={estilos.quitar} onClick={() => onFiltrar(null)}>
          Ver todas
        </button>
      )}
    </div>
  );
}
