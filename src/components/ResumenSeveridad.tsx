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
}

export function ResumenSeveridad({ resumen }: Props) {
  const presentes = ORDEN.filter((severidad) => resumen[severidad] > 0);
  if (presentes.length === 0) return null;

  return (
    <ul className={estilos.resumen}>
      {presentes.map((severidad) => {
        const cantidad = resumen[severidad];
        const [singular, plural] = PLURAL[severidad];
        return (
          <li key={severidad} className={estilos.chip} data-severidad={severidad}>
            <span className={estilos.punto} aria-hidden="true" />
            <strong>{cantidad}</strong> {cantidad === 1 ? singular : plural}
          </li>
        );
      })}
    </ul>
  );
}
