import type { PosicionCursor } from './EditorCodigo';
import estilos from './BarraEstado.module.css';

interface Props {
  etiquetaLenguaje: string;
  cursor: PosicionCursor;
  totalHallazgos: number | null;
  duracionMs: number | null;
  escaneando: boolean;
}

export function BarraEstado({
  etiquetaLenguaje,
  cursor,
  totalHallazgos,
  duracionMs,
  escaneando,
}: Props) {
  const estadoAnalisis = () => {
    if (escaneando) return 'analizando…';
    if (totalHallazgos === null) return 'sin análisis';
    const plural = totalHallazgos === 1 ? 'hallazgo' : 'hallazgos';
    // Un análisis de medio milisegundo redondeaba a "0 ms", que parece un error.
    const tiempo = duracionMs !== null && duracionMs < 1 ? '<1 ms' : `${duracionMs} ms`;
    return `${totalHallazgos} ${plural} · ${tiempo}`;
  };

  return (
    <div className={estilos.barra}>
      <div className={estilos.grupo}>
        <span className={estilos.marca}>SecScan</span>
        <span>{etiquetaLenguaje}</span>
      </div>
      <div className={estilos.grupo}>
        <span>
          Ln {cursor.linea}, Col {cursor.columna}
        </span>
        <span>UTF-8</span>
        <span className={estilos.estado}>{estadoAnalisis()}</span>
      </div>
    </div>
  );
}
