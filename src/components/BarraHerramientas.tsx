import { EJEMPLOS } from '../samples/ejemplos';
import { IconoLenguaje } from './IconoLenguaje';
import estilos from './BarraHerramientas.module.css';

interface Props {
  escaneando: boolean;
  hayCodigo: boolean;
  ejemploActivo: string | null;
  onEjecutar: () => void;
  onLimpiar: () => void;
  onCargarEjemplo: (id: string) => void;
}

export function BarraHerramientas({
  escaneando,
  hayCodigo,
  ejemploActivo,
  onEjecutar,
  onLimpiar,
  onCargarEjemplo,
}: Props) {
  return (
    <div className={estilos.barra}>
      <button
        type="button"
        className={estilos.primario}
        onClick={onEjecutar}
        disabled={!hayCodigo || escaneando}
        title="Ejecutar análisis (Ctrl + Enter)"
      >
        <svg className={estilos.iconoEjecutar} viewBox="0 0 12 12" aria-hidden="true">
          <path d="M3 1.8l6.4 4.2L3 10.2z" fill="currentColor" />
        </svg>
        {escaneando ? 'Analizando…' : 'Ejecutar análisis'}
      </button>

      <button type="button" className={estilos.secundario} onClick={onLimpiar} disabled={!hayCodigo}>
        Limpiar
      </button>

      <span className={estilos.separador} aria-hidden="true" />

      <span className={estilos.etiqueta} id="etiqueta-ejemplos">
        Ejemplos
      </span>

      <div className={estilos.ejemplos} role="group" aria-labelledby="etiqueta-ejemplos">
        {EJEMPLOS.map((ejemplo) => (
          <button
            key={ejemplo.id}
            type="button"
            className={
              ejemploActivo === ejemplo.id ? `${estilos.ejemplo} ${estilos.activo}` : estilos.ejemplo
            }
            onClick={() => onCargarEjemplo(ejemplo.id)}
            title={ejemplo.subtitulo}
          >
            <IconoLenguaje lenguaje={ejemplo.lenguaje} />
            {ejemplo.titulo}
          </button>
        ))}
      </div>
    </div>
  );
}
