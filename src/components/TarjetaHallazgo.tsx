import type { Hallazgo, Severidad } from '../engine/tipos';
import { CodigoResaltado } from './CodigoResaltado';
import estilos from './TarjetaHallazgo.module.css';

const ETIQUETA: Record<Severidad, string> = {
  critica: 'Crítica',
  alta: 'Alta',
  media: 'Media',
  baja: 'Baja',
};

interface Props {
  hallazgo: Hallazgo;
  expandida: boolean;
  onAlternar: () => void;
  onIrALinea: (linea: number) => void;
}

/**
 * Iconos de las tres fichas. Trazo fino y color heredado del bloque:
 * ordenan la lectura sin bajar el registro del contenido.
 */
function IconoHallazgo() {
  return (
    <svg className={estilos.iconoBloque} viewBox="0 0 16 16" aria-hidden="true">
      <rect x="3" y="2" width="10" height="12" rx="1.5" fill="none" stroke="currentColor" />
      <path d="M5.6 6h4.8M5.6 8.6h4.8M5.6 11.2h2.8" stroke="currentColor" strokeLinecap="round" />
    </svg>
  );
}

function IconoAtaque() {
  return (
    <svg className={estilos.iconoBloque} viewBox="0 0 16 16" aria-hidden="true">
      <circle cx="8" cy="8" r="5.4" fill="none" stroke="currentColor" />
      <circle cx="8" cy="8" r="1.5" fill="none" stroke="currentColor" />
      <path d="M8 .8v2.4M8 12.8v2.4M.8 8h2.4M12.8 8h2.4" stroke="currentColor" strokeLinecap="round" />
    </svg>
  );
}

function IconoSolucion() {
  return (
    <svg className={estilos.iconoBloque} viewBox="0 0 16 16" aria-hidden="true">
      <path d="M8 1.6l5 1.7v4c0 3-2 5.6-5 6.5-3-.9-5-3.5-5-6.5v-4l5-1.7z" fill="none" stroke="currentColor" strokeLinejoin="round" />
      <path d="M5.9 7.9l1.6 1.7 2.9-3.4" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function TarjetaHallazgo({ hallazgo, expandida, onAlternar, onIrALinea }: Props) {
  const idDetalle = `detalle-${hallazgo.id.replace(/[^\w-]/g, '_')}`;

  return (
    <article className={estilos.tarjeta} data-severidad={hallazgo.severidad}>
      <button
        type="button"
        className={estilos.cabecera}
        onClick={onAlternar}
        aria-expanded={expandida}
        aria-controls={idDetalle}
      >
        <span className={estilos.severidad}>{ETIQUETA[hallazgo.severidad]}</span>
        <span className={estilos.titulo}>{hallazgo.titulo}</span>
        <span className={estilos.meta}>
          Línea {hallazgo.linea} · {hallazgo.owasp.id} · {hallazgo.cwe.id}
        </span>
        <svg className={estilos.flecha} viewBox="0 0 16 16" aria-hidden="true">
          <path
            d="M4 6l4 4 4-4"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.6"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </button>

      {expandida && (
        <div className={estilos.detalle} id={idDetalle}>
          <button
            type="button"
            className={estilos.fragmento}
            onClick={() => onIrALinea(hallazgo.linea)}
            title="Ver esta línea en el editor"
          >
            <span className={estilos.numeroLinea}>{hallazgo.linea}</span>
            <code>
              <CodigoResaltado texto={hallazgo.fragmento} />
            </code>
          </button>

          <section className={estilos.bloque}>
            <h4 className={estilos.subtitulo}>
              <IconoHallazgo /> Qué encontramos
            </h4>
            <p>{hallazgo.ficha.queEncontramos}</p>
          </section>

          <section className={`${estilos.bloque} ${estilos.bloqueAtaque}`}>
            <h4 className={estilos.subtitulo}>
              <IconoAtaque /> Cómo te atacarían
            </h4>
            <p>{hallazgo.ficha.comoTeAtacarian}</p>
          </section>

          <section className={`${estilos.bloque} ${estilos.bloqueSolucion}`}>
            <h4 className={estilos.subtitulo}>
              <IconoSolucion /> Cómo se arregla
            </h4>
            <p>{hallazgo.ficha.comoSeArregla}</p>
            <figure className={estilos.solucion}>
              <figcaption className={estilos.lenguajeFix}>{hallazgo.ficha.fix.lenguaje}</figcaption>
              <pre>
                <code>
                  <CodigoResaltado texto={hallazgo.ficha.fix.codigo} />
                </code>
              </pre>
            </figure>
          </section>

          <footer className={estilos.referencias}>
            <span>
              <strong>{hallazgo.owasp.id}</strong> {hallazgo.owasp.nombre}
            </span>
            <span>
              <strong>{hallazgo.cwe.id}</strong> {hallazgo.cwe.nombre}
            </span>
          </footer>
        </div>
      )}
    </article>
  );
}
