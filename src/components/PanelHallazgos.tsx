import type { ResultadoAnalisis } from '../engine/tipos';
import estilos from './PanelHallazgos.module.css';
import { ResumenSeveridad } from './ResumenSeveridad';
import { TarjetaHallazgo } from './TarjetaHallazgo';

interface Props {
  resultado: ResultadoAnalisis | null;
  escaneando: boolean;
  expandidas: Set<string>;
  onAlternarTarjeta: (id: string) => void;
  onExpandirTodo: () => void;
  onIrALinea: (linea: number) => void;
}

export function PanelHallazgos({
  resultado,
  escaneando,
  expandidas,
  onAlternarTarjeta,
  onExpandirTodo,
  onIrALinea,
}: Props) {
  const hallazgos = resultado?.hallazgos ?? [];
  const todasAbiertas = hallazgos.length > 0 && expandidas.size === hallazgos.length;

  return (
    <section className={estilos.panel} aria-label="Resultados del análisis">
      <header className={estilos.cabecera}>
        <h2 className={estilos.tituloPanel}>
          Hallazgos
          {resultado && <span className={estilos.contador}>{hallazgos.length}</span>}
        </h2>
        {hallazgos.length > 0 && (
          <button type="button" className={estilos.accion} onClick={onExpandirTodo}>
            {todasAbiertas ? 'Contraer todo' : 'Expandir todo'}
          </button>
        )}
      </header>

      {resultado && hallazgos.length > 0 && <ResumenSeveridad resumen={resultado.resumen} />}

      <div className={estilos.contenido} aria-live="polite" aria-busy={escaneando}>
        {escaneando && (
          <div className={estilos.estado}>
            <span className={estilos.radar} aria-hidden="true" />
            <p className={estilos.tituloEstado}>Analizando…</p>
            <p className={estilos.textoEstado}>Aplicando las reglas sobre tu código.</p>
          </div>
        )}

        {!escaneando && !resultado && (
          <div className={estilos.estado}>
            <svg className={estilos.icono} viewBox="0 0 32 32" aria-hidden="true">
              <path
                d="M16 4l10 3.5v7.8c0 5.9-4 11.2-10 12.7-6-1.5-10-6.8-10-12.7V7.5L16 4z"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinejoin="round"
              />
            </svg>
            <p className={estilos.tituloEstado}>Aún no hay análisis</p>
            <p className={estilos.textoEstado}>
              Pega tu código a la izquierda y pulsa <strong>Ejecutar análisis</strong>, o carga uno
              de los ejemplos.
            </p>
          </div>
        )}

        {!escaneando && resultado && hallazgos.length === 0 && (
          <div className={`${estilos.estado} ${estilos.limpio}`}>
            <svg className={estilos.icono} viewBox="0 0 32 32" aria-hidden="true">
              <circle cx="16" cy="16" r="11" fill="none" stroke="currentColor" strokeWidth="1.5" />
              <path
                d="M11 16.5l3.5 3.5L21 12"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.8"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
            <p className={estilos.tituloEstado}>Sin patrones de riesgo detectados</p>
            <p className={estilos.textoEstado}>
              Ninguna de las {resultado.lineasAnalizadas} líneas analizadas coincide con las reglas
              de SecScan. Ten en cuenta que esto no garantiza que el código sea seguro: hay fallos
              que el análisis estático no puede detectar.
            </p>
          </div>
        )}

        {!escaneando && hallazgos.length > 0 && (
          <ul className={estilos.lista}>
            {hallazgos.map((hallazgo) => (
              <li key={hallazgo.id}>
                <TarjetaHallazgo
                  hallazgo={hallazgo}
                  expandida={expandidas.has(hallazgo.id)}
                  onAlternar={() => onAlternarTarjeta(hallazgo.id)}
                  onIrALinea={onIrALinea}
                />
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
