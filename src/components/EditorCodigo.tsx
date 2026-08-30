import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { Lenguaje } from '../engine/tipos';
import { CodigoResaltado } from './CodigoResaltado';
import { IconoLenguaje } from './IconoLenguaje';
import estilos from './EditorCodigo.module.css';

/** Deben coincidir con --editor-linea y --editor-pad-y de tokens.css. */
const ALTO_LINEA = 21;
const RELLENO_VERTICAL = 12;

/** Mas de esto no es codigo que alguien vaya a revisar a mano. */
const MAXIMO_ARCHIVO = 2 * 1024 * 1024;

export interface PosicionCursor {
  linea: number;
  columna: number;
}

interface Props {
  valor: string;
  nombreArchivo: string;
  lenguaje: Lenguaje;
  lineaResaltada: number | null;
  onCambio: (valor: string) => void;
  onMoverCursor: (posicion: PosicionCursor) => void;
  onEjecutar: (fuente?: string) => void;
}

const MARCADOR = `// Pega aquí tu código o tu archivo de configuración.
//
// Ejemplos que puedes probar:
//   · Python o JavaScript con inyección SQL o XSS
//   · Configuración con contraseñas o claves de API
//   · Código que use eval(), md5() o verify=False
//
// O carga uno de los ejemplos de arriba con un clic.`;

/**
 * Editor minimo: un textarea sobre una capa de resaltado, con su propia
 * columna de numeros de linea.
 *
 * Se prefirio esto a una libreria de edicion (CodeMirror, Monaco) porque
 * aqui solo hacen falta numeros de linea, posicion del cursor y resaltar
 * la linea de un hallazgo — y el resultado pesa unos pocos kilobytes.
 */
export function EditorCodigo({
  valor,
  nombreArchivo,
  lenguaje,
  lineaResaltada,
  onCambio,
  onMoverCursor,
  onEjecutar,
}: Props) {
  const refTexto = useRef<HTMLTextAreaElement>(null);
  const refNumeros = useRef<HTMLDivElement>(null);
  const refCapa = useRef<HTMLDivElement>(null);

  const totalLineas = useMemo(() => valor.split('\n').length, [valor]);

  const sincronizarDesplazamiento = useCallback(() => {
    const texto = refTexto.current;
    if (!texto) return;
    if (refNumeros.current) refNumeros.current.scrollTop = texto.scrollTop;
    if (refCapa.current) {
      refCapa.current.scrollTop = texto.scrollTop;
      refCapa.current.scrollLeft = texto.scrollLeft;
    }
  }, []);

  const informarCursor = useCallback(() => {
    const texto = refTexto.current;
    if (!texto) return;
    const hasta = texto.value.slice(0, texto.selectionStart);
    const salto = hasta.lastIndexOf('\n');
    onMoverCursor({ linea: hasta.split('\n').length, columna: hasta.length - salto });
  }, [onMoverCursor]);

  // Al pulsar un hallazgo, su linea se centra en pantalla.
  useEffect(() => {
    const texto = refTexto.current;
    if (!texto || lineaResaltada === null) return;
    const alturaLinea = parseFloat(getComputedStyle(texto).lineHeight) || ALTO_LINEA;
    const objetivo = (lineaResaltada - 1) * alturaLinea - texto.clientHeight / 2 + alturaLinea;
    texto.scrollTop = Math.max(0, objetivo);
    sincronizarDesplazamiento();
  }, [lineaResaltada, sincronizarDesplazamiento]);

  useLayoutEffect(() => {
    sincronizarDesplazamiento();
  }, [valor, sincronizarDesplazamiento]);

  const numeros = useMemo(
    () => Array.from({ length: Math.max(totalLineas, 16) }, (_, i) => i + 1),
    [totalLineas],
  );

  const [arrastrando, setArrastrando] = useState(false);

  /**
   * Soltar un archivo encima lo carga y lo analiza. Se lee como texto: si
   * alguien suelta una imagen o un binario saldra ruido, asi que se descarta
   * por tamano y se avisa de que solo tiene sentido con codigo.
   */
  const soltarArchivo = useCallback(
    async (evento: React.DragEvent) => {
      evento.preventDefault();
      setArrastrando(false);
      const archivo = evento.dataTransfer.files[0];
      if (!archivo) return;
      if (archivo.size > MAXIMO_ARCHIVO) {
        onCambio(`// El archivo "${archivo.name}" pasa de 2 MB y no se ha cargado.`);
        return;
      }
      const texto = await archivo.text();
      onCambio(texto);
      onEjecutar(texto);
    },
    [onCambio, onEjecutar],
  );


  return (
    <div className={estilos.editor}>
      <div className={estilos.pestana}>
        <span className={estilos.nombreArchivo}>
          <IconoLenguaje lenguaje={lenguaje} />
          {nombreArchivo}
        </span>
      </div>

      <div
        className={arrastrando ? `${estilos.area} ${estilos.arrastrando}` : estilos.area}
        onDragOver={(evento) => {
          evento.preventDefault();
          setArrastrando(true);
        }}
        onDragLeave={() => setArrastrando(false)}
        onDrop={soltarArchivo}
      >
        <div className={estilos.numeros} ref={refNumeros} aria-hidden="true">
          {numeros.map((numero) => (
            <div
              key={numero}
              className={numero === lineaResaltada ? estilos.numeroActivo : undefined}
            >
              {numero}
            </div>
          ))}
        </div>

        <div className={estilos.lienzo}>
          {/* Capa de color: se ve a traves del textarea, que lleva el texto
              transparente. Ambos comparten fuente, tamano, interlineado y
              relleno, asi que cada glifo cae justo encima de su color. */}
          <div className={estilos.capa} ref={refCapa} aria-hidden="true">
            <div className={estilos.contenidoCapa}>
              {lineaResaltada !== null && lineaResaltada <= totalLineas && (
                <div
                  className={estilos.resaltado}
                  style={{ top: (lineaResaltada - 1) * ALTO_LINEA + RELLENO_VERTICAL }}
                />
              )}
              <pre className={estilos.sintaxis}>
                <CodigoResaltado texto={valor} />
                {/* Un textarea reserva una linea vacia al final y un `pre` no.
                    Este salto extra iguala las dos alturas; sin el, la capa de
                    color se queda corta al llegar al final del archivo. */}
                {'\n'}
              </pre>
            </div>
          </div>

          <textarea
            ref={refTexto}
            className={estilos.texto}
            value={valor}
            onChange={(evento) => onCambio(evento.target.value)}
            onScroll={sincronizarDesplazamiento}
            onKeyUp={informarCursor}
            onClick={informarCursor}
            onSelect={informarCursor}
            onKeyDown={(evento) => {
              if ((evento.ctrlKey || evento.metaKey) && evento.key === 'Enter') {
                evento.preventDefault();
                onEjecutar();
              }
            }}
            placeholder={MARCADOR}
            spellCheck={false}
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="off"
            wrap="off"
            aria-label="Código a analizar"
          />
        </div>
      </div>
    </div>
  );
}
