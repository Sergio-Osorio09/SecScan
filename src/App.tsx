import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import estilos from './App.module.css';
import { BarraEstado } from './components/BarraEstado';
import { BarraHerramientas } from './components/BarraHerramientas';
import { CatalogoReglas } from './components/CatalogoReglas';
import { EditorCodigo } from './components/EditorCodigo';
import type { PosicionCursor } from './components/EditorCodigo';
import { Encabezado } from './components/Encabezado';
import { PanelHallazgos } from './components/PanelHallazgos';
import { PieDePagina } from './components/PieDePagina';
import { analizar } from './engine/analizar';
import { CATALOGO_DE_REGLAS } from './engine/reglas';
import { ETIQUETA_LENGUAJE, EXTENSION_LENGUAJE, detectarLenguaje } from './engine/preprocesar';
import type { ResultadoAnalisis, Severidad } from './engine/tipos';
import { useTema } from './hooks/useTema';
import { LIMITE_CARACTERES } from './components/resaltarSintaxis';
import { EJEMPLOS_POR_ID } from './samples/ejemplos';

/**
 * Pausa deliberada antes de mostrar los resultados. El analisis tarda un par de
 * milisegundos: sin esta espera el estado "analizando" parpadearia y el cambio
 * de la pantalla vacia a la lista de hallazgos resultaria brusco.
 */
const ESPERA_ANALISIS_MS = 220;

/** Enlaza el boton del encabezado con el panel del catalogo para los lectores de pantalla. */
const ID_CATALOGO = 'catalogo-de-reglas';

export default function App() {
  const { tema, alternarTema } = useTema();

  const [codigo, setCodigo] = useState('');
  const [resultado, setResultado] = useState<ResultadoAnalisis | null>(null);
  const [escaneando, setEscaneando] = useState(false);
  const [expandidas, setExpandidas] = useState<Set<string>>(new Set());
  const [lineaResaltada, setLineaResaltada] = useState<number | null>(null);
  const [cursor, setCursor] = useState<PosicionCursor>({ linea: 1, columna: 1 });
  const [ejemploActivo, setEjemploActivo] = useState<string | null>(null);
  const [catalogoAbierto, setCatalogoAbierto] = useState(false);
  const [filtro, setFiltro] = useState<Severidad | null>(null);

  const temporizador = useRef<number | null>(null);
  useEffect(() => () => window.clearTimeout(temporizador.current ?? undefined), []);

  const lenguaje = useMemo(() => detectarLenguaje(codigo), [codigo]);

  const ejecutar = useCallback(
    (fuente?: string) => {
      const texto = fuente ?? codigo;
      if (!texto.trim()) return;

      setEscaneando(true);
      setResultado(null);
      setExpandidas(new Set());
      setLineaResaltada(null);
      setFiltro(null);

      window.clearTimeout(temporizador.current ?? undefined);
      temporizador.current = window.setTimeout(() => {
        const nuevoResultado = analizar(texto);
        setResultado(nuevoResultado);
        setEscaneando(false);
        // El hallazgo mas grave se abre solo: quien no es tecnico ve de
        // inmediato la explicacion, sin tener que descubrir que se despliega.
        const primero = nuevoResultado.hallazgos[0];
        if (primero) setExpandidas(new Set([primero.id]));
      }, ESPERA_ANALISIS_MS);
    },
    [codigo],
  );

  const cambiarCodigo = useCallback((texto: string) => {
    setCodigo(texto);
    setEjemploActivo(null);
    // Los resultados dejan de corresponder al codigo en cuanto se edita.
    setResultado(null);
    setLineaResaltada(null);
  }, []);

  const cargarEjemplo = useCallback(
    (id: string) => {
      const ejemplo = EJEMPLOS_POR_ID.get(id);
      if (!ejemplo) return;
      setCodigo(ejemplo.codigo);
      setEjemploActivo(id);
      setCursor({ linea: 1, columna: 1 });
      ejecutar(ejemplo.codigo);
    },
    [ejecutar],
  );

  const limpiar = useCallback(() => {
    window.clearTimeout(temporizador.current ?? undefined);
    setCodigo('');
    setResultado(null);
    setEscaneando(false);
    setExpandidas(new Set());
    setLineaResaltada(null);
    setEjemploActivo(null);
    setFiltro(null);
    setCursor({ linea: 1, columna: 1 });
  }, []);

  const alternarTarjeta = useCallback((id: string) => {
    setExpandidas((actuales) => {
      const siguiente = new Set(actuales);
      if (siguiente.has(id)) siguiente.delete(id);
      else siguiente.add(id);
      return siguiente;
    });
  }, []);

  const alternarTodas = useCallback(() => {
    setExpandidas((actuales) => {
      const hallazgos = resultado?.hallazgos ?? [];
      if (actuales.size === hallazgos.length) return new Set();
      return new Set(hallazgos.map((hallazgo) => hallazgo.id));
    });
  }, [resultado]);

  return (
    <div className={estilos.pagina}>
      <Encabezado
        totalReglas={CATALOGO_DE_REGLAS.length}
        catalogoAbierto={catalogoAbierto}
        idCatalogo={ID_CATALOGO}
        onAlternarCatalogo={() => setCatalogoAbierto((abierto) => !abierto)}
      />

      {catalogoAbierto && <CatalogoReglas id={ID_CATALOGO} />}

      <main className={estilos.consola}>
        <div className={estilos.barraTitulo}>
          <span className={estilos.semaforos} aria-hidden="true">
            <i />
            <i />
            <i />
          </span>
          <span className={estilos.tituloVentana}>SecScan — analizador de seguridad</span>
          <button type="button" className={estilos.botonTema} onClick={alternarTema}>
            {tema === 'oscuro' ? 'Tema claro' : 'Tema oscuro'}
          </button>
        </div>

        <BarraHerramientas
          escaneando={escaneando}
          hayCodigo={codigo.trim().length > 0}
          ejemploActivo={ejemploActivo}
          onEjecutar={() => ejecutar()}
          onLimpiar={limpiar}
          onCargarEjemplo={cargarEjemplo}
        />

        <div className={estilos.cuerpo}>
          <EditorCodigo
            valor={codigo}
            nombreArchivo={EXTENSION_LENGUAJE[lenguaje]}
            lenguaje={lenguaje}
            lineaResaltada={lineaResaltada}
            onCambio={cambiarCodigo}
            onMoverCursor={setCursor}
            onEjecutar={ejecutar}
          />

          <PanelHallazgos
            resultado={resultado}
            escaneando={escaneando}
            expandidas={expandidas}
            filtro={filtro}
            onFiltrar={setFiltro}
            onAlternarTarjeta={alternarTarjeta}
            onExpandirTodo={alternarTodas}
            onIrALinea={setLineaResaltada}
          />
        </div>

        <BarraEstado
          etiquetaLenguaje={ETIQUETA_LENGUAJE[lenguaje]}
          cursor={cursor}
          totalHallazgos={resultado ? resultado.hallazgos.length : null}
          duracionMs={resultado ? resultado.duracionMs : null}
          escaneando={escaneando}
          resaltadoActivo={codigo.length <= LIMITE_CARACTERES}
        />
      </main>

      <PieDePagina />
    </div>
  );
}
