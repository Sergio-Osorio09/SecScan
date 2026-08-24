import estilos from './Encabezado.module.css';

/** Silueta de la cabeza (pelaje, orejas y hocico). */
const SILUETA_JASPPER =
  'M21.5 25L20.64 13.79Q20.5 12 21.87 13.17L30.5 20.5ZM33.5 20.5L42.13 13.17Q43.5 12 43.36 13.79L42.5 25ZM32 20.3A4.28 4.28 0 0 1 40 22.2A4.07 4.07 0 0 1 45.86 27.4A3.86 3.86 0 0 1 48 34.5A3.86 3.86 0 0 1 45.86 41.6A4.07 4.07 0 0 1 40 46.8A4.28 4.28 0 0 1 32 48.7A4.28 4.28 0 0 1 24 46.8A4.07 4.07 0 0 1 18.14 41.6A3.86 3.86 0 0 1 16 34.5A3.86 3.86 0 0 1 18.14 27.4A4.07 4.07 0 0 1 24 22.2A4.28 4.28 0 0 1 32 20.3ZM32 36.7A5.31 5.31 0 0 1 39.1 40.1A4.59 4.59 0 0 1 39.1 46.9A5.31 5.31 0 0 1 32 50.3A5.31 5.31 0 0 1 24.9 46.9A4.59 4.59 0 0 1 24.9 40.1A5.31 5.31 0 0 1 32 36.7Z';

/** Ojos, nariz y boca. */
const RASGOS_JASPPER =
  'M23.1 32.4A2.5 2.7 0 0 1 28.1 32.4A2.5 2.7 0 0 1 23.1 32.4ZM35.9 32.4A2.5 2.7 0 0 1 40.9 32.4A2.5 2.7 0 0 1 35.9 32.4ZM28.8 40.4C28.8 38 35.2 38 35.2 40.4C35.2 43.76 33.6 45.2 32 45.2C30.4 45.2 28.8 43.76 28.8 40.4ZM29 46.4C29 48.6 35 48.6 35 46.4L33.6 46.4C33.6 47.3 30.4 47.3 30.4 46.4Z';

/**
 * Jaspper, el pomerania de la casa, hace de logo.
 *
 * Los rasgos se recortan con una mascara y no invirtiendo el sentido del
 * trazado: el hocico se superpone a la cabeza, y sobre dos capas un agujero
 * por regla de relleno no llega a abrir. Con mascara, blanco es lo que se ve
 * y negro lo que se quita, y el color lo pone `currentColor`.
 */
function JaspperLogo() {
  return (
    <svg className={estilos.logo} viewBox="0 0 64 64" role="img" aria-label="Jaspper, la mascota de SecScan">
      <mask id="silueta-jaspper" maskUnits="userSpaceOnUse" x="0" y="0" width="64" height="64">
        <path d={SILUETA_JASPPER} fill="#fff" />
        <path d={RASGOS_JASPPER} fill="#000" />
      </mask>
      <rect width="64" height="64" fill="currentColor" mask="url(#silueta-jaspper)" />
    </svg>
  );
}

const PILDORAS = [
  { texto: '100% en tu navegador', destacada: true },
  { texto: 'Nada se envía a un servidor', destacada: false },
  { texto: 'Sin registro', destacada: false },
  { texto: 'Gratis', destacada: false },
];

interface Props {
  totalReglas: number;
  catalogoAbierto: boolean;
  idCatalogo: string;
  onAlternarCatalogo: () => void;
}

export function Encabezado({
  totalReglas,
  catalogoAbierto,
  idCatalogo,
  onAlternarCatalogo,
}: Props) {
  return (
    <header className={estilos.encabezado}>
      <div className={estilos.marca}>
        <JaspperLogo />
        <h1 className={estilos.nombre}>SecScan</h1>
      </div>

      <p className={estilos.lema}>
        Analiza tu código y aprende a protegerlo: detecta secretos, inyecciones y malas
        configuraciones, y te explica cada hallazgo en español —{' '}
        <strong>qué es, cómo te atacarían y cómo se arregla</strong>.
      </p>

      <ul className={estilos.pildoras}>
        {PILDORAS.map((pildora) => (
          <li
            key={pildora.texto}
            className={pildora.destacada ? `${estilos.pildora} ${estilos.destacada}` : estilos.pildora}
          >
            {pildora.texto}
          </li>
        ))}
      </ul>

      <button
        type="button"
        className={estilos.verCatalogo}
        onClick={onAlternarCatalogo}
        aria-expanded={catalogoAbierto}
        aria-controls={idCatalogo}
      >
        {catalogoAbierto ? 'Ocultar el catálogo' : `Ver las ${totalReglas} reglas que detecta`}
        <svg className={estilos.flechaCatalogo} viewBox="0 0 16 16" aria-hidden="true">
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
    </header>
  );
}
