import type { Lenguaje } from '../engine/tipos';
import estilos from './IconoLenguaje.module.css';

interface Props {
  lenguaje: Lenguaje;
}

/**
 * Distintivo del lenguaje junto al nombre del archivo, como la pestana de un
 * IDE o la columna de iconos de un gestor de archivos de terminal.
 *
 * Son las marcas reales dibujadas como trazado, no glifos de una Nerd Font:
 * empaquetar una fuente de simbolos costaria megabytes para tres iconos, y
 * ademas la aplicacion promete no pedir nada a ningun servidor.
 */

/**
 * Mitad del logotipo de Python. La marca son dos piezas identicas giradas 180
 * grados entre si, asi que se dibuja una sola vez y se reutiliza rotada.
 * El ojo va en el mismo trazado con relleno `evenodd`, que lo convierte en hueco.
 */
const MITAD_PYTHON =
  'M31.9 5.3c-2.2 0-4.3.2-6.2.5-5.5 1-6.5 3-6.5 6.8v5h13v1.6H14.4c-3.8 0-7.1 2.3-8.2 6.7-1.2 5-1.2 8.1 0 13.3.9 3.9 3.1 6.7 6.9 6.7h4.5v-6c0-4.3 3.7-8.1 8.2-8.1h13c3.6 0 6.5-3 6.5-6.7V12.6c0-3.5-3-6.2-6.6-6.8-2.2-.4-4.6-.5-6.8-.5zM24.9 9.3c1.3 0 2.4 1.1 2.4 2.5s-1.1 2.4-2.4 2.4c-1.4 0-2.4-1.1-2.4-2.4 0-1.4 1.1-2.5 2.4-2.5z';

export function IconoLenguaje({ lenguaje }: Props) {
  if (lenguaje === 'python') {
    return (
      <svg className={estilos.icono} viewBox="0 0 64 64" aria-hidden="true">
        <path d={MITAD_PYTHON} fill="#3776ab" fillRule="evenodd" />
        <path
          d={MITAD_PYTHON}
          fill="#ffd43b"
          fillRule="evenodd"
          transform="rotate(180 32 32.5)"
        />
      </svg>
    );
  }

  if (lenguaje === 'javascript') {
    return (
      <svg className={estilos.icono} viewBox="0 0 64 64" aria-hidden="true">
        <rect width="64" height="64" rx="6" fill="#f7df1e" />
        {/* La "J" y la "S" del logotipo, alineadas abajo a la derecha como en la marca */}
        <path
          d="M17.5 53.4l4.9-3c.9 1.7 1.8 3.1 3.9 3.1 2 0 3.3-.8 3.3-3.9V28.5h6v21.2c0 6.2-3.7 9.1-9 9.1-4.8 0-7.6-2.5-9.1-5.4"
          fill="#15150c"
        />
        <path
          d="M38.7 52.8l4.9-2.8c1.3 2.1 3 3.7 6 3.7 2.5 0 4.1-1.3 4.1-3 0-2.1-1.7-2.9-4.5-4.1l-1.5-.7c-4.4-1.9-7.4-4.3-7.4-9.3 0-4.6 3.5-8.1 9-8.1 3.9 0 6.7 1.4 8.7 5l-4.8 3c-1-1.9-2.2-2.6-3.9-2.6-1.8 0-2.9 1.1-2.9 2.6 0 1.8 1.1 2.5 3.7 3.7l1.5.6c5.2 2.2 8.2 4.5 8.2 9.7 0 5.6-4.4 8.6-10.3 8.6-5.7 0-9.4-2.7-11.2-6.3"
          fill="#15150c"
        />
      </svg>
    );
  }

  if (lenguaje === 'java') {
    return (
      <svg className={estilos.icono} viewBox="0 0 64 64" aria-hidden="true">
        {/* El vapor, en el naranja de la marca */}
        <g fill="none" stroke="#f89820" strokeWidth="3.4" strokeLinecap="round">
          <path d="M26 6c-5 4.5 1 7 1 10.5 0 2.5-2 4-2 4" />
          <path d="M37 3c-6 5.5 1.5 8.5 1.5 12.5 0 3-2.5 5-2.5 5" />
        </g>
        {/* La taza y su asa, en el azul de la marca */}
        <path d="M17 27h25v11.5c0 5.5-4.5 10-10 10h-5c-5.5 0-10-4.5-10-10V27z" fill="#5382a1" />
        <path
          d="M43.5 30h3c3.6 0 6.5 2.5 6.5 5.8s-2.9 5.7-6.5 5.7h-3"
          fill="none"
          stroke="#5382a1"
          strokeWidth="3.6"
        />
        <rect x="13" y="52" width="33" height="5" rx="2.5" fill="#5382a1" />
      </svg>
    );
  }

  return (
    <svg className={estilos.icono} viewBox="0 0 64 64" aria-hidden="true">
      <path
        d="M15 6h22l12 12v40H15z"
        fill="none"
        stroke="currentColor"
        strokeWidth="4.5"
        strokeLinejoin="round"
      />
      <path d="M37 6v12h12" fill="none" stroke="currentColor" strokeWidth="4.5" strokeLinejoin="round" />
    </svg>
  );
}
