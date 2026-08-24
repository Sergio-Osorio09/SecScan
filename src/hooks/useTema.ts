import { useCallback, useEffect, useState } from 'react';

export type Tema = 'oscuro' | 'claro';

export const TEMA_POR_DEFECTO: Tema = 'oscuro';

/**
 * La clave guarda el tema que la persona ELIGIO, no el que estaba viendo.
 * El nombre cambio a proposito respecto de la version anterior: aquella
 * escribia el tema en cada arranque, asi que a quien tuviera el sistema en
 * claro le quedaba "claro" guardado sin haberlo pedido nunca, y esa
 * preferencia fantasma seguia ganandole al valor por defecto.
 */
const CLAVE = 'secscan:tema-elegido';

/**
 * El acceso a localStorage puede lanzar una excepcion: navegacion privada en
 * Safari, cookies bloqueadas, iframes con almacenamiento restringido. Como la
 * preferencia de tema no es critica, se prefiere perderla antes que romper la
 * aplicacion entera al arrancar.
 */
function leerTemaElegido(): Tema | null {
  try {
    const guardado = window.localStorage.getItem(CLAVE);
    return guardado === 'oscuro' || guardado === 'claro' ? guardado : null;
  } catch {
    return null;
  }
}

function guardarTemaElegido(tema: Tema) {
  try {
    window.localStorage.setItem(CLAVE, tema);
  } catch {
    // Sin almacenamiento disponible: la eleccion dura lo que dure la sesion.
  }
}

/**
 * SecScan arranca en oscuro siempre, tambien si el sistema esta en claro: es
 * una consola, y la paleta oscura de Xcode es la identidad del producto. El
 * tema claro existe para quien lo prefiera, pero hay que pedirlo — y solo
 * entonces se recuerda.
 */
function temaInicial(): Tema {
  if (typeof window === 'undefined') return TEMA_POR_DEFECTO;
  return leerTemaElegido() ?? TEMA_POR_DEFECTO;
}

/**
 * Tema de la aplicacion. Lo unico que SecScan guarda en el navegador es esta
 * eleccion: el codigo que se analiza no se almacena en ningun sitio.
 */
export function useTema() {
  const [tema, setTema] = useState<Tema>(temaInicial);

  useEffect(() => {
    document.documentElement.dataset.tema = tema;
  }, [tema]);

  const alternarTema = useCallback(() => {
    const siguiente: Tema = tema === 'oscuro' ? 'claro' : 'oscuro';
    // Solo se recuerda cuando es una decision explicita de la persona.
    guardarTemaElegido(siguiente);
    setTema(siguiente);
  }, [tema]);

  return { tema, alternarTema };
}
