import { useMemo } from 'react';
import { resaltarSintaxis } from './resaltarSintaxis';
import estilos from './sintaxis.module.css';

interface Props {
  texto: string;
}

/**
 * Pinta un fragmento de codigo con la paleta de Xcode. Devuelve solo los
 * nodos de texto y los `span` de color, sin envoltorio: asi quien lo use
 * decide si va dentro de un `pre`, un `code` o el editor.
 */
export function CodigoResaltado({ texto }: Props) {
  const tokens = useMemo(() => resaltarSintaxis(texto), [texto]);

  return (
    <>
      {tokens.map((token, indice) =>
        token.tipo === 'texto' ? (
          token.texto
        ) : (
          <span key={indice} className={estilos[token.tipo]}>
            {token.texto}
          </span>
        ),
      )}
    </>
  );
}
