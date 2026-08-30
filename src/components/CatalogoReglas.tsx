import { useMemo } from 'react';
import { CATALOGO_DE_REGLAS } from '../engine/reglas';
import { ETIQUETA_SEVERIDAD, urlDeCwe } from '../engine/tipos';
import type { Severidad } from '../engine/tipos';
import estilos from './CatalogoReglas.module.css';

const ORDEN: Severidad[] = ['critica', 'alta', 'media', 'baja'];

/**
 * El catalogo completo, a la vista.
 *
 * Quien viene a probar la herramienta no sabe que pegar, y un panel vacio se
 * interpreta como que no detecta nada. Esta lista responde a esa pregunta antes
 * de que haga falta escribir una linea de codigo.
 */
export function CatalogoReglas({ id }: { id: string }) {
  const { porSeveridad, categorias, debilidades } = useMemo(() => {
    const porSeveridad = ORDEN.map((severidad) => ({
      severidad,
      reglas: CATALOGO_DE_REGLAS.filter((regla) => regla.severidad === severidad).sort((a, b) =>
        a.owasp.id.localeCompare(b.owasp.id),
      ),
    })).filter((grupo) => grupo.reglas.length > 0);

    return {
      porSeveridad,
      categorias: new Set(CATALOGO_DE_REGLAS.map((regla) => regla.owasp.id)).size,
      debilidades: new Set(CATALOGO_DE_REGLAS.map((regla) => regla.cwe.id)).size,
    };
  }, []);

  return (
    <section className={estilos.catalogo} id={id} aria-label="Catálogo de reglas">
      <header className={estilos.cabecera}>
        <h2 className={estilos.titulo}>Qué detecta SecScan</h2>
        <p className={estilos.cuenta}>
          {CATALOGO_DE_REGLAS.length} reglas · {categorias} categorías del OWASP Top 10 ·{' '}
          {debilidades} debilidades CWE
        </p>
      </header>

      <div className={estilos.columnas}>
        {porSeveridad.map(({ severidad, reglas }) => (
          <div key={severidad} className={estilos.grupo} data-severidad={severidad}>
            <h3 className={estilos.severidad}>
              <span className={estilos.punto} aria-hidden="true" />
              {ETIQUETA_SEVERIDAD[severidad]}
              <span className={estilos.numero}>{reglas.length}</span>
            </h3>
            <ul className={estilos.lista}>
              {reglas.map((regla) => (
                <li key={regla.id} className={estilos.regla}>
                  <span className={estilos.nombre}>{regla.titulo}</span>
                  <span className={estilos.referencias}>
                    <a href={regla.owasp.url} target="_blank" rel="noopener noreferrer">
                      {regla.owasp.id}
                    </a>{' · '}
                    <a href={urlDeCwe(regla.cwe)} target="_blank" rel="noopener noreferrer">
                      {regla.cwe.id}
                    </a>
                  </span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>

      <p className={estilos.limite}>
        <strong>Lo que no ve:</strong> SecScan no sigue el flujo de los datos, no resuelve
        dependencias ni busca CVE, y no ejecuta el código. Por eso no detecta fallos de control de
        acceso entre usuarios, SSRF que dependa del origen del dato, ni errores de lógica de
        negocio. Es análisis de patrones, con lo que eso permite y con lo que no.
      </p>
    </section>
  );
}
