import estilos from './PieDePagina.module.css';

export function PieDePagina() {
  return (
    <footer className={estilos.pie}>
      <p className={estilos.aviso}>
        <strong>Herramienta educativa.</strong> SecScan detecta patrones de riesgo comunes mediante
        análisis estático. Ayuda a aprender y a revisar, pero no reemplaza una auditoría de
        seguridad profesional: puede haber falsos positivos y no lo detecta todo. Úsalo como primera
        línea de defensa y para entender el <em>porqué</em> de cada vulnerabilidad.
      </p>
      <p className={estilos.firma}>
        Todo el análisis ocurre en tu navegador: tu código nunca se envía a ningún servidor.
      </p>
      <p className={estilos.creditos}>
        Creado por Sergio Osorio · Toda aportación es bienvenida
      </p>
    </footer>
  );
}
