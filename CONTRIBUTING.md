# Contribuir a SecScan

Toda aportación es bienvenida, y hay una que vale más que ninguna otra: **decirme dónde se
equivoca**. Si SecScan marca como fallo un código que está bien escrito, ese informe mejora la
herramienta más que cualquier regla nueva.

## Reportar un falso positivo

Es lo más útil que puedes hacer. Abre una incidencia con la plantilla *Falso positivo* y pega la
línea exacta que lo provoca. No hace falta nada más: con la línea puedo reproducirlo, convertirlo
en una prueba y cerrarlo.

El proyecto ya trae [una medición de cuánto ruido genera](docs/falsos-positivos.md) sobre código
real, y cada falso positivo corregido está ahí documentado con la línea que lo destapó.

## Añadir una regla

El camino es corto y está pensado para que no haya que tocar nada más:

1. **Escribe la regla** en el archivo de su categoría del OWASP Top 10, dentro de
   `src/engine/reglas/`. Es un objeto con su patrón, sus guardas negativas y su ficha educativa.
2. **Escribe la ficha.** Es la parte que de verdad importa y la que más tiempo lleva: qué
   encontramos, cómo te atacarían —con un ataque concreto, no una generalidad— y cómo se arregla,
   con código corregido. En español y sin jerga innecesaria.
3. **Añade los casos** a la tabla `CASOS` de `src/engine/__tests__/reglas.test.ts`, por los dos
   lados: `detecta` con el código vulnerable y `noDetecta` con el código correcto que **no** debe
   marcarse. Ninguna regla entra sin su lista de falsos positivos.
4. `npm run test` y `npm run lint` en verde.

### Las guardas negativas no son opcionales

Un motor que marca `password = os.getenv("DB_PASS")` —que es justo la forma correcta— es un motor
que nadie usa dos veces. Cada regla declara `ignorarSiLinea` e `ignorarSiCoincide` para el código
que ya hace las cosas bien, y hay guardas compartidas en `src/engine/reglas/utiles.ts` para los
casos habituales: líneas que definen en vez de llamar, rutas relativas de un `import`, ejemplos
dentro de un docstring.

## Antes de abrir un pull request

```bash
npm install
npm run lint      # ESLint
npm run test      # el motor y sus fichas
npm run build     # comprobación de tipos + build
```

Si tocas el motor, pasa también la auditoría sobre código real y revisa que no aparecen hallazgos
nuevos donde no debería:

```bash
npm run auditoria -- <carpeta-con-repos-de-referencia> informe.json
```

## Cómo está organizado

| Dónde | Qué hay |
| --- | --- |
| `src/engine/` | El motor: tipos, preprocesado, reglas y `analizar()`. Sin dependencias |
| `src/engine/reglas/` | Un archivo por categoría OWASP, más las guardas compartidas |
| `src/components/` | La interfaz, en componentes con CSS Modules |
| `src/samples/` | Los ejemplos de un clic |
| `scripts/auditoria.ts` | La medición de falsos positivos sobre código real |
| `docs/` | Capturas y el informe de la medición |

## Estilo

El código y los comentarios están en español, igual que el producto. Los comentarios explican el
**porqué** de una decisión, no lo que ya dice el código: por qué una regla ignora las cadenas de
tres comillas, o por qué el resaltado se apaga en archivos grandes.
