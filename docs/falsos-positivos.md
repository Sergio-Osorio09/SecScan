# Cuánto ruido genera SecScan

Las 217 pruebas del motor comprueban que no marca el código correcto **que yo elegí**. Eso no
demuestra gran cosa: los casos los escribe quien escribe la regla. La pregunta honesta es otra —
¿cuánto molesta sobre código ajeno, real y bien escrito?

Esta es la medición, con el método y los datos para repetirla.

## Método

Cuatro proyectos conocidos, en versiones concretas, elegidos por estar bien escritos y por ser de
los dos lenguajes que SecScan cubre de punta a punta:

| Proyecto | Versión | Lenguaje |
| --- | --- | --- |
| [requests](https://github.com/psf/requests) | 2.32.3 | Python |
| [flask](https://github.com/pallets/flask) | 3.0.3 | Python |
| [express](https://github.com/expressjs/express) | 4.19.2 | JavaScript |
| [axios](https://github.com/axios/axios) | 1.7.7 | JavaScript |

Se analiza el código fuente escrito a mano: quedan fuera las dependencias, los artefactos de
compilación y el código minificado. Y se separan dos grupos, porque mezclarlos falsearía la cifra:

- **Librería** — el código que se distribuye y se ejecuta en producción.
- **Pruebas** — su batería de tests, que contiene patrones inseguros **a propósito** (un cliente
  HTTP tiene que probar qué pasa con `verify=False`, y un framework web tiene que probar rutas
  con `../`).

Para repetirla:

```bash
npm run auditoria -- <carpeta-con-los-repos> informe.json
```

## Resultado

Sobre **26.821 líneas** de código de librería, tras corregir lo que la propia medición destapó:

| Proyecto | Archivos | Líneas | Hallazgos | Por cada 1.000 líneas |
| --- | --- | --- | --- | --- |
| requests | 21 | 6.267 | 4 | 0,64 |
| flask | 25 | 9.146 | 4 | 0,44 |
| axios | 85 | 7.225 | 1 | 0,14 |
| express | 13 | 4.183 | 0 | 0,00 |
| **Total** | **144** | **26.821** | **9** | **0,34** |

**La primera pasada dio 30 hallazgos.** Revisé los treinta uno a uno: 21 eran errores del motor y 9
eran detecciones correctas. Los 21 se corrigieron y cada uno se convirtió en una prueba de
regresión con la línea real que lo provocó.

## Los nueve que quedan

Ninguno es una detección equivocada. Son patrones que están realmente ahí, y en todos los casos la
decisión de convivir con ellos es deliberada:

| Dónde | Qué detecta | Por qué sigue apareciendo |
| --- | --- | --- |
| `requests/auth.py` (×3) | MD5 y SHA-1 | La autenticación HTTP Digest **exige** esos algoritmos por especificación. El algoritmo es débil de verdad; requests no puede cambiarlo |
| `flask/sessions.py` | SHA-1 | Firma de la cookie de sesión. Dentro de un HMAC, SHA-1 no está roto, pero el patrón es indistinguible sin más contexto |
| `flask/config.py`, `flask/cli.py` | `exec(compile(...))` | Flask ejecuta a propósito el archivo de configuración del usuario. Bandit también lo marca (B102) |
| `requests/setup.py` | `exec(f.read(), about)` | El patrón clásico para leer `__version__.py`. Intencional |
| `axios/bin/ssl_hotfix.js` | `shell: true` | Script de compilación con un comando fijo. El patrón es real, el riesgo nulo |
| `flask/helpers.py` | `send_file(` | Es la propia implementación de `send_file` de Flask: la ruta es dinámica por definición |

Esto es exactamente lo que un análisis de patrones puede decir y lo que no. Sin seguir el origen
del dato, `hashlib.sha1(x)` dentro de un HMAC y `hashlib.sha1(password)` son la misma línea.

## Los 21 errores corregidos

La medición no solo dio una cifra: destapó **un fallo real y tres reglas demasiado amplias**.

**1. Mayúsculas mal aplicadas (1 caso).** `AppOrBlueprintKey = t.Optional[str]` se marcaba como
credencial. El patrón estilo `.env`, pensado para variables en MAYÚSCULAS, compartía la bandera de
ignorar mayúsculas con el resto de la regla. Se separó en dos patrones con banderas distintas.

**2. `exec(` de Node confundido con `exec()` de Python (9 casos).** En JavaScript, `exec(` es de
`child_process`: ejecuta un comando, no evalúa código. La ficha que mostraba hablaba de
`__import__("os")`, un consejo inútil ahí. Ahora esos casos los cubre la regla de inyección de
comandos, que es la que tiene la explicación correcta.

**3. Ejemplos dentro de un docstring (4 casos).** `DEBUG = True`, `SECRET_KEY = 'development key'` y
un par de URLs `http://` que estaban **dentro de la documentación** de Flask y de requests. El
preprocesador ahora distingue las cadenas de tres comillas y las reglas las ignoran por defecto.

**4. Reglas de ruta demasiado amplias (7 casos).** Se marcaba `fs.writeFile(ruta, a + b)` — donde la
concatenación está en el contenido, no en la ruta —, los `../../` de un `import`, y las líneas que
**definen** `send_file` o `render_template_string` en lugar de llamarlas. Tres guardas nuevas,
compartidas entre reglas.

## Y las pruebas de esos proyectos

El otro grupo, medido por separado, da un contraste que vale la pena mirar:

| Proyecto | Líneas de pruebas | Hallazgos | Por cada 1.000 líneas |
| --- | --- | --- | --- |
| requests | 4.978 | 201 | 40,4 |
| axios | 9.906 | 60 | 6,1 |
| flask | 8.501 | 42 | 4,9 |
| express | 19.365 | 83 | 4,3 |

Cien veces más ruido en las pruebas de requests que en su librería. No es un fallo del motor: es que
una suite de tests de un cliente HTTP está llena de `verify=False`, de URLs `http://` y de
credenciales de juguete, todo deliberado. Sirve como recordatorio de que **el contexto decide**, y
de que una herramienta como esta se apunta al código que se despliega, no al que lo prueba.
