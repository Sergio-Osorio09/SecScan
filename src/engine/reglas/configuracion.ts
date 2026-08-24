import type { Regla } from '../tipos';
import { CWE, OWASP, unir } from './utiles';

export const modoDepuracion: Regla = {
  id: 'modo-depuracion',
  titulo: 'Modo depuración activado',
  severidad: 'baja',
  owasp: OWASP.A05,
  cwe: CWE.DEPURACION,
  // En JSON o YAML la clave va entre comillas: "debug": true
  ignorarEnCadenas: false,
  patron: unir(
    [
      // El `["']?` cubre la forma de JSON y YAML: "debug": true
      '\\bDEBUG\\s*["\']?\\s*[:=]\\s*(?:True|true|1)\\b',
      '\\bdebug\\s*["\']?\\s*[:=]\\s*true\\b',
      '\\bapp\\.run\\s*\\([^)\\n]*debug\\s*=\\s*True',
      '\\bFLASK_DEBUG\\s*=\\s*1\\b',
      '\\bDJANGO_DEBUG\\s*=\\s*(?:True|1)\\b',
    ],
    'g',
  ),
  // Si el valor viene del entorno, la decision se toma al desplegar: es correcto.
  ignorarSiLinea: [/os\.getenv|os\.environ|process\.env|import\.meta\.env|argv|NODE_ENV/i],
  ficha: {
    queEncontramos:
      'El modo depuración está activado en el código. En desarrollo es cómodo; si esa misma línea llega a producción, la aplicación empieza a contarle a cualquiera cómo está hecha por dentro.',
    comoTeAtacarian:
      'Al atacante le basta con provocar un error — un parámetro con letras donde esperabas un número — para que la página de excepción le muestre la traza completa: rutas del servidor, versiones de las librerías, fragmentos del código y, muy a menudo, variables de configuración con la cadena de conexión a la base de datos dentro. Con Flask en modo debug, la consola interactiva permite además ejecutar Python en el servidor, y su PIN de protección se ha roto más de una vez. Es la fase de reconocimiento resuelta sin esfuerzo: el atacante deja de probar a ciegas y sabe exactamente qué versión atacar.',
    comoSeArregla:
      'Que el valor no esté escrito en el código: que venga del entorno y que su valor por defecto sea el seguro (desactivado). Así la seguridad en producción no depende de que alguien se acuerde de cambiarlo. Y muestra páginas de error genéricas al usuario, mientras el detalle queda únicamente en el registro interno del servidor.',
    fix: {
      lenguaje: 'python',
      codigo: `import os

# MAL: queda activado en cualquier entorno donde se despliegue
# DEBUG = True

# BIEN: lo decide el entorno y por defecto esta apagado
DEBUG = os.getenv("APP_DEBUG", "false").lower() == "true"

# En produccion: pagina de error generica para el usuario,
# traza completa solo en los logs del servidor.`,
    },
  },
};

export const corsPermisivo: Regla = {
  id: 'cors-permisivo',
  titulo: 'CORS abierto a cualquier origen',
  severidad: 'media',
  owasp: OWASP.A05,
  cwe: CWE.CORS,
  ignorarEnCadenas: false,
  patron: unir(
    [
      'Access-Control-Allow-Origin["\']?\\s*[:,]\\s*["\']?\\*',
      '\\borigin\\s*:\\s*["\']\\*["\']',
      '\\borigin\\s*:\\s*true\\b',
      '\\bcors\\s*\\(\\s*\\)',
      '\\bCORS\\s*\\(\\s*app\\s*\\)',
      '\\bAccess-Control-Allow-Credentials["\']?\\s*[:,]\\s*["\']?true',
      '\\bcredentials\\s*:\\s*true[^\\n]*origin\\s*:\\s*(?:true|["\']\\*)',
    ],
    'gi',
  ),
  ficha: {
    queEncontramos:
      'La política de origen cruzado está abierta a cualquier sitio. El navegador impide por defecto que una página lea las respuestas de otro dominio; esta configuración le dice que, en el caso de tu API, no lo impida.',
    comoTeAtacarian:
      'Cualquier página web puede llamar a tu API desde el navegador de tu usuario y, ahora sí, leer la respuesta. Si además la API se autentica con cookies y se permiten credenciales, el atacante monta un sitio cualquiera, espera a que lo visite alguien con la sesión abierta en tu aplicación, y desde su JavaScript lee los datos de esa persona con su propia sesión: perfil, correos, facturación. Es un robo de datos silencioso, sin que la víctima haga nada más que visitar una página. Conviene saber que el comodín y las credenciales son incompatibles por norma — y que la forma habitual de "solucionar" ese error, devolver como origen permitido el que envía el navegador, equivale a permitirlos todos.',
    comoSeArregla:
      'Enumera los orígenes que de verdad necesitan acceso, en una lista cerrada. Si tienes que reflejar el origen de la petición, compáralo antes contra esa lista con una igualdad exacta, no con un "contiene" ni con un "termina en" — miapp.com.atacante.com pasa esos dos filtros. Y limita también los métodos y las cabeceras permitidas.',
    fix: {
      lenguaje: 'javascript',
      codigo: `const ORIGENES_PERMITIDOS = new Set([
  "https://app.miempresa.com",
  "https://admin.miempresa.com",
]);

app.use(
  cors({
    origin: (origen, listo) =>
      listo(null, !origen || ORIGENES_PERMITIDOS.has(origen)), // igualdad exacta
    credentials: true,
    methods: ["GET", "POST"],
  }),
);`,
    },
  },
};

export const cookieInsegura: Regla = {
  id: 'cookie-insegura',
  titulo: 'Cookie de sesión sin sus atributos de seguridad',
  severidad: 'media',
  owasp: OWASP.A05,
  cwe: CWE.COOKIE,
  ignorarEnCadenas: false,
  patron: unir(
    [
      '\\bhttp[_]?only\\s*[:=]\\s*(?:false|False|0)\\b',
      '\\bSESSION_COOKIE_(?:SECURE|HTTPONLY)\\s*=\\s*False',
      '\\bCSRF_COOKIE_SECURE\\s*=\\s*False',
      '\\bsame[_]?site\\s*[:=]\\s*["\']?(?:none|None)["\']?',
      '(?:cookie|session|sesi[oó]n)[^\\n]{0,60}\\bsecure\\s*[:=]\\s*(?:false|0)\\b',
      '\\bsecure\\s*[:=]\\s*false[^\\n]{0,60}(?:cookie|session)',
    ],
    // Sin distinguir mayusculas: httpOnly y sameSite se escriben asi.
    'gi',
  ),
  ficha: {
    queEncontramos:
      'La cookie de sesión se está creando sin alguna de sus protecciones. Son tres atributos y cada uno tapa un agujero distinto: HttpOnly impide que el JavaScript de la página la lea, Secure impide que viaje por HTTP sin cifrar, y SameSite impide que se envíe en peticiones que vienen de otros sitios.',
    comoTeAtacarian:
      'Sin HttpOnly, cualquier XSS deja de ser un susto y pasa a ser un robo de sesión: dos líneas de JavaScript envían document.cookie al servidor del atacante y este entra como la víctima, sin necesitar su contraseña ni su segundo factor. Sin Secure, basta con que la persona abra una vez el sitio por HTTP en un wifi compartido para que la cookie viaje en claro y alguien la copie. Y con SameSite=None, el navegador adjunta la cookie en peticiones lanzadas desde cualquier página, que es justo lo que hace posible el CSRF.',
    comoSeArregla:
      'Los tres atributos activos en toda cookie de sesión: HttpOnly, Secure y SameSite=Lax (o Strict si el flujo lo permite). SameSite=None solo tiene sentido si la cookie debe funcionar de verdad entre dominios, y en ese caso Secure es obligatorio. Añade también una expiración razonable.',
    fix: {
      lenguaje: 'python',
      codigo: `# Flask
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # el JavaScript no la puede leer
    SESSION_COOKIE_SECURE=True,     # solo viaja por HTTPS
    SESSION_COOKIE_SAMESITE="Lax",  # no se envia desde otros sitios
)

# Express
# res.cookie("sid", valor, { httpOnly: true, secure: true, sameSite: "lax" })`,
    },
  },
};

export const entidadesXml: Regla = {
  id: 'entidades-xml',
  titulo: 'XML procesado con entidades externas habilitadas',
  severidad: 'alta',
  owasp: OWASP.A05,
  cwe: CWE.XXE,
  patron: unir(
    [
      '\\b(?:etree|ElementTree)\\.(?:parse|fromstring|XML)\\s*\\(',
      '\\bXMLParser\\s*\\([^)\\n]*(?:resolve_entities\\s*=\\s*True|no_network\\s*=\\s*False|load_dtd\\s*=\\s*True)',
      '\\bnoent\\s*=\\s*True',
      '\\bxml\\.dom\\.minidom\\.parse',
      '\\bxml\\.sax\\.(?:parse|make_parser)',
      '\\blibxml_disable_entity_loader\\s*\\(\\s*false\\s*\\)',
      '\\bDocumentBuilderFactory\\.newInstance\\s*\\(',
      '\\bLIBXML_NOENT\\b',
    ],
    'g',
  ),
  ignorarSiLinea: [/defusedxml|forbid_dtd|resolve_entities\s*=\s*False|FEATURE_SECURE_PROCESSING/i],
  ficha: {
    queEncontramos:
      'Se está leyendo XML con un analizador que, por defecto, acepta entidades externas. Una entidad es un atajo declarado dentro del propio documento, y puede apuntar a un archivo del disco o a una URL: el analizador la resuelve y pega el contenido dentro del XML antes de que tu código lo vea.',
    comoTeAtacarian:
      'El atacante envía un XML que declara una entidad apuntando a file:///etc/passwd y la usa en un campo cualquiera. Tu aplicación devuelve ese campo en la respuesta —o en un mensaje de error— y con él, el contenido del archivo. Lo mismo sirve para leer tu configuración o para hacer que el servidor haga peticiones a direcciones internas que desde fuera no son accesibles, que es como se llega a los metadatos de la nube y a sus credenciales. Y existe una variante que solo pretende tumbarte: entidades que se referencian entre sí y se expanden hasta agotar la memoria. Cualquier punto que acepte XML vale: una factura, un SOAP, un SVG subido, un DOCX.',
    comoSeArregla:
      'En Python, sustituye el analizador por defusedxml, que trae las protecciones puestas: es cambiar el import. En Java, desactiva DTD en DocumentBuilderFactory. En PHP, no reactives el cargador de entidades. Y si tienes elección, prefiere JSON: no tiene este problema porque no tiene entidades.',
    fix: {
      lenguaje: 'python',
      codigo: `# MAL: el analizador por defecto resuelve entidades externas
# from xml.etree import ElementTree
# arbol = ElementTree.parse(archivo_recibido)

# BIEN: mismo API, protecciones activadas
from defusedxml.ElementTree import parse

arbol = parse(archivo_recibido)

# Con lxml, si lo necesitas directamente:
# parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)`,
    },
  },
};

export const reglasDeConfiguracion: Regla[] = [
  modoDepuracion,
  corsPermisivo,
  cookieInsegura,
  entidadesXml,
];
