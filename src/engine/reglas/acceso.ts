import type { Regla } from '../tipos';
import { BT, CWE, ES_DEFINICION, ES_IMPORTACION, OWASP, unir } from './utiles';

export const recorridoDeRutas: Regla = {
  id: 'recorrido-rutas',
  titulo: 'Ruta de archivo construida con datos de fuera',
  severidad: 'alta',
  owasp: OWASP.A01,
  cwe: CWE.RUTA,
  // La ruta peligrosa es justamente el contenido de la cadena.
  ignorarEnCadenas: false,
  patron: unir(
    [
      // open("archivos/" + nombre)  ·  open(f"archivos/{nombre}")
      // Se exige la concatenacion o la interpolacion: `open("config.yaml", "r")`
      // no tiene nada de malo y no debe aparecer.
      `\\bopen\\s*\\(\\s*["'${BT}][^"'${BT}\\n]*["'${BT}]\\s*\\+`,
      `\\bopen\\s*\\(\\s*f["'${BT}][^"'${BT}\\n]*\\{`,
      // Rutas compuestas con lo que llega en la peticion
      '\\bos\\.path\\.join\\s*\\([^)\\n]*(?:request\\.|req\\.|params|argv)',
      // El destino tiene que ser dinamico. `send_file("informe.pdf")` es una
      // constante y no se puede manipular; `send_file(ruta)` si.
      '\\bsend_file\\s*\\(\\s*(?!["\'][^"\']*["\']\\s*\\))',
      // La concatenacion debe estar en el PRIMER argumento, que es la ruta:
      // `fs.writeFile(ruta, a + b)` concatena el contenido, no el destino.
      `\\bfs\\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink)\\s*\\(\\s*[^,)\\n]*(?:\\+|\\$\\{|req\\.)`,
      '\\bres\\.sendFile\\s*\\(\\s*[^,)\\n]*(?:\\+|\\$\\{|req\\.)',
      // El payload clasico, escrito tal cual
      '\\.\\./\\.\\./',
      '%2e%2e(?:%2f|/)',
    ],
    'gi',
  ),
  ignorarSiLinea: [
    /secure_filename|os\.path\.basename|path\.basename|send_from_directory|sanitiz|allowlist|lista_blanca/i,
    ES_DEFINICION,
    ES_IMPORTACION,
  ],
  ficha: {
    queEncontramos:
      'Se está armando la ruta de un archivo pegando texto que puede venir de fuera: un parámetro de la URL, un campo del formulario, el nombre de un archivo subido. Quien controla ese texto controla qué archivo abre tu programa.',
    comoTeAtacarian:
      'El atacante no pide "factura.pdf": pide "../../../../etc/passwd", y como cada "../" sube un directorio, se sale de tu carpeta y llega a donde quiera del disco. Los objetivos habituales son el archivo .env con tus credenciales, las claves SSH del servidor o el propio código fuente. Y si la ruta se usa para escribir en vez de para leer, la cosa empeora: puede sobrescribir un archivo de configuración o dejar un script en una carpeta que el servidor ejecute. Los codificados tipo %2e%2e%2f existen para saltarse los filtros ingenuos que solo buscan puntos.',
    comoSeArregla:
      'Nunca uses el texto recibido como ruta. Quédate solo con el nombre del archivo, descartando cualquier directorio, y después comprueba que la ruta final resuelta sigue estando dentro de la carpeta permitida — esa segunda comprobación es la que de verdad cierra el agujero, porque se hace sobre la ruta ya normalizada. Mejor aún: no aceptes nombres de archivo, acepta identificadores y busca tú la ruta real en tu base de datos.',
    fix: {
      lenguaje: 'python',
      codigo: `from pathlib import Path

CARPETA = Path("/var/app/archivos").resolve()

def ruta_segura(nombre_pedido: str) -> Path:
    # 1. Nos quedamos solo con el nombre, sin directorios
    nombre = Path(nombre_pedido).name
    # 2. Y comprobamos que lo resuelto sigue dentro de la carpeta permitida
    destino = (CARPETA / nombre).resolve()
    if not destino.is_relative_to(CARPETA):
        raise ValueError("Ruta fuera de la carpeta permitida")
    return destino`,
    },
  },
};

export const descompresionInsegura: Regla = {
  id: 'descompresion-insegura',
  titulo: 'Descompresión sin validar el destino (zip slip)',
  severidad: 'alta',
  owasp: OWASP.A01,
  cwe: CWE.RUTA,
  patron: unir(
    [
      // Abrir el archivo no tiene nada de malo; el riesgo esta en extraerlo.
      '\\.extractall\\s*\\(',
      '\\bzipfile\\.ZipFile\\s*\\([^)\\n]*\\)\\s*\\.extract\\s*\\(',
      '\\bunzipper\\.Extract\\s*\\(',
      '\\badmZip[^\\n]*\\.extractAllTo\\s*\\(',
    ],
    'g',
  ),
  ignorarSiLinea: [/filter\s*=\s*["'](?:data|tar)["']|is_relative_to|resolve\(\)|realpath/],
  ficha: {
    queEncontramos:
      'El programa descomprime un archivo confiando en las rutas que vienen dentro. Un ZIP o un TAR no guarda solo contenidos: guarda también el nombre de cada entrada, y ese nombre puede ser una ruta con "../" o incluso una ruta absoluta.',
    comoTeAtacarian:
      'Es el ataque conocido como zip slip. El atacante prepara un archivo cuya entrada se llama "../../../../etc/cron.d/tarea" o "../../app/config.py", te lo hace subir —una importación de datos, un plugin, un backup restaurado— y al descomprimir, tu propio código escribe ese archivo fuera de la carpeta de destino. El resultado va desde sobrescribir tu configuración hasta dejar un archivo que el sistema ejecutará solo, sin que nadie más tenga que hacer nada.',
    comoSeArregla:
      'Comprueba cada entrada antes de escribirla: resuelve la ruta de destino y verifica que sigue dentro de la carpeta prevista. En Python 3.12 basta con pasar filter="data" a extractall, que descarta rutas absolutas y saltos hacia arriba. Y limita también el tamaño descomprimido, o el mismo archivo sirve para llenarte el disco.',
    fix: {
      lenguaje: 'python',
      codigo: `import tarfile
from pathlib import Path

DESTINO = Path("/var/app/subidas").resolve()

with tarfile.open(archivo) as paquete:
    # Python 3.12+: descarta rutas absolutas y saltos hacia arriba
    paquete.extractall(DESTINO, filter="data")

# Si no puedes usar filter, valida entrada por entrada:
# destino_final = (DESTINO / entrada.name).resolve()
# if not destino_final.is_relative_to(DESTINO): raise ValueError(...)`,
    },
  },
};

export const csrfDesactivado: Regla = {
  id: 'csrf-desactivado',
  titulo: 'Protección CSRF desactivada',
  severidad: 'media',
  owasp: OWASP.A01,
  cwe: CWE.CSRF,
  patron: unir(
    [
      '@csrf_exempt',
      '\\bcsrf_exempt\\s*\\(',
      '@csrf\\.exempt',
      '\\bWTF_CSRF_ENABLED\\s*[:=]\\s*False',
      '\\bCSRF_ENABLED\\s*[:=]\\s*False',
      '\\bcsrf(?:Protection)?\\s*[:=]\\s*false',
      '\\bCsrfViewMiddleware[^\\n]*#',
    ],
    'g',
  ),
  ficha: {
    queEncontramos:
      'Se está desactivando la protección contra falsificación de peticiones. Esa protección consiste en un valor secreto que tu formulario incluye y que un sitio ajeno no puede adivinar: es lo que distingue una petición hecha desde tu página de una hecha desde otra.',
    comoTeAtacarian:
      'El navegador de tu usuario envía sus cookies de sesión en toda petición a tu dominio, venga de donde venga. Así que el atacante monta una página con un formulario oculto que se envía solo contra tu servidor, y le pasa el enlace a alguien que tiene la sesión abierta. Desde tu lado la petición es indistinguible de una legítima: viene con la cookie correcta, del usuario correcto. Si el endpoint cambia el correo de la cuenta o transfiere saldo, la víctima acaba de hacerlo sin enterarse, solo por visitar una página.',
    comoSeArregla:
      'Deja el CSRF activado en todo lo que modifique estado. Si lo desactivaste para una API que consumen otros servicios, la solución no es apagarlo: es autenticar esa API con un token en la cabecera (que un navegador no adjunta solo) en lugar de con cookies. Y pon SameSite=Lax en las cookies de sesión como segunda barrera.',
    fix: {
      lenguaje: 'python',
      codigo: `# MAL: la excepcion se queda para siempre y nadie la revisa
# @csrf_exempt
# def cambiar_email(request): ...

# BIEN: el formulario web mantiene la proteccion...
def cambiar_email(request):
    ...

# ...y la API para servicios se autentica con cabecera, no con cookie:
# Authorization: Bearer <token>   -> el navegador no la envia solo`,
    },
  },
};

export const redireccionAbierta: Regla = {
  id: 'redireccion-abierta',
  titulo: 'Redirección hacia un destino que llega de fuera',
  severidad: 'baja',
  owasp: OWASP.A01,
  cwe: CWE.REDIRECCION,
  patron: unir(
    [
      // Se exige que el destino venga de la peticion: redirigir a una ruta
      // interna construida por nosotros —redirect("/perfil/" + id)— es correcto.
      '\\bredirect\\s*\\(\\s*(?:request\\.(?:args|GET|POST|values|params)|req\\.(?:query|body|params))',
      '\\bres\\.redirect\\s*\\(\\s*req\\.',
      '\\bwindow\\.location(?:\\.href)?\\s*=\\s*[^;\\n]*(?:location\\.search|location\\.hash|params\\.get)',
    ],
    'g',
  ),
  ignorarSiLinea: [/url_for|is_safe_url|allowlist|lista_blanca|startsWith\(["']\//i],
  ficha: {
    queEncontramos:
      'La dirección a la que se redirige al usuario viene de fuera — normalmente de un parámetro tipo ?next= o ?url=. Tu servidor está aceptando que un tercero decida a dónde manda a tus visitantes.',
    comoTeAtacarian:
      'El enlace empieza por tu dominio, que es el que la víctima lee y reconoce, pero termina llevándola a una copia del sitio en un dominio del atacante. Es el envoltorio clásico del phishing: el correo pasa los filtros porque el enlace apunta a un dominio legítimo, y la persona confía porque ve tu marca al principio de la URL. La variante peor es cuando el parámetro se usa después del login: el usuario se autentica de verdad en tu sitio y a continuación se le devuelve al dominio del atacante con el token en la URL.',
    comoSeArregla:
      'No redirijas a una URL recibida. Acepta solo rutas internas —que empiecen por una sola barra— o, mejor, un identificador corto que traduzcas tú a un destino de una lista cerrada. Si de verdad necesitas destinos externos, valida el dominio contra una lista permitida, no con un "contiene", que se salta con dominios como tudominio.atacante.com.',
    fix: {
      lenguaje: 'python',
      codigo: `from urllib.parse import urlparse

def destino_seguro(siguiente: str, por_defecto: str = "/") -> str:
    if not siguiente:
        return por_defecto
    partes = urlparse(siguiente)
    # Solo rutas internas: sin esquema y sin dominio
    if partes.scheme or partes.netloc:
        return por_defecto
    if not siguiente.startswith("/") or siguiente.startswith("//"):
        return por_defecto
    return siguiente`,
    },
  },
};

export const reglasDeAcceso: Regla[] = [
  recorridoDeRutas,
  descompresionInsegura,
  csrfDesactivado,
  redireccionAbierta,
];
