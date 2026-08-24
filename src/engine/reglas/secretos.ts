import type { Regla } from '../tipos';
import { BT, CWE, OWASP, unir } from './utiles';

/** Nombres de variable que delatan una credencial. */
const NOMBRES_SENSIBLES =
  '(?:password|passwd|pwd|contrase(?:n|ñ)a|clave|secreto|secret|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|auth[_-]?token|token|private[_-]?key|client[_-]?secret|connection[_-]?string)';

/**
 * Valores que NO son un secreto aunque esten escritos entre comillas:
 * marcadores de posicion, interpolaciones y texto de relleno.
 */
const VALORES_DE_RELLENO =
  /(["'\x60])\s*(?:\$\{|\{\{|\{[a-z_]|<[a-z_/]|%[sdv]|x{3,}|X{3,}|your[-_ ]|tu[-_ ]|mi[-_ ]|placeholder|change[-_ ]?me|cambiar|replace[-_ ]?me|example|ejemplo|sample|dummy|todo|fixme|redacted|hidden|\*{3,}|\.{3,}|none|null|undefined)/i;

/** Formas correctas de obtener un secreto: si aparecen en la linea, no hay hallazgo. */
const FUENTES_LEGITIMAS =
  /os\.getenv|os\.environ|process\.env|import\.meta\.env|Deno\.env|System\.getenv|dotenv|config\.get|getSecret|get_secret|secretsmanager|secret_manager|keyring|keyvault|vault\.|sys\.argv|input\s*\(|prompt\s*\(|getpass/i;

export const secretoEmbebido: Regla = {
  id: 'secreto-embebido',
  titulo: 'Contraseña o clave escrita en el código',
  severidad: 'critica',
  owasp: OWASP.A07,
  cwe: CWE.CREDENCIALES_EMBEBIDAS,
  // El nombre de la clave puede venir entre comillas (JSON, YAML, diccionarios),
  // asi que no se descartan las coincidencias que caen dentro de una cadena.
  ignorarEnCadenas: false,
  patron: unir(
    [
      // password = "admin123"  ·  "api_key": "sk_live_..."  ·  token := "..."
      // Se usa `(?<![A-Za-z0-9])` y no `\b`: hace falta reconocer DB_PASSWORD
      // (donde no hay frontera de palabra tras el guion bajo) sin picar con
      // palabras que solo contienen la raiz, como "monkey" o "keyboard".
      `(?<![A-Za-z0-9])${NOMBRES_SENSIBLES}\\s*["']?\\s*(?::=|=|:)\\s*(["'${BT}])(?![\\s"'${BT}])[^"'${BT}\\n]{3,}\\1`,
      // Estilo .env / CI: DB_PASSWORD=SuperSecreta123 (sin comillas, en mayusculas)
      `^[ \\t]*[A-Z][A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|KEY|CREDENTIALS?)\\s*=\\s*[^\\s"'${BT}#$]{6,}[ \\t]*$`,
    ],
    'gim',
  ),
  ignorarSiLinea: [FUENTES_LEGITIMAS],
  ignorarSiCoincide: [VALORES_DE_RELLENO],
  ficha: {
    queEncontramos:
      'Hay una credencial escrita tal cual dentro del código. Cualquiera que abra el archivo la lee, y si el proyecto está en un repositorio queda también en el historial de Git: borrarla en el siguiente commit no la elimina, sigue ahí para quien sepa mirar.',
    comoTeAtacarian:
      'No hace falta un ataque sofisticado. Existen bots que vigilan GitHub en tiempo real buscando exactamente este patrón: se han documentado credenciales utilizadas por terceros a los pocos minutos de publicarse. Con esa contraseña el atacante accede a tu base de datos con tus mismos permisos: lee los datos de tus usuarios, los modifica o los borra. Y aunque el repositorio sea privado, la credencial queda al alcance de cualquiera que tenga acceso al código —empleados, contratistas, proveedores—, hoy y dentro de tres años.',
    comoSeArregla:
      'La credencial sale del código y pasa a una variable de entorno o a un gestor de secretos; el programa la pide al arrancar y falla ruidosamente si no está. Y algo que casi siempre se olvida: rota la clave expuesta. Quitarla del archivo no la invalida — hay que cambiarla en el servicio.',
    fix: {
      lenguaje: 'python',
      codigo: `import os

# El valor vive fuera del codigo: .env local, secretos del CI/CD, AWS Secrets Manager...
# Si falta, el programa no arranca — mejor eso que arrancar inseguro.
DB_PASSWORD = os.environ["DB_PASSWORD"]

conexion = conectar(usuario="app", password=DB_PASSWORD)`,
    },
  },
};

export const claveAws: Regla = {
  id: 'clave-aws',
  titulo: 'Clave de acceso de AWS expuesta',
  severidad: 'critica',
  owasp: OWASP.A07,
  cwe: CWE.CREDENCIALES_EMBEBIDAS,
  // El identificador vive dentro de una cadena: ahi es justo donde hay que mirar.
  ignorarEnCadenas: false,
  patron: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA)[0-9A-Z]{16}\b/g,
  // AKIAIOSFODNN7EXAMPLE y similares son las claves de juguete de la documentacion de AWS.
  ignorarSiCoincide: [/EXAMPLE$/],
  ficha: {
    queEncontramos:
      'Este identificador con formato AKIA/ASIA seguido de 16 caracteres es una clave de acceso de Amazon Web Services. Identifica a un usuario o rol de tu cuenta de nube, con todos los permisos que tenga asignados.',
    comoTeAtacarian:
      'Existen bots dedicados en exclusiva a rastrear este prefijo en repositorios, gists, foros y hasta en el JavaScript compilado de sitios web. El uso más frecuente es levantar decenas de instancias de gran capacidad para minar criptomonedas: el beneficio es del atacante y la factura es tuya, y suele alcanzar las cinco cifras antes de que alguien lo detecte. Otros se limitan a descargar el contenido de tus buckets de S3, o a borrar tus copias de seguridad para pedir un rescate.',
    comoSeArregla:
      'Primero lo urgente: desactiva la clave en IAM ya, y revisa en CloudTrail si alguien la usó. Después lo estructural: dentro de AWS no necesitas claves — EC2, Lambda o ECS asumen un rol IAM y el SDK obtiene las credenciales solo, temporales y rotadas automáticamente.',
    fix: {
      lenguaje: 'bash',
      codigo: `# 1. Desactivar la clave filtrada AHORA (antes de arreglar el codigo)
aws iam update-access-key --access-key-id AKIA... --status Inactive

# 2. Comprobar si ya la usaron
aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA...

# 3. En el codigo, ninguna clave: el rol de la instancia o de la funcion
#    provee credenciales temporales y el SDK las toma solo.
#    boto3.client("s3")  <- sin argumentos, sin secretos`,
    },
  },
};

export const formatoDeSecreto: Regla = {
  id: 'formato-de-secreto',
  titulo: 'Credencial de un servicio conocido, por su formato',
  severidad: 'critica',
  owasp: OWASP.A07,
  cwe: CWE.CREDENCIALES_EMBEBIDAS,
  // El valor vive dentro de una cadena o de un archivo de configuracion.
  ignorarEnCadenas: false,
  patron: unir(
    [
      '-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----',
      'gh[pousr]_[A-Za-z0-9]{16,}', // GitHub
      'github_pat_[A-Za-z0-9_]{20,}',
      'glpat-[A-Za-z0-9_-]{16,}', // GitLab
      '\\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}', // Stripe
      '\\bAIza[0-9A-Za-z_-]{30,}', // Google
      '\\bxox[baprs]-[A-Za-z0-9-]{10,}', // Slack
      '\\bSG\\.[A-Za-z0-9_-]{16,}\\.[A-Za-z0-9_-]{16,}', // SendGrid
      '\\bnpm_[A-Za-z0-9]{30,}',
      '\\bdop_v1_[a-f0-9]{32,}', // DigitalOcean
      '\\beyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}', // JWT firmado
      '\\bxapp-\\d-[A-Za-z0-9-]{10,}',
    ],
    'g',
  ),
  ignorarSiCoincide: [/EXAMPLE|XXXXX|your[_-]|tu[_-]|placeholder|ejemplo/i],
  ficha: {
    queEncontramos:
      'Esto no parece una credencial: lo es. Cada servicio marca sus claves con un prefijo reconocible —ghp_ en GitHub, sk_live_ en Stripe, AIza en Google, xoxb- en Slack— y lo que hay aquí encaja con uno de esos formatos. Un bloque BEGIN PRIVATE KEY es directamente una clave privada completa.',
    comoTeAtacarian:
      'Ese prefijo es justamente lo que buscan los rastreadores automáticos, porque permite encontrar claves sin ambigüedad y comprobarlas al instante contra la API del servicio. El daño depende de la clave: con una de Stripe se emiten cobros o reembolsos; con un token de GitHub se clona el código privado y se inyecta código en tus repositorios; con una clave privada SSH o TLS se entra al servidor o se suplanta tu dominio. Los propios proveedores escanean GitHub para revocar claves filtradas, pero llegan después del bot.',
    comoSeArregla:
      'Rota la credencial en el servicio antes que nada: quitarla del archivo no la desactiva. Luego sácala del repositorio y llévala a variables de entorno o a un gestor de secretos. Y como el historial de Git la conserva, añade un escaneo de secretos en el pre-commit (gitleaks, git-secrets) para que la próxima no llegue a subirse.',
    fix: {
      lenguaje: 'bash',
      codigo: `# 1. Rotar la credencial en el servicio (GitHub, Stripe, Google...)
#    Quitarla del codigo no la invalida.

# 2. Fuera del repositorio: al entorno o a un gestor de secretos
export STRIPE_API_KEY="..."   # y .env en .gitignore

# 3. Que no vuelva a pasar: escaneo antes de cada commit
gitleaks protect --staged`,
    },
  },
};

export const jwtSinVerificar: Regla = {
  id: 'jwt-sin-verificar',
  titulo: 'Token JWT leído sin verificar la firma',
  severidad: 'alta',
  owasp: OWASP.A07,
  cwe: CWE.FIRMA,
  // Las opciones viajan en un diccionario: la clave esta entre comillas.
  ignorarEnCadenas: false,
  patron: unir(
    [
      '\\bjwt\\.decode\\s*\\([^)\\n]*verify\\s*=\\s*False',
      'verify_signature["\']?\\s*:\\s*False',
      'algorithms?\\s*[=:]\\s*\\[?\\s*["\']none["\']',
      '\\bjwt\\.decode\\s*\\(\\s*[\\w.\\[\\]"\']+\\s*\\)',
      '\\bjsonwebtoken[^\\n]*\\.decode\\s*\\(',
      '\\bdecodeJwt\\s*\\(',
    ],
    'g',
  ),
  ficha: {
    queEncontramos:
      'Se está leyendo el contenido de un JWT sin comprobar su firma. Un JWT no está cifrado: cualquiera puede abrirlo y leerlo, porque solo va codificado en base64. Lo único que impide falsificarlo es la firma, y aquí se está saltando esa comprobación.',
    comoTeAtacarian:
      'El atacante coge su propio token, lo abre —dos clics en jwt.io—, cambia "rol": "usuario" por "rol": "admin" o el identificador por el de otra cuenta, y lo vuelve a enviar. Como nadie valida la firma, tu servidor se cree el contenido y le da los permisos que el token dice tener. La variante con algoritmo "none" es la misma idea por otro camino: el token declara que no lleva firma y la librería, si se lo permites, lo acepta tal cual.',
    comoSeArregla:
      'Verifica siempre la firma con la clave secreta y, muy importante, indica de forma explícita qué algoritmo aceptas: si dejas que lo elija el token, un atacante puede cambiar RS256 por HS256 y firmar con tu propia clave pública. Comprueba además la expiración y el emisor. Si solo necesitas mirar el contenido para depurar, hazlo en un script, nunca en el camino de la autenticación.',
    fix: {
      lenguaje: 'python',
      codigo: `import jwt

# MAL: se lee lo que diga el token, sin comprobar nada
# datos = jwt.decode(token, options={"verify_signature": False})

# BIEN: firma verificada y algoritmo fijado por nosotros
datos = jwt.decode(
    token,
    CLAVE_SECRETA,
    algorithms=["HS256"],   # nunca lo que proponga el token
    options={"require": ["exp", "iat"]},
)`,
    },
  },
};

export const reglasDeSecretos: Regla[] = [
  secretoEmbebido,
  claveAws,
  formatoDeSecreto,
  jwtSinVerificar,
];
