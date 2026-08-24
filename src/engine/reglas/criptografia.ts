import type { Regla } from '../tipos';
import { BT, CWE, OWASP, unir } from './utiles';

export const hashDebil: Regla = {
  id: 'hash-debil',
  titulo: 'Algoritmo de hash débil (MD5 / SHA-1)',
  severidad: 'media',
  owasp: OWASP.A02,
  cwe: CWE.HASH_DEBIL,
  patron: unir(
    [
      '\\bhashlib\\.(?:md5|sha1)\\s*\\(',
      '(?<![\\w.])md5\\s*\\(',
      '(?<![\\w.])sha1\\s*\\(',
      `createHash\\s*\\(\\s*["'${BT}](?:md5|sha1)["'${BT}]\\s*\\)`,
      '\\bCryptoJS\\.(?:MD5|SHA1)\\s*\\(',
    ],
    'gi',
  ),
  // Python 3.9+ permite declarar que el hash no se usa con fines de seguridad.
  ignorarSiLinea: [/usedforsecurity\s*=\s*False/i],
  ficha: {
    queEncontramos:
      'El código usa MD5 o SHA-1. Los dos están rotos desde hace años: existen colisiones prácticas y, si se usan para guardar contraseñas, son demasiado rápidos — que es justo lo contrario de lo que necesitas ahí.',
    comoTeAtacarian:
      'Si es una contraseña, la velocidad juega en tu contra: una GPU doméstica prueba miles de millones de MD5 por segundo, de modo que un volcado de tu base de datos se convierte en contraseñas en claro en cuestión de horas. Y para las más comunes ni siquiera hace falta calcular nada: el hash ya figura en tablas de consulta publicadas. Si el hash se usa para verificar integridad, el problema es distinto: con SHA-1 se pueden fabricar dos archivos diferentes con la misma firma, así que "el hash coincide" deja de demostrar que el archivo no fue alterado.',
    comoSeArregla:
      'Distingue los dos usos. Para contraseñas, un algoritmo diseñado para ser lento y con sal automática: bcrypt, scrypt o argon2 — nunca un hash de propósito general. Para integridad o firmas, SHA-256 o superior. MD5 solo sobrevive para cosas sin implicación de seguridad, como una clave de caché, y ahí conviene dejarlo escrito en el código para que se vea que es intencional.',
    fix: {
      lenguaje: 'python',
      codigo: `import bcrypt   # o argon2-cffi

# MAL: rapido, sin sal, roto
# hash = hashlib.md5(password.encode()).hexdigest()

# BIEN: lento a proposito, con sal unica incluida en el resultado
hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# Al verificar, comparacion en tiempo constante:
bcrypt.checkpw(password_intento.encode(), hash)

# Para integridad de archivos (no contrasenas): hashlib.sha256(...)`,
    },
  },
};

export const tlsDesactivado: Regla = {
  id: 'tls-desactivado',
  titulo: 'Verificación de certificados TLS desactivada',
  severidad: 'media',
  owasp: OWASP.A02,
  cwe: CWE.CERTIFICADO,
  patron: unir(
    [
      'verify\\s*=\\s*False',
      'rejectUnauthorized\\s*:\\s*false',
      `NODE_TLS_REJECT_UNAUTHORIZED\\s*[=:]\\s*["'${BT}]?0`,
      'ssl\\._create_unverified_context',
      'check_hostname\\s*=\\s*False',
      '\\bCERT_NONE\\b',
      'InsecureSkipVerify\\s*:\\s*true',
      'curl\\s+(?:-k\\b|--insecure\\b)',
    ],
    'gi',
  ),
  ficha: {
    queEncontramos:
      'Se está desactivando la comprobación del certificado del servidor. La conexión sigue cifrada, sí, pero ya no verifica con quién está hablando — y ese segundo paso es la mitad del valor de HTTPS. Suele empezar como un parche temporal para saltarse un certificado caducado y acaba llegando a producción.',
    comoTeAtacarian:
      'Basta con que alguien se sitúe en medio de la conexión: el wifi de una cafetería o de un aeropuerto, un router comprometido, un DNS envenenado, o el propio proveedor en una red hostil. Presenta su propio certificado, tu cliente lo acepta sin rechistar y a partir de ahí lee y modifica todo lo que pasa: tokens de API, credenciales, respuestas. Tú ves tráfico cifrado y todo parece normal, pero el canal cifrado es con el atacante. Es el ataque de intermediario de manual, y esta línea era lo único que lo impedía.',
    comoSeArregla:
      'Deja la verificación activada y arregla la causa real. Si el certificado es interno o autofirmado, no lo ignores: añade la CA de tu organización al paquete de confianza y apúntala explícitamente. Si está caducado, renuévalo. Y si necesitas desactivarlo de verdad, que sea solo en desarrollo, detrás de una condición explícita que nunca se cumpla en producción.',
    fix: {
      lenguaje: 'python',
      codigo: `import requests

# MAL: acepta cualquier certificado, incluido el del atacante
# requests.get(url, verify=False)

# BIEN: verificacion activada (es el valor por defecto)
requests.get(url, timeout=10)

# Con una CA interna, se apunta al certificado de la CA:
requests.get(url, verify="/etc/ssl/certs/ca-interna.pem", timeout=10)`,
    },
  },
};

export const conexionSinCifrar: Regla = {
  id: 'conexion-sin-cifrar',
  titulo: 'Conexión HTTP sin cifrar',
  severidad: 'baja',
  owasp: OWASP.A02,
  cwe: CWE.TEXTO_PLANO,
  // La URL vive dentro de una cadena: es exactamente donde hay que mirar.
  ignorarEnCadenas: false,
  patron: new RegExp(`http://[^\\s"'${BT}<>)\\]]+`, 'gi'),
  ignorarSiCoincide: [
    // Desarrollo local: no viaja por ninguna red.
    /^http:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal|[\w.-]+\.(?:local|test|internal)\b)/i,
    // Identificadores de espacios de nombres: son nombres, no direcciones que se visiten.
    /^http:\/\/(?:www\.)?(?:w3\.org|schemas?\.|purl\.org|json-schema\.org|xmlns|maven\.apache\.org|java\.sun\.com|docbook\.org)/i,
  ],
  ignorarSiLinea: [/xmlns|DOCTYPE|schemaLocation|xsi:|<!--/i],
  ficha: {
    queEncontramos:
      'Hay una dirección http:// (sin la ese). Lo que se envíe por ahí viaja en texto plano: cualquiera que esté en el camino puede leerlo y, lo que es peor, cambiarlo.',
    comoTeAtacarian:
      'Quien comparta la red — el wifi abierto de una cafetería, un hotel, un aeropuerto — ve el contenido tal cual con herramientas de captura de tráfico al alcance de cualquiera: tokens, claves de API, datos personales. Y no se limita a leer: también puede alterar la respuesta en tránsito. Si lo que se descarga por HTTP es un script o un instalador, el atacante sustituye el archivo por el suyo y tu propio programa lo ejecuta. Por eso los navegadores llevan años marcando estas páginas como "no seguras".',
    comoSeArregla:
      'Cambia el esquema a https:// y comprueba que el servidor lo soporta. En el servidor, redirige todo el tráfico HTTP a HTTPS y activa HSTS para que el navegador ni lo intente por el canal inseguro. Los certificados llevan años siendo gratis con Let’s Encrypt, así que ya no hay excusa de coste.',
    fix: {
      lenguaje: 'javascript',
      codigo: `// MAL: viaja en claro y puede ser modificado en transito
// const API = "http://api.miempresa.com/v1";

// BIEN
const API = "https://api.miempresa.com/v1";

// En el servidor, ademas: redireccion 301 de HTTP a HTTPS
// y cabecera Strict-Transport-Security (HSTS).`,
    },
  },
};

export const aleatoriedadDebil: Regla = {
  id: 'aleatoriedad-debil',
  titulo: 'Valor de seguridad generado con azar predecible',
  severidad: 'media',
  owasp: OWASP.A02,
  cwe: CWE.ALEATORIEDAD,
  // Hace falta el contexto: `Math.random()` para barajar una lista es
  // perfectamente correcto. El problema es usarlo para algo que debe ser
  // imposible de adivinar, asi que se exige que la linea hable de ello.
  patron: unir(
    [
      '(?:token|password|passwd|contrase|secret|otp|c[oó]digo|code|session|sesi[oó]n|nonce|salt|api[_-]?key|clave|pin|uuid|reset)[^\\n]{0,60}(?:Math\\.random\\s*\\(|\\brandom\\.(?:random|randint|choice|randrange|sample|shuffle|getrandbits)\\s*\\()',
      '(?:Math\\.random\\s*\\(|\\brandom\\.(?:random|randint|choice|randrange|sample|getrandbits)\\s*\\()[^\\n]{0,60}(?:token|password|contrase|secret|otp|session|sesi[oó]n|nonce|salt|clave|pin|reset)',
    ],
    'gi',
  ),
  ignorarSiLinea: [
    /secrets\.|crypto\.randomBytes|randomUUID|getRandomValues|os\.urandom|SystemRandom/i,
  ],
  ficha: {
    queEncontramos:
      'Se está generando algo que debería ser imposible de adivinar —un token, un código de un solo uso, una contraseña temporal— con el generador de números aleatorios normal del lenguaje. Ese generador está pensado para simulaciones y juegos: es rápido y reproducible, no impredecible.',
    comoTeAtacarian:
      'Math.random() y random de Python producen una secuencia calculada a partir de un estado interno. Quien observe unos cuantos valores puede reconstruir ese estado y, a partir de ahí, predecir todos los siguientes — y también los anteriores. En la práctica: el atacante pide veinte veces "restablecer contraseña" para su propia cuenta, recoge los códigos que le llegan, deduce la semilla y calcula el código que le va a llegar a la cuenta de otra persona. No necesita interceptar nada, le basta con hacer sus propias peticiones.',
    comoSeArregla:
      'Para cualquier valor con implicación de seguridad usa el generador criptográfico: el módulo secrets en Python, crypto.randomBytes o crypto.randomUUID en Node, y crypto.getRandomValues en el navegador. Son igual de fáciles de usar, y su salida no permite reconstruir el estado interno. Deja random para barajar cartas.',
    fix: {
      lenguaje: 'python',
      codigo: `import secrets

# MAL: predecible a partir de unas cuantas muestras
# codigo = "".join(random.choice("0123456789") for _ in range(6))

# BIEN: generador criptografico
codigo = "".join(secrets.choice("0123456789") for _ in range(6))
token = secrets.token_urlsafe(32)

# En JavaScript: crypto.randomUUID() o crypto.randomBytes(32)`,
    },
  },
};

export const cifradoObsoleto: Regla = {
  id: 'cifrado-obsoleto',
  titulo: 'Cifrado obsoleto o en modo ECB',
  severidad: 'media',
  owasp: OWASP.A02,
  cwe: CWE.HASH_DEBIL,
  patron: unir(
    [
      '\\bDES\\.new\\s*\\(',
      '\\bARC4\\.new\\s*\\(',
      '\\bBlowfish\\.new\\s*\\(',
      '\\bMODE_ECB\\b',
      '\\b(?:AES|DES)\\s*/\\s*ECB',
      `createCipheriv?\\s*\\(\\s*["'${BT}](?:des|des-ede3?|rc4|aes-\\d+-ecb)`,
      // createCipher (sin iv) esta obsoleto: deriva la clave de forma insegura
      '\\bcreateCipher\\s*\\(',
      '\\bcreateDecipher\\s*\\(',
    ],
    'gi',
  ),
  ficha: {
    queEncontramos:
      'El algoritmo o el modo de cifrado elegido está roto o no oculta lo que debería. DES y RC4 llevan años descartados. ECB no es un algoritmo sino un modo de uso, y es el que hace que dos bloques de texto idénticos produzcan dos bloques cifrados idénticos.',
    comoTeAtacarian:
      'Con DES, la clave es tan corta que se recorre entera por fuerza bruta con hardware asequible. Con ECB no hace falta ni romper el cifrado: como los patrones se conservan, el atacante deduce el contenido mirando las repeticiones — el ejemplo famoso es una imagen cifrada en ECB en la que se sigue distinguiendo el dibujo. Sobre datos estructurados, permite reconocer qué registros son iguales y, con suficiente control, reordenar bloques para alterar el mensaje descifrado sin conocer la clave.',
    comoSeArregla:
      'Usa AES en un modo autenticado: GCM o ChaCha20-Poly1305. "Autenticado" significa que, además de cifrar, detecta si alguien manipuló el mensaje — sin eso, el cifrado protege la confidencialidad pero no la integridad. Nunca reutilices el nonce con la misma clave. Y si puedes, no montes esto a mano: usa una biblioteca de alto nivel como libsodium o Fernet.',
    fix: {
      lenguaje: 'python',
      codigo: `from cryptography.fernet import Fernet

# MAL: modo ECB, sin autenticacion
# cifrador = AES.new(clave, AES.MODE_ECB)

# BIEN: Fernet usa AES-CBC + HMAC y gestiona el nonce por ti
cifrador = Fernet(clave)
secreto = cifrador.encrypt(datos)

# Si necesitas AES directamente, que sea AES-GCM con nonce unico:
# AESGCM(clave).encrypt(nonce, datos, None)`,
    },
  },
};

export const reglasDeCriptografia: Regla[] = [
  hashDebil,
  tlsDesactivado,
  conexionSinCifrar,
  aleatoriedadDebil,
  cifradoObsoleto,
];
