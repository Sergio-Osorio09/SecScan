import { describe, expect, it } from 'vitest';
import { analizar } from '../analizar';
import { CATALOGO_DE_REGLAS, REGLAS_POR_ID } from '../reglas';

/**
 * Cada regla se prueba por los dos lados:
 *
 *  - `detecta`   : codigo vulnerable que TIENE que aparecer.
 *  - `noDetecta` : codigo correcto que NO puede aparecer.
 *
 * El segundo bloque es el que de verdad importa. Un motor de reglas que grita
 * ante `password = os.getenv("DB_PASS")` — que es la forma correcta de hacerlo —
 * es un motor que nadie usa dos veces.
 */
interface CasoDeRegla {
  reglaId: string;
  detecta: string[];
  noDetecta: string[];
}

const CASOS: CasoDeRegla[] = [
  {
    reglaId: 'secreto-embebido',
    detecta: [
      'DB_PASSWORD = "admin123"',
      "api_key = 'sk_live_9f2b7c1d4e'",
      'const config = { "password": "hunter2" };',
      'AUTH_TOKEN = "ghp_a1b2c3d4e5f6g7h8"',
      'DB_PASSWORD=SuperSecreta2024',
      'private_key: "MIIEvQIBADANBgkq"',
    ],
    noDetecta: [
      'DB_PASSWORD = os.environ["DB_PASSWORD"]',
      'api_key = os.getenv("API_KEY")',
      'const token = process.env.AUTH_TOKEN;',
      'password = ""',
      'api_key = "your_api_key_here"',
      'token = "${GITHUB_TOKEN}"',
      'password = "********"',
      '# password = "admin123"',
      'password = getpass.getpass("Clave: ")',
      'SECRET_KEY = config.get("secret_key")',
    ],
  },
  {
    reglaId: 'clave-aws',
    detecta: [
      'AWS_ACCESS_KEY = "AKIAIOSFODNN7QWERTYU"',
      'export ASIAJKLMNOPQRSTUVWXY',
    ],
    noDetecta: [
      // La clave de juguete que aparece en la documentacion de AWS.
      'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"',
      'clave = "AKIA123"',
      'prefijo = "AKIA"',
    ],
  },
  {
    reglaId: 'inyeccion-sql',
    detecta: [
      'cursor.execute(f"SELECT * FROM users WHERE email = \'{email}\'")',
      'query = "SELECT * FROM users WHERE id = " + user_id',
      'cursor.execute("DELETE FROM logs WHERE id = %s" % log_id)',
      'sql = "UPDATE users SET nombre = \'" + nombre + "\' WHERE id = 1"',
      'db.query(`SELECT id FROM users WHERE token = ${token}`)',
      'cursor.execute("SELECT * FROM t WHERE id = {}".format(id))',
    ],
    noDetecta: [
      'cursor.execute("SELECT * FROM users WHERE email = %s", (email,))',
      'await db.query("SELECT * FROM users WHERE id = $1", [id])',
      'query = "SELECT nombre, email FROM users"',
      'document.querySelector(`select ${nombre}`)',
      'titulo = "Selecciona el archivo desde " + carpeta',
      '# query = "SELECT * FROM users WHERE id = " + user_id',
    ],
  },
  {
    reglaId: 'inyeccion-comandos',
    detecta: [
      'os.system("ping -c 1 " + host)',
      'subprocess.run("ls " + carpeta, shell=True)',
      'os.popen(comando).read()',
      'child_process.exec(`git clone ${repo}`)',
      'execSync("rm -rf " + ruta)',
    ],
    noDetecta: [
      'subprocess.run(["ping", "-c", "1", host], shell=False, check=True)',
      'subprocess.run(["ls", carpeta])',
      '// os.system("ping " + host)',
      'systemctl_status = leer_estado()',
    ],
  },
  {
    reglaId: 'evaluacion-dinamica',
    detecta: [
      'resultado = eval(entrada_usuario)',
      'exec(codigo_recibido)',
      'const fn = new Function("a", cuerpo);',
      'setTimeout("hacerAlgo()", 1000)',
    ],
    noDetecta: [
      'datos = ast.literal_eval(texto)',
      'const coincidencia = patron.exec(cadena);',
      'cursor.execute(consulta, parametros)',
      'setTimeout(() => refrescar(), 1000)',
      'const datos = JSON.parse(cuerpo);',
      '# resultado = eval(entrada_usuario)',
    ],
  },
  {
    reglaId: 'xss-navegador',
    detecta: [
      'contenedor.innerHTML = "<p>" + comentario + "</p>";',
      'document.write(parametroUrl);',
      '<div dangerouslySetInnerHTML={{ __html: contenido }} />',
      'lista.insertAdjacentHTML("beforeend", fila);',
    ],
    noDetecta: [
      'saludo.textContent = "Hola, " + nombre;',
      'contenido.innerHTML = DOMPurify.sanitize(htmlUsuario);',
      'contenedor.innerHTML = "";',
      '// contenedor.innerHTML = comentario;',
    ],
  },
  {
    reglaId: 'deserializacion-insegura',
    detecta: [
      'datos = pickle.loads(cuerpo_peticion)',
      'config = yaml.load(texto)',
      'obj = marshal.loads(blob)',
    ],
    noDetecta: [
      'config = yaml.safe_load(texto)',
      'config = yaml.load(texto, Loader=yaml.SafeLoader)',
      'datos = json.loads(cuerpo_peticion)',
    ],
  },
  {
    reglaId: 'hash-debil',
    detecta: [
      'hash = hashlib.md5(password.encode()).hexdigest()',
      'huella = hashlib.sha1(datos).hexdigest()',
      'const h = crypto.createHash("md5").update(clave).digest("hex");',
    ],
    noDetecta: [
      'hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())',
      'huella = hashlib.sha256(datos).hexdigest()',
      'clave_cache = hashlib.md5(url.encode(), usedforsecurity=False).hexdigest()',
    ],
  },
  {
    reglaId: 'tls-desactivado',
    detecta: [
      'requests.get(url, verify=False)',
      'const agente = new https.Agent({ rejectUnauthorized: false });',
      'contexto = ssl._create_unverified_context()',
    ],
    noDetecta: [
      'requests.get(url, timeout=10)',
      'requests.get(url, verify="/etc/ssl/certs/ca-interna.pem")',
      'const agente = new https.Agent({ rejectUnauthorized: true });',
    ],
  },
  {
    reglaId: 'conexion-sin-cifrar',
    detecta: [
      'const API = "http://api.miempresa.com/v1";',
      'requests.post("http://pagos.example.org/cobrar", datos)',
    ],
    noDetecta: [
      'const API = "https://api.miempresa.com/v1";',
      'const DEV = "http://localhost:5173";',
      'const LOCAL = "http://127.0.0.1:8000/api";',
      '<svg xmlns="http://www.w3.org/2000/svg">',
      '// ver http://ejemplo.com/docs',
    ],
  },
  {
    reglaId: 'formato-de-secreto',
    detecta: [
      'PRIVADA = "-----BEGIN RSA PRIVATE KEY-----"',
      'GITHUB_TOKEN = "ghp_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r"',
      'STRIPE = "sk_live_DEMOsecscan1234567"',
      'GOOGLE = "AIzaSyD1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p"',
      'SLACK = "xoxb-123456789012-abcdefghijkl"',
    ],
    noDetecta: [
      'GITHUB = "ghp_XXXXXXXXXXXXXXXXXXXXXXXX"',
      'STRIPE = "sk_live_EXAMPLE1234567890"',
      'mensaje = "esto no contiene ninguna credencial"',
    ],
  },
  {
    reglaId: 'jwt-sin-verificar',
    detecta: [
      'datos = jwt.decode(token, options={"verify_signature": False})',
      'datos = jwt.decode(token, verify=False)',
      'datos = jwt.decode(token, clave, algorithms=["none"])',
      'const datos = jwt.decode(token);',
    ],
    noDetecta: [
      'datos = jwt.decode(token, CLAVE_SECRETA, algorithms=["HS256"])',
      'token = jwt.encode(datos, CLAVE_SECRETA, algorithm="HS256")',
    ],
  },
  {
    reglaId: 'plantilla-servidor',
    detecta: [
      'return render_template_string("<h1>Hola " + nombre + "</h1>")',
      'plantilla = jinja2.Template(contenido_del_usuario)',
      'plantilla = env.from_string(texto_recibido)',
    ],
    noDetecta: [
      'return render_template("bienvenida.html", nombre=nombre)',
      'plantilla = Template("bienvenida.html")',
    ],
  },
  {
    reglaId: 'recorrido-rutas',
    detecta: [
      'archivo = open("archivos/" + nombre)',
      'contenido = open(f"/datos/{nombre}").read()',
      'ruta = os.path.join(BASE, request.args["archivo"])',
      'return send_file(ruta)',
      'fs.readFile("./subidas/" + req.query.f, devolver);',
      'ruta = "../../etc/passwd"',
    ],
    noDetecta: [
      'archivo = open("config.yaml")',
      'archivo = open("config.yaml", "r")',
      'ruta = os.path.join(BASE, secure_filename(nombre))',
      'return send_from_directory(CARPETA, nombre)',
      'nombre = os.path.basename(entrada)',
    ],
  },
  {
    reglaId: 'descompresion-insegura',
    detecta: [
      'paquete.extractall(destino)',
      'zipfile.ZipFile(archivo).extract(nombre, destino)',
      'const zip = new admZip(archivo); zip.extractAllTo("/tmp", true);',
    ],
    noDetecta: [
      'paquete.extractall(DESTINO, filter="data")',
      'nombres = zipfile.ZipFile(archivo).namelist()',
    ],
  },
  {
    reglaId: 'csrf-desactivado',
    detecta: [
      '@csrf_exempt',
      'WTF_CSRF_ENABLED = False',
      'const opciones = { csrf: false };',
    ],
    noDetecta: ['WTF_CSRF_ENABLED = True', 'const opciones = { csrf: true };'],
  },
  {
    reglaId: 'redireccion-abierta',
    detecta: [
      'return redirect(request.args.get("next"))',
      'res.redirect(req.query.url);',
      'window.location = new URLSearchParams(location.search).get("destino");',
    ],
    noDetecta: [
      'return redirect(url_for("perfil"))',
      'res.redirect("/inicio");',
      'return redirect("/perfil/" + usuario_id)',
      'return redirect(destino_seguro(siguiente))',
    ],
  },
  {
    reglaId: 'aleatoriedad-debil',
    detecta: [
      'codigo = "".join(random.choice("0123456789") for _ in range(6))',
      'const token = Math.random().toString(36).slice(2);',
      'password_temporal = random.randint(100000, 999999)',
    ],
    noDetecta: [
      'token = secrets.token_urlsafe(32)',
      'codigo = secrets.choice(digitos)',
      'random.shuffle(cartas)',
      'const indice = Math.floor(Math.random() * lista.length);',
    ],
  },
  {
    reglaId: 'cifrado-obsoleto',
    detecta: [
      'cifrador = AES.new(clave, AES.MODE_ECB)',
      'cifrador = DES.new(clave, DES.MODE_CBC, iv)',
      'const c = crypto.createCipher("aes-256-cbc", clave);',
    ],
    noDetecta: [
      'cifrador = AESGCM(clave)',
      'const c = crypto.createCipheriv("aes-256-gcm", clave, iv);',
      'cifrador = Fernet(clave)',
    ],
  },
  {
    reglaId: 'cors-permisivo',
    detecta: [
      'app.use(cors());',
      'res.header("Access-Control-Allow-Origin", "*");',
      'CORS(app)',
      'app.use(cors({ origin: "*" }));',
    ],
    noDetecta: [
      'app.use(cors({ origin: ORIGENES_PERMITIDOS }));',
      'res.header("Access-Control-Allow-Origin", "https://app.miempresa.com");',
    ],
  },
  {
    reglaId: 'cookie-insegura',
    detecta: [
      'res.cookie("sid", valor, { httpOnly: false });',
      'SESSION_COOKIE_SECURE = False',
      'res.cookie("sid", valor, { sameSite: "none" });',
    ],
    noDetecta: [
      'res.cookie("sid", valor, { httpOnly: true, secure: true, sameSite: "lax" });',
      'SESSION_COOKIE_SECURE = True',
    ],
  },
  {
    reglaId: 'entidades-xml',
    detecta: [
      'arbol = ElementTree.parse(archivo_recibido)',
      'parser = etree.XMLParser(resolve_entities=True)',
      'documento = xml.dom.minidom.parse(entrada)',
    ],
    noDetecta: [
      'arbol = defusedxml.ElementTree.parse(archivo_recibido)',
      'parser = etree.XMLParser(resolve_entities=False)',
      'datos = json.loads(cuerpo_peticion)',
    ],
  },
  {
    reglaId: 'modo-depuracion',
    detecta: [
      'DEBUG = True',
      'app.run(host="0.0.0.0", debug=True)',
      'const opciones = { debug: true };',
      '"debug": true',
    ],
    noDetecta: [
      'DEBUG = False',
      'DEBUG = os.getenv("APP_DEBUG", "false").lower() == "true"',
      'const debug = process.env.NODE_ENV !== "production";',
      '# DEBUG = True',
    ],
  },
];

function analizarSoloCon(reglaId: string, codigo: string) {
  const regla = REGLAS_POR_ID.get(reglaId);
  if (!regla) throw new Error(`Regla desconocida: ${reglaId}`);
  return analizar(codigo, { reglas: [regla] }).hallazgos;
}

describe('catalogo de reglas', () => {
  it('cubre las 23 reglas del catalogo', () => {
    expect(CATALOGO_DE_REGLAS).toHaveLength(23);
  });

  it('no repite identificadores', () => {
    const ids = CATALOGO_DE_REGLAS.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('cada regla trae ficha educativa completa', () => {
    for (const regla of CATALOGO_DE_REGLAS) {
      expect(regla.ficha.queEncontramos.length, regla.id).toBeGreaterThan(40);
      expect(regla.ficha.comoTeAtacarian.length, regla.id).toBeGreaterThan(40);
      expect(regla.ficha.comoSeArregla.length, regla.id).toBeGreaterThan(40);
      expect(regla.ficha.fix.codigo.length, regla.id).toBeGreaterThan(20);
      expect(regla.owasp.id, regla.id).toMatch(/^A\d{2}:2021$/);
      expect(regla.cwe.id, regla.id).toMatch(/^CWE-\d+$/);
      expect(regla.patron.flags, regla.id).toContain('g');
    }
  });

  it('hay un caso de prueba por cada regla del catalogo', () => {
    expect(CASOS.map((c) => c.reglaId).sort()).toEqual(CATALOGO_DE_REGLAS.map((r) => r.id).sort());
  });
});

describe.each(CASOS)('regla $reglaId', ({ reglaId, detecta, noDetecta }) => {
  it.each(detecta)('detecta: %s', (codigo) => {
    expect(analizarSoloCon(reglaId, codigo)).toHaveLength(1);
  });

  it.each(noDetecta)('no detecta (falso positivo): %s', (codigo) => {
    expect(analizarSoloCon(reglaId, codigo)).toHaveLength(0);
  });
});
