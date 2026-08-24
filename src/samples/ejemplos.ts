import type { Lenguaje } from '../engine/tipos';

export interface Ejemplo {
  id: string;
  titulo: string;
  /** Que se va a ver al cargarlo: sirve de subtitulo en el boton. */
  subtitulo: string;
  lenguaje: Lenguaje;
  codigo: string;
}

/**
 * Los tres ejemplos de un clic. Estan escritos para que cualquiera —
 * tecnico o no — vea en dos segundos de que va la herramienta: cada uno
 * dispara varios hallazgos de severidades distintas.
 *
 * Son codigo vulnerable a proposito. Sirven de demostracion, no de plantilla.
 */
export const EJEMPLOS: Ejemplo[] = [
  {
    id: 'login-vulnerable',
    titulo: 'Login vulnerable',
    subtitulo: 'Python · contraseña en el código, inyección SQL y MD5',
    lenguaje: 'python',
    codigo: `import hashlib
import sqlite3

# Credenciales del servicio
DB_PASSWORD = "admin123"
SECRET_KEY = "clave-de-sesion-del-portal-2024"


def login(email, password):
    conexion = sqlite3.connect("app.db", password=DB_PASSWORD)
    cursor = conexion.cursor()

    # La consulta se arma pegando el texto que escribio el usuario
    cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")
    usuario = cursor.fetchone()
    if usuario is None:
        return None

    # Hash rapido y sin sal para comparar la contrasena
    intento = hashlib.md5(password.encode()).hexdigest()
    if intento == usuario["password_hash"]:
        return usuario
    return None
`,
  },
  {
    id: 'config-con-secretos',
    titulo: 'Config con secretos',
    subtitulo: 'Claves de API, credencial de AWS, HTTP y modo depuración',
    lenguaje: 'python',
    codigo: `# ------------------------------------------------------------
#  Configuracion de la aplicacion
# ------------------------------------------------------------
import requests

DEBUG = True

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7QWERTYU"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMIbPxRfiCYzK7MDENGkey01"

STRIPE_API_KEY = "sk_live_DEMOsecscan1234567"
SENDGRID_TOKEN = "SG.7f2b9c1d4e6a8b3c5d7e9f1a"

DATABASE_URL = "http://app:clave123@db.miempresa.com:5432/produccion"

# El certificado del proveedor caduco y "lo arreglamos" asi
respuesta = requests.get("https://proveedor.example.com/saldo", verify=False)
`,
  },
  {
    id: 'web-insegura',
    titulo: 'Web insegura',
    subtitulo: 'JavaScript · innerHTML sin sanitizar, eval() y document.write',
    lenguaje: 'javascript',
    codigo: `// Panel de comentarios (version insegura)
const params = new URLSearchParams(window.location.search);
const nombre = params.get("nombre");

// El nombre llega desde la URL y se inserta como HTML
document.getElementById("saludo").innerHTML = "<h2>Hola, " + nombre + "</h2>";

function pintarComentarios(comentarios) {
  const lista = document.getElementById("lista");
  comentarios.forEach((comentario) => {
    lista.insertAdjacentHTML("beforeend", "<li>" + comentario.texto + "</li>");
  });
}

// Las preferencias se guardan como texto y se "reviven" ejecutandolas
const preferencias = eval(localStorage.getItem("prefs"));

document.write("Ultima visita: " + localStorage.getItem("visita"));

fetch("http://api.miempresa.com/comentarios")
  .then((respuesta) => respuesta.json())
  .then(pintarComentarios);
`,
  },
  {
    id: 'api-vulnerable',
    titulo: 'API vulnerable',
    subtitulo: 'Python · CORS abierto, JWT sin verificar, rutas y plantillas',
    lenguaje: 'python',
    codigo: `# ------------------------------------------------------------
#  API de facturas — con los fallos tipicos de una prisa
# ------------------------------------------------------------
import random
import tarfile
from xml.etree import ElementTree

import jwt
from Crypto.Cipher import AES
from flask import Flask, redirect, render_template_string, request, send_file
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

app.config.update(
    SESSION_COOKIE_SECURE=False,
    WTF_CSRF_ENABLED=False,
)

STRIPE_API_KEY = "sk_live_51H8xKlMnOpQrStUvWxYz"


@app.route("/factura")
def factura():
    sesion = jwt.decode(request.args["token"], options={"verify_signature": False})
    return send_file("/var/facturas/" + request.args["archivo"])


@app.route("/bienvenida")
def bienvenida():
    return render_template_string("<h1>Hola " + request.args["nombre"] + "</h1>")


@app.route("/salir")
def salir():
    return redirect(request.args.get("next"))


@app.route("/adjunto", methods=["POST"])
def adjunto():
    arbol = ElementTree.parse(request.files["xml"])
    return {"etiquetas": len(arbol.getroot())}


def codigo_de_verificacion():
    codigo = "".join(random.choice("0123456789") for _ in range(6))
    return codigo


def cifrar_documento(datos):
    cifrador = AES.new(CLAVE_MAESTRA, AES.MODE_ECB)
    return cifrador.encrypt(datos)


def restaurar_copia(archivo):
    with tarfile.open(archivo) as paquete:
        paquete.extractall("/var/app")
`,
  },
];

export const EJEMPLOS_POR_ID: ReadonlyMap<string, Ejemplo> = new Map(
  EJEMPLOS.map((ejemplo) => [ejemplo.id, ejemplo]),
);
