import type { Regla } from '../tipos';
import { BT, CWE, ES_DEFINICION, OWASP, unir } from './utiles';

/**
 * Genera los patrones de SQL peligroso para UN delimitador de cadena concreto.
 *
 * Se hace por delimitador y no con una clase generica `[^"']` porque el caso
 * mas comun del mundo real lleva comillas anidadas:
 *   f"SELECT * FROM users WHERE email = '{email}'"
 * Un patron que excluyera ambas comillas a la vez se detendria en la interior
 * y dejaria pasar justo la consulta que hay que detectar.
 *
 * Se exigen DOS palabras clave relacionadas (`select ... from`, `insert into`,
 * ...) y no una suelta: asi una plantilla de CSS como `select ${x}` de un
 * querySelector no se confunde con una consulta.
 */
function patronesSql(delimitador: string): string[] {
  const salvoDelimitador = `[^${delimitador}\\n]`;
  const nucleo = [
    `select\\b${salvoDelimitador}{0,120}\\bfrom\\b`,
    'insert\\s+into\\b',
    `update\\b${salvoDelimitador}{0,120}\\bset\\b`,
    'delete\\s+from\\b',
    'drop\\s+table\\b',
    `where\\b${salvoDelimitador}{0,60}=`,
  ].join('|');

  return [
    // Interpolacion dentro de la cadena:  f"... {email}"  ·  `... ${id}`  ·  "... {}".format(id)
    `${delimitador}(?=${salvoDelimitador}*(?:${nucleo}))${salvoDelimitador}*\\$?\\{${salvoDelimitador}*\\}${salvoDelimitador}*${delimitador}`,
    // Concatenacion o formateo tras cerrar la cadena:  "..." + id  ·  "..." % id  ·  "...".format(id)
    `${delimitador}(?=${salvoDelimitador}*(?:${nucleo}))${salvoDelimitador}*${delimitador}\\s*(?:\\+\\s*[\\w(]|%\\s*[\\w(]|\\.format\\s*\\()`,
  ];
}

export const inyeccionSql: Regla = {
  id: 'inyeccion-sql',
  titulo: 'Inyección SQL: la consulta se arma pegando texto',
  severidad: 'critica',
  owasp: OWASP.A03,
  cwe: CWE.SQL,
  patron: unir(
    [...patronesSql('"'), ...patronesSql("'"), ...patronesSql(BT)],
    'gi',
  ),
  ficha: {
    queEncontramos:
      'La consulta a la base de datos se está construyendo pegando texto: lo que escribe el usuario se mezcla con las instrucciones SQL. Para la base de datos todo llega como una sola frase, y no tiene forma de distinguir qué parte escribiste tú y qué parte vino de fuera.',
    comoTeAtacarian:
      'El atacante no escribe su correo en el formulario: escribe \' OR \'1\'=\'1 -- y la condición pasa a ser siempre verdadera, de modo que entra como el primer usuario de la tabla, normalmente el administrador. Si quiere ir más lejos, encadena un UNION SELECT y se lleva la tabla de usuarios completa con sus hashes de contraseña, o añade "; DROP TABLE users; --" y la borra. No necesita herramientas exóticas: sqlmap automatiza todo el proceso y lleva dos décadas disponible de forma gratuita. Año tras año, esta es la causa de buena parte de las filtraciones masivas que llegan a los medios.',
    comoSeArregla:
      'Usa consultas parametrizadas. La idea es separar la instrucción de los datos: primero le das a la base de datos la frase con huecos (%s, ? o $1), luego los valores por separado. Así el motor ya sabe dónde termina la orden y dónde empiezan los datos, y lo que llegue en el hueco se trata siempre como texto, nunca como instrucción — aunque contenga comillas o un DROP TABLE. Ojo: escapar comillas a mano no sustituye a esto; siempre se escapa un caso menos de los que hay.',
    fix: {
      lenguaje: 'python',
      codigo: `# MAL: el email entra a formar parte de la instruccion
# cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")

# BIEN: la instruccion lleva un hueco y el valor viaja aparte
cursor.execute(
    "SELECT * FROM users WHERE email = %s AND activo = %s",
    (email, True),
)

# El mismo principio en JavaScript (node-postgres):
# await db.query("SELECT * FROM users WHERE id = $1", [id]);`,
    },
  },
};

export const inyeccionDeComandos: Regla = {
  id: 'inyeccion-comandos',
  titulo: 'Inyección de comandos del sistema',
  severidad: 'alta',
  owasp: OWASP.A03,
  cwe: CWE.COMANDOS,
  patron: unir(
    [
      '\\bos\\.system\\s*\\(',
      '\\bos\\.popen\\s*\\(',
      '\\bcommands\\.getoutput\\s*\\(',
      '\\bsubprocess\\.(?:run|call|check_call|check_output|Popen)\\s*\\([^\\n]*shell\\s*=\\s*True',
      '\\bchild_process\\.exec(?:Sync)?\\s*\\(',
      '\\bexecSync\\s*\\(',
      '\\bshell\\s*:\\s*true',
      // PHP
      '\\b(?:shell_exec|passthru|proc_open|popen)\\s*\\(',
      // Java
      '\\bRuntime\\.getRuntime\\(\\)\\.exec\\s*\\(',
      '\\bnew\\s+ProcessBuilder\\s*\\(',
    ],
    'g',
  ),
  ignorarSiLinea: [
    ES_DEFINICION,
    // `os.system("python setup.py sdist")` es una constante: no hay nada que
    // inyectar. Solo se avisa cuando el comando se compone con algo.
    /\b(?:os\.system|os\.popen|shell_exec|passthru)\s*\(\s*["'][^"']*["']\s*\)/,
  ],
  ficha: {
    queEncontramos:
      'El programa le está pidiendo al sistema operativo que ejecute un comando a través de una shell. Si alguna parte de ese comando viene de fuera — un formulario, un parámetro de la URL, un nombre de archivo — el usuario acaba escribiendo órdenes en tu servidor.',
    comoTeAtacarian:
      'La shell interpreta caracteres especiales, y ahí está el problema. Si tu código hace ping a la dirección que le pasan, el atacante escribe 8.8.8.8; cat /etc/passwd y el punto y coma convierte una línea en dos órdenes. Con una tubería hacia curl descarga su propio programa y lo ejecuta. A partir de ahí no está atacando tu aplicación: ya está dentro de la máquina, con los permisos de tu proceso, mirando qué más hay en la red interna.',
    comoSeArregla:
      'Casi siempre no hace falta una shell. Pasa el comando como lista de argumentos y con shell=False (el valor por defecto): así el punto y coma es simplemente un carácter más dentro del argumento, no un separador de órdenes. Y cuando exista una biblioteca nativa que haga el trabajo (mover archivos, comprimir, resolver DNS), úsala en lugar de llamar al sistema.',
    fix: {
      lenguaje: 'python',
      codigo: `import subprocess

# MAL: la shell interpreta ; | && y demas metacaracteres
# os.system("ping -c 1 " + host)

# BIEN: lista de argumentos, sin shell. "8.8.8.8; rm -rf /" seria
# un unico argumento invalido, no dos comandos.
subprocess.run(
    ["ping", "-c", "1", host],
    shell=False,
    check=True,
    timeout=5,
)`,
    },
  },
};

export const evaluacionDinamica: Regla = {
  id: 'evaluacion-dinamica',
  titulo: 'Uso de eval() / exec(): se ejecuta texto como código',
  severidad: 'alta',
  owasp: OWASP.A03,
  cwe: CWE.EVAL,
  patron: unir(
    [
      // Se descartan `objeto.eval(` y `regex.exec(` — no son lo mismo.
      '(?<![\\w.$])eval\\s*\\(',
      '(?<![\\w.$])exec\\s*\\(',
      '\\bnew\\s+Function\\s*\\(',
      `\\bset(?:Timeout|Interval)\\s*\\(\\s*["'${BT}]`,
    ],
    'g',
  ),
  ignorarSiLinea: [
    /ast\.literal_eval|JSON\.parse/,
    ES_DEFINICION,
    // En Node, `exec(` es el de child_process: ejecuta un comando, no evalua
    // codigo. Lo cubre la regla de inyeccion de comandos, y con la ficha
    // correcta. Medido sobre codigo real, esta linea sola quitaba 9 avisos
    // equivocados de 12.
    /\bawait\s+exec\s*\(|child_process|promisify|\bstdout\b/,
  ],
  ficha: {
    queEncontramos:
      'eval() y exec() cogen una cadena de texto y la ejecutan como si fuera parte de tu programa. Cualquier dato que llegue hasta ahí deja de ser un dato y pasa a ser código con todos los permisos de la aplicación.',
    comoTeAtacarian:
      'Si el texto que evalúas viene, aunque sea a medias, de fuera, el atacante no necesita encontrar un fallo: le estás ofreciendo un intérprete. En Python le basta con enviar __import__("os").system("...") para ejecutar lo que quiera; en el navegador, con un eval sobre un parámetro de la URL se roba la sesión de quien abra el enlace. Es la diferencia entre que te lean un dato y que te ejecuten un programa.',
    comoSeArregla:
      'Casi ningún uso de eval() es necesario. Si lo que llega es JSON, parséalo con json.loads o JSON.parse. Si es una expresión matemática, usa un evaluador acotado. Si necesitas elegir entre varias acciones según un texto, usa un diccionario que mapee nombres permitidos a funciones — lo que no esté en la lista, se rechaza.',
    fix: {
      lenguaje: 'python',
      codigo: `import json

# MAL: convierte texto en codigo ejecutable
# config = eval(texto_recibido)

# BIEN: si son datos, se parsean como datos
config = json.loads(texto_recibido)

# BIEN: si hay que elegir una accion, lista blanca explicita
ACCIONES = {"crear": crear_usuario, "borrar": borrar_usuario}
accion = ACCIONES.get(nombre_accion)
if accion is None:
    raise ValueError("Accion no permitida")
accion()`,
    },
  },
};

export const xssEnNavegador: Regla = {
  id: 'xss-navegador',
  titulo: 'XSS: se inserta HTML sin sanitizar',
  severidad: 'alta',
  owasp: OWASP.A03,
  cwe: CWE.XSS,
  patron: unir(
    [
      '\\.innerHTML\\s*\\+?=',
      '\\.outerHTML\\s*=',
      '\\bdocument\\.write(?:ln)?\\s*\\(',
      '\\bdangerouslySetInnerHTML',
      '\\.insertAdjacentHTML\\s*\\(',
      '\\)\\.html\\s*\\(\\s*[^)\\s]',
      // Vue y Angular tienen su propia puerta trasera al HTML crudo
      '\\bv-html\\s*=',
      '\\$sce\\.trustAsHtml\\s*\\(',
      '\\[innerHTML\\]\\s*=',
      '\\.srcdoc\\s*=',
      // Un enlace que ejecuta codigo al pulsarlo
      `href\\s*=\\s*["'${BT}]?\\s*javascript:`,
    ],
    'g',
  ),
  ignorarSiLinea: [
    /DOMPurify|sanitiz(?:e|ar|eHtml)|escapeHtml|textContent/i,
    // Vaciar un contenedor con innerHTML = "" es inofensivo.
    new RegExp(`innerHTML\\s*=\\s*(?:""|''|${BT}${BT})\\s*;?\\s*$`),
  ],
  ficha: {
    queEncontramos:
      'Se está metiendo contenido en la página como HTML, no como texto. El navegador no distingue de dónde vino: si dentro de ese contenido hay etiquetas, las interpreta y las ejecuta.',
    comoTeAtacarian:
      'El atacante pone como nombre de usuario, comentario o término de búsqueda algo como <img src=x onerror="fetch(...+document.cookie)">. La imagen falla a propósito, salta el onerror y su código corre dentro de tu página, con la sesión de quien la esté mirando. Puede robar la cookie y entrar como esa persona, cambiar lo que se ve en pantalla para pedir la contraseña, o hacer peticiones a tu API en su nombre. Si eso lo ve un administrador, el atacante hereda el panel de administración.',
    comoSeArregla:
      'Si vas a mostrar texto, insértalo como texto: textContent en lugar de innerHTML — el navegador lo escribe tal cual y nunca lo interpreta. En React basta con {variable}, que escapa el contenido automáticamente; el nombre de dangerouslySetInnerHTML es una advertencia deliberada. Y cuando de verdad necesites permitir HTML (un editor enriquecido, por ejemplo), pásalo antes por un sanitizador como DOMPurify.',
    fix: {
      lenguaje: 'javascript',
      codigo: `// MAL: el navegador interpreta las etiquetas que vengan dentro
// saludo.innerHTML = "Hola, " + nombreUsuario;

// BIEN: se inserta como texto, las etiquetas se ven como texto
saludo.textContent = "Hola, " + nombreUsuario;

// Si de verdad necesitas HTML enriquecido, sanitizalo antes:
// contenido.innerHTML = DOMPurify.sanitize(htmlDelUsuario);`,
    },
  },
};

export const plantillaDeServidor: Regla = {
  id: 'plantilla-servidor',
  titulo: 'Plantilla del servidor construida con datos de fuera',
  severidad: 'alta',
  owasp: OWASP.A03,
  cwe: CWE.PLANTILLA,
  patron: unir(
    [
      '\\brender_template_string\\s*\\(',
      '\\bTemplate\\s*\\(\\s*[^)\\n]*(?:\\+|\\$\\{|f["\'])',
      '\\bjinja2\\.Template\\s*\\(',
      '\\benv\\.from_string\\s*\\(',
      '\\bhandlebars\\.compile\\s*\\([^)\\n]*(?:\\+|\\$\\{)',
      '\\bejs\\.render\\s*\\([^)\\n]*(?:\\+|\\$\\{)',
    ],
    'g',
  ),
  ignorarSiLinea: [ES_DEFINICION],
  ficha: {
    queEncontramos:
      'La plantilla que se va a renderizar no es un texto fijo: se está construyendo con datos que pueden venir de fuera. Y una plantilla no es texto — es código que el motor ejecuta en el servidor para producir el HTML.',
    comoTeAtacarian:
      'Es la inyección de plantillas del lado del servidor. El atacante escribe {{ 7*7 }} en el campo que acaba dentro de la plantilla; si la respuesta muestra 49, ya sabe que el motor está evaluando lo que él envía. A partir de ahí la escalada es conocida: en Jinja2 se navega por los atributos internos de Python hasta alcanzar la clase base de todos los objetos, y desde ahí se llega a os.system. El resultado no es un XSS, es ejecución de código en tu servidor — con el agravante de que el campo de entrada suele ser algo tan inocente como el nombre que aparece en un correo de bienvenida.',
    comoSeArregla:
      'La plantilla siempre fija en un archivo, y los datos siempre como variables. render_template("hola.html", nombre=nombre) es seguro; render_template_string("Hola " + nombre) no lo es, aunque hagan lo mismo a simple vista. Si de verdad necesitas plantillas que escriben los usuarios, ejecútalas en un entorno restringido, como SandboxedEnvironment de Jinja2.',
    fix: {
      lenguaje: 'python',
      codigo: `from flask import render_template

# MAL: el nombre pasa a formar parte de la plantilla
# return render_template_string("<h1>Hola " + nombre + "</h1>")

# BIEN: plantilla fija en un archivo, el dato viaja como variable
return render_template("bienvenida.html", nombre=nombre)

# En la plantilla, Jinja2 ya escapa el valor:
#   <h1>Hola {{ nombre }}</h1>`,
    },
  },
};

export const reglasDeInyeccion: Regla[] = [
  inyeccionSql,
  inyeccionDeComandos,
  evaluacionDinamica,
  xssEnNavegador,
  plantillaDeServidor,
];
