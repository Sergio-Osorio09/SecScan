import { describe, expect, it } from 'vitest';
import { EJEMPLOS } from '../../samples/ejemplos';
import { analizar } from '../analizar';
import { detectarLenguaje, lineaDeOffset, prepararCodigo } from '../preprocesar';

describe('analizar', () => {
  it('devuelve un resultado vacio para codigo vacio', () => {
    const resultado = analizar('   \n  \n');
    expect(resultado.hallazgos).toEqual([]);
    expect(resultado.resumen.total).toBe(0);
    expect(resultado.lineasAnalizadas).toBe(0);
  });

  it('no reporta nada sobre codigo correcto', () => {
    const codigo = `import os
import bcrypt
import requests

DB_PASSWORD = os.environ["DB_PASSWORD"]


def login(email, password):
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    usuario = cursor.fetchone()
    return bcrypt.checkpw(password.encode(), usuario["hash"])


respuesta = requests.get("https://api.miempresa.com/saldo", timeout=10)
`;
    expect(analizar(codigo).hallazgos).toEqual([]);
  });

  it('apunta a la linea y la columna correctas', () => {
    const codigo = ['# comentario', '', 'DEBUG = True', ''].join('\n');
    const [hallazgo] = analizar(codigo).hallazgos;
    expect(hallazgo.linea).toBe(3);
    expect(hallazgo.columna).toBe(1);
    expect(hallazgo.fragmento).toBe('DEBUG = True');
  });

  it('ordena por severidad y despues por linea', () => {
    const codigo = ['DEBUG = True', 'hash = hashlib.md5(clave).hexdigest()', 'API_KEY = "sk_live_9f2b7c"'].join(
      '\n',
    );
    const severidades = analizar(codigo).hallazgos.map((h) => h.severidad);
    expect(severidades).toEqual(['critica', 'media', 'baja']);
  });

  it('no repite el mismo problema dos veces en la misma linea', () => {
    const codigo = 'eval(a); eval(b); eval(c)';
    expect(analizar(codigo).hallazgos).toHaveLength(1);
  });

  it('respeta el tope de hallazgos y avisa de que la lista se recorto', () => {
    const codigo = Array.from({ length: 50 }, () => 'DEBUG = True').join('\n');
    const resultado = analizar(codigo, { maxHallazgos: 5 });
    expect(resultado.hallazgos).toHaveLength(5);
    expect(resultado.truncado).toBe(true);
  });

  it('un analisis normal no queda marcado como recortado', () => {
    expect(analizar('DEBUG = True').truncado).toBe(false);
    expect(analizar('').truncado).toBe(false);
  });

  it('el resumen cuadra con la lista de hallazgos', () => {
    const codigo = EJEMPLOS.map((ejemplo) => ejemplo.codigo).join('\n\n');
    const { hallazgos, resumen } = analizar(codigo);
    expect(resumen.total).toBe(hallazgos.length);
    expect(resumen.critica + resumen.alta + resumen.media + resumen.baja).toBe(hallazgos.length);
  });

  it('es una funcion pura: dos ejecuciones dan lo mismo', () => {
    const codigo = EJEMPLOS[0].codigo;
    expect(analizar(codigo).hallazgos).toEqual(analizar(codigo).hallazgos);
  });
});

describe('ejemplos precargados', () => {
  it.each(EJEMPLOS)('$titulo dispara varias severidades', (ejemplo) => {
    const { resumen, hallazgos } = analizar(ejemplo.codigo);
    expect(hallazgos.length).toBeGreaterThanOrEqual(3);
    const severidadesDistintas = new Set(hallazgos.map((h) => h.severidad));
    expect(severidadesDistintas.size).toBeGreaterThanOrEqual(2);
    expect(resumen.total).toBe(hallazgos.length);
  });

  it('el ejemplo de login muestra secreto, inyeccion SQL y hash debil', () => {
    const ids = analizar(EJEMPLOS[0].codigo).hallazgos.map((h) => h.reglaId);
    expect(ids).toContain('secreto-embebido');
    expect(ids).toContain('inyeccion-sql');
    expect(ids).toContain('hash-debil');
  });

  it('el ejemplo de configuracion muestra la clave de AWS y el TLS desactivado', () => {
    const ids = analizar(EJEMPLOS[1].codigo).hallazgos.map((h) => h.reglaId);
    expect(ids).toContain('clave-aws');
    expect(ids).toContain('tls-desactivado');
    expect(ids).toContain('modo-depuracion');
    expect(ids).toContain('conexion-sin-cifrar');
  });

  it('el ejemplo web muestra XSS y evaluacion dinamica', () => {
    const ids = analizar(EJEMPLOS[2].codigo).hallazgos.map((h) => h.reglaId);
    expect(ids).toContain('xss-navegador');
    expect(ids).toContain('evaluacion-dinamica');
  });

  it('el ejemplo de API cubre las reglas anadidas al catalogo', () => {
    const ids = new Set(analizar(EJEMPLOS[3].codigo).hallazgos.map((h) => h.reglaId));
    for (const esperada of [
      'formato-de-secreto',
      'jwt-sin-verificar',
      'recorrido-rutas',
      'plantilla-servidor',
      'entidades-xml',
      'descompresion-insegura',
      'cors-permisivo',
      'cookie-insegura',
      'csrf-desactivado',
      'cifrado-obsoleto',
      'aleatoriedad-debil',
      'redireccion-abierta',
    ]) {
      expect(ids, esperada).toContain(esperada);
    }
  });

  it('los cuatro ejemplos cubren las cuatro severidades', () => {
    const severidades = new Set(
      EJEMPLOS.flatMap((ejemplo) => analizar(ejemplo.codigo).hallazgos).map((h) => h.severidad),
    );
    expect([...severidades].sort()).toEqual(['alta', 'baja', 'critica', 'media']);
  });

  it('cada ejemplo se detecta con el lenguaje que anuncia', () => {
    for (const ejemplo of EJEMPLOS) {
      expect(detectarLenguaje(ejemplo.codigo), ejemplo.id).toBe(ejemplo.lenguaje);
    }
  });
});

describe('prepararCodigo', () => {
  it('borra los comentarios pero conserva las posiciones', () => {
    const codigo = 'a = 1  # secreto\nb = 2';
    const preparado = prepararCodigo(codigo);
    expect(preparado.limpio).toHaveLength(codigo.length);
    expect(preparado.limpio).toContain('a = 1');
    expect(preparado.limpio).not.toContain('secreto');
    expect(preparado.limpio.split('\n')).toHaveLength(2);
  });

  it('no confunde las dos barras de una URL con un comentario', () => {
    const preparado = prepararCodigo('const API = "http://api.com/v1";');
    expect(preparado.limpio).toContain('http://api.com/v1');
  });

  it('no confunde una almohadilla dentro de una cadena con un comentario', () => {
    const preparado = prepararCodigo('color = "#ff0000"  # rojo');
    expect(preparado.limpio).toContain('#ff0000');
    expect(preparado.limpio).not.toContain('rojo');
  });

  it('marca lo que esta dentro de una cadena', () => {
    const codigo = 'x = "hola"';
    const { enCadena } = prepararCodigo(codigo);
    expect(enCadena[codigo.indexOf('hola')]).toBe(true);
    expect(enCadena[codigo.indexOf('x')]).toBe(false);
    // La comilla que abre no cuenta como interior de la cadena.
    expect(enCadena[codigo.indexOf('"')]).toBe(false);
  });

  it('entiende comentarios de bloque y cadenas de tres comillas', () => {
    const bloque = prepararCodigo('a = 1; /* eval(x) */ b = 2;');
    expect(bloque.limpio).not.toContain('eval');

    const triple = prepararCodigo('"""\nDocumentacion con password = "x"\n"""\ny = 1');
    expect(triple.limpio).toHaveLength('"""\nDocumentacion con password = "x"\n"""\ny = 1'.length);
  });

  it('mapea offsets a numero de linea', () => {
    const { iniciosDeLinea } = prepararCodigo('uno\ndos\ntres');
    expect(lineaDeOffset(iniciosDeLinea, 0)).toBe(1);
    expect(lineaDeOffset(iniciosDeLinea, 4)).toBe(2);
    expect(lineaDeOffset(iniciosDeLinea, 9)).toBe(3);
  });
});

describe('detectarLenguaje', () => {
  it('reconoce Python', () => {
    expect(detectarLenguaje('def suma(a, b):\n    return a + b\n')).toBe('python');
  });

  it('reconoce JavaScript', () => {
    expect(detectarLenguaje('const suma = (a, b) => a + b;\nconsole.log(suma(1, 2));')).toBe(
      'javascript',
    );
  });

  it('reconoce Java y no lo confunde con JavaScript', () => {
    const java = `package com.miempresa.app;

import java.util.List;

public class Facturas {
    public String buscar(String id) throws SQLException {
        System.out.println(id);
        return null;
    }
}
`;
    expect(detectarLenguaje(java)).toBe('java');
  });

  it('no confunde JavaScript con Java', () => {
    const js = `const lista = [];
export function buscar(id) {
  console.log(id);
  return lista.find((f) => f.id === id) ?? null;
}
`;
    expect(detectarLenguaje(js)).toBe('javascript');
  });

  it('no se inventa un lenguaje cuando no hay senales', () => {
    expect(detectarLenguaje('hola mundo')).toBe('generico');
    expect(detectarLenguaje('')).toBe('generico');
  });
});
