import { describe, expect, it } from 'vitest';
import { EJEMPLOS } from '../../samples/ejemplos';
import { resaltarSintaxis } from '../resaltarSintaxis';
import type { TipoToken } from '../resaltarSintaxis';

const reconstruir = (codigo: string) =>
  resaltarSintaxis(codigo)
    .map((token) => token.texto)
    .join('');

const tipoDe = (codigo: string, fragmento: string): TipoToken | undefined =>
  resaltarSintaxis(codigo).find((token) => token.texto === fragmento)?.tipo;

describe('resaltarSintaxis', () => {
  /**
   * La capa de color se dibuja debajo del textarea. Si el resaltado perdiera o
   * duplicara un caracter, el texto de color dejaria de coincidir con el que se
   * escribe: por eso esta es la prueba mas importante del modulo.
   */
  it('reconstruye el texto original caracter por caracter', () => {
    const casos = [
      '',
      'x = 1',
      'def login(email):\n    return None\n',
      'const a = `hola ${nombre}`; // saludo',
      '"""\nDocumentacion\n"""\n@decorador\nclass Usuario:\n    pass\n',
      'texto = "comilla sin cerrar',
      ...EJEMPLOS.map((ejemplo) => ejemplo.codigo),
    ];
    for (const caso of casos) {
      expect(reconstruir(caso), JSON.stringify(caso.slice(0, 30))).toBe(caso);
    }
  });

  it('clasifica comentarios de ambos lenguajes', () => {
    expect(tipoDe('x = 1  # nota', '# nota')).toBe('comentario');
    expect(tipoDe('const x = 1; // nota', '// nota')).toBe('comentario');
    expect(tipoDe('a = 1; /* nota */ b = 2;', '/* nota */')).toBe('comentario');
  });

  it('no confunde una almohadilla dentro de una cadena con un comentario', () => {
    expect(tipoDe('color = "#ff0000"', '"#ff0000"')).toBe('cadena');
  });

  it('no confunde las barras de una URL con un comentario', () => {
    expect(tipoDe('api = "http://ejemplo.com"', '"http://ejemplo.com"')).toBe('cadena');
  });

  it('distingue palabras clave, tipos, funciones, numeros y decoradores', () => {
    const codigo = '@app.route\ndef cobrar(monto=100):\n    return Decimal(monto)\n';
    expect(tipoDe(codigo, '@app')).toBe('decorador');
    expect(tipoDe(codigo, 'def')).toBe('clave');
    expect(tipoDe(codigo, 'cobrar')).toBe('funcion');
    expect(tipoDe(codigo, '100')).toBe('numero');
    expect(tipoDe(codigo, 'Decimal')).toBe('tipo');
  });

  it('devuelve un unico token plano cuando el archivo es enorme', () => {
    const enorme = 'x = 1\n'.repeat(20_000);
    const tokens = resaltarSintaxis(enorme);
    expect(tokens).toHaveLength(1);
    expect(tokens[0].tipo).toBe('texto');
  });
});
