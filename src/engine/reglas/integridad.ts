import type { Regla } from '../tipos';
import { CWE, OWASP, unir } from './utiles';

export const deserializacionInsegura: Regla = {
  id: 'deserializacion-insegura',
  titulo: 'Deserialización insegura de datos no confiables',
  severidad: 'alta',
  owasp: OWASP.A08,
  cwe: CWE.DESERIALIZACION,
  patron: unir(
    [
      '\\b(?:pickle|cPickle)\\.loads?\\s*\\(',
      '\\bmarshal\\.loads?\\s*\\(',
      '\\bshelve\\.open\\s*\\(',
      '\\bjsonpickle\\.decode\\s*\\(',
      // yaml.load sin SafeLoader; yaml.safe_load no entra aqui.
      '\\byaml\\.load\\s*\\(',
      '\\bnode-serialize',
      '\\bunserialize\\s*\\(',
    ],
    'g',
  ),
  ignorarSiLinea: [/Loader\s*=\s*(?:yaml\.)?(?:Safe|CSafe|Base)Loader/, /safe_load/],
  ficha: {
    queEncontramos:
      'Se están reconstruyendo objetos a partir de datos serializados. Formatos como pickle o el yaml.load por defecto no se limitan a leer valores: el propio formato puede indicar qué clases instanciar y qué métodos llamar durante la carga. Es decir, el archivo que estás leyendo puede contener instrucciones, no solo datos.',
    comoTeAtacarian:
      'El atacante prepara un archivo pickle que, al deserializarse, invoca os.system con lo que él quiera — hay herramientas que lo generan en una línea. Luego solo tiene que conseguir que tu programa lo lea: una cookie de sesión, una caché en Redis, un archivo subido, una cola de mensajes. No hay validación posible que lo salve, porque el código se ejecuta durante la carga, antes de que puedas revisar nada de lo que llegó.',
    comoSeArregla:
      'Para intercambiar datos con el exterior usa un formato que solo describa datos: JSON, o YAML con safe_load. Si necesitas objetos con tipo, valídalos después con un esquema (pydantic, zod). Reserva pickle para datos que genera y consume tu propio proceso en un entorno de confianza, y aun así fírmalos con HMAC si viajan por la red.',
    fix: {
      lenguaje: 'python',
      codigo: `import json
import yaml

# MAL: ejecuta lo que venga dentro del archivo
# datos = pickle.loads(cuerpo_peticion)
# config = yaml.load(texto)

# BIEN: formatos que solo transportan datos
datos = json.loads(cuerpo_peticion)
config = yaml.safe_load(texto)

# Y si hay que garantizar la forma, se valida despues:
# Usuario.model_validate(datos)   # pydantic`,
    },
  },
};

export const reglasDeIntegridad: Regla[] = [deserializacionInsegura];
