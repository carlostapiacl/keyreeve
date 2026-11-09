# keyreeve

[![Licencia: MIT](https://img.shields.io/badge/licencia-MIT-blue.svg)](LICENSE)

Guarda tus claves de API en una bóveda en tu propio Mac, deja que los agentes las usen sin verlas y rótalas con
recetas que la comunidad escribe para cada proveedor.

[Sitio](https://carlostapiacl.github.io/keyreeve/es/) · [English](README.md) · [Modelo de amenazas](THREAT_MODEL.md) ·
[Cómo contribuir](CONTRIBUTING.es.md) · [Seguridad](SECURITY.md)

Rotar una clave a mano es crear una nueva, pegarla en cada lugar donde se usa, revisar que nada se rompió y revocar la
vieja. Cada proveedor lo hace un poco distinto. keyreeve guarda esas diferencias en un archivo chico, así una receta
escrita una vez sirve para todos. Alrededor de eso mantiene tus claves selladas, revisa que sigan funcionando y deja que
un agente use una clave a través de un proxy local, mientras el agente solo tiene un reemplazo que no sirve para nada más.

**Estado: temprano.** La bóveda, las herramientas para agentes, las pruebas y el motor de rotación funcionan y se usan a
diario en un Mac. Todavía no corre ninguna rotación contra un proveedor real y no hay descargas listas. Mira
[lo que falta](#lo-que-falta).

La documentación técnica completa está en inglés, en [README.md](README.md). Aquí va lo necesario para entender la
herramienta y empezar.

## Pruébalo

Necesitas [Rust](https://rustup.rs). Esto corre sin conexión y no usa claves reales.

```bash
cargo install --git https://github.com/carlostapiacl/keyreeve
git clone https://github.com/carlostapiacl/keyreeve
cd keyreeve
keyreeve check examples/recipe.yaml
keyreeve simulate examples/recipe.yaml
```

`simulate` arma un proveedor falso a partir de la receta, le mete fallas y corta el proceso en cada operación, y después
en cada operación de la recuperación. Tras cada corte revisa que la clave guardada y cada servicio tengan una clave que
funciona, que al cerrar todos tengan la misma, que cualquier clave sobrante en el proveedor quede reportada y que ningún
valor llegue al registro ni a un error. Pasar la simulación prueba la receta y el motor contra el simulador, no que el
proveedor real se comporte como dice la receta.

El CI revisa el comando en Linux y la app en macOS. En Windows no se ha probado.

## La app para Mac

Una ventana nativa sobre tus claves, sin web adentro, en español e inglés. Se compila con las Command Line Tools:

```bash
app/build-app.sh
ditto app/dist/Keyreeve.app /Applications/Keyreeve.app   # una vez, para tenerla con tus otras apps
open /Applications/Keyreeve.app
```

Cuando ya hay una copia en Aplicaciones, cada compilación la actualiza, y si Keyreeve estaba abierto lo cierra y lo vuelve
a abrir. La compilación no está notarizada, así que macOS te avisa la primera vez.

Al abrirla eliges tu carpeta de claves, o **Empezar sin carpeta** para partir con una bóveda vacía. **Inicio** muestra lo
que necesita tu atención, cada cosa con su botón. **Mis claves** es la lista. **Por revisar** junta lo que hay que mirar y
**Seguridad y respaldo** tiene la bóveda. **Agentes**, **Proveedores**, **Rotación** y **Registro** están aparte, en
Herramientas.

**Probar todas**, en Inicio o en Mis claves, manda cada clave a su propio proveedor, de a seis como máximo, con avance y un
resumen. Cada prueba es una sola consulta de lectura. Una clave sin copia sellada y cuyo archivo ya no está sale como **No
está en la bóveda**, separada de las que el proveedor no respondió. La app nunca adivina a qué empresa mandar una clave: lo
eliges tú, o lo demuestra el inicio de la clave.

Si un proveedor dice cuándo vence una clave, como GitHub o Cloudflare, la fecha se guarda al identificarla. Dos semanas
antes la clave pasa a **Por revisar** con los días que le quedan.

## La bóveda

En **Seguridad y respaldo**, aprieta **Crear mi bóveda**. Te muestra una clave de recuperación una sola vez y no guarda
nada hasta que escribas sus últimos 6 caracteres. Guárdala lejos de este Mac: si el Mac muere, es la única forma de volver
a entrar.

Después eliges claves y aprietas **Sellar**. Cada archivo queda sellado para una llave dentro del Secure Enclave de tu Mac,
que no puede salir de ahí, y para la clave de recuperación. También se sellan archivos binarios, como un `.pfx` o un `.jks`.
Tus archivos originales se quedan donde están, y keyreeve nunca los borra: moverlos o borrarlos es decisión tuya cuando
confíes en la bóveda. Desde ese momento las pruebas y tus acciones usan la copia sellada.

Cada clave sellada es un archivo [age](https://age-encryption.org) estándar, y la clave de recuperación es una llave age
común. Con la bóveda y el comando `age` puedes abrir tus claves en cualquier computador, sin keyreeve:

```bash
keyreeve-vault export hosting-token --recovery | age -d -i recovery-key.txt
```

El código que escribe ese formato es mío y no ha tenido revisión externa.

## Claves y agentes

Cada clave puede tener un identificador aparte de su archivo, como `netlify` o `mail-shop`. Un agente la usa sin verla:

```bash
keyreeve-vault use netlify --reason "deploy" -- netlify deploy --prod
```

El comando recibe en su variable un reemplazo con la misma forma que la clave, y un proxy local pone la clave real solo en
las consultas que van a los servidores de ese proveedor. Si el reemplazo se manda a otro lado, no sirve. El cambio se hace en
los encabezados y en las contraseñas Basic. Si va en la dirección de un proveedor que la espera en un encabezado, el proxy lo
corta y responde dónde tiene que ir.

Por [MCP](https://modelcontextprotocol.io) (`keyreeve-vault mcp`) un agente como Claude Code o Codex tiene estas herramientas:

| herramienta | qué hace |
|---|---|
| `list_keys` | las claves que puede usar, las que tiene cerradas y los proveedores sin clave guardada |
| `use_key` | corre un comando con el reemplazo, a través del proxy |
| `run_with_key` | corre un programa que tú aprobaste, fijado por su SHA-256, con la clave real |
| `request_access` | te pide abrir una clave cerrada, o guardar una para un proveedor |
| `rotate_key` | te pide rotar una clave sellada |
| `inventory`, `propose` | leen la carpeta sin valores y proponen cambios para muchos archivos, si lo activas |

Para cada clave eliges un nivel. *Solo yo*, el que viene por defecto, deja fuera a los agentes. *Preguntar* te muestra el
comando y el motivo que da el agente, y decides con tu huella por una vez o por 1, 4, 8 o 24 horas. *Libre* pide la huella
una vez y después sirve hasta que cierres Keyreeve, un día como máximo. *Siempre, sin huella* sella una copia para una segunda
llave del chip que abre sin huella: déjalo para claves que solo leen. Una sesión se puede nombrar al partir, por ejemplo
`KEYREEVE_AGENT=ventas claude`, y entonces es `claude/ventas`.

Cerrar Keyreeve, **Cerrar todo** en la barra de menú o `keyreeve-vault revoke` terminan todos los permisos. Cada sí, cada no y
cada uso queda en `~/.keyreeve/audit.jsonl`, sin valores, con cada línea encadenada a la anterior para que una edición se note.

## Recetas

Todo lo de un proveedor vive en un archivo YAML, y la app no conoce a ningún proveedor por su nombre. Este es
[`recipes/github.yaml`](recipes/github.yaml):

```yaml
schema: 1
provider: github
name: GitHub
dashboard: https://github.com/settings/tokens
prefixes: [ghp_, github_pat_]
hosts: [api.github.com]
auth: { header: Authorization, prefix: "Bearer " }
verify: { method: GET, path: /user }
identify:
  request: { method: GET, path: /user }
  fields: { account: $.login, email: $.email }
suggested_name: "GitHub · {account}"
```

Una receta es solo datos y no puede correr código. Habla por HTTPS, solo con los servidores que declara, sin redirecciones,
y la clave va en el encabezado que nombra. Igual puede declarar un servidor que guarde lo que recibe, así que lee `hosts`
antes de usar una. keyreeve trae recetas para 33 proveedores, y 22 ya pasaron una prueba con una clave real. Para escribir
una, mira [CONTRIBUTING.es.md](CONTRIBUTING.es.md).

## Rotar una clave

Abres una clave sellada, dices dónde más se usa y cuánto debe durar la vieja, y aprietas **Rotar esta clave**. Con una huella,
keyreeve crea la clave nueva y la sella, la prueba, actualiza cada lugar donde se usa y revoca la vieja. Si algo falla antes
de revocar, deshace todo. Cada paso se anota antes en un registro, sin valores, para retomar o deshacer después de un corte.

## Lo que falta

- Una rotación probada contra un proveedor real
- Descargas listas, que necesitan la firma de Apple para la app
- La bóveda en Linux y Windows
- Otras bóvedas como almacenamiento, por ejemplo 1Password o el llavero del sistema
- Más recetas que sepan rotar

## Seguridad

[THREAT_MODEL.md](THREAT_MODEL.md) dice de qué protege y de qué no. keyreeve cuida claves y no es un sandbox: un programa que
corre con tu usuario puede hacer lo mismo que tú. Para reportar una vulnerabilidad, mira [SECURITY.md](SECURITY.md).

## Licencia

[MIT](LICENSE)
