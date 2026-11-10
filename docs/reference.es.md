# Referencia de keyreeve

Los detalles que el [README](../README.es.md) deja fuera. [English](reference.md)

Contenido: [Pruébalo sin conexión](#pruébalo-sin-conexión) · [La app para Mac](#la-app-para-mac) · [La bóveda](#la-bóveda-mac) ·
[Claves y agentes](#claves-y-agentes) · [Desde una terminal](#desde-una-terminal) · [Proveedores y recetas](#proveedores-y-recetas) ·
[Rotar una clave](#rotar-una-clave) · [Lo que falta](#lo-que-falta)

## Pruébalo sin conexión

Necesitas [Rust](https://rustup.rs). Esto corre sin conexión y no usa claves reales.

```bash
cargo install --git https://github.com/carlostapiacl/keyreeve
git clone https://github.com/carlostapiacl/keyreeve
cd keyreeve
keyreeve check examples/recipe.yaml
keyreeve simulate examples/recipe.yaml
```

`simulate` arma un proveedor falso a partir de la receta, le inyecta fallas y detiene el proceso en cada operación, y después
otra vez en cada operación de la recuperación. Tras cada detención revisa que:

- la clave guardada y cada servicio tengan una clave que funciona
- al cerrar la rotación, todos tengan la misma clave y no quede ninguna copia temporal
- cualquier clave sobrante en el proveedor se haya informado para limpiarla a mano
- ningún valor de clave haya llegado al diario, a un error o a un resultado

Que pase significa que la receta y el motor resisten frente al simulador. No prueba que el proveedor real se comporte
como la receta lo describe.

El CI prueba el comando en Linux y la app en macOS. Windows no se ha probado.

## La app para Mac

Una ventana nativa sobre tus claves, sin web por dentro, en inglés y español. Se compila con las Command Line Tools:

```bash
app/build-app.sh
ditto app/dist/Keyreeve.app /Applications/Keyreeve.app   # una vez, para tenerla junto a tus otras apps
open /Applications/Keyreeve.app
```

Cuando ya hay una copia en /Applications, cada compilación la actualiza también, y si Keyreeve estaba abierta se cierra antes y se
vuelve a abrir después, así ninguna copia antigua sigue corriendo junto a los archivos que escribe la nueva. La compilación no está
notarizada, así que macOS te avisa la primera vez.

La primera vez, aprieta **Trae tus claves** ([más abajo](#traer)), elige tu carpeta de claves, o **Empezar sin carpeta y pegar una clave** para partir con una bóveda vacía. La app se
abre con tu huella o con la contraseña de tu Mac, o sin ninguna de las dos si lo desactivas en Ajustes, ya que la lista no guarda
ningún valor. Este bloqueo cubre la ventana. Las claves las protege [la bóveda](#la-bóveda-mac).

Está ordenada por tarea. **Inicio** parte por lo que te necesita, cada cosa con su acción. **Mis claves** es la lista, con filtros
para claves archivadas y proyectos. **Por revisar** reúne lo que hay que mirar, y **Seguridad y respaldo**, la bóveda. **Agentes**,
**Proveedores**, **Rotación** y **Registro** quedan aparte, bajo Herramientas. La página de una clave tiene cuatro pestañas: Resumen,
Uso, Seguridad e Historial, con lo técnico detrás de "Más detalles y opciones".

**Probar todas**, en Inicio o en Mis claves, pregunta primero y después manda cada clave a su propio proveedor, seis a la vez como
máximo, con avance y un resumen. Una clave sin copia sellada cuyo archivo ya no está aparece como **No está en la bóveda**, aparte de
las claves cuyo proveedor no respondió. En Ajustes también puedes probar cada semana las claves marcadas "Se prueba sin preguntar",
lo que no pide huella y te avisa si una deja de funcionar. La prueba semanal lee archivos, así que una clave cuyo original salió de la
carpeta se salta ahí, y la pruebas desde la app.

Probar una clave la envía a una empresa, así que la app nunca adivina adónde: lo eliges tú, o lo demuestra el prefijo de la clave.
Una prueba es una sola consulta de solo lectura, las claves marcadas "Preguntarme" piden tu huella y las marcadas "Solo yo" no se
ofrecen. Tu huella dura 5 minutos por defecto, y bloquear la app la termina. En Ajustes están ese plazo, el idioma, la apariencia y el
bloqueo automático.

Junto a la lista puedes ponerle nombre a una clave y describirla, calificarla de 1 a 5 según lo grave que sería una filtración,
cambiar quién puede usarla y archivarla. Un nombre no renombra el archivo, así que nada de lo que usa el archivo se rompe. Archivar
oculta una clave y no la detiene, así que una clave archivada que todavía funciona mantiene un aviso. **Identificar** le pregunta al
proveedor de quién es la clave, guarda solo los campos que declara el archivo de ese proveedor y sugiere un nombre.

Para revocar una clave, abre la página del proveedor, revócala y aprieta "Ya la revoqué": la app vuelve a probar la clave, y el
aviso desaparece solo si el proveedor la rechaza. Una clave sin prueba disponible se marca a mano. "Ignorar 30 días" dura eso, y
después el aviso vuelve.

Una IA que ya usas en tu terminal, como Claude Code, Codex u OpenCode, puede ayudar con tu propia suscripción. Elegida en Ajustes,
redacta archivos de proveedor en **Proveedores** y, en **Ordenar claves**, propone un proveedor para las claves que keyreeve todavía
no puede probar. Recibe nombres de archivo, etiquetas y nombres de campo, nunca un valor, y la app lo dice cada vez. keyreeve nunca le
entrega una clave, pero Codex, OpenCode o un comando tuyo pueden leer archivos de tu Mac mientras trabajan. Claude Code queda limitado
a buscar en la web.

### Traer

**Trae tus claves** (en la primera pantalla, en **Seguridad y respaldo**, o en Archivo > Traer claves…) busca claves y sella las que
elijas, en una sola pantalla:

- **Dónde buscar.** *Lugares típicos de este Mac*: `~/.aws`, GitHub CLI, gcloud, `~/.netrc`, `~/.npmrc`, `~/.pypirc`, Docker, las
  líneas `export` de los archivos de inicio de tu shell y tus llaves SSH (solo se lee su primera línea), más los `.env` de las
  carpetas de proyectos que marques. *En toda mi carpeta de inicio*: toda, buscando archivos `.env` y archivos cuyo nombre o inicio
  dice que tienen una clave (`.pem`, `.p12`, `.key`, notas llamadas `api-key.txt`, un `.txt` o `.json` que parte con el prefijo de un
  proveedor); los demás archivos no se abren. Se salta Librería, la Papelera, las bibliotecas de fotos y música, iCloud Drive, las
  apps y los archivos grandes, se detiene a los dos minutos y te dice qué carpetas no terminó, con **Buscar en esas** para seguir.
  macOS puede pedirte permiso antes de leer Escritorio, Documentos y Descargas. O *Elegir una carpeta*. Se salta `node_modules`,
  `.git`, compilaciones y cachés, y no necesita Acceso total al disco.
- **Qué hace.** Separa cada archivo en piezas, dice qué es cada una (clave, configuración, usuario y clave, documento o llave
  pública), junta las partes de una clave (client id y secreto, las tres de Google, una access key con su secreto y el endpoint como
  servidor) y une la misma clave encontrada en dos lugares. Una clave solo se prueba con el único proveedor que indica su
  prefijo, el nombre de su variable o su client id; un nombre que solo menciona un proveedor se muestra como sugerencia y no envía nada.
- **Revisar.** Los valores siguen tapados. Las que funcionan quedan elegidas, las muertas no, la configuración y las llaves públicas
  nunca se sellan, y tú decides solo las dudosas.
- **Sellar.** Una huella. Cada clave queda con identificador y sin ofrecer a los agentes. Con un clic puedes ofrecer las que ya usa
  el `.env` de un proyecto. Los archivos originales nunca se mueven, cambian ni borran; de dónde vino cada clave queda guardado
  con su copia.

### Agregar una clave

**Agregar clave** (el **+** de la ventana, o la barra de menús) lee el portapapeles, reconoce el proveedor por cómo empieza la clave
y la sella sin dejar archivo en el disco. La clave nunca se muestra, solo su inicio conocido y su largo, y el portapapeles se borra.
Un enlace abre la página del proveedor donde se crean las claves. Ponle un nombre con tus palabras; su identificador, para scripts y
agentes, se arma a partir de ese nombre y se muestra antes de guardar. Una clave sin proveedor conocido también se guarda y se puede
copiar: se prueba o se usa a través del proxy cuando eliges su proveedor.

### Cuando una clave vence

Muchas claves terminan en una fecha: un token creado por 90 días, un token de usuario que dura 60. Escribe la fecha en **Vence**, bajo
**Más detalles y opciones** en una clave, o deja que un agente la entregue con `propose`. Un proveedor que lo indica la completa al
identificar la clave, como hacen GitHub y Cloudflare. Dos semanas antes, la clave pasa a **Por revisar** con los días que le quedan;
cuando la fecha ya pasó, lo dice hasta que se renueva. **Vencen pronto** muestra las claves que terminan dentro de treinta días, y los
agentes ven la fecha en `inventory`.

### La barra de menús

Keyreeve se queda en la barra de menús con la ventana cerrada. El ícono cuenta las solicitudes pendientes. Su menú las muestra, junto
con lo que los agentes tienen ahora y hasta cuándo, los últimos usos y **Bloquear todo**: termina todos los permisos, bloquea la
ventana y pausa a los agentes, así que cada solicitud se rechaza sin ventana hasta que aprietes **Reanudar agentes**.

**Copiar la clave**, en una clave sellada, la deja en el portapapeles después de tu huella. Va marcada para que las herramientas de
historial del portapapeles la omitan, y se borra a los 60 segundos, o cuando bloqueas la app, salvo que para entonces hayas copiado
otra cosa.

## La bóveda (Mac)

En la app, abre **Seguridad y respaldo** y aprieta **Crear mi bóveda**. Muestra una clave de recuperación una sola vez, y no guarda
nada hasta que escribes sus últimos 6 caracteres. Guarda esa clave lejos de este Mac, porque si el Mac muere es la única forma de
volver a entrar.

Después elige claves y aprieta **Sellar**. Cada archivo se sella para una llave dentro del Secure Enclave de tu Mac, de donde no puede
salir, y para la clave de recuperación. Tus archivos originales se quedan donde están. **Comparar con los archivos** abre cada copia
sellada y te dice si coincide. Desde ahí, las pruebas, la identificación y tus propias acciones usan la copia sellada, y piden tu dedo
una vez por lote. Los archivos binarios, como un `.pfx` o un `.jks`, también se pueden sellar.

Si un archivo cambia después de sellarlo, la app lo dice y usa el archivo, porque la copia sellada puede ser una clave antigua.
**Sellar de nuevo los archivos que cambiaron** reemplaza la copia, y la antigua sigue sellada. Después de una comparación, puedes mover
los archivos que coincidieron fuera de la carpeta de claves a `~/.keyreeve/originals`. Ahí siguen legibles, la lista los sigue
mostrando y puedes devolverlos. keyreeve nunca los borra, así que ese paso es tuyo cuando confíes en la bóveda. Una clave sellada cuyo
archivo borras a mano también sigue en la lista, y si la carpeta de claves entera desaparece, la app lo dice y conserva lo que tiene la
bóveda.

**Copiar la bóveda…** guarda el archivo sellado de la bóveda en una carpeta que eliges, sin huella. En otro Mac, deja ese archivo en
`~/.keyreeve/vault/vault.json` y corre `keyreeve-vault recover` con tu clave de recuperación. `keyreeve-vault backup <folder>` hace lo
mismo desde una terminal, y `keyreeve-vault check-recovery <backup>` comprueba que un respaldo se abre con tu clave de recuperación.

La misma bóveda funciona desde una terminal:

```bash
app/dist/keyreeve-vault init
app/dist/keyreeve-vault add hosting-token
app/dist/keyreeve-vault run hosting-token --as HOSTING_TOKEN -- ./deploy.sh
```

`put <name>` agrega una clave, o para una que ya está deja un valor nuevo esperando ([más abajo](#cómo-entran-las-claves)), y
`reseal <name>` vuelve a sellar el archivo de una clave tal como está ahora, desde la carpeta de donde se selló, para un archivo que cambió un script. Agregar una clave no pide huella, así que un agente
puede guardar una clave que después no puede leer. Usarla pide tu dedo. `init` se niega a correr fuera de una terminal para que la clave
de recuperación no termine en un log. Ningún comando imprime una clave, y la app copia una solo cuando aprietas su botón.

Una copia sellada desde la app guarda el archivo completo, así que `run` le entrega a un programa todo lo que contiene. Para un archivo
con varios valores, usa `env` (más abajo) y nombra el campo.

### Cómo entran las claves

Toda entrada deja el mismo rastro: el **+** de la app, Traer, **Sellar**, una petición respondida con **Guardar y permitir**, y desde una
terminal `add`, `put` y `reseal`. Cada clave recibe un registro en `keys.toml`, hecho a partir de su nombre (`added/openai-prod` es
`openai-prod`, con un número si ya está tomado), con `added_by` y `added_at`. No se ofrece a los agentes, así que `list_keys` y
`keyreeve-vault list` no la muestran. El registro de uso nombra a quien la agregó como nombra cualquier otro evento: el programa y sus
padres según el sistema, y el agente cuando el árbol de procesos o `KEYREEVE_AGENT` lo nombran. La app y `keyreeve-vault` escriben
`keys.toml` con un mismo candado, y cada uno lo lee como está y escribe solo su propio cambio, así que una clave que un agente agrega
con la ventana abierta nunca se pierde por una edición en la app, y la ventana la muestra en pocos segundos.

```bash
pbpaste | keyreeve-vault add added/openai-prod --description "OpenAI, producción" --tags trabajo,ia
keyreeve-vault orphans    # nombres de la bóveda sin registro en keys.toml
```

Una clave que agregó algo distinto de ti en la app lleva `reviewed = false`. **Mis claves** la muestra bajo **Nuevas, sin revisar**,
y la barra de menús y **Agentes** dicen "claude agregó 21 claves". En la página de la clave la miras, la nombras y aprietas **Marcar
como revisada**. Nada de eso la ofrece: eso sigue siendo **Ofrecida a los agentes**, en **Uso**.

`put` sobre una clave que ya está sella el valor nuevo como `<name>#pending`, el mismo nombre que usa una rotación para su clave nueva,
y la clave conserva el valor que tenía. La app dice "Hay un valor nuevo para X esperando, de claude". **Aceptar el valor nuevo** pide tu
huella y deja el valor anterior sellado como historial; **Descartarlo** bota el nuevo. Un `put` más nuevo reemplaza a un valor que
todavía espera. Mientras una rotación de esa clave está abierta, se rechaza el `put` de cualquier otro, y el motor, que corre como
`keyreeve-cli rotate`, sigue escribiendo sus copias y dejando la clave nueva en su lugar como antes. Una rotación no parte mientras un
valor espera.

Una entrada de la bóveda sin registro, como una que selló una versión anterior, aparece como **Sellada sin registro**, con **Darle un
identificador**, sin ofrecer. En un `keys.toml` escrito por `keyreeve migrate` (schema 2) eso es cualquier entrada; antes, solo las
claves sin archivo en la carpeta de claves, porque un archivo de ahí tiene su propia línea en la lista.

### Tus claves no dependen de esta herramienta

Cada clave sellada es un archivo [age](https://age-encryption.org) estándar, y la clave de recuperación es una clave age común. Con solo
la bóveda y el comando `age`, en cualquier computador:

```bash
keyreeve-vault export hosting-token --recovery | age -d -i recovery-key.txt
```

La primera línea de lo que sale nombra la clave, y el resto es su valor. Las claves del chip usan el destinatario `p256tag` de age. El
formato de archivo es público y lo usan otras herramientas, y aquí se prueba contra el oficial en ambas direcciones. El código que lo
escribe es mío y no ha tenido revisión externa.

## Claves y agentes

Cada clave tiene un identificador, separado de su archivo: `netlify`, `mail-shop`. Un archivo con varios valores puede tener varios, y
renombrar o mover un archivo no rompe nada de lo que usa uno. Un identificador también puede decir de quién es la clave, su `account`,
que distingue varias claves de un mismo proveedor. Viene del proveedor cuando su archivo puede preguntarlo, y de ti cuando no, y el
aviso de huella lo muestra.

### keys.toml

`~/.keyreeve/keys.toml` dice qué es cada clave: su identificador, el archivo de donde salió, proveedor, campo, cuenta, descripción,
nivel, servidor, la fecha en que termina y si está archivada. No guarda ningún valor. Un archivo con `schema = 2` contiene todas las
claves, y la lista de la app lo lee.

```bash
keyreeve migrate ~/.keyreeve --dry-run   # lo que escribiría
keyreeve migrate ~/.keyreeve
```

`migrate` escribe ese archivo a partir de lo que keyreeve sabía antes: las reglas, las ediciones de la app, lo que dijeron los
proveedores y los identificadores que tenías. Los identificadores mantienen su nombre y solo ganan lo que les faltaba. Cada otro archivo
recibe un identificador propio, no ofrecido a los agentes. Antes, una copia de cada archivo que lee va a una carpeta nueva bajo
`~/.keyreeve/backups`, y correrlo dos veces no cambia nada.

### Ofrecida a los agentes

Una clave está ofrecida a los agentes o no. Los agentes, `list_keys`, `request_access`, `use_key`, `run_with_key` y
`keyreeve-vault use` solo ven las claves ofrecidas. Una clave no ofrecida responde como un nombre que no existe. En `keys.toml` lleva
`offered = false`.

Una clave que agregas con **+**, o un identificador que agregas a mano en la página de una clave, queda ofrecida. Los identificadores
dados en bloque, con **Darles identificador** en **Agentes** o con `keyreeve migrate`, no. Para ofrecer una, abre su página, ve a
**Uso** y marca **Ofrecida a los agentes**. Darle a una clave un nivel, un programa o un permiso también la ofrece. Desmarcarla cierra
la clave: se van su nivel, los agentes a los que estaba abierta y los programas permitidos con ella.

```bash
keyreeve-vault list
keyreeve-vault use netlify --reason "deploy" -- netlify deploy --prod
keyreeve-vault grants
keyreeve-vault revoke
keyreeve-vault audit --key netlify
keyreeve-vault audit --verify
```

`use` corre un comando con una clave, y el comando nunca la tiene. Su variable tiene un reemplazo con la misma forma, y un proxy local
pone la clave real en las consultas a los hosts de ese proveedor, que salen de su archivo. `printenv` muestra el reemplazo, y enviado a
cualquier otro lado no sirve. Tu dedo se pide una vez para esa clave con ese programa, y el permiso dura 5 minutos salvo que `--for`
diga otra cosa. Un pequeño servicio lo mantiene, y se detiene solo cuando no tiene trabajo. Salir de la app termina todos los permisos.
La variable sale del archivo del proveedor, o de `--as`.

El cambio ocurre en los encabezados y en las contraseñas Basic, y en la dirección para un proveedor que recibe ahí su clave. Un
reemplazo en la dirección de un proveedor que la recibe en un encabezado se detiene en el proxy, con una respuesta que dice dónde va.
Un cuerpo mantiene el reemplazo, así que una herramienta que manda su clave en un cuerpo falla y no filtra nada. Una respuesta que
repite la clave recibe de vuelta el reemplazo. Los demás hosts reciben un túnel, con TLS de punta a punta. El reemplazo es lo que
permite que una consulta use la clave, así que nada más necesita estar en el entorno del comando.

Una clave SSH funciona igual, con `provider = "ssh"` en `keys.toml` o un archivo de proveedor que use `auth: { type: ssh }`:

```bash
keyreeve-vault use vps --reason "restart" -- ssh root@my-server uptime
keyreeve-vault use deploy-key -- git push
```

El comando recibe `SSH_AUTH_SOCK`, que apunta a una puerta frente al `ssh-agent` del propio sistema, que tiene la clave mientras dure
el permiso. La puerta deja pasar el listado y la firma y nada más, así que la clave no se puede leer, reemplazar ni usar para firmar un
archivo o un commit. OpenSSH le dice al agente para qué servidor es cada conexión, así que el permiso cubre el primer servidor y cada
uno de los demás pide tu dedo. Cada firma queda en el registro con el usuario y la huella del servidor. Una clave con passphrase la
pide en un diálogo cuando se abre el permiso.

Para permitir solo los servidores que nombres, lista sus huellas, como las muestran `ssh-keygen -lf` o el registro de uso. Con una
lista no hay primer servidor libre:

```toml
[[key]]
id = "vps"
source = "vps-key"
provider = "ssh"
servers = "SHA256:abc... SHA256:def..."
```

`ssh`, `scp` y `sftp` reciben opciones que mandan sobre tu `~/.ssh/config` y ofrecen esta clave primero. `git` y `rsync` reciben lo
mismo a través de `GIT_SSH_COMMAND` y `RSYNC_RSH`, salvo que tú mismo las definas. Cualquier otro programa usa `SSH_AUTH_SOCK` y tu
configuración.

`keyreeve-vault grant vps --for 1h` abre un permiso por adelantado, así el trabajo de un agente no se detiene a preguntar. Una clave
que no es SSH lleva `--program`, ya que su permiso es para un programa. La app hace lo mismo desde la página de una clave, muestra lo
que está vigente y el uso reciente de la clave, y puede terminarlo.

Una credencial OAuth, como el archivo `authorized_user` de Google con un client id, un client secret y un refresh token, funciona
igual. Su variable tiene la ruta de una copia privada del archivo con reemplazos para el secreto y el refresh token, y el client id
real, que no es secreto (`GOOGLE_APPLICATION_CREDENTIALS` para Google). Cuando la biblioteca del comando le pide un token de acceso
al host de tokens, el proxy le responde por su cuenta, con un reemplazo, y nunca reenvía esa consulta. Consigue el token de acceso
real del proveedor por su cuenta, lo guarda hasta poco antes de que venza y lo pone en las consultas a los hosts de la receta que
llevan el reemplazo. Una consulta de token con cualquier otra cosa se rechaza. Si el proveedor responde `invalid_grant`, no se
vuelve a intentar, y la app muestra la clave como que hay que autorizarla de nuevo, como una clave vencida, hasta que la
reemplaces. Así funcionan las bibliotecas que hablan HTTP/1.1 por `HTTPS_PROXY`, como google-auth de Python y el cliente de APIs de
Google. Los clientes gRPC no.

```bash
keyreeve-vault use search-console --as GOOGLE_APPLICATION_CREDENTIALS -- python3 informe_semanal.py
```

`--real` le entrega al comando la clave real, para lo que no puede usar un reemplazo, como un proveedor que firma las consultas o un
script tuyo. Pide tu dedo cada vez y queda registrado aparte. Un comando que manda un reemplazo saltándose el proxy, o que ignora sus
variables, simplemente no logra autenticarse.

Cada decisión queda en `~/.keyreeve/audit.jsonl`: qué clave, qué permiso, el proceso y sus padres según los informa el sistema, y
aparte de eso lo que quien llama dice de sí mismo. No guarda ningún valor ni argumentos. Cada línea lleva el hash de la anterior, así
que `--verify` encuentra una edición. Otro programa que corra como tú podría reescribir la cadena entera, así que esto detecta cambios
y no los impide. La cadena de procesos es una pista de quién pidió, y no una prueba.

Un archivo env puede tener referencias en lugar de valores, así que se puede dejar en un repositorio sin riesgo:

```bash
# app.env
HOSTING_TOKEN=keyreeve://hosting
MAIL_KEY=keyreeve://mail-shop
LOG_LEVEL=info
```

```bash
keyreeve-vault env app.env -- ./deploy.sh
```

Una huella las abre todas para ese comando.

### Varias claves a la vez

```bash
keyreeve-vault use meta-ads,calcom,sentry -- python3 reporte.py
keyreeve-vault use --set reporte-semanal --as calcom=CAL_KEY -- python3 reporte.py
```

Cada clave va en su propia variable. Una ventana las muestra con el programa, la carpeta y el motivo: desmarcas las que no quieras,
eliges 5 minutos, hasta que termine, un día, o siempre para este programa en esta carpeta, y pones una huella. Los usos sueltos de un
mismo script que llegan dentro de dos segundos comparten esa ventana.

*Siempre* queda atado a la ruta y el SHA-256 del programa, al script que corre cuando su primer argumento es un archivo, y a la
carpeta. Se sella una copia de cada clave para la llave del chip que no pide nada, como en *Siempre, sin huella*, así un script que
corre el lunes a las 9:00 no necesita a nadie. Un programa o script cambiado, otra carpeta o una clave agregada después vuelve a
preguntar. Se quita en **Agentes**, en **Conjuntos de claves**.

Un conjunto es un nombre para una lista de claves, que se arma en la app en **Agentes**: a mano, o con **Armar un conjunto con lo que
usó este proyecto**, que sugiere las claves que usó una carpeta y un programa en la última hora. Los conjuntos viven en
`~/.keyreeve/sets.toml`. Un conjunto por sí solo no permite nada y solo lista claves ofrecidas a agentes. Ninguna herramienta de los
agentes crea uno.

### Agentes por MCP

Un agente puede usar claves por [MCP](https://modelcontextprotocol.io) con `keyreeve-vault mcp`. La sección **Agentes** de la app
muestra si Claude Code está conectado, copia el comando que lo conecta en todas las carpetas y lista cada clave sellada ofrecida a los
agentes con dos opciones:

- **Nivel.** *Solo yo*, el valor por defecto, deja fuera a los agentes. *Preguntar* muestra una ventana con la clave, el comando y el
  motivo del agente en sus propias palabras, donde eliges **Solo esta vez**, 1, 4, 8 o 24 horas, o **No permitir**, y después confirmas
  con tu dedo. *Libre* pide tu dedo una vez y después cubre cualquier comando hasta que salgas de Keyreeve, por un día como máximo.
  *Siempre, sin huella* pide tu dedo una vez, para sellar una copia de la clave para una segunda llave del chip que se abre sin huella,
  y desde ahí los agentes la usan a través del proxy sin preguntar, también después de reiniciar. Un agente puede pedirlo con `request_access`, pero solo tú lo activas, en la app;
  la clave real, `run_with_key` y `get` siguen preguntando. Úsalo solo para claves de lectura.
- **Agentes.** Cualquier agente, o solo Claude o solo Codex. El agente se identifica por el proceso que inició el servidor, lo que es
  una pista fuerte y no una prueba, ya que todo corre como tú. Una sesión puede nombrarse a sí misma si arranca con `KEYREEVE_AGENT`
  definido, como `KEYREEVE_AGENT=sales claude`, y entonces es `claude/sales`: una clave abierta a `claude` la atiende como antes, y una
  abierta a `claude/sales` atiende solo a esa sesión.

Las herramientas que recibe un agente:

| herramienta | qué hace |
|---|---|
| `list_keys` | las claves que puede usar, las que tiene cerradas y los proveedores para los que todavía no tienes clave |
| `use_key` | corre un comando con un reemplazo, a través del proxy, así la clave real solo llega a su proveedor |
| `run_with_key` | corre un programa que permitiste, fijado por su SHA-256, con la clave real en una variable |
| `request_access` | te pide abrir una clave cerrada, o guardar una para un proveedor |
| `rotate_key` | te pide rotar una clave sellada |
| `inventory`, `propose` | leen la carpeta sin valores y proponen cambios para muchos archivos, cuando lo activas |
| `find_keys` | busca claves en toda tu carpeta de inicio, en los lugares típicos o en carpetas, sin valores y sin probar nada con el proveedor |
| `propose_bring` | propone cuáles sellar de las encontradas, para que la revises en Traer y selles con una sola huella |

`use_key` funciona con cualquier comando, incluido `curl`. Una clave SSH inicia sesión a través de keyreeve. Una clave sin proveedor
solo puede ir a un programa que permitas con `run_with_key`: si el archivo cambia, se rechaza hasta que lo vuelvas a permitir. Las
shells, los intérpretes, `curl`, `env` y otros parecidos no se pueden permitir de esa forma. Una ejecución se detiene a los 2 minutos,
y su salida nunca muestra la clave ni el reemplazo.

El servidor de un agente que encuentra instalada una Keyreeve más nueva se convierte en ella en su siguiente mensaje, en el mismo
proceso y la misma conexión, así una sesión sigue con la versión nueva sin empezar de nuevo.

Salir de Keyreeve, `keyreeve-vault revoke`, **Cerrar todo** en la barra de menús o **Que vuelvan a pedir** terminan todos los permisos
dados a los agentes. Bloquear la ventana solo oculta tus claves, así el trabajo de un agente no se detiene cuando dejas de mirar. Las
opciones viven en `~/.keyreeve/agents.toml` ([ejemplo](../examples/agents.toml)), que el servidor lee en cada solicitud, así que un
cambio cuenta sin reiniciar el agente. Un archivo con un error no permite nada. Cada sí, no y rechazo queda en el registro de uso con
el motivo del agente. La ventana muestra el comando completo antes de que elijas, y **Terminal de agentes**, en la misma sección,
muestra cada comando que un agente corrió con una clave, su código de salida, cuánto tardó y los primeros 2.000 caracteres de lo que
devolvió, guardados en `~/.keyreeve/agent-runs.jsonl`.

### Cuando un agente pide una clave

Con `request_access` el agente pide una clave, dice para qué y sugiere por cuánto tiempo. Te aparece una ventana: **Permitir** por 1,
4, 8 o 24 horas o siempre, o **No permitir**. Después de un sí, la clave queda libre para ese agente solamente, con una huella y sin más
preguntas, hasta que se cumpla el plazo. Un no hace que ese agente no vuelva a pedirla en su sesión. Una clave ya abierta a otro agente
no se vuelve a abrir con condiciones nuevas: agregas el segundo agente en **Agentes**.

Un agente que necesita varias claves manda `keys` en vez de `key`. Las ves en una sola ventana, desmarcas las que no quieras y una
huella abre el resto, así su siguiente `use_key` no pregunta nada.

Cuando el agente pide un proveedor cuya clave no está guardada, la solicitud espera en la app. Elige el archivo que la tiene y aprieta
**Guardar y permitir**: se sella, se nombra y se abre a ese agente en un solo paso. Sin archivo, **Pegar una nueva** recibe una clave
que copias del proveedor. Si el agente sabe a qué cuenta debería pertenecer la clave, lo dice con `account`, y el archivo que coincide
aparece primero.

### Cuando un agente pide rotar una clave

Con `rotate_key` un agente pide rotar una clave sellada y dice por qué: se filtró, es antigua o se lo pediste tú. La solicitud espera en
**Agentes** con el destino de la clave nueva, que es lo que definiste en la pestaña **Seguridad** de la clave: el agente no puede
elegirlo. Para un proveedor sin forma de crear claves desde aquí, creas la nueva en su página y la pegas en la solicitud. **Rotar esta
clave** pide tu huella, y el agente sabe cómo salió cuando vuelve a preguntar. Nunca ve ninguna de las dos claves. Un destino puede ser
un botón tuyo que recibe la clave nueva por stdin, como un archivo env en un servidor por ssh (`examples/places/ssh-env.sh`).

### Cuando un agente ordena la carpeta entera

Activa **Los agentes pueden ordenar mis claves** en **Agentes**, y un agente puede leer, con `inventory`, el nombre de cada archivo,
los nombres de sus campos, el proveedor y el estado, y los proveedores que keyreeve conoce. Nunca un valor, y nada en absoluto mientras
el interruptor está apagado. Con `propose` manda cambios para muchos archivos a la vez: qué proveedor y campo, nada que probar, un
secreto interno, nada secreto, qué es, si sellarlo, probarlo o archivarlo, el servidor de un proveedor que corres tú mismo, la fecha
en que vence y si dividir un archivo que tiene varias claves de un mismo proveedor. Esperan en **Agentes** como una sola lista, con
cada cambio marcado de entrada. **Aplicar** se queda con los marcados, prueba los que corresponde, lo que puede pedir tu huella, y
sella el resto. El agente lee cómo salió en su siguiente `inventory`. Una carpeta de archivos sueltos termina como claves con nombre,
probadas y selladas, que tus agentes usan con `use_key`.

Un servidor que sugiere un agente se guarda pero no queda aprobado. La página de la clave lo dice, y **Aprobar … y probar** lo aprueba
después de que confirmas y prueba la clave ahí.

### Cuando un agente trae tus claves

Pídele a un agente "busca todas mis claves y sella las que corresponda". Con `find_keys` corre lo mismo que [Traer](#traer), sin
probar nada. `where` es `everywhere` (toda la carpeta de inicio), `places` (los lugares típicos, y los `.env` de las carpetas
`projects` que indique) o `folders` (solo esas, igual que en todas partes). Si a `everywhere` se le acaba el tiempo, `unfinished`
nombra las carpetas que faltan y el agente sigue con `where: "folders"`. Recibe cada clave
y cada usuario con clave por número, con su archivo y línea, los nombres que tiene, su proveedor (solo con evidencia fuerte) o una
sugerencia, si apareció dos veces y si parece ya sellada, según el lugar y nunca según el valor. La configuración, los documentos y
las llaves públicas solo se cuentan. Ningún valor y ninguna consulta a un proveedor.

Con `propose_bring` indica los números que hay que sellar, con un identificador, una descripción y etiquetas si quiere, y los que hay
que omitir con un motivo. Un número que no salió de una búsqueda, o un proveedor que keyreeve no conoce, rechaza la propuesta entera.
La propuesta espera en **Agentes**. **Revisar** busca de nuevo donde buscó el agente, prueba cada clave con su propio proveedor como
lo hace Traer y abre la revisión con lo que eligió el agente marcado. Cambia lo que quieras, o desactiva sus nombres, y **Sellar** con
una sola huella. El proveedor que nombra el agente solo se muestra: la clave se guarda con el proveedor que indica su propia
evidencia. Las claves selladas reciben identificador y no se ofrecen a los agentes, así que el agente no las ve en `list_keys` y
solo tú puedes ofrecerlas. El agente sabe cuántas se sellaron, nunca cuáles.

### Un registro para todo

```bash
keyreeve-vault log --since 7d            # una línea JSON por evento, la más antigua primero
keyreeve-vault log --key resend --csv    # para una planilla
```

Junta el registro de uso, lo que corrieron los agentes, cada prueba de una clave y tus propios usos, con nombres en lugar de rutas de
archivo. Cada decisión que tomas en la app también queda ahí: un nivel cambiado, una solicitud respondida, una pausa. Ninguno guarda
valores. En el **Registro** de la app, una consulta o un uso que se repite, como un bot que consulta cada treinta segundos, es una
sola fila con la cuenta; el archivo guarda cada línea.

### Con seisin

[seisin](https://github.com/carlostapiacl/seisin) le da a cada agente sus propias carpetas y claves, y toma una clave de cualquier
comando que la imprima. `keyreeve-vault get` es ese comando: imprime la clave real después de tu huella, cada vez, y lo registra.

```toml
# seisin.toml
[keys.providers.keyreeve]
command = ["/path/to/keyreeve-vault", "get", "{ref}"]

[network]
allow = ["api.resend.com"]

[roles.mailer]
keys = ["RESEND_API_KEY=keyreeve://resend"]
key_mode = "env"
```

El rol recibe la clave en su entorno y solo puede llegar a los dominios que listes. seisin la oculta en la salida, y ningún archivo la
guarda en el disco. Aquí el rol tiene la clave real, así que prefiere `use` y el proxy donde sea que el agente corra fuera de seisin.

## Desde una terminal

El comando `keyreeve` funciona en cualquier sistema con Rust, y no necesita ni la app ni la bóveda.

### Mira lo que tienes

`keyreeve bring` es lo que corre Traer en la app. Muestra cada clave que encuentra, qué es, su proveedor y si funciona, y nunca un
valor ni un cambio a un archivo. Una clave solo se envía al único proveedor que indica su prefijo, su variable o su client id:

```bash
keyreeve bring --places --projects ~/code --dry-run   # busca, no prueba nada
keyreeve bring --folder ~/mis-claves                  # busca y prueba cada clave con una consulta de solo lectura
keyreeve bring --everywhere --dry-run                 # toda la carpeta de inicio, en dos minutos como máximo
keyreeve bring --everywhere --under ~/code --dry-run  # sigue en una carpeta que no terminó
```

Con `--json` sale el informe que lee la app: rutas, nombres, líneas y dónde está cada valor en su archivo.

Si tus claves viven en una carpeta de archivos de texto, también puedes partir aquí. Ninguno de los dos comandos cambia un archivo.

```bash
keyreeve inventory ~/my-keys --out ~/.keyreeve/inventory.json
keyreeve catalog ~/.keyreeve/inventory.json --rules ~/.keyreeve/rules.yaml --history ~/.keyreeve/history.jsonl --edits ~/.keyreeve/edits.json --out ~/.keyreeve/catalog.csv
```

`inventory` describe cada archivo: nombre, fecha, permisos, formato, etiquetas y el tipo de clave, reconocido por su prefijo. Lee
archivos `.env`, JSON y notas sueltas con `=`, `:`, `=>`, `|` o tabulaciones, en cualquier mezcla. Lo que va después de un separador se
ignora. De los comentarios y notas guarda solo palabras de una lista cerrada, como `token` o el nombre de un proveedor, y una etiqueta
con cualquier otra palabra se cuenta pero no se muestra. Para permitir tus propias palabras, como nombres de proyectos, pasa `--words`
con un archivo de una palabra por línea.

`catalog` le da a cada archivo etiquetas y un nivel de acceso según [tus reglas](../examples/rules.yaml), y te dice qué archivos no
cubren. Lee solo el inventario, así que nunca abre un archivo de claves.

Los valores quedan fuera de ambos, así que puedes pasárselos a un agente que no debe ver tus claves. Los nombres de archivo y las
etiquetas sí entran, así que mantenlos privados. Se escriben con modo 600. Una contraseña en mayúsculas puesta antes de un separador se
leería como nombre de variable, y un archivo con el nombre de un secreto mostraría ese nombre.

### Prueba si una clave todavía funciona

```bash
keyreeve recipes
keyreeve verify hetzner --key-file ~/my-keys/hetzner.txt
keyreeve verify github --key-file ~/my-keys/app.env --field GITHUB_TOKEN
keyreeve verify --plan ~/.keyreeve/plan.yaml --keys ~/my-keys
```

Cada prueba es una sola consulta GET, así que no puede cambiar nada. Un proveedor que usa OAuth primero cambia la clave por un token,
con un POST que lleva las credenciales. Imprime el resultado y nunca la clave. Un plan lista muchas claves a la vez:

```yaml
keys:
  - { file: hetzner.txt, recipe: hetzner }
  - { file: app.env, recipe: github, field: GITHUB_TOKEN }
```

Una clave rechazada puede seguir viva para otros usos: un token restringido puede fallar una prueba para la que no tiene permiso. Que
pase dice que la clave funciona, y no lo que puede hacer.

## Proveedores y recetas

Todo lo de un proveedor vive en un archivo, y la app no conoce ningún proveedor por su nombre. Una receta que solo prueba claves se ve
como [`recipes/github.yaml`](../recipes/github.yaml):

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

Para rotar, también dice cómo crear y revocar una clave:

```yaml
create:
  method: POST
  path: /v1/keys
  body: { name: "{key_name}" }
  value_from: $.secret
  id_from: $.id
revoke: { method: DELETE, path: "/v1/keys/{id}" }
```

Una receta corre con una credencial que puede crear claves, así que una receta maliciosa podría intentar robarla. Por eso una receta
es datos y no tiene forma de ejecutar código. Las consultas van por HTTPS, solo a los hosts que lista, con las redirecciones
desactivadas. La credencial va en el encabezado que nombra la receta y nunca va en un cuerpo. Solo una receta con
`auth: { type: url }` la pone en la dirección, con `{key}`, para proveedores que no la reciben de otra forma. Igual puede elegir el encabezado equivocado, o listar un host que guarda lo que recibe, así que lee `hosts` antes
de usar una.

keyreeve trae recetas para 33 proveedores en [`recipes/`](../recipes). La línea `tested` de un archivo dice cuándo pasó por última vez
una prueba con una clave real: 22 lo han hecho. Pon las tuyas en `~/.keyreeve/providers/` y funcionan sin compilar de nuevo, una vez
que apruebas los hosts que listan, en Ajustes o con `keyreeve recipes approve <name>`. Cambiar sus hosts deshace la aprobación, y un
archivo no puede reemplazar a uno de los que vienen incluidos. Para compartirla con todos, abre un pull request.
[CONTRIBUTING.es.md](../CONTRIBUTING.es.md) explica cómo escribir una.

Un archivo también puede declarar:

| campo | qué hace |
|---|---|
| `auth: { header }` | manda la clave en un encabezado. El caso habitual |
| `auth: { type: url }` | pone `{key}` en la dirección, para proveedores sin otra forma, como Telegram |
| `auth: { type: basic }` | HTTP Basic |
| `auth: { type: oauth_token }` | cambia dos o tres campos por un token de corta duración, como Google o PayPal. `token_host` está en `hosts`, y los otros hosts son las APIs a las que un comando puede llegar con él. `client_id_ends` reconoce un archivo de credenciales pegado |
| `auth: { type: aws_sigv4 }` | firma cada consulta, así el secreto nunca viaja. AWS y R2 |
| `auth: { type: ssh }` | saluda a un servidor con una clave SSH a través del `ssh` del sistema, como una deploy key de GitHub |
| `self_hosted: true` | cada persona indica su propio servidor, aprobado de a uno, siempre por HTTPS |
| `prefixes` | encuentra la clave dentro de un archivo de notas, y se niega si hay dos |
| `alive_if` | un rechazo que aun así demuestra que la clave sigue viva, como una clave restringida |
| `fields` en `identify` | `$.path`, `header:name`, `token:name` o `reply:`. `$.*.slug` guarda cada elemento de una lista, como cada organización a la que llega un token. Llámalos `scopes` o `expires` para decir qué puede hacer una clave y cuándo termina |
| `also` en `identify` | hasta tres consultas GET más que solo agregan campos que faltan, como el vencimiento de Cloudflare |
| `rotate_every_days` | una antigüedad sugerida, que se muestra como "más antigua de lo sugerido" |
| `criticality_hint` | una calificación de 1 a 5, que se muestra atenuada hasta que confirmas la tuya |

Una receta `self_hosted` necesita primero tu servidor. Escribirlo en la app lo aprueba.

### Tus propias pruebas y botones

Para lo que un archivo no puede describir, un archivo tuyo puede correr un programa tuyo. Mira [`examples/providers`](../examples/providers).
Los archivos genéricos los comparten todos, y los tuyos se quedan en tu carpeta:

```yaml
auth:
  type: command
  run: { program: my-service-check.sh }
actions:
  - id: open-runbook
    label: Open the runbook
    open: https://example.com/runbook
  - id: restart-worker
    label: Restart the worker
    run: { program: my-service-check.sh, args: [--restart] }
    needs_key: true
```

El programa recibe la clave por stdin y responde en JSON, como `{"result":"works","fields":{"account":"me"}}`. Corre con un entorno
limpio y un límite de tiempo, y solo después de que lo apruebas. Cambiar el archivo o el programa aunque sea en un byte deshace la
aprobación. Un archivo que viene con keyreeve nunca puede correr un programa.

Un secreto sin proveedor, como una clave de firma, se marca como interno, y no se ofrece prueba. Los secretos de tus propios productos
van igual: un archivo tuyo, en esa carpeta, nunca en un repositorio.

## Rotar una clave

Abre una clave sellada en la app. Si su proveedor puede rotar, indicas dónde más se usa la clave y cuánto debe durar la antigua, y
aprietas **Rotar esta clave**. Una huella, y keyreeve:

1. Crea la clave nueva en el proveedor, con un nombre como `keyreeve-2026-11-06`, y la sella.
2. La prueba. Si falla, la clave nueva se revoca y todo queda como estaba.
3. Actualiza cada destino: archivos donde se reemplaza el valor antiguo, y botones tuyos que reciben la clave nueva por stdin. Si uno
   falla, se restauran todos los destinos y la clave nueva se revoca.
4. Deja la clave nueva como la vigente, y espera el traslape si definiste uno.
5. Revoca la clave antigua, de inmediato o más tarde cuando aprietes el botón en **Rotación**.

Cada paso se escribe primero en un diario, `~/.keyreeve/rotations.jsonl`, así que una caída en cualquier paso retoma o deshace la
rotación. El diario guarda ids de claves y nombres de pasos, nunca valores.

La mayoría de los proveedores no da forma de saber el id de una clave que ya tienes, así que la primera rotación puede pedirte revocar
la clave antigua a mano. Las siguientes ya conocen el id.

Hay tres formas de rotar, y el archivo de un proveedor dice cuál:

- **Dos claves por un tiempo.** Resend y LangSmith. Una falla en cualquier punto antes de que se vaya la clave antigua deshace todo.
- **`rotation: single`.** GitLab y Cal.com terminan la clave antigua en cuanto existe la nueva, así que nada se puede deshacer. Un
  destino que falla se te informa para que lo arregles, y la rotación sigue.
- **A mano.** Un proveedor sin forma de crear claves por su API, como Hetzner o Netlify. Creas la clave en su página y la pegas.
  keyreeve la prueba, actualiza los destinos y después comprueba que la clave antigua dejó de funcionar cuando la revocas. Esto funciona
  para proveedores que prueban una clave con una sola consulta simple.

Ninguna de estas ha corrido todavía contra un servicio real, y la lista en Ajustes muestra con qué se ha probado cada archivo. Para
agregar un proveedor, dale a su archivo `create` y `revoke`, y `keyreeve simulate` lo prueba contra fallas y caídas. Las garantías del
simulador no aplican a `rotation: single`.

Un destino puede ser un archivo, o un botón tuyo que recibe la clave nueva por stdin. Hay [ejemplos](../examples/places) para GitHub
Actions, Vercel y un archivo env en un servidor, que no se han corrido contra esos servicios. Una clave formada por dos campos, como la
de AWS, todavía no puede rotar.

## Lo que falta

- Una rotación probada contra un proveedor real
- Descargas ya compiladas, que necesitan una firma de Apple para la app
- Leer la respuesta temprana de un proveedor durante una subida. Un proveedor que rechaza un cuerpo grande antes de leerlo recibe un 502 del proxy
- Usar la bóveda en Linux y Windows, y una llave sin chip para ellos. El formato de archivo ya funciona ahí
- Otras bóvedas como almacenamiento, como 1Password o el llavero del sistema
- Un escaneo que encuentre dónde se usa cada clave, y qué permisos tiene cada una
- Recetas para más proveedores que pueden rotar, claves formadas por dos campos y rotación escrita como un programa tuyo
- Un reemplazo para los roles dentro de [seisin](https://github.com/carlostapiacl/seisin), para que lleguen a un proveedor a través del proxy y nunca tengan la clave
- Una huella para varias ejecuciones de seisin, sin dejar que otro programa se aproveche de ella
