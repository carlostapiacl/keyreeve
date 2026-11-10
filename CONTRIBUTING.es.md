# Cómo contribuir

[English](CONTRIBUTING.md)

Gracias por ayudar. Quien participa sigue el [código de conducta](CODE_OF_CONDUCT.md). Si encontraste una vulnerabilidad, no
abras un issue: mira [SECURITY.md](SECURITY.md).

Lo que más sirve es una receta para un proveedor que uses. El detalle del formato está en [CONTRIBUTING.md](CONTRIBUTING.md), en
inglés.

## Una receta

1. Copia `recipes/hetzner.yaml` si la receta solo prueba claves, o `examples/recipe.yaml` si también rota.
2. Escríbela con la documentación oficial del proveedor, no con la guía de otra persona: una receta va bajo MIT y muchas guías
   tienen otra licencia.
3. La prueba tiene que ser un GET. Pruébala primero con una clave inventada: si el proveedor responde algo distinto de 401,
   agrega ese código en `reject`.
4. Agrégala a `BUILTIN` en `src/providers.rs`.
5. Corre `keyreeve check recipes/<proveedor>.yaml` y `keyreeve simulate recipes/<proveedor>.yaml`.

En el pull request indica el enlace a la documentación de cada paso, el permiso mínimo que necesita la clave y si la probaste
con una cuenta real, y cuándo. Nunca pegues una clave, un id ni una respuesta reales.

## Antes de abrir un pull request

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cd app && swift test
```

- Una receta por pull request.
- Commits y pull requests en inglés.
- Un cambio por pull request, en borrador mientras trabajas.
- Si arreglas un bug, suma un test que falle sin el arreglo.

`app/build-app.sh` compila la app. Si hay una copia en Aplicaciones la reemplaza, y si Keyreeve estaba abierto lo cierra y lo
vuelve a abrir, así que no lo corras si solo quieres los tests.
