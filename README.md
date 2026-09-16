# Scan Blunder Front

![Scan Blunder Front Banner](screenshot/Captura%20desde%202026-05-10%2013-47-47.png)

**Scan Blunder Front** es un scanner de seguridad para aplicaciones frontend
(React, Next.js, Vue, Nuxt, Angular, Svelte, WordPress, Laravel, sitios
estáticos…). Descarga la página, recorre todo su bundle y reporta secretos
expuestos, SQL en el cliente, lógica de autorización en el navegador, los
backends con los que habla y el stack completo con versiones.

El objetivo de diseño es **no reportar ruido**: cada hallazgo pasa por una
cadena de filtros antes de llegar al informe.

## Qué detecta

| Área | Ejemplos |
|---|---|
| **Secretos** | AWS, Google, Stripe, GitHub, GitLab, Slack, SendGrid, Twilio, OpenAI, Anthropic, npm, Firebase, Supabase, claves PEM, cadenas de conexión a BD, JWT (se decodifican y se leen sus claims) |
| **SQL en el front** | `SELECT/INSERT/UPDATE/DELETE` reales, con distinción entre SQL crudo y SQL **concatenado** (inyectable), más ORMs en el cliente (Prisma, Knex, Sequelize, TypeORM, Mongoose) |
| **Roles y permisos** | catálogos de roles, permisos granulares (`invoice.delete`), chequeos client-side (`hasRole`, `can`), flags de bypass (`skipAuth`), roles privilegiados dentro de JWTs |
| **Endpoints y backends** | rutas de API con su método HTTP real, GraphQL, WebSockets, rutas del router SPA, y el listado de hosts backend |
| **Tecnologías y versiones** | frameworks, librerías, bundlers, CMS, servidor y CDN — por headers, cookies, banners, nombres de archivo y `?ver=`; enumera **plugins y temas de WordPress con su versión** |
| **Servicios de terceros** | analytics, pagos, identidad, monitoreo, CDNs, soporte |
| **Vulnerabilidades del cliente** | sinks de DOM XSS (con detección de taint), open redirect, TLS deshabilitado, CORS permisivo, credenciales en `localStorage`, `Math.random()` para valores de seguridad, hosts internos, entornos de staging |
| **Exposición** | source maps publicados, `serverRuntimeConfig` de Next.js, variables de entorno en `__NEXT_DATA__`, versiones en headers, rutas sensibles (`/.env`, `/.git/config`, `/actuator/env`…) |
| **Headers** | CSP (y su calidad), HSTS, X-Frame-Options, CORS peligroso, cookies sin `HttpOnly`/`Secure`/`SameSite` |

## Cómo evita los falsos positivos

Esta es la parte que más importa. Un scanner que reporta de más no se lee.

1. **Las regex de código solo corren sobre código.** En un HTML el scanner extrae
   el contenido de `<script>`, los manejadores inline y las URIs `javascript:`.
   El texto de la página nunca llega a los detectores, así que
   *"Seleccione un plan de nuestro catálogo"* jamás se reporta como SQL.
2. **El SQL se busca dentro de string literals**, usando un tokenizador de JS que
   además ignora comentarios. Un `SELECT` tiene que tener una tabla con nombre de
   identificador válido (no `our`, `the`, `nuestro`), una cláusula que lo respalde
   (`WHERE`, `JOIN`, `VALUES`, un parámetro `$1`/`?`) y no contener markup.
3. **Los valores se validan, no solo se reconocen.** Un JWT se decodifica de
   verdad; si no es JSON válido con claims, no es un JWT. Un valor genérico
   necesita entropía y longitud reales.
4. **Lista de placeholders.** `credentials:"same-origin"`, `api_key:"apikey"`,
   `password:"password"`, `${API_KEY}`, `****`, `your-key-here` y compañía se
   descartan. Si el valor es igual al nombre de la clave, se descarta.
5. **Contexto de ARIA y de framework.** `role="button"` es ARIA, no un rol de
   aplicación. `window.next` no es un open redirect. `navigator.language` no es un
   host `.lan`.
6. **Cada hallazgo lleva confianza** (`CONFIRMED` / `FIRM` / `TENTATIVE`). Por
   defecto solo se muestran los dos primeros; `--include-tentative` muestra el resto.

## Instalación

```bash
git clone https://github.com/AlenMartinez/scan-blunder-front.git
cd scan-blunder-front

python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Uso

```bash
python3 main.py ejemplo.com
```

El esquema es opcional: si no se indica se intenta `https://` y se cae a `http://`
automáticamente.

### Ejemplos

```bash
# escaneo estándar, 20 hilos
python3 main.py https://ejemplo.com --threads 20

# recorrer también 1 nivel de páginas internas
python3 main.py https://ejemplo.com --depth 1

# mostrar también los hallazgos de baja confianza
python3 main.py https://ejemplo.com --include-tentative

# solo secretos y SQL, sin tocar rutas sensibles
python3 main.py https://ejemplo.com --only secrets,sql --no-probe

# pasar sesión autenticada y salir con código 2 si hay algo HIGH o peor
python3 main.py https://ejemplo.com -H "Cookie: session=abc" --fail-on HIGH

# a través de Burp / mitmproxy
python3 main.py https://ejemplo.com --proxy http://127.0.0.1:8080 --insecure
```

### Opciones principales

| Opción | Descripción |
|---|---|
| `--threads N` | peticiones concurrentes (10) |
| `--depth N` | además, recorre N niveles de páginas del mismo sitio (0) |
| `--max-assets N` | tope de archivos descargados (300) |
| `--max-size MB` | tope por archivo (5) |
| `--no-sourcemaps` | no descargar `.map` |
| `--no-probe` | no pedir rutas sensibles conocidas |
| `--only` / `--skip` | elegir detectores: `technology,secrets,sql,xss,misc,access,endpoints,headers` |
| `--timeout` / `--delay` | timeout por petición y pausa mínima entre peticiones |
| `--proxy` / `--insecure` | proxy HTTP y desactivar verificación TLS |
| `-H 'Name: value'` | header extra (repetible) |
| `--output DIR` | carpeta de informes (`findings`) |
| `--format` | `json`, `md`, `txt` (por defecto `json,md`) |
| `--include-tentative` | mostrar hallazgos de baja confianza |
| `--min-severity` | ocultar por debajo de esa severidad |
| `--fail-on SEVERITY` | salir con código 2 si hay hallazgos a ese nivel (para CI) |
| `-v` / `-q` | verbose / silencioso |

### Informes

Cada escaneo escribe en `findings/`:

- `dominio_fecha.json` — resultado completo, pensado para automatizar.
- `dominio_fecha.md` — informe legible con detalle, ubicación y remediación.
- `dominio_fecha.txt` — con `--format txt`.

## Arquitectura

```
scanner/
├── cli/          argumentos, validación y presentación en terminal
├── core/
│   ├── models.py     Finding, Asset, ScanResults, regiones de código
│   ├── lexer.py      tokenizador de JS (string literals y comentarios)
│   ├── filters.py    entropía, placeholders, guardas de HTML/prosa, validadores
│   ├── context.py    configuración del escaneo
│   ├── engine.py     orquestación: crawl, chunks, source maps, probes
│   ├── patterns/     catálogos: secrets, vulns, technologies, access, endpoints
│   ├── detector/     un detector por área, todos con la misma interfaz
│   └── findings/     escritura de informes (json / md / txt)
└── services/     cliente HTTP con reintentos, tope de tamaño y extracción de enlaces
```

Agregar una comprobación nueva es agregar una regla a `patterns/`, o una clase a
`detector/` y registrarla en `DETECTOR_CLASSES`.

## Tests

```bash
python3 -m unittest discover -s tests -t .
```

La suite incluye los falsos positivos concretos que versiones anteriores
reportaron contra sitios reales; son tests de regresión y deben seguir pasando.

## Disclaimer

Herramienta para auditoría de seguridad autorizada y fines educativos. El modo
por defecto realiza peticiones activas (incluidas rutas como `/.env` o
`/.git/config`); usá `--no-probe` para limitarte a lo que haría un navegador.
No la uses contra sistemas sin permiso explícito del propietario.

---
Hecho para la comunidad de seguridad.
