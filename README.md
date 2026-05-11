# Scan Blunder Front

![Scan Blunder Front Banner](screenshot/Captura%20desde%202026-05-10%2013-47-47.png)


**Scan Blunder Front** es un potente scanner de seguridad para aplicaciones frontend (React, Next.js, Vue, WordPress, etc.). Está diseñado para detectar de forma automática tokens expuestos, secretos, malas prácticas de desarrollo y vulnerabilidades en archivos JavaScript.

## Caracteristicas

- **Detección de Tecnologías**: Identifica automáticamente si el sitio usa Next.js, React, Vue, jQuery, Angular o WordPress.
- **Buscador de Secretos**: Localiza claves de Google API, AWS, Firebase, JWT, Slack, Stripe y más.
- **Vulnerabilidades y Malas Prácticas**: Detecta consultas SQL directas o uso de ORMs (como Prisma) en el frontend.
- **Extracción de Endpoints**: Lista URLs y métodos HTTP (GET, POST, PUT, DELETE) encontrados en el código.
- **Multi-threading**: Escaneo rápido y eficiente de múltiples archivos JS y chunks en paralelo.
- **Reporte Visual**: Resultados organizados en tablas legibles directamente en la terminal.

## Instalacion

1. **Clonar el repositorio**:
   ```bash
   git clone https://github.com/AlenMartinez/scan-blunder-front.git
   cd scan-blunder-front
   ```

2. **Instalar dependencias**:
   ```bash
   pip install -r requirements.txt
   # O directamente:
   pip install .
   ```

   *Nota: Asegúrate de tener instalado `requests`, `beautifulsoup4` y `rich`.*

## Uso

Para escanear una web, simplemente ejecuta el comando `main.py` pasando la URL objetivo:

```bash
python3 main.py https://ejemplo.com
```

### Opciones avanzadas

Puedes ajustar el número de hilos para aumentar la velocidad de escaneo:

```bash
python3 main.py https://ejemplo.com --threads 20
```

## Disclaimer

Este software es para fines educativos y de auditoría de seguridad ética. No utilices esta herramienta en sitios web sin el permiso explícito del propietario.

---
Hecho para la comunidad de seguridad.
