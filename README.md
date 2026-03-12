#  Domain Reader - Web Recon & Audit Tool

**Domain Reader** es una herramienta de automatización escrita en Python diseñada para realizar reconocimiento (OSINT) y auditorías de seguridad iniciales sobre dominios web. Centraliza diversas pruebas de infraestructura, red y vulnerabilidades web en un solo reporte detallado.

##  Características Principales


La herramienta ejecuta un flujo de trabajo modular que incluye:

* **OSINT & Red:** Consulta de WHOIS, resolución de IP, geolocalización y detección de subdominios vía certificados (`crt.sh`).
* **Análisis de Seguridad:** Integración con la API de **VirusTotal** para verificar reputación.
* **Auditoría Web:** Análisis de cabeceras de seguridad HTTP, inspección de `robots.txt` y verificación de certificados SSL.
* **Infraestructura:** Escaneo de puertos comunes con detección de banners de servicio y consulta de registros DNS (MX/TXT).
* **Scanner Activo:** Búsqueda de fugas de información crítica (`.env`, `.git`, backups).


##  Requisitos Previos

*  Python 3.10 o superior.

*  Una API Key de VirusTotal (Gratuita).


##  Instalación y Configuración

1.  Clonar o descargar este repositorio en tu máquina local.
   
* git clone https://github.com/FIsaimorales/Domain-Reader.git

2.  Crear un entorno virtual para mantener las librerías aisladas:

*   python -m venv venv

3.  Activar el entorno virtual:

*   Windows: .\venv\Scripts\activate

*   Linux/Mac: source venv/bin/activate

4.  Instalar las dependencias:

*   pip install -r requirements.txt

5.  Configurar las credenciales:
   
*    Crea un archivo .env en la raíz del proyecto y añade tu llave de VirusTotal:

*   VT_API_KEY=tu_api_key_aqui


## Uso

### Simplemente ejecuta el script principal y sigue las instrucciones en pantalla:

* python main.py

Introduce el dominio (ej: google.com) cuando se solicite. Al finalizar, el programa generará un archivo reporte_{dominio}.txt con todos los hallazgos detallados.

