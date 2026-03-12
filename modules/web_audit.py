import requests
import ssl
import socket
import urllib3
import warnings
from urllib.parse import urljoin

def analizar_cabeceras_seguridad(dominio):
    # Definimos qué cabeceras queremos buscar y para qué sirven
    cabeceras_criticas = {
        "Strict-Transport-Security": "Protege contra interceptación (fuerza HTTPS).",
        "Content-Security-Policy": "Previene inyección de scripts maliciosos (XSS).",
        "X-Frame-Options": "Evita que clonen tu web en un marco (Clickjacking).",
        "X-Content-Type-Options": "Evita que el navegador adivine el tipo de archivo incorrectamente.",
        "Referrer-Policy": "Controla qué información de origen se comparte al hacer clic en links.",
        "Permissions-Policy": "Controla qué funciones del navegador (cámara, micro, geolocalización) puede usar el sitio.",
        "Expect-CT": "Ayuda a detectar certificados SSL falsos o mal emitidos.",
        "Cross-Origin-Embedder-Policy": "Evita que el sitio cargue recursos externos que no hayan dado permiso explícito."
    }
    
    try:
        # Hacemos una petición HEAD (solo pedimos los encabezados, es más rápido)
        # Usamos https:// porque ya sabemos que tiene el puerto 443 abierto
        url = f"https://{dominio}"
        response = requests.head(url, timeout=5, allow_redirects=True)
        headers_recibidas = response.headers
        
        resultado = "--- ANALISIS DE CABECERAS DE SEGURIDAD (HTTP Headers) ---\n"
        
        for header, descripcion in cabeceras_criticas.items():
            if header in headers_recibidas:
                resultado += f"[+] {header}: PRESENTE\n    └─ {headers_recibidas[header][:80]}...\n"
            else:
                resultado += f"[-] {header}: AUSENTE\n    └─ Riesgo: {descripcion}\n"
                
        return resultado + "\n"
    except Exception as e:
        return f"--- ANALISIS DE CABECERAS ---\nError al conectar: {e}\n\n"
    
def analizar_robots_txt(dominio):
    url = f"https://{dominio}/robots.txt"
    # Añadimos un User-Agent real para evitar bloqueos de firewalls
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}
    
    try:
        # allow_redirects=True es vital por si el archivo está en otra ruta
        resp = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
        
        if resp.status_code == 200:
            return f"--- ANALISIS DE ROBOTS.TXT ---\n{resp.text}\n\n"
        elif resp.status_code == 404:
            return "--- ANALISIS DE ROBOTS.TXT ---\nEl archivo no existe (404 Not Found).\n\n"
        else:
            return f"--- ANALISIS DE ROBOTS.TXT ---\nError: El servidor respondió con código {resp.status_code}\n\n"
    except Exception as e:
        return f"--- ANALISIS DE ROBOTS.TXT ---\nError de conexión: {str(e)}\n\n"

def verificar_ssl(dominio):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((dominio, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                cert = ssock.getpeercert()
                # Extraemos datos clave
                expira = cert.get('notAfter')
                emisor = dict(x[0] for x in cert.get('issuer'))
                
                res = "--- ESTADO DEL CERTIFICADO SSL ---\n"
                res += f"Emitido por: {emisor.get('organizationName', 'Desconocido')}\n"
                res += f"Fecha de expiracion: {expira}\n"
                return res + "\n"
    except Exception as e:
        return f"--- ESTADO DEL CERTIFICADO SSL ---\nError al verificar: {e}\n\n"

def detectar_cms_avanzado(dominio):
    """
    Detecta CMS + vulnerabilidades críticas. Retorna string formateado para reporte.
    """
    try:
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0 (compatible; PentestScanner/1.0)'})
        url_base = f"https://{dominio}" if requests.get(f"https://{dominio}", timeout=3, verify=False).status_code == 200 else f"http://{dominio}"
        
        resultado = f"\n--- CMS Y VULNERABILIDADES ---\n{'='*40}\n"
        resultado += f"URL Base: {url_base}\n"
        
        # Chequeo CMS básico (tus paths originales + nuevos)
        paths_cms = ['/wp-json', '/ghost', '/admin', '/wp-admin', '/webflow-admin']
        cms_detectado = "Desconocido"
        
        for path in paths_cms:
            try:
                resp = session.get(urljoin(url_base, path), timeout=5, verify=False)
                if 'wp-json' in resp.text.lower():
                    cms_detectado = "WordPress"
                    break
                elif 'ghost' in resp.text.lower():
                    cms_detectado = "Ghost"
                elif path == '/webflow-admin/':
                    cms_detectado = "Webflow (sospechado)"
            except:
                continue
        
        resultado += f"CMS Detectado: {cms_detectado}\n"
        
        # Headers de seguridad (rentoso.cl style)
        headers_resp = session.get(url_base, timeout=5, verify=False)
        headers = {k.lower(): v for k, v in headers_resp.headers.items()}

        criticos = ['x-frame-options', 'content-security-policy', 'strict-transport-security', 'referrer-policy']
        faltantes = [h for h in criticos if h not in headers]
        
        if faltantes:
            resultado += f" CLICKJACKING Vulnerable! Faltan: {', '.join(faltantes)}\n"
            resultado += f" PoC: data:text/html,<iframe src={url_base}></iframe><div onclick='alert(1)'>CLICK!</div>\n"
        else:
            resultado += " Headers de seguridad OK\n"
        
        # Referrer leak
        resp_ref = session.get(url_base, headers={'Referer': 'https://evil.com'}, timeout=5, verify=False)
        if 'evil.com' not in resp_ref.text and 'referrer-policy' not in headers:
            resultado += " Referrer Leak (no filtra dominios externos)\n"
            resultado += " Test: curl -e https://evil.com -I " + url_base + "\n"
        
        # MIME XSS SVG rápido
        svg_test = '<svg onload=alert(1)>'
        resp_svg = session.post(url_base, data={'q': svg_test}, timeout=5, verify=False)
        if svg_test.lower() in resp_svg.text.lower():
            resultado += " MIME XSS SVG Vulnerable!\n"
        
        # Dirs expuestos
        dirs_sospechosos = ['/admin', '/wp-admin', '/.git/HEAD', '/backup']
        for direc in dirs_sospechosos:
            try:
                resp_dir = session.get(urljoin(url_base, direc), timeout=3, verify=False)
                if resp_dir.status_code == 200:
                    resultado += f" Directorio expuesto: {direc} (Status: {resp_dir.status_code})\n"
            except:
                pass
        
        resultado += "="*40 + "\n"
        return resultado
        
    except Exception as e:
        return f"\n CMS Y VULNERABILIDADES:\n{'='*40}\n Error analizando CMS: {str(e)}\n{'='*40}\n"
