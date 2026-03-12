import requests
import os
from urllib.parse import urljoin

def buscar_fugas_criticas(dominio):
    # Diccionario de objetivos con su nivel de riesgo
    objetivos = {
        "/.env": "CRÍTICO: Credenciales y llaves de API expuestas",
        "/.git/config": "ALTO: Repositorio expuesto (fuga de código fuente)",
        "/.ssh/id_rsa": "CRÍTICO: Llave privada SSH detectada",
        "/config.php.bak": "ALTO: Respaldo de configuración con posibles claves",
        "/backup.sql": "CRÍTICO: Base de datos completa expuesta",
        "/.htaccess": "MEDIO: Reglas de servidor expuestas",
        "/phpinfo.php": "BAJO: Revela versiones y rutas internas"
    }
    
    headers = {'User-Agent': 'Mozilla/5.0 (PentestScanner/1.0)'}
    url_base = f"https://{dominio}"
    resultado = "--- BUSQUEDA DE FUGAS DE INFORMACION CRITICA ---\n"
    encontrado = False

    for ruta, riesgo in objetivos.items():
        try:
            url = urljoin(url_base, ruta)
            # Usamos stream=True y verificamos solo el status code
            resp = requests.get(url, headers=headers, timeout=4, verify=False, stream=True)
            
            if resp.status_code == 200:
                # Verificación extra: si es un .env, no debería ser HTML
                if "text/html" not in resp.headers.get('Content-Type', ''):
                    resultado += f"[!] DETECTADO: {ruta}\n    └─ Riesgo: {riesgo}\n"
                    encontrado = True
                # Si es un .git/config, suele tener la palabra [core]
                elif ".git" in ruta:
                    resultado += f"[!] DETECTADO: {ruta}\n    └─ Riesgo: {riesgo}\n"
                    encontrado = True
                    
        except:
            continue

    if not encontrado:
        resultado += "No se detectaron archivos sensibles en las rutas comunes.\n"
    
    return resultado + "\n"