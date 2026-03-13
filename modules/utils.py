from datetime import datetime
import json, os
import requests

def clean_datetime(date):
    if isinstance(date, list):
        date = date[0]

    if isinstance(date, datetime):
        return date.strftime("%d-%m-%Y")

    return str(date)

def validar_API_KEY(KEY):
    url = "https://www.virustotal.com/api/v3/users/validate"
    headers = {"x-apikey": KEY}

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return True, "API KEY Valida!"
        else:
            return False, f"API Key invalida (Codigo: {response.status_code})"
    except Exception as e:
        return False, f"Error de conexion: {e}"

def generar_reporte(dominio, contenido):
    carpeta = "escaneos"

    if not os.path.exists(carpeta):
        os.makedirs(carpeta)
        print(f"[*] Carpeta '{carpeta}' creada para organizar los reportes.")

    nombre_archivo = f"reporte_{dominio}.txt"
    ruta_completa = os.path.join(carpeta, nombre_archivo)

    with open(ruta_completa, "w", encoding="utf-8") as f:
        f.write(contenido)

    print(f"Analisis completado. Reporte guardado en: {nombre_archivo}")

def limpiar_dominio(url):
    limpio = url.replace("https://", "").replace("http://", "")
    return limpio.split("/")[0]
