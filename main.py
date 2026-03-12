import os
from dotenv import load_dotenv
from tqdm import tqdm
from modules.network import *
from modules.scanner import *
from modules.utils import *
from modules.web_audit import *

load_dotenv()

# MAIN
def __main__():

    target = input("Introduce el dominio a analizar (ej: google.com): ")
    target = limpiar_dominio(target)

    API_KEY = os.getenv("VT_API_KEY")

    pasos = [
        ("Obteniendo WHOIS", obtener_info_whois),
        ("Resolviendo IP", obtener_ip),
        ("Escaneando Puertos", escanear_puertos_con_banner),
        ("Geolocalizando IP", lambda t: geolocalizar_ip(t)),
        ("Consultando VirusTotal", lambda t: consultar_virustotal(t, API_KEY)),
        ("Buscando Subdominios (crt.sh)", obtener_subdominios_crt),
        ("Analizando Registros MX", obtener_registros_mx),
        ("Politicas De Seguridad TXT", obtener_registros_txt),
        ("Cabeceras De Seguridad", analizar_cabeceras_seguridad),
        ("Archivo Robots.txt", analizar_robots_txt),
        ("Verificando SSL", verificar_ssl),
        ("Buscando Fugas Criticas", buscar_fugas_criticas),
        ("Detectando CMS y Vulnerabilidades", detectar_cms_avanzado)
    ]

    print("Verificando configuracion.....")
    es_valido, mensaje = validar_API_KEY(API_KEY)

    if not es_valido:
        print(f"ALERTA: {mensaje}")
        return
    
    print(f"Analizando {target}...")

    reporte_final = f"ANALISIS DEL DOMINIO: {target}\n"
    reporte_final += "="*40 + "\n"

    print(f"\n[*] Analizando {target}...")
    with tqdm(total=len(pasos), desc="Progreso", unit="paso", bar_format='{l_bar}{bar:20}{r_bar}{bar:-10b}') as pbar:
        for nombre_paso, funcion in pasos:
            pbar.set_description(f"Ejecutando: {nombre_paso}")
            
            reporte_final += funcion(target)

            pbar.update(1)
    
    generar_reporte(target, reporte_final)

if __name__ == "__main__":
    __main__()