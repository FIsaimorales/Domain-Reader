import os
from dotenv import load_dotenv
from tqdm import tqdm
from modules.network import *
from modules.scanner import *
from modules.utils import *
from modules.web_audit import *

load_dotenv()

# MAIN
def __main__(): # Cambié __main__ por main (es más estándar)
    while True:
        print("\n" + "="*40)
        print(" DOMAIN READER - Herramienta de Auditoría")
        print("="*40)

        target = input("\nIntroduce el dominio a analizar (ej: google.com) o 'salir': ").strip().lower()

        if target == 'salir':
            print("Saliendo del programa...")
            break
        
        if not target:
            print(" Debes introducir un dominio.")
            continue

        target = limpiar_dominio(target)
        API_KEY = os.getenv("VT_API_KEY")

        # Verificando configuración
        print("\nVerificando configuración.....")
        es_valido, mensaje = validar_API_KEY(API_KEY)

        if not es_valido:
            print(f" ALERTA: {mensaje}")
            input("\nCorrige el archivo .env y presiona Enter para reintentar...")
            continue # Vuelve al inicio del bucle en lugar de cerrar el programa
    
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

        reporte_final = f"ANALISIS DEL DOMINIO: {target}\n"
        reporte_final += "="*40 + "\n"

        print(f"\n[*] Analizando {target}...")
        
        with tqdm(total=len(pasos), desc="Progreso", unit="paso", bar_format='{l_bar}{bar:20}{r_bar}{bar:-10b}') as pbar:
            for nombre_paso, funcion in pasos:
                try:
                    pbar.set_description(f"Ejecutando: {nombre_paso}")
                    reporte_final += funcion(target)
                except Exception as e:
                    reporte_final += f"\n[!] Error en {nombre_paso}: {e}\n"
                
                pbar.update(1)
    
        generar_reporte(target, reporte_final)
        print(f"\n Análisis completado. Reporte generado para {target}")

        # Pregunta final para decidir si seguir o no
        respuesta = input("\n¿Deseas realizar otro escaneo? (s/n): ").strip().lower()
        if respuesta != 's':
            print("¡Gracias por usar Domain Reader!")
            break

if __name__ == "__main__":
    __main__()