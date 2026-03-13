import whois, requests, socket, dns.resolver, time
from modules.utils import clean_datetime

def obtener_info_whois(dominio):
    try:
        who = whois.whois(dominio)

        fecha_creacion = clean_datetime(who.creation_date)
        fecha_expiracion = clean_datetime(who.expiration_date)

        info = f"--- INFORMACION DETALLADA DEL DOMINIO ---\n"
        info += f"Nombre del Registrante: {who.name if who.name else 'Privado / No disponible'}\n"
        info += f"Organizacion: {who.org}\n"
        info += f"Registrador: {who.registrar}\n"
        info += f"URL del Registrador: {who.registrar_url}\n"
        info += f"Fecha de creacion: {fecha_creacion}\n"
        info += f"Fecha de expiracion: {fecha_expiracion}\n"

        info += "Servidores de nombre:\n"
        if isinstance(who.name_servers, list):
            for name_server in who.name_servers:
                info += f"  - {name_server.lower()}\n"
        else:
            info += f"  - {str(who.name_servers).lower()}\n"
            
        info += f"Email de contacto de abuso: {who.emails if who.emails else 'No disponible en WHOIS publico'}\n"
        return info + "\n"
    except Exception as e:
        return f"--- INFORMACION DEL DOMINIO ---\nAVISO: No se pudo conectar al servidor WHOIS (Puerto 43 bloqueado o servidor saturado).\nDetalle tecnico: {e}\n\n"

def obtener_ip(dominio):
    try:
        ip = socket.gethostbyname(dominio)
        return f"--- INFORMACION DE RED ---\nDireccion IP: {ip}\n\n"
    except:
        return "--- INFORMACION DE RED ---\nNo se pudo resolver la IP.\n\n"

def geolocalizar_ip(dominio):
    try:
        ip = socket.gethostbyname(dominio)
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            res = "--- GEOLOCALIZACION DE RED ---\n"
            res += f"Pais: {data.get('country')} ({data.get('countryCode')})\n"
            res += f"Ciudad: {data.get('city')}\n"
            res += f"Proveedor (ISP): {data.get('isp')}\n"
            return res + "\n"
    except:
        return ""
    return ""

def obtener_registros_txt(dominio):
    try:
        # Consultamos específicamente los registros de tipo TXT
        respuestas = dns.resolver.resolve(dominio, 'TXT')
        
        resultado = "--- REGISTROS TXT (Seguridad y Configuración) ---\n"
        for rdata in respuestas:
            # Los registros TXT a veces vienen divididos en partes, los unimos
            txt_linea = "".join([part.decode('utf-8') if isinstance(part, bytes) else str(part) for part in rdata.strings])
            resultado += f"- {txt_linea}\n"
            
        return resultado + "\n"
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return "--- REGISTROS TXT ---\nNo se encontraron registros TXT.\n\n"
    except Exception as e:
        return f"--- REGISTROS TXT ---\nError al consultar registros TXT: {str(e)}\n\n"

def obtener_registros_mx(dominio):
    try:
        answers = dns.resolver.resolve(dominio, 'MX')
        resultado = "--- REGISTROS DE CORREO (MX) ---\n"
        for rdata in answers:
            resultado += f"- Servidor: {rdata.exchange} (Prioridad: {rdata.preference})\n"
        return resultado + "\n"
    except Exception:
        return "--- REGISTROS DE CORREO ---\nNo se detectaron servidores MX.\n\n"
    
def escanear_puertos_con_banner(dominio):
    # Puertos comunes para web y administración
    puertos = {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS", 8080: "HTTP-Proxy"}
    try:
        ip = socket.gethostbyname(dominio)
        resultado = f"--- ANALISIS DE SERVICIOS Y BANNERS (IP: {ip}) ---\n"
        
        for puerto, servicio in puertos.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            
            if sock.connect_ex((ip, puerto)) == 0:
                resultado += f"[!] Puerto {puerto} ({servicio}): ABIERTO\n"
                
                try:
                    # Enviamos una petición genérica para forzar respuesta
                    if puerto == 80:
                        sock.send(b"HEAD / HTTP/1.1\r\nHost: " + dominio.encode() + b"\r\n\r\n")
                    
                    banner = sock.recv(1024).decode(errors='ignore').strip()
                    if banner:
                        # Extraemos solo la línea que dice "Server:" si existe
                        lineas = banner.split('\n')
                        server_info = next((s for s in lineas if "Server:" in s), banner.split('\n')[0])
                        resultado += f"    └─ Info detectada: {server_info[:100]}\n"
                except:
                    resultado += "    └─ No se pudo obtener banner (servicio silencioso)\n"
            sock.close()
            
        return resultado + "\n"
    except Exception as e:
        return f"--- ESCANEO DE PUERTOS ---\nError: {e}\n\n"

def obtener_subdominios_crt(dominio):
    url = f"https://crt.sh/?q={dominio}&output=json"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }

    # Intentaremos hasta 2 veces si hay un error de conexión
    for intento in range(2):
        try:
            # Aumentamos el timeout a 30 para darle más tiempo al servidor
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                subdominios = set()
                for entry in data:
                    names = entry['name_value'].split('\n')
                    for name in names:
                        name = name.strip().lower()
                        if name != dominio and not name.startswith('*'):
                            subdominios.add(name)
                
                resultado = "--- SUBDOMINIOS DETECTADOS (Certificados) ---\n"
                if subdominios:
                    for sub in sorted(subdominios):
                        resultado += f"- {sub}\n"
                else:
                    resultado += "No se encontraron subdominios registrados.\n"
                return resultado + "\n"
            
            elif response.status_code == 502 or response.status_code == 503:
                # Si el servidor está sobrecargado, esperamos 3 segundos y reintentamos
                time.sleep(3)
                continue
            else:
                return f"--- SUBDOMINIOS ---\nServidor crt.sh reportó error {response.status_code}\n\n"

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            if intento == 0:
                time.sleep(2) # Breve espera antes del segundo intento
                continue
            return "--- SUBDOMINIOS ---\nError: El servidor de crt.sh no responde (Timeout).\n\n"
        except Exception as e:
            return f"--- SUBDOMINIOS ---\nError inesperado: {str(e)}\n\n"
            
    return "--- SUBDOMINIOS ---\nNo se pudo conectar tras varios intentos.\n\n"

def consultar_virustotal(dominio, api_key):
    url = f"https://www.virustotal.com/api/v3/domains/{dominio}"
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()

            stats = data['data']['attributes']['last_analysis_stats']
            resultado = "--- RESULTADOS VIRUSTOTAL ---\n"
            resultado += f"Maliciosos: {stats['malicious']}\n"
            resultado += f"Sospechosos: {stats['suspicious']}\n"
            resultado += f"Inofensivos: {stats['harmless']}\n\n"
            return resultado
        else:
            return "Error: No se pudo conectar con VirusTotal (revisa tu API Key).\n"
    except Exception as e:
        return f"Error en la consulta de VT: {e}\n"
