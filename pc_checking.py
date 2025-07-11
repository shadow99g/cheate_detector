import os
import psutil
import socket
from datetime import datetime, timedelta
import platform
import subprocess
from reportlab.lib.pagesizes import LETTER
from reportlab.pdfgen import canvas
import ctypes
import codecs
import win32evtlog
import sys
import urllib.request
import zipfile
import json
import re
import winreg  # Para acceder al registro y obtener la ruta de servicios

# correo
import smtplib
from email.message import EmailMessage

SUSPECT_SOFTWARE = [
    "teamviewer",
    "anydesk",
    "vnc",
    "ultraviewer",
    "cheatengine",
    "autoclicker",
    "cheat",
    "trainer",
    "injector",
    "aimbot",
    "wallhack",
    "h4x"
]
# Puedes ajustar esto
EXTENSIONES_SOSPECHOSAS = [".exe", ".bat", ".ps1", ".vbs", ".jar", ".scr", ".com"]

dispositivos_conocidos = [
        "Intel",
        "NVIDIA",
        "Realtek",
        "AMD",
        "Standard SATA AHCI Controller",
        "USB Host Controller",
        "Intel(R) Management Engine Interface",
        "PCI Express Root Port",
        "Bluetooth",
        "Wi-Fi",
        "Ethernet",
    ]

# Carpetas típicas para buscar trampas
CARPETAS_CLAVE = [
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~\\AppData\\Local\\Temp")
]
known_programs = [
    # Navegadores
    "chrome.exe", "firefox.exe", "msedge.exe",

    # Correo
    "outlook.exe", "thunderbird.exe",

    # IDEs y dev tools
    "code.exe", "pycharm64.exe", "sublime_text.exe", "python.exe", "java.exe",

    # Apps comunes
    "discord.exe", "spotify.exe", "teams.exe",

    # Antivirus y seguridad
    "msmpeng.exe",  # Windows Defender
    "avastui.exe", "avastsvc.exe",  # Avast
    "avgui.exe", "avgsrma.exe",  # AVG
    "avp.exe",  # Kaspersky
    "bdservicehost.exe", "bdagent.exe",  # Bitdefender
    "mcshield.exe", "mcsvhost.exe",  # McAfee
    "ns.exe", "ccsvchst.exe",  # Norton/Symantec
    "egui.exe", "ekrn.exe",  # ESET NOD32
    "psanhost.exe", "psuicnt.exe",  # Panda Security
    "sophosui.exe", "sophossvc.exe",  # Sophos
    "mbam.exe", "mbamtray.exe",  # Malwarebytes
    "tmccsf.exe", "tmbmsrv.exe"  # Trend Micro
]


def enviar_pdf_por_correo(destinatario, archivo_pdf, remitente, clave_app):
    asunto = f"Reporte de seguridad - {os.getlogin()} {socket.gethostname()}(PC - Check)"
    cuerpo = "Adjunto encontrarás el reporte en PDF generado por el script de análisis."

    msg = EmailMessage()
    msg['Subject'] = asunto
    msg['From'] = remitente
    msg['To'] = destinatario
    msg.set_content(cuerpo)

    # Adjuntar el archivo PDF
    try:
        with open(archivo_pdf, 'rb') as f:
            pdf_data = f.read()
            msg.add_attachment(pdf_data, maintype='application', subtype='pdf', filename=archivo_pdf)
    except Exception as e:
        print(f"❌ No se pudo adjuntar el PDF: {e}")
        return

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(remitente, clave_app)
            smtp.send_message(msg)
            print("📧 Correo enviado exitosamente.")
    except Exception as e:
        print(f"❌ Error al enviar correo: {e}")


def guardar_archivos_sospechosos_json(lista_archivos, nombre_archivo="sospechosos.json"):
    salida = []
    for nombre, ruta, fecha, razones in lista_archivos:
        salida.append({
            "nombre": nombre,
            "ruta": ruta,
            "modificado": fecha.strftime("%Y-%m-%d %H:%M:%S"),
            "razones": razones
        })
    try:
        with open(nombre_archivo, "w", encoding="utf-8") as f:
            json.dump(salida, f, indent=4, ensure_ascii=False)
        print(f"📝 Se guardaron los archivos sospechosos en '{nombre_archivo}'")
    except Exception as e:
        print(f"❌ Error al guardar JSON: {e}")


def verificar_sysmon_activo():
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] and 'sysmon' in proc.info['name'].lower():
            return True
    return False


def existe_log_sysmon():
    try:
        log = 'Microsoft-Windows-Sysmon/Operational'
        win32evtlog.OpenEventLog(None, log)
        return True
    except:
        return False


def sysmon_instalado():
    return verificar_sysmon_activo() and existe_log_sysmon()


def es_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def elevar_permisos():
    if not es_admin():
        print("⚠️ Elevando permisos para administrador...")
        script = sys.executable
        params = ' '.join([f'"{arg}"' if ' ' in arg else arg for arg in [sys.argv[0]] + sys.argv[1:]])
        # Lanzar el script elevado (runas)
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", script, params, None, 1)
        if ret <= 32:
            print("❌ No se pudo elevar permisos. Ejecuta el script manualmente como administrador.")
        sys.exit()


def instalar_sysmon():
    print("\n🚧 Iniciando instalación de Sysmon...")

    url = "https://download.sysinternals.com/files/Sysmon.zip"
    carpeta_destino = "C:\\Sysmon"
    zip_path = os.path.join(carpeta_destino, "Sysmon.zip")
    exe_path = os.path.join(carpeta_destino, "Sysmon64.exe")
    config_path = os.path.join(carpeta_destino, "config.xml")

    # Config básica mínima
    config_minima = """<Sysmon schemaversion="4.50">
  <EventFiltering>
    <ProcessCreate onmatch="include" />
  </EventFiltering>
</Sysmon>
"""

    try:
        if not os.path.exists(carpeta_destino):
            os.makedirs(carpeta_destino)

        print("⬇️ Descargando Sysmon...")
        urllib.request.urlretrieve(url, zip_path)

        print("📦 Extrayendo archivo...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(carpeta_destino)

        print("📝 Guardando configuración básica...")
        with open(config_path, 'w') as f:
            f.write(config_minima)

        print("⚙️ Instalando Sysmon como servicio...")
        resultado = subprocess.run([exe_path, "-accepteula", "-i", config_path], capture_output=True, text=True)
        if resultado.returncode == 0:
            print("✅ Sysmon instalado correctamente.")
            return True
        else:
            print("❌ Error al instalar Sysmon:\n", resultado.stdout + resultado.stderr)
            return False
    except Exception as e:
        print(f"❌ Falló la instalación automática: {e}")
        return False


def detectar_dispositivos_dma_avanzado():
    resultado = ["\n🎯 Escaneo de posibles trampas DMA (aimbot hardware):"]

    # Palabras clave sospechosas (comunes en trampas DMA)
    palabras_clave_sospechosas = [
        "thunderbolt", "fpga", "external", "dma", "capture", "inject", "interceptor"
    ]

    try:
        # Obtener dispositivos con relación a DMA o acceso directo
        cmd = (
            "Get-PnpDevice | Where-Object { "
            "$_.FriendlyName -match 'thunderbolt|pci|express|fpga|dma|external|capture' -or "
            "$_.InstanceId -match 'PCI' -or "
            "$_.Class -match 'System|Media|Net' } "
            "| Select-Object FriendlyName, InstanceId, Manufacturer"
        )

        proceso = subprocess.run(
            ["powershell", "-Command", cmd],
            capture_output=True, text=True, shell=True
        )
        salida = proceso.stdout.strip()

        if salida:
            lineas = salida.splitlines()
            sospechosos = []

            for linea in lineas:
                # Si contiene palabra clave sospechosa Y no está en la lista blanca
                if (
                        any(palabra in linea.lower() for palabra in palabras_clave_sospechosas)
                        and not any(conocido.lower() in linea.lower() for conocido in dispositivos_conocidos)
                ):
                    sospechosos.append(linea)

            if sospechosos:
                resultado.append("⚠️ Dispositivos NO reconocidos con riesgo potencial (posibles trampas DMA):\n")
                resultado.extend(sospechosos)
            else:
                resultado.append("✅ No se detectaron trampas DMA fuera de la lista blanca.")
        else:
            resultado.append("✅ No se encontraron dispositivos DMA sospechosos.")
    except Exception as e:
        resultado.append(f"❌ Error durante el escaneo de trampas DMA: {e}")

    return "\n".join(resultado)


def verificar_proteccion_dma_kernel():
    resultado = ["\n🛡️ Verificación de protección DMA del kernel (si está disponible):"]
    try:
        cmd = "systeminfo"
        proceso = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        salida = proceso.stdout
        for linea in salida.splitlines():
            if "Protección DMA del kernel" in linea or "Kernel DMA Protection" in linea:
                resultado.append(f"🔍 {linea.strip()}")
                break
        else:
            resultado.append("ℹ️ No se encontró información sobre protección DMA. Es posible que no esté disponible.")
    except Exception as e:
        resultado.append(f"❌ Error al verificar protección DMA: {e}")
    return "\n".join(resultado)


def leer_eventos_sysmon_procesos_recientes():
    info = []
    info.append("\n📋 Sysmon - Ejecución de procesos recientes:")

    server = 'localhost'
    logtype = 'Microsoft-Windows-Sysmon/Operational'
    hand = win32evtlog.OpenEventLog(server, logtype)

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total = 0
    max_entries = 1000
    max_dias = 2  # cambiar si quieres ver más o menos historial
    ahora = datetime.now()

    try:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        while events and total < max_entries:
            for ev_obj in events:
                if ev_obj.EventID == 1:  # ID 1 = Process Creation
                    fecha = ev_obj.TimeGenerated
                    if ahora - fecha > timedelta(days=max_dias):
                        continue

                    datos = ev_obj.StringInserts
                    if datos:
                        imagen = datos[4]  # Ruta del ejecutable
                        pid = datos[1]
                        usuario = datos[11] if len(datos) > 11 else "N/A"
                        info.append(f"▶️ {imagen} (PID {pid}) ejecutado por {usuario} en {fecha}")
                    if total >= max_entries:
                        break
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    total += 1
            events = win32evtlog.ReadEventLog(hand, flags, 0)
    except Exception as e:
        info.append(f"❌ Error leyendo eventos Sysmon: {e}")

    if len(info) == 1:
        info.append("✅ No se detectaron procesos recientes en Sysmon.")
    return "\n".join(info)


def conexiones_red_sospechosas():
    info = []
    info.append("\n📡 Conexiones activas a IPs externas (fuera de red local):")
    conexiones_externas = []

    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
            ip = conn.raddr.ip
            if not ip.startswith(("192.", "10.", "127.", "172.")):
                try:
                    proc = psutil.Process(conn.pid)
                    pname = proc.name()
                    conexiones_externas.append(f"🔗 {pname} (PID {proc.pid}) conectado a {ip}:{conn.raddr.port}")
                except:
                    continue

    if conexiones_externas:
        info.extend(conexiones_externas)
    else:
        info.append("✅ No se detectaron conexiones activas fuera de red local.")
    return "\n".join(info)


def procesos_escuchando_lan():
    info = []
    info.append("\n🧿 Procesos escuchando en red local (posible control remoto):")
    escuchando = []

    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_LISTEN and conn.laddr:
            ip = conn.laddr.ip
            if not ip.startswith("127.") and not ip.startswith("::1"):
                try:
                    proc = psutil.Process(conn.pid)
                    escuchando.append(f"🟡 {proc.name()} (PID {proc.pid}) escuchando en {ip}:{conn.laddr.port}")
                except:
                    continue

    if escuchando:
        info.extend(escuchando)
    else:
        info.append("✅ No se detectaron procesos escuchando en red.")
    return "\n".join(info)


def userassist_history():
    info = []
    info.append("\n🧾 Historial de ejecución reciente (UserAssist):")

    try:
        base_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base_path) as base_key:
            for i in range(winreg.QueryInfoKey(base_key)[0]):
                guid = winreg.EnumKey(base_key, i)
                count_path = base_path + "\\" + guid + "\\Count"
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, count_path) as count_key:
                        for j in range(winreg.QueryInfoKey(count_key)[1]):
                            name, _, _ = winreg.EnumValue(count_key, j)
                            decoded = codecs.decode(name, 'rot_13')
                            if ".exe" in decoded.lower():
                                info.append(f"▶️ Ejecutado: {decoded}")
                except:
                    continue
    except Exception as e:
        info.append(f"❌ Error al leer UserAssist: {e}")

    if len(info) == 1:
        info.append("✅ No se encontraron datos de ejecución reciente.")
    return "\n".join(info)


def obtener_unidades_removibles():
    usb_drives = []
    bitmask = ctypes.cdll.kernel32.GetLogicalDrives()
    for letra in range(26):
        if bitmask & (1 << letra):
            unidad = chr(65 + letra) + ":\\"
            tipo = ctypes.windll.kernel32.GetDriveTypeW(unidad)
            if tipo == 2:  # DRIVE_REMOVABLE
                usb_drives.append(unidad)
    return usb_drives


def servicios_sospechosos():
    info = []
    info.append("\n🛠️ Servicios sospechosos (sin descripción o ruta no común):")

    try:
        import wmi
        c = wmi.WMI()
        sospechosos = []

        for service in c.Win32_Service():
            if not service.Description or "temp" in (service.PathName or "").lower():
                sospechosos.append(f"⚠️ {service.Name} | Estado: {service.State} | Ruta: {service.PathName or 'N/A'}")

        if sospechosos:
            info.extend(sospechosos)
        else:
            info.append("✅ No se encontraron servicios sospechosos.")
    except Exception as e:
        info.append(f"❌ Error al revisar servicios con WMI: {e}")
    return "\n".join(info)


def deteccion_completa_usb():
    info = []
    info.append("\n💿 Detección completa en unidades USB conectadas:")

    unidades = obtener_unidades_removibles()
    if not unidades:
        info.append("ℹ️ No hay unidades USB conectadas.")
        return "\n".join(info)

    encontrados = False

    for unidad in unidades:
        info.append(f"\n📁 Unidad: {unidad}")

        # 🔍 Archivos ejecutables encontrados
        for root, _, files in os.walk(unidad):
            for archivo in files:
                if archivo.lower().endswith(tuple(EXTENSIONES_SOSPECHOSAS)):
                    ruta = os.path.join(root, archivo)
                    try:
                        tamano = os.path.getsize(ruta)
                        modificado = datetime.fromtimestamp(os.path.getmtime(ruta))
                        info.append(f"⚠️ Archivo ejecutable encontrado: {archivo}")
                        info.append(f"    ➤ Ruta: {ruta}")
                        info.append(f"    ➤ Tamaño: {tamano // 1024} KB | Modificado: {modificado}")
                        encontrados = True
                    except:
                        continue

        # 🔎 Procesos ejecutándose desde el USB
        for proc in psutil.process_iter(['pid', 'exe', 'name']):
            try:
                exe_path = proc.info['exe']
                if exe_path and exe_path.lower().startswith(unidad.lower()):
                    info.append(f"🛑 Proceso en ejecución desde USB: {proc.info['name']} (PID: {proc.pid})")
                    info.append(f"    ➤ Ejecutable: {exe_path}")
                    encontrados = True
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

    if not encontrados:
        info.append("✅ No se detectaron archivos ni procesos sospechosos en USBs.")
    return "\n".join(info)


def guardar_en_pdf(nombre_archivo, contenido):
    c = canvas.Canvas(nombre_archivo, pagesize=LETTER)
    width, height = LETTER
    margin = 40
    max_width = width - 2 * margin
    y = height - margin
    line_height = 14

    for linea in contenido.split('\n'):
        # Si la línea es muy larga, la dividimos en partes
        while linea:
            # Encuentra el máximo número de caracteres que caben en max_width
            for i in range(len(linea), 0, -1):
                ancho = c.stringWidth(linea[:i], "Helvetica", 10)
                if ancho <= max_width:
                    break
            fragmento = linea[:i]
            linea = linea[i:]
            if y < margin + line_height:
                c.showPage()
                y = height - margin
            c.setFont("Helvetica", 10)
            c.drawString(margin, y, fragmento)
            y -= line_height

    c.save()
    print(f"\n📄 Reporte guardado como: {nombre_archivo}")


def system_summary():
    info = []
    info.append("===== PC Check - Análisis básico de trampas o anomalías =====")
    info.append("\n🖥️  Información del sistema:")
    info.append(f"Usuario: {os.getlogin()}")
    info.append(f"Sistema: {platform.system()} {platform.release()}")
    info.append(f"Nombre del host: {socket.gethostname()}")
    uptime = datetime.now() - datetime.fromtimestamp(psutil.boot_time())
    info.append(f"Tiempo activo: {uptime}")
    return "\n".join(info)

def detectar_ejecuciones_desde_red():
    info = []
    info.append("\n🌐 Procesos ejecutados desde red compartida (UNC o mapeada):")
    encontrados = False

    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            exe_path = proc.info['exe']
            if exe_path and (exe_path.startswith('\\\\') or exe_path[0] in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' and exe_path[1:3] == ':\\'):
                # Verificar si la unidad es una red mapeada
                letra = exe_path[0]
                ruta_mapeada = f"{letra}:\\"
                tipo = ctypes.windll.kernel32.GetDriveTypeW(ruta_mapeada)
                if exe_path.startswith('\\\\') or tipo == 4:  # DRIVE_REMOTE
                    info.append(f"⚠️ {proc.info['name']} (PID {proc.pid}) desde: {exe_path}")
                    encontrados = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not encontrados:
        info.append("✅ No se detectaron procesos desde rutas de red.")
    return "\n".join(info)

def check_suspicious_processes():
    info = []
    info.append("\n[🔍] Procesos sospechosos:")
    found = False

    # Convertir la lista a minúsculas para comparación exacta
    sospechosos = set(name.lower() for name in SUSPECT_SOFTWARE)
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pname = proc.info['name'].lower()
            # Comparar nombre exacto del ejecutable
            if pname in sospechosos:
                info.append(f"⚠️  Proceso sospechoso detectado: {pname} (PID: {proc.pid})")
                found = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if not found:
        info.append("✅ No se detectaron procesos sospechosos.")
    return "\n".join(info)


def check_recently_installed_programs():
    info = []
    info.append("\n[🗃️] Verificación de programas instalados recientes:")
    if platform.system() == "Windows":
        try:
            import winreg
            paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            ]
            found_recent = False
            for path in paths:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            subkey = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey) as sk:
                                name = ""
                                install_date = ""
                                try:
                                    name = winreg.QueryValueEx(sk, "DisplayName")[0]
                                except:
                                    pass
                                try:
                                    install_date = winreg.QueryValueEx(sk, "InstallDate")[0]
                                except:
                                    pass
                                if name and install_date:
                                    try:
                                        install_date_dt = datetime.strptime(install_date, "%Y%m%d")
                                        if datetime.now() - install_date_dt < timedelta(days=7):
                                            info.append(
                                                f"⚠️  Instalado recientemente: {name} ({install_date_dt.date()})")
                                            found_recent = True
                                    except:
                                        pass
                        except:
                            continue
            if not found_recent:
                info.append("✅ No se detectaron instalaciones recientes.")
        except ImportError:
            info.append("❌ Función solo disponible en Windows.")
    else:
        info.append("🔸 Verificación de instalación reciente no disponible en este sistema.")
    return "\n".join(info)


def check_active_connections(known_programs):
    info = []
    info.append("\n🌐 Conexiones activas detectadas:")
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == psutil.CONN_ESTABLISHED:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                pid = conn.pid
                try:
                    proc = psutil.Process(pid)
                    pname = proc.name().lower()
                except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                    continue

                # Evita mostrar conexiones de programas conocidos o direcciones locales
                if pname.lower() not in (p.lower() for p in known_programs):
                    if (conn.raddr and
                            hasattr(conn.raddr, 'ip') and
                            conn.raddr.ip and
                            not conn.raddr.ip.startswith("127.")):
                        proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                        info.append(f"🔗 {pname} (PID {pid}) | {proto} | {laddr} -> {raddr}")
    except Exception as e:
        info.append(f"❌ Error al obtener conexiones: {e}")
    if len(info) == 1:
        info.append("✅ No se detectaron conexiones activas fuera de programas conocidos.")
    return "\n".join(info)


def escanear_archivos_sospechosos():
    info = []
    info.append("\n🗂️ Escaneo de archivos sospechosos en carpetas clave:")
    ahora = datetime.now()
    encontrados = []

    def calcular_entropia(data):
        from math import log2
        if not data:
            return 0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        prob = [f / len(data) for f in freq if f]
        return -sum(p * log2(p) for p in prob)

    def tiene_encabezado_pe(ruta):
        try:
            with open(ruta, "rb") as f:
                cabecera = f.read(2)
                return cabecera == b"MZ"
        except:
            return False

    def permisos_y_ubicacion_sospechosos(ruta):
        try:
            ubicacion_sospechosa = any(d.lower() in ruta.lower() for d in ["\\temp", "\\downloads"])
            permisos_lectura = os.access(ruta, os.R_OK)
            return ubicacion_sospechosa or not permisos_lectura
        except:
            return True  # si no podemos acceder, lo consideramos sospechoso

    for carpeta in CARPETAS_CLAVE:
        info.append(f"\n📁 Revisando: {carpeta}")
        if not os.path.exists(carpeta):
            info.append("❌ Carpeta no encontrada.")
            continue

        for root, dirs, files in os.walk(carpeta):
            for archivo in files:
                ruta = os.path.join(root, archivo)
                _, ext = os.path.splitext(archivo)
                if ext.lower() in EXTENSIONES_SOSPECHOSAS:
                    try:
                        modificado = datetime.fromtimestamp(os.path.getmtime(ruta))
                        tamano = os.path.getsize(ruta)
                        sospechosas_criticas = 0
                        razones = []

                        if ahora - modificado < timedelta(days=7):
                            razones.append("modificado recientemente")
                            sospechosas_criticas += 1

                        if tamano < 20 * 1024:
                            razones.append("tamaño muy pequeño")
                            sospechosas_criticas += 1
                        elif tamano > 100 * 1024 * 1024:
                            razones.append("tamaño excesivo")
                            sospechosas_criticas += 1

                        with open(ruta, "rb") as f:
                            contenido = f.read(8192)  # solo analizamos los primeros 8KB para eficiencia
                            entropia = calcular_entropia(contenido)
                            if entropia > 7.5:
                                razones.append(f"entropía alta ({entropia:.2f})")
                                sospechosas_criticas += 1

                        if tiene_encabezado_pe(ruta):
                            razones.append("encabezado PE detectado")
                            sospechosas_criticas += 1

                        if permisos_y_ubicacion_sospechosos(ruta):
                            razones.append("ubicación o permisos sospechosos")

                        # Solo marcar si hay al menos 2 indicadores fuertes
                        if sospechosas_criticas >= 2:
                            encontrados.append((archivo, ruta, modificado, razones))
                    except:
                        continue

    if encontrados:
        for nombre, ruta, fecha, razones in encontrados:
            info.append(f"⚠️ {nombre} | {ruta} | modificado: {fecha.strftime('%Y-%m-%d %H:%M')}")
            info.append(f"    ➤ Razones: {', '.join(razones)}")
    else:
        info.append("✅ No se encontraron archivos sospechosos recientes.")
    return "\n".join(info), encontrados


def obtener_ruta_servicio(nombre_servicio):
    """Obtiene la ruta del ejecutable del servicio desde el registro"""
    import winreg
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\{}".format(nombre_servicio))
        ruta, _ = winreg.QueryValueEx(key, "ImagePath")
        # La ruta puede contener parámetros, limpiamos para obtener solo la ruta del ejecutable
        ruta = ruta.strip('"')
        ruta = re.split(r'\s', ruta)[0]
        return ruta
    except Exception:
        return None


def es_firmado_digitalmente(ruta_archivo):
    """Chequea si un archivo está firmado digitalmente (simplificado)"""
    # Esto requiere pywin32 y puede ser complejo; aquí dejo una comprobación básica que verifica que el archivo exista
    return os.path.exists(ruta_archivo)
    # Nota: para chequeos reales de firma digital se requieren librerías como 'win32crypt' o herramientas externas


def listar_servicios_y_drivers():
    info = []
    info.append("\n🧩 Análisis de servicios y drivers del sistema:")

    lista_negra = ["hack", "cheat", "aimbot", "wallhack", "inject", "trap", "crack"]

    try:
        salida = subprocess.check_output("sc query type= service state= all", shell=True, text=True)
    except Exception as e:
        info.append(f"❌ Error al listar servicios: {e}")
        return "\n".join(info)

    servicios_raw = salida.split("\n\n")
    for servicio_raw in servicios_raw:
        if not servicio_raw.strip():
            continue
        nombre_match = re.search(r"SERVICE_NAME:\s+(\S+)", servicio_raw)
        estado_match = re.search(r"STATE\s+:\s+\d+\s+(\w+)", servicio_raw)
        if not nombre_match or not estado_match:
            continue
        nombre = nombre_match.group(1)
        estado = estado_match.group(1)
        ruta = obtener_ruta_servicio(nombre)

        sospechoso = False
        razon_sospecha = []

        for palabra in lista_negra:
            if palabra in nombre.lower():
                sospechoso = True
                razon_sospecha.append(f"Nombre sospechoso ({palabra})")

        if ruta:
            ruta_lower = ruta.lower()
            if any(x in ruta_lower for x in ["temp", "appdata", "downloads", "user\\"]):
                sospechoso = True
                razon_sospecha.append(f"Ruta sospechosa: {ruta}")

        firmado = es_firmado_digitalmente(ruta) if ruta else False
        if not firmado:
            sospechoso = True
            razon_sospecha.append("No firmado digitalmente o archivo no encontrado")

        resumen = f"🔧 Servicio: {nombre} | Estado: {estado} | Ruta: {ruta or 'Desconocida'}"
        if sospechoso:
            resumen += f"\n    ⚠️ Sospechoso → {'; '.join(razon_sospecha)}"
        else:
            resumen += f"\n    ✅ Sin anomalías detectadas"
        info.append(resumen)

    return "\n".join(info)



if __name__ == "__main__":
    # elevar_permisos()
    if not sysmon_instalado():
        print("\n⚠️ Sysmon no está instalado o activo.")
        respuesta = input("¿Deseas instalar Sysmon automáticamente? (s/n): ").strip().lower()
        if respuesta == 's':
            if instalar_sysmon():
                print("🔁 Reinicia el script para que Sysmon comience a registrar eventos.")
                exit()
        else:
            print("🚫 Se omitirá el análisis avanzado con Sysmon.")

    # print("===== PC Check - Análisis básico de trampas o anomalías =====")

    resultados = []

    resultados.append(system_summary())
    resultados.append(check_suspicious_processes())
    resultados.append(detectar_ejecuciones_desde_red())
    resultados.append(check_recently_installed_programs())
    resultados.append(check_active_connections(known_programs))

    texto_archivos, archivos_json = escanear_archivos_sospechosos()
    resultados.append(texto_archivos)
    guardar_archivos_sospechosos_json(archivos_json)

    resultados.append(listar_servicios_y_drivers())
    resultados.append(userassist_history())
    resultados.append(deteccion_completa_usb())
    resultados.append(leer_eventos_sysmon_procesos_recientes())
    resultados.append(detectar_dispositivos_dma_avanzado())
    resultados.append(verificar_proteccion_dma_kernel())

    todo_el_texto = "\n\n".join(resultados)
    print(todo_el_texto)
    guardar_en_pdf("reporte_seguridad.pdf", todo_el_texto)

    # Parámetros de correo
    correo_destino = "jordyvalenzuela19@gmail.com"

    correo_remitente = "gabriel.vs0604@gmail.com"
    clave_aplicacion = "qsfh vvwn alvj jubx"  # Tu contraseña de aplicación de Gmail
    nombre_pdf = "reporte_seguridad.pdf"

    # Enviar correo
    enviar_pdf_por_correo(correo_destino, nombre_pdf, correo_remitente, clave_aplicacion)
    input("\n⏹️ Presiona Enter para salir...")
