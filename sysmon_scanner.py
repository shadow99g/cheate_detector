import win32evtlog
from datetime import datetime, timedelta
import sys
import psutil
import ctypes
import os
import zipfile
import urllib.request
import subprocess

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
