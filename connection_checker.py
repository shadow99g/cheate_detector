import psutil
import socket
import wmi
import os
import requests
import ipaddress

known_programs = [
    # Navegadores
    "chrome.exe", "firefox.exe", "msedge.exe",

    # Correo
    "outlook.exe", "thunderbird.exe",

    # IDEs y dev tools
    "code.exe", "pycharm64.exe", "sublime_text.exe", "python.exe", "java.exe",

    # Apps comunes
    "discord.exe", "spotify.exe", "teams.exe", "steam.exe",

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

def es_ip_valida(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def info_ip(ip):
    try:
        if not es_ip_valida(ip):
            return ''
        resp = requests.get(f"https://ipinfo.io/{ip}/json")
        data = resp.json()
        return {
            "ip": ip,
            "city": data["city"],
            "country": data["country"],
            "region": data["region"],
            "org": data["org"],
        }
    except Exception as e:
        print(f"❌ Error al obtener info IP: {e}")

def check_active_connections():
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
                        data = info_ip(raddr)
                        if data:
                            info.append(f"🔗 {pname} (PID {pid}) | {proto} | {laddr} -> {raddr}"
                                        f"\n Organización: {data.get('org')} | Ciudad: {data.get('city')}")
                        else:
                            info.append(f"🔗 {pname} (PID {pid}) | {proto} | {laddr} -> {raddr}")
    except Exception as e:
        info.append(f"❌ Error al obtener conexiones: {e}")
    if len(info) == 1:
        info.append("✅ No se detectaron conexiones activas fuera de programas conocidos.")
    return "\n".join(info)


def detectar_svchost_sospechosos():
    w = wmi.WMI()
    ruta_legitima = os.path.join(os.environ["SystemRoot"], "System32", "svchost.exe").lower()
    sospechosos = []

    print("⏳ Analizando servicios...")

    # Crear un mapa rápido de PID → lista de servicios
    servicios_por_pid = {}
    for s in w.Win32_Service():
        servicios_por_pid.setdefault(s.ProcessId, []).append(s.Name)

    print("🔍 Analizando procesos svchost.exe...")

    for proc in w.Win32_Process(name="svchost.exe"):
        pid = proc.ProcessId
        ruta = (proc.ExecutablePath or "").lower()
        cmd = proc.CommandLine or ""
        servicios = servicios_por_pid.get(pid, [])

        razones = []
        if ruta != ruta_legitima:
            razones.append(f"ruta inesperada: {ruta}")
        if not servicios:
            razones.append("sin servicios asociados")
        if "-k" not in cmd:
            razones.append("línea de comando inusual")

        if razones:
            sospechosos.append({
                "PID": pid,
                "Servicio": servicios,
                "Ruta": ruta,
                "Cmd": cmd,
                "Razones": razones
            })

    # Mostrar resultados
    if sospechosos:
        print("\n🚨 svchost.exe sospechosos detectados:")
        for p in sospechosos:
            print(f"\n🔸 PID: {p['PID']}")
            print(f"   Servicio: {', '.join(p['Servicio'])}")
            print(f"   Ruta: {p['Ruta']}")
            print(f"   Cmd: {p['Cmd']}")
            print(f"   ⚠️ Razones: {', '.join(p['Razones'])}")
    else:
        print("✅ Todas las instancias de svchost.exe parecen legítimas.")
