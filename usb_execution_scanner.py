import ctypes
import psutil

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

def procesos_desde_usb():
    info = []
    info.append("\n💾 Procesos ejecutados desde unidades extraíbles:")
    usb_drives = obtener_unidades_removibles()
    if not usb_drives:
        info.append("ℹ️ No se detectaron unidades extraíbles activas.")
        return "\n".join(info)

    encontrados = False
    for proc in psutil.process_iter(['pid', 'exe', 'name']):
        try:
            exe_path = proc.info['exe']
            if exe_path and any(exe_path.lower().startswith(drive.lower()) for drive in usb_drives):
                info.append(f"⚠️ {proc.info['name']} (PID {proc.pid}) desde {exe_path}")
                encontrados = True
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            continue

    if not encontrados:
        info.append("✅ No se detectaron procesos ejecutados desde unidades extraíbles.")
    return "\n".join(info)