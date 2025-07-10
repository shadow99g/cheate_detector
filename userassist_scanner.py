import winreg
import codecs
import struct
from datetime import datetime


def rot13(s):
    return codecs.decode(s, 'rot_13')

def filetime_to_dt(filetime_bytes):
    if len(filetime_bytes) != 8:
        return None
    low, high = struct.unpack('<II', filetime_bytes)
    ft = (high << 32) + low
    try:
        return datetime.utcfromtimestamp((ft - 116444736000000000) / 10000000)
    except:
        return None

def scan_userassist():
    print("Analizando programas ejecutados anteriormente (UserAssist)...\n")
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        root = winreg.HKEY_CURRENT_USER
        userassist = winreg.OpenKey(root, key_path)

        for i in range(0, winreg.QueryInfoKey(userassist)[0]):
            guid = winreg.EnumKey(userassist, i)
            guid_key_path = f"{key_path}\\{guid}\\Count"
            try:
                count_key = winreg.OpenKey(root, guid_key_path)
                for j in range(0, winreg.QueryInfoKey(count_key)[1]):
                    value_name, value_data, _ = winreg.EnumValue(count_key, j)
                    decoded_name = rot13(value_name)

                    # Obtener número de ejecuciones y fecha
                    run_count = struct.unpack("<i", value_data[4:8])[0]
                    last_run_time = filetime_to_dt(value_data[60:68])

                    if run_count > 0:
                        print(f"[+] {decoded_name}")
                        print(f"    - Ejecutado: {run_count} veces")
                        if last_run_time:
                            print(f"    - Última vez: {last_run_time}")
            except Exception as e:
                continue

    except Exception as e:
        print(f"Error al leer UserAssist: {e}")

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