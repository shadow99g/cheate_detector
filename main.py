from process_scanner import scan_processes
from usb_monitor import list_usb_devices
from network_monitor import check_network_shares
from userassist_scanner import scan_userassist, userassist_history
from usb_execution_scanner import procesos_desde_usb
from sysmon_scanner import leer_eventos_sysmon_procesos_recientes, sysmon_instalado, instalar_sysmon
from connection_checker import check_active_connections
from file_scanner import escanear_archivos_sospechosos


def main():
    print("===== PC Check - Análisis básico de trampas o anomalías =====")
    print("==== Cheat Detector v1 ====\n")

    if not sysmon_instalado():
        print("\n⚠️ Sysmon no está instalado o activo.")
        respuesta = input("¿Deseas instalar Sysmon automáticamente? (s/n): ").strip().lower()
        if respuesta == 's':
            if instalar_sysmon():
                print("🔁 Reinicia el script para que Sysmon comience a registrar eventos.")
                exit()
        else:
            print("🚫 Se omitirá el análisis avanzado con Sysmon.")

    print("[1] Escaneando procesos sospechosos...")
    scan_processes()

    print("\n[2] Detectando unidades USB conectadas...")
    list_usb_devices()

    print("\n[3] Consultando acceso a recursos compartidos...")
    check_network_shares()

    print("\n✅ Análisis completo.")

    # al final del main()

    info_sospechoso,data =escanear_archivos_sospechosos()
    print(info_sospechoso)
    info_connections = check_active_connections()
    print(info_connections)
    print("\n[4] Revisando historial de ejecuciones con UserAssist...")
    scan_userassist()
    print(userassist_history())
    print(procesos_desde_usb())
    print(leer_eventos_sysmon_procesos_recientes())


if __name__ == "__main__":
    main()
