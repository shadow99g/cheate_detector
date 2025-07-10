import wmi

def list_usb_devices():
    c = wmi.WMI()
    removable_drives = c.Win32_LogicalDisk(DriveType=2)  # Tipo 2 = USB

    if not removable_drives:
        print("No se detectaron unidades extraíbles.")
    else:
        for d in removable_drives:
            print(f"Unidad USB: {d.DeviceID} - {d.VolumeName or 'Sin etiqueta'}")
