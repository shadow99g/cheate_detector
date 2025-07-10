from datetime import datetime, timedelta
import os

# Carpetas típicas para buscar trampas
CARPETAS_CLAVE = [
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~\\AppData\\Local\\Temp")
]
# Puedes ajustar esto
EXTENSIONES_SOSPECHOSAS = [".exe", ".bat", ".ps1", ".vbs", ".jar", ".scr", ".com"]


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
