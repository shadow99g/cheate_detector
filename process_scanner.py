import psutil
import json
import os


def load_suspects():
    suspects_path = os.path.join("data", "suspects.json")
    if os.path.exists(suspects_path):
        with open(suspects_path, "r") as f:
            return json.load(f)
    return []


def scan_processes():
    keywords = load_suspects()
    found = False

    # Convertir la lista a minúsculas para comparación exacta
    sospechosos = set(name.lower() for name in keywords)
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pname = proc.info['name'].lower()
            # Comparar nombre exacto del ejecutable
            if pname in sospechosos:
                print(f"⚠️  Proceso sospechoso detectado: {pname} (PID: {proc.pid})")
                found = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if not found:
        print("✅ No se detectaron procesos sospechosos.")
