import subprocess

def check_network_shares():
    try:
        result = subprocess.run(["net", "use"], capture_output=True, text=True)
        if "No hay entradas en la lista" in result.stdout:
            print("No hay recursos de red conectados.")
        else:
            print("Recursos compartidos activos detectados:\n")
            print(result.stdout)
    except Exception as e:
        print(f"Error al consultar recursos compartidos: {e}")
