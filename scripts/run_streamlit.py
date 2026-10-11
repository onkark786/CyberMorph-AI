import os
import socket
import sys
from pathlib import Path

# Find a free TCP port
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
addr, port = s.getsockname()
s.close()

print(f"Selected free port: {port}")

# Build command to run Streamlit with chosen port
cmd = [sys.executable, "-m", "streamlit", "run", "app.py", "--server.address", "127.0.0.1", "--server.port", str(port), "--server.headless", "true"]
print("Launching Streamlit with:", " ".join(cmd))

# Ensure the project's root is on PYTHONPATH and set cwd so `import src` resolves
project_root = Path(__file__).resolve().parents[1]
os.environ.setdefault("PYTHONPATH", os.environ.get("PYTHONPATH", ""))
if str(project_root) not in os.environ["PYTHONPATH"]:
	os.environ["PYTHONPATH"] = str(project_root) + os.pathsep + os.environ["PYTHONPATH"]

# Change working directory to project root before exec
os.chdir(project_root)

# Execute Streamlit with the updated environment
os.execv(sys.executable, cmd)
