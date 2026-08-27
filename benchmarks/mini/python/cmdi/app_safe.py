"""MINI benchmark: python/cmdi (CWE-78) — safe variant（argv 列表、shell=False）。"""
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping_host():
    """Entry point: GET /ping?host=<host>."""
    host = request.args.get("host", "127.0.0.1")
    proc = subprocess.run(  # SAFE: argument list, no shell
        ["ping", "-c", "1", host],
        shell=False,
        capture_output=True,
        text=True,
        check=False,
    )
    return {"stdout": proc.stdout}
