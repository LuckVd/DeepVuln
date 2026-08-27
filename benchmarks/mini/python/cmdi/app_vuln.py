"""MINI benchmark: python/cmdi (CWE-78) — vulnerable variant.

链路：HTTP 路由参数（source）→ os.system 拼接命令（sink）。
"""
import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping_host():
    """Entry point: GET /ping?host=<host>."""
    host = request.args.get("host", "127.0.0.1")
    exit_code = os.system("ping -c 1 " + host)  # SINK: command-injection (CWE-78)
    return {"exit_code": exit_code}
