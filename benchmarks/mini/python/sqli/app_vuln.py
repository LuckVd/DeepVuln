"""MINI benchmark: python/sqli (CWE-89) — vulnerable variant.

模式来源：SecurityEval / django.nV 同型 taint 流。
链路：HTTP 路由参数（source）→ 字符串拼接 SQL（sink），无参数化。
"""
from flask import Flask, request
import sqlite3

app = Flask(__name__)
DB_PATH = "users.db"


@app.route("/user")
def get_user():
    """Entry point: GET /user?id=<uid>."""
    user_id = request.args.get("id", "")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = "SELECT username FROM users WHERE id = '%s'" % user_id
    cursor.execute(query)  # SINK: sql-injection (CWE-89)
    row = cursor.fetchone()
    conn.close()
    return {"username": row[0] if row else None}
