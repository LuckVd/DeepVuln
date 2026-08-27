"""MINI benchmark: python/sqli (CWE-89) — safe variant（参数化查询）。

期望：任何引擎都不应在此文件产出 finding（FP 对照样本）。
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
    query = "SELECT username FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))  # SAFE: parameterized query
    row = cursor.fetchone()
    conn.close()
    return {"username": row[0] if row else None}
