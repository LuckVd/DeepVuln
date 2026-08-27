"""MINI benchmark: python/eval (CWE-95) — vulnerable variant。

链路：HTTP 路由参数（source）→ eval 动态求值（sink）。
"""
from flask import Flask, request

app = Flask(__name__)


@app.route("/calc")
def calc_expr():
    """Entry point: GET /calc?expr=<expression>."""
    expr = request.args.get("expr", "1+1")
    result = eval(expr)  # SINK: code-injection (CWE-95)
    return {"result": repr(result)}
