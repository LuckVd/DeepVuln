"""MINI benchmark: python/eval (CWE-95) — safe variant（ast.literal_eval 白名单求值）。"""
import ast

from flask import Flask, request

app = Flask(__name__)


@app.route("/calc")
def calc_expr():
    """Entry point: GET /calc?expr=<expression>."""
    expr = request.args.get("expr", "1+1")
    result = ast.literal_eval(expr)  # SAFE: literal-only evaluation
    return {"result": repr(result)}
