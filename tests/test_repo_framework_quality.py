"""STEP 68 — framework route extraction quality."""

from __future__ import annotations

from magic_security.framework_analysis import (
    detect_framework,
    extract_express_routes,
    extract_fastapi_routes,
)


def test_fastapi_route_extraction(tmp_path):
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/items/{item_id}')\n"
        "def read_item(item_id: int): return item_id\n"
        "@app.post('/items')\n"
        "def create_item(): return {}\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    assert detect_framework(tmp_path) == "fastapi"
    routes = extract_fastapi_routes(tmp_path)
    paths = {r.path for r in routes}
    assert "/items/{item_id}" in paths or any("items" in p for p in paths)


def test_express_route_extraction(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"express":"4.18.0"}}',
        encoding="utf-8",
    )
    (tmp_path / "server.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.get('/users/:id', (req,res)=>res.send('ok'));\n"
        "app.post('/users', (req,res)=>res.send('ok'));\n",
        encoding="utf-8",
    )
    assert detect_framework(tmp_path) == "express"
    routes = extract_express_routes(tmp_path)
    assert any("users" in r.path for r in routes)
