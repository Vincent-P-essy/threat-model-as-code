"""A cut-down version of the service the model describes.

Deliberately out of step with examples/payments-api.yaml in one place, so
`tmac drift` has something real to find.
"""

import os

import psycopg2
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

DB_URL = os.environ.get("DATABASE_URL", "postgresql://payments@core-db:5432/payments")


@app.post("/v1/payments")
def submit_payment():
    """Modelled as flow f_submit."""
    instruction = request.get_json()
    return jsonify({"status": "accepted", "amount_cents": instruction["amount_cents"]}), 202


@app.get("/v1/payments/<payment_id>")
def payment_status(payment_id: str):
    """Modelled as part of f_submit."""
    return jsonify({"id": payment_id, "state": "settled"})


@app.post("/internal/reconciliation/callback")
def reconciliation_callback():
    """Modelled as flow f_vendor_return."""
    return jsonify({"ok": True})


@app.post("/ops/limits/override")
def override_limit():
    """NOT in the threat model.

    Added during an incident, never modelled. It changes payment limits and it
    is the kind of endpoint a threat model is supposed to know about - which is
    the whole point of the drift check.
    """
    return jsonify({"ok": True})


def notify_vendor(payload: dict) -> None:
    requests.post("https://api.reconciliation-vendor.example/v2/positions", json=payload)


def connect():
    return psycopg2.connect(DB_URL)
