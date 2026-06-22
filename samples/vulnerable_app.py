"""INTENTIONALLY VULNERABLE demo target — DO NOT DEPLOY.

A small Flask app with one planted vulnerability per CodeGuard rule, so the
harness has something to find. Run only in an isolated lab. Each issue is
labelled with the rule it should trip.
"""

import hashlib
import logging
import os
import pickle
import sqlite3
import subprocess

import requests
from flask import Flask, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# CG-SECRET-001: hardcoded credential
API_KEY = "DEMO_PLACEHOLDER_not_a_real_secret_0000"


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # CG-INJECT-002: command injection via shell=True with user input
    out = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True)
    return out.stdout


@app.route("/user")
def get_user():
    uid = request.args.get("id", "1")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # CG-SQLI-003: SQL injection via f-string
    cur.execute(f"SELECT name, email FROM users WHERE id = {uid}")
    return str(cur.fetchall())


def hash_password(pw):
    # CG-CRYPTO-004: weak hash for passwords
    return hashlib.md5(pw.encode()).hexdigest()


@app.route("/load")
def load_state():
    blob = request.get_data()
    # CG-DESER-005: insecure deserialization of untrusted input
    state = pickle.loads(blob)
    return str(state)


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    # CG-SSRF-006: SSRF — outbound request to unvalidated user URL
    r = requests.get(url, timeout=5)
    return r.text


@app.route("/checkout", methods=["POST"])
def checkout():
    card = request.form.get("card_number")
    ssn = request.form.get("ssn")
    # CG-PII-007: PII written to logs in plaintext
    logging.info("processing checkout card=%s ssn=%s", card, ssn)
    return "ok"


def run_report(name):
    # CG-INJECT-002: command injection via os.system
    os.system("generate_report " + name)


if __name__ == "__main__":
    # CG-CONFIG-008: debug console enabled
    app.run(host="0.0.0.0", port=5000, debug=True)
