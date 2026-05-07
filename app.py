from flask import Flask, request, jsonify
import os
import hmac

app = Flask(__name__)

API_TOKEN = os.getenv("SIGNER_API_TOKEN")


@app.get("/")
def index():
    return jsonify({
        "status": "online",
        "service": "pdf-signer"
    })


@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "pdf-signer",
        "token_loaded": API_TOKEN is not None
    })


@app.post("/sign")
def sign_pdf():
    if not API_TOKEN:
        return jsonify({
            "error": "SIGNER_API_TOKEN não configurado no servidor."
        }), 500

    token = request.headers.get("X-Signer-Token")

    if not token or not hmac.compare_digest(token, API_TOKEN):
        return jsonify({
            "error": "Unauthorized"
        }), 401

    return jsonify({
        "message": "Serviço de assinatura funcionando. Endpoint /sign recebido com sucesso."
    })
