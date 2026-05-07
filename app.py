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

    if "pdf" not in request.files:
        return jsonify({
            "error": "Nenhum arquivo PDF enviado. Use o campo 'pdf'."
        }), 400

    pdf_file = request.files["pdf"]

    if pdf_file.filename == "":
        return jsonify({
            "error": "Arquivo sem nome."
        }), 400

    if not pdf_file.filename.lower().endswith(".pdf"):
        return jsonify({
            "error": "O arquivo precisa ser PDF."
        }), 400

    content = pdf_file.read()

    return jsonify({
        "message": "PDF recebido com sucesso.",
        "filename": pdf_file.filename,
        "size_bytes": len(content)
    })
