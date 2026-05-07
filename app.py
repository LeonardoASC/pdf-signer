from flask import Flask, request, jsonify, send_file
import os
import hmac
import base64
from io import BytesIO
from werkzeug.utils import secure_filename

from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter


app = Flask(__name__)

API_TOKEN = os.getenv("SIGNER_API_TOKEN")
CERT_PFX_BASE64 = os.getenv("CERT_PFX_BASE64")
CERT_PASSWORD = os.getenv("CERT_PASSWORD")


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
        "token_loaded": API_TOKEN is not None,
        "cert_loaded": CERT_PFX_BASE64 is not None,
        "cert_password_loaded": CERT_PASSWORD is not None
    })


def validate_token():
    if not API_TOKEN:
        return False

    token = request.headers.get("X-Signer-Token")

    if not token:
        return False

    return hmac.compare_digest(token, API_TOKEN)


def load_signer():
    if not CERT_PFX_BASE64:
        raise RuntimeError("CERT_PFX_BASE64 não configurado.")

    if not CERT_PASSWORD:
        raise RuntimeError("CERT_PASSWORD não configurado.")

    pfx_bytes = base64.b64decode(CERT_PFX_BASE64)

    signer = signers.SimpleSigner.load_pkcs12_data(
        pkcs12_bytes=pfx_bytes,
        passphrase=CERT_PASSWORD.encode("utf-8"),
        other_certs=()
    )

    if signer is None:
        raise RuntimeError("Não foi possível carregar o certificado PFX.")

    return signer


@app.post("/sign")
def sign_pdf():
    if not validate_token():
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

    try:
        original_filename = secure_filename(pdf_file.filename)
        input_pdf_bytes = pdf_file.read()

        signer = load_signer()

        input_stream = BytesIO(input_pdf_bytes)
        output_stream = BytesIO()

        writer = IncrementalPdfFileWriter(input_stream)

        signature_meta = signers.PdfSignatureMetadata(
            field_name="Signature1",
            md_algorithm="sha256"
        )

        pdf_signer = signers.PdfSigner(
            signature_meta=signature_meta,
            signer=signer
        )

        pdf_signer.sign_pdf(
            writer,
            output=output_stream
        )

        output_stream.seek(0)

        signed_filename = f"assinado-{original_filename}"

        return send_file(
            output_stream,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=signed_filename
        )

    except Exception as e:
        return jsonify({
            "error": "Erro ao assinar PDF.",
            "details": str(e)
        }), 500
