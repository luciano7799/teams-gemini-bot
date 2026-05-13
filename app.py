from flask import Flask, request, jsonify
import os
import hmac
import hashlib
import base64
import re
from google import genai

app = Flask(__name__)

SYSTEM_PROMPT = """Você é um assistente útil integrado ao Microsoft Teams.
Responda de forma clara, objetiva e profissional.
Formate respostas longas em tópicos quando fizer sentido."""


def validate_hmac(body: bytes, auth_header: str | None, security_token: str) -> bool:
    if not auth_header or not auth_header.startswith("HMAC "):
        return False
    received_sig = auth_header[5:]
    key = base64.b64decode(security_token)
    mac = hmac.new(key, body, hashlib.sha256)
    expected_sig = base64.b64encode(mac.digest()).decode()
    return hmac.compare_digest(received_sig, expected_sig)


def strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text).strip()


def call_gemini(user_message: str) -> str:
    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    response = client.models.generate_content(
        model="gemini-1.5-flash",
        contents=[{"role": "user", "parts": [{"text": SYSTEM_PROMPT + "\n\n" + user_message}]}],
    )
    return response.text


@app.route("/webhook", methods=["POST"])
def webhook():
    body = request.get_data()
    security_token = os.environ.get("TEAMS_SECURITY_TOKEN", "")

    if security_token:
        auth_header = request.headers.get("Authorization")
        if not validate_hmac(body, auth_header, security_token):
            return jsonify({"type": "message", "text": "Unauthorized."}), 401

    try:
        data = request.get_json(force=True)
        user_message = strip_html(data.get("text", ""))

        if not user_message:
            return jsonify({"type": "message", "text": "Não entendi. Pode repetir?"})

        reply = call_gemini(user_message)
        return jsonify({"type": "message", "text": reply})

    except Exception as e:
        return jsonify({"type": "message", "text": f"Erro interno: {str(e)}"}), 500


@app.route("/health", methods=["GET"])
def health():
    return "OK", 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
