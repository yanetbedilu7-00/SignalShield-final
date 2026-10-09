
import os

from flask import Flask, request, jsonify, send_from_directory
from analyzer import analyze_message, llm_is_configured

app = Flask(__name__)


@app.get("/")
def index():
    return send_from_directory(".", "index.html")


@app.get("/style.css")
def stylesheet():
    return send_from_directory(".", "style.css")


@app.get("/app.js")
def javascript():
    return send_from_directory(".", "app.js")


@app.post("/api/analyze")
def analyze():
    data = request.get_json(silent=True) or {}

    message = str(data.get("message", ""))[:12000]
    context = str(data.get("context", "general"))[:80]

    if len(message.strip()) < 12:
        return jsonify({
            "error": (
                "Paste a message with at least 12 characters so "
                "SignalShield has something meaningful to inspect."
            )
        }), 400

    try:
        result = analyze_message(message, context=context)
        return jsonify(result)

    except Exception:
        app.logger.exception("Analysis failed")
        return jsonify({
            "error": (
                "The analysis could not be completed. "
                "Check the server logs and try again."
            )
        }), 500


@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "ai_mode_configured": llm_is_configured(),
        "api_key_present": bool(os.getenv("OPENAI_API_KEY")),
        "base_url_present": bool(os.getenv("OPENAI_BASE_URL")),
        "model_present": bool(os.getenv("AI_MODEL")),
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )
