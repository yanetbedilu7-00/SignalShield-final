from flask import Flask, request, jsonify, send_from_directory
from analyzer import analyze_message

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
        return jsonify({"error": "Paste a message with at least 12 characters so SignalShield has something meaningful to inspect."}), 400
    try:
        result = analyze_message(message, context=context)
        return jsonify(result)
    except Exception as exc:
        app.logger.exception("Analysis failed")
        return jsonify({"error": "The analysis could not be completed. Check the server logs and try again."}), 500

@app.get("/api/health")
def health():
    from analyzer import llm_is_configured
    return jsonify({"status": "ok", "ai_mode_configured": llm_is_configured()})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(__import__("os").environ.get("PORT", "5000")), debug=False)
