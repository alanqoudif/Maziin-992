"""
Gemini AI Chat Assistant
Provides a chat interface for security analysts to ask about vulnerabilities,
attack techniques, and remediation steps.
"""
import json
import requests
from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required

ai_chat_bp = Blueprint("ai_chat", __name__)

_SYSTEM_PROMPT = """You are an expert cybersecurity assistant integrated into the Tadamun Smart City Security Operations Center (SOC) dashboard.

Your role:
- Help security analysts understand vulnerabilities, CVEs, and attack techniques
- Provide clear, actionable remediation steps
- Explain MITRE ATT&CK tactics and techniques in plain language
- Give context about attack severity and real-world impact
- Suggest detection methods and defensive controls

Guidelines:
- Be concise but thorough — analysts need fast, accurate answers
- Always mention CVSS score context when discussing vulnerabilities
- Format responses with clear sections when appropriate (use markdown headings)
- If asked about a specific CVE, include: description, affected software, CVSS score, exploitation status, and patch availability
- When listing steps, use numbered lists for ordered actions and bullet points for options
- Do not generate or explain actual exploit code; focus on defense and understanding

Respond in the same language the user writes in (Arabic or English)."""


def _call_gemini(messages: list[dict], api_key: str, model: str) -> str:
    """
    Call the Gemini REST API.
    messages: list of {"role": "user"|"model", "parts": [{"text": "..."}]}
    """
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model}:generateContent?key={api_key}"
    )

    payload = {
        "system_instruction": {
            "parts": [{"text": _SYSTEM_PROMPT}]
        },
        "contents": messages,
        "generationConfig": {
            "temperature": 0.4,
            "maxOutputTokens": 1024,
        },
    }

    try:
        resp = requests.post(url, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        # Extract text from response
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except requests.exceptions.HTTPError as e:
        # Try to extract Gemini error message
        try:
            err_body = e.response.json()
            err_msg = err_body.get("error", {}).get("message", str(e))
        except Exception:
            err_msg = str(e)
        raise ValueError(f"Gemini API error: {err_msg}") from e
    except requests.exceptions.Timeout:
        raise ValueError("Gemini API timed out. Please try again.")
    except Exception as e:
        raise ValueError(f"Failed to reach Gemini API: {e}") from e


@ai_chat_bp.route("/ai-chat")
@login_required
def chat_page():
    """Render the AI chat interface."""
    initial_question = request.args.get("q", "")
    context = request.args.get("ctx", "")  # optional vulnerability context
    return render_template(
        "ai_chat/index.html",
        initial_question=initial_question,
        context=context,
    )


@ai_chat_bp.route("/api/v1/ai/chat", methods=["POST"])
@login_required
def chat_api():
    """
    POST /api/v1/ai/chat
    Body: {
        "message": "user message",
        "history": [{"role": "user"|"model", "text": "..."}],  # optional
        "context": "optional vulnerability context injected as system note"
    }
    Response: {"reply": "...", "model": "..."}
    """
    data = request.get_json(silent=True) or {}
    user_message = (data.get("message") or "").strip()
    history = data.get("history") or []
    context = (data.get("context") or "").strip()

    if not user_message:
        return jsonify({"error": "Message cannot be empty"}), 400

    api_key = current_app.config.get("GEMINI_API_KEY", "")
    model = current_app.config.get("GEMINI_MODEL", "gemini-2.0-flash-lite")

    if not api_key:
        return jsonify({"error": "Gemini API key not configured"}), 500

    # Build conversation history in Gemini format
    contents = []
    for turn in history:
        role = "user" if turn.get("role") == "user" else "model"
        contents.append({"role": role, "parts": [{"text": turn.get("text", "")}]})

    # If there's vulnerability context, prepend it to the user's message
    final_message = user_message
    if context:
        final_message = f"[Context about the vulnerability/topic I'm asking about]\n{context}\n\n[My question]\n{user_message}"

    contents.append({"role": "user", "parts": [{"text": final_message}]})

    try:
        reply = _call_gemini(contents, api_key, model)
        return jsonify({"reply": reply, "model": model})
    except ValueError as e:
        return jsonify({"error": str(e)}), 502
