import os
import json


def get_claude_client():
    try:
        from google import genai

        api_key = os.environ.get("GEMINI_API_KEY")

        if not api_key:
            raise ValueError("GEMINI_API_KEY environment variable not set")

        model = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash-lite")
        client = genai.Client(api_key=api_key)

        return {
            "client": client,
            "model": model
        }

    except ImportError:
        raise ImportError(
            "google-genai package not installed. "
            "Run: pip install google-genai"
        )












async def call_claude(
    llm: dict,
    system_prompt: str,
    user_message: str,
    max_tokens: int = 4096
) -> str:

    response = llm["client"].models.generate_content(
        model=llm["model"],
        contents=(
            f"SYSTEM INSTRUCTIONS:\n{system_prompt}\n\n"
            f"USER REQUEST:\n{user_message}"
        ),
        config={
            "max_output_tokens": max_tokens,
            "response_mime_type": "application/json"
        }
    )

    if not response.text:
        raise ValueError("Gemini returned an empty response")

    return response.text

def parse_json_response(text: str) -> dict:
    if not text:
        raise ValueError("Gemini returned an empty response")

    text = text.strip()

    # Remove markdown code fences
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]

    if text.endswith("```"):
        text = text[:-3]

    text = text.strip()

    try:
        result = json.loads(text)

        if not isinstance(result, dict):
            raise ValueError(
                "Gemini response was not a JSON object"
            )

        return result

    except json.JSONDecodeError as e:
        raise ValueError(
            f"Gemini returned invalid JSON: {e}"
        ) from e
