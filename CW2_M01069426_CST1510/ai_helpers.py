import os
import streamlit as st
from google import genai

# ---------- SETUP ----------
def make_gemini_client():
    """
    Create a Gemini API client using the key stored in Streamlit secrets.
    """
    api_key = st.secrets["GEMINI_API_KEY"]
    os.environ["GEMINI_API_KEY"] = api_key
    client = genai.Client()
    return client


# ---------- NON-STREAMING CHAT ----------
def gemini_chat_simple(prompt, model="gemini-2.0-flash"):
    """
    Simple non-streaming call to Gemini.
    """
    client = make_gemini_client()
    try:
        response = client.models.generate_content(
            model=model,
            contents=prompt
        )
        return getattr(response, "text", "")
    except Exception as e:
        return f"Gemini Error: {e}"


# ---------- STREAMING CHAT ----------
def gemini_stream_generator(prompt, model="gemini-2.0-flash"):
    """
    Streaming generator that yields partial text chunks.
    """
    client = make_gemini_client()

    # Streaming call
    try:
        stream = client.models.generate_content_stream(
            model=model,
            contents=prompt
        )

        # Stream tokens as they arrive
        for chunk in stream:
            if hasattr(chunk, "text") and chunk.text:
                yield chunk.text

    except Exception as e:
        yield f"[Streaming Error] {e}"
