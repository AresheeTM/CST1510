import streamlit as st
import google.generativeai as genai


def _configure():
    api_key = st.secrets.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY missing in st.secrets")
    genai.configure(api_key=api_key)


def gemini_chat_simple(prompt, model="gemini-2.0-flash"):
    _configure()
    model_obj = genai.GenerativeModel(model)
    response = model_obj.generate_content(prompt)
    return response.text


def gemini_stream_generator(prompt, model="gemini-2.0-flash"):
    _configure()
    model_obj = genai.GenerativeModel(model)
    response = model_obj.generate_content(prompt, stream=True)

    for chunk in response:
        if chunk.text:
            yield chunk.text



