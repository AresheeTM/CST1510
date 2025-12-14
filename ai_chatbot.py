# ai_chatbot.py
# ============================
# AI Chatbot Engine for Streamlit
# Requirements:
#  - ai_helpers must provide gemini_chat_simple & gemini_stream_generator
#  - API keys in ai_helpers or st.secrets (DO NOT hardcode)
# ============================

import streamlit as st
from datetime import datetime
import json
import uuid

# ----------------------------
# Try to import Gemini helpers
# ----------------------------
try:
    from ai_helpers import gemini_chat_simple, gemini_stream_generator
    AI_AVAILABLE = True
except Exception:
    gemini_chat_simple = None
    gemini_stream_generator = None
    AI_AVAILABLE = False



# ----------------------------
# Page mapping to chat keys
# ----------------------------
PAGE_KEY_MAP = {
    "Cyber": "chat_history_cyber",
    "Data": "chat_history_data",
    "IT": "chat_history_it",
    "Cyber Incidents": "chat_history_cyber",
    "Datasets": "chat_history_data",
    "IT Tickets": "chat_history_it",
    "Tickets": "chat_history_it"
}

# ----------------------------
# Session helpers
# ----------------------------
def _ensure_session_keys():
    for v in PAGE_KEY_MAP.values():
        if v not in st.session_state:
            st.session_state[v] = []
    if "show_chat_panel" not in st.session_state:
        st.session_state["show_chat_panel"] = {}
    if "ai_system_prompt" not in st.session_state:
        st.session_state["ai_system_prompt"] = {}

def _get_chat_key_for_page(page):
    return PAGE_KEY_MAP.get(page, f"chat_history_{page.lower().replace(' ','_')}")

def _make_system_prompt_for(page):
    default = f"You are a concise analytics assistant for the {page} dashboard. Answer succinctly, include bullet suggestions when helpful, and ask clarifying questions if needed."
    return st.session_state["ai_system_prompt"].get(page, default)

def _append_message(chat_key, role, content):
    st.session_state[chat_key].append({
        "role": role,
        "content": content,
        "time": datetime.utcnow().isoformat()
    })

def _download_conversation(chat_key):
    payload = json.dumps(st.session_state[chat_key], indent=2)
    st.download_button(
        "Download conversation (JSON)", 
        payload, 
        file_name=f"{chat_key}_conversation.json", 
        mime="application/json"
    )

st.write("AI_AVAILABLE:", AI_AVAILABLE)
st.write("gemini_stream_generator callable?", callable(gemini_stream_generator))

# ---------------------------
# Dashboard Chat
# ---------------------------
def dashboard_chat(page):
    _ensure_session_keys()
    chat_key = _get_chat_key_for_page(page)

    # Ensure system message exists
    if not any(m["role"]=="system" for m in st.session_state[chat_key]):
        _append_message(chat_key, "system", _make_system_prompt_for(page))

    # ===== HEADER =====
    header_col1, header_col2 = st.columns([0.06,1.0])
    with header_col1:
        pass
    with header_col2:
        st.markdown(f"### <span style='color:#ff00ff'>Assistant — {page}</span>", unsafe_allow_html=True)

    # Slide-up panel visibility
    visible = st.session_state["show_chat_panel"].get(page, True)

    # ===== CONTROLS =====
    ctrl1, ctrl2, ctrl3, ctrl4 = st.columns([1,1,1,1])
    with ctrl1:
     if st.button("Clear history", key=f"clear_{chat_key}_{page.replace(' ','_')}_{uuid.uuid4().hex}"):
        st.session_state[chat_key] = []
        _append_message(chat_key, "system", _make_system_prompt_for(page))
        st.session_state["force_rerun"] = True
        st.stop()


    with ctrl2:
        if st.button("Download", key=f"dl_{chat_key}_{page.replace(' ','_')}"):
            _download_conversation(chat_key)

    with ctrl3:
        if st.button("Set assistant persona", key=f"persona_btn_{page.replace(' ','_')}"):
            st.session_state["show_persona_input"] = not st.session_state.get("show_persona_input", False)

    with ctrl4:
        if st.checkbox("Auto-scroll", value=True, key=f"autoscroll_{page.replace(' ','_')}"):
            pass

    # ===== PERSONA INPUT =====
    if st.session_state.get("show_persona_input", False):
        prompt_text = st.text_area(
            "SYSTEM prompt (assistant persona)",
            value=_make_system_prompt_for(page),
            key=f"sys_prompt_{page.replace(' ','_')}"
        )
        if st.button("Save persona", key=f"save_persona_{page.replace(' ','_')}"):
            st.session_state["ai_system_prompt"][page] = prompt_text
            st.session_state[chat_key] = [m for m in st.session_state[chat_key] if m["role"]!="system"]
            _append_message(chat_key, "system", prompt_text)
            st.success("Persona updated.")

    # ===== CHAT PANEL =====
    if visible:
        st.markdown("---")
        for msg in st.session_state[chat_key]:
            if msg["role"]=="system":
                continue
            role = "assistant" if msg["role"]=="assistant" else "user"
            with st.chat_message(role):
                st.write(msg["content"])

        # Chat input with unique key per page
        user_msg = st.chat_input(
        "Ask the assistant (press Enter)", 
        key=f"chat_input_{page.replace(' ','_')}"  # stable key per page
)

    if user_msg:
        # 1. Save & show user message
        _append_message(chat_key, "user", user_msg)
        with st.chat_message("user"):
            st.write(user_msg)

        # 2. Build system prompt
        system_prompt = _make_system_prompt_for(page)

        # 3. Build full prompt text (Gemini needs TEXT, not list)
        full_prompt = system_prompt + "\n\n"
        for m in st.session_state[chat_key]:
            full_prompt += f"{m['role'].upper()}: {m['content']}\n"

                # 4. Stream Gemini response (SAFE)
        with st.chat_message("assistant"):
            placeholder = st.empty()
            assistant_reply = ""

            if not AI_AVAILABLE or gemini_stream_generator is None:
                assistant_reply = (
                    "⚠️ AI assistant is unavailable.\n\n"
                    "Please check:\n"
                    "- Gemini SDK installed\n"
                    "- GEMINI_API_KEY in st.secrets\n"
                    "- ai_helpers.py imports correctly"
                )
                placeholder.markdown(assistant_reply)
            else:
                try:
                    for token in gemini_stream_generator(full_prompt):
                        assistant_reply += token
                        placeholder.markdown(assistant_reply)
                except Exception as e:
                    assistant_reply = f"❌ Gemini error: {e}"
                    placeholder.markdown(assistant_reply)

        # 5. Save assistant reply
        _append_message(chat_key, "assistant", assistant_reply)













