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
    st.download_button("Download conversation (JSON)", payload, file_name=f"{chat_key}_conversation.json", mime="application/json")

# ----------------------------
# Dashboard Chat
# ----------------------------
def dashboard_chat(page):
    _ensure_session_keys()
    chat_key = _get_chat_key_for_page(page)

    # Ensure system message
    if not any(m["role"]=="system" for m in st.session_state[chat_key]):
        _append_message(chat_key, "system", _make_system_prompt_for(page))

    header_col1, header_col2 = st.columns([0.06,1.0])
    with header_col1:
        # Neon SVG AI icon
        svg_icon = """
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#ff69b4"
             stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="ai-svg-icon">
          <circle cx="12" cy="12" r="10"></circle>
          <path d="M8 12h8"></path>
          <path d="M12 8v8"></path>
        </svg>
        """
        unique_key = f"ai_icon_{page}_{uuid.uuid4().hex}"
        if st.button(svg_icon, key=unique_key):
            st.session_state["show_chat_panel"][page] = not st.session_state["show_chat_panel"].get(page, True)

    with header_col2:
        st.markdown(f"### <span style='color:#ff00ff'>Assistant — {page}</span>", unsafe_allow_html=True)

    # Slide-up panel
    visible = st.session_state["show_chat_panel"].get(page, True)

    # Controls row
    ctrl1, ctrl2, ctrl3, ctrl4 = st.columns([1,1,1,1])
    with ctrl1:
        if st.button("Clear history", key=f"clear_{chat_key}"):
            st.session_state[chat_key] = []
            _append_message(chat_key, "system", _make_system_prompt_for(page))
            st.experimental_rerun()
    with ctrl2:
        if st.button("Download", key=f"dl_{chat_key}"):
            _download_conversation(chat_key)
    with ctrl3:
        if st.button("Set assistant persona", key=f"persona_btn_{page}"):
            st.session_state["show_persona_input"] = not st.session_state.get("show_persona_input", False)
    with ctrl4:
        if st.checkbox("Auto-scroll", value=True, key=f"autoscroll_{page}"):
            pass

    dashboard_chat("Home")

    # Persona input
    if st.session_state.get("show_persona_input", False):
        prompt_text = st.text_area("SYSTEM prompt (assistant persona)", value=_make_system_prompt_for(page), key=f"sys_prompt_{page}")
        if st.button("Save persona", key=f"save_persona_{page}"):
            st.session_state["ai_system_prompt"][page] = prompt_text
            st.session_state[chat_key] = [m for m in st.session_state[chat_key] if m["role"]!="system"]
            _append_message(chat_key, "system", prompt_text)
            st.success("Persona updated.")

    # Chat panel
    if visible:
        st.markdown("---")
        for msg in st.session_state[chat_key]:
            if msg["role"]=="system": continue
            role = "assistant" if msg["role"]=="assistant" else "user"
            with st.chat_message(role):
                st.write(msg["content"])

        # Chat input
        user_msg = st.chat_input("Ask the assistant (press Enter)")
        if user_msg:
            _append_message(chat_key, "user", user_msg)
            with st.chat_message("user"): st.write(user_msg)

            messages_for_ai = [{"role": m["role"], "content": m["content"]} for m in st.session_state[chat_key]]

            # ---------- Trigger typing animation ON ----------
            st.session_state.js_event = "ai_typing_on"
            st.experimental_rerun()

    # AI response
   # Streaming path with synchronized sidebar/main chat
    if st.session_state.get("js_event") == "ai_typing_on" and AI_AVAILABLE and gemini_stream_generator:
        # Rebuild messages in case we were rerun
        messages_for_ai = [{"role": m["role"], "content": m["content"]} for m in st.session_state[chat_key]]
        with st.chat_message("assistant") as main_placeholder:
            placeholder_sidebar = st.sidebar.empty()  # Placeholder in sidebar
            partial = ""
            try:
                for token in gemini_stream_generator(messages_for_ai):
                    partial += token
                    # Update both main chat and sidebar in real-time
                    main_placeholder.markdown(partial + "<span class='typing-dots'></span>", unsafe_allow_html=True)
                    placeholder_sidebar.markdown(partial + "<span class='typing-dots'></span>", unsafe_allow_html=True)
                # Append final message
                _append_message(chat_key, "assistant", partial)
            except Exception as e:
                err = f"Error during streaming: {e}"
                _append_message(chat_key, "assistant", err)
                main_placeholder.markdown(err)
                placeholder_sidebar.markdown(err)
        # Clear the typing event so we don't stream again on next rerun
        st.session_state["js_event"] = None



