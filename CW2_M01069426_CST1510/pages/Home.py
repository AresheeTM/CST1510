# ----------------------------
# Home Page — Welcome + Animated AI (Gemini)
# ----------------------------
import streamlit as st
from datetime import datetime

# ----------------------------
# Page setup
# ----------------------------
st.set_page_config(page_title="Intelligence Platform - Home", layout="wide")
username = st.session_state.get("username", "Guest")

# ----------------------------
# Gemini API
# ----------------------------
try:
    from ai_helpers import gemini_chat_simple, gemini_stream_generator
    AI_AVAILABLE = True
except Exception:
    gemini_chat_simple = None
    gemini_stream_generator = None
    AI_AVAILABLE = False

# ----------------------------
# Initialize chat history
# ----------------------------
if "chat_history_home" not in st.session_state:
    st.session_state["chat_history_home"] = []

if "show_ai_chat" not in st.session_state:
    st.session_state["show_ai_chat"] = False

# ----------------------------
# CSS: Animated AI robot, typing, glass card, neon, animations
# ----------------------------
st.markdown("""
<style>
body {
    background: linear-gradient(135deg, #0f0a1f, #1b0f2e);
    color: #f5c1f5;
    font-family: 'Segoe UI', sans-serif;
}
.glass-card {
    background: rgba(255,255,255,0.05);
    backdrop-filter: blur(15px);
    border-radius: 20px;
    border: 1px solid rgba(255,255,255,0.2);
    padding: 30px;
    margin: 30px auto;
    text-align: center;
    max-width: 600px;
    transition: all 0.4s ease, transform 0.3s ease;
    box-shadow: 0 0 20px #ff00ff20;
    /* Floating + subtle rotate animation continuously */
    animation: floatRotate 6s ease-in-out infinite;
}
.glass-card:hover {
    transform: rotateY(3deg) rotateX(2deg) translateY(-5px);
}

@keyframes floatRotate {
    0% { transform: translateY(0px) rotate(0deg); }
    25% { transform: translateY(-5px) rotate(-1deg); }
    50% { transform: translateY(-10px) rotate(1deg); }
    75% { transform: translateY(-5px) rotate(-1deg); }
    100% { transform: translateY(0px) rotate(0deg); }
}

h1 {
    text-shadow: 0 0 10px #ff00ff, 0 0 20px #ff00ff;
}

/* AI robot button */
.ai-robot {
    position: fixed;
    bottom: 30px;
    right: 30px;
    width: 80px;
    height: 80px;
    cursor: pointer;
    z-index: 9999;
    border-radius: 50%;
    background: url('images/robot.gif') no-repeat center;
    background-size: contain;
    animation: bounce 2s infinite, glow 3s infinite;
    transition: transform 0.3s ease;
}
.ai-robot:hover {
    transform: scale(1.1);
}
@keyframes bounce {
    0%,100% { transform: translateY(0);}
    50% { transform: translateY(-10px);}
}
@keyframes glow {
    0%,100% { box-shadow: 0 0 10px #ff00ff; }
    50% { box-shadow: 0 0 30px #ff00ff; }
}

/* AI chat panel */
.ai-chat-panel {
    position: fixed;
    bottom: 120px;
    right: 30px;
    width: 350px;
    max-height: 500px;
    background: rgba(0,0,0,0.85);
    border-radius: 15px;
    padding: 15px;
    z-index: 9999;
    overflow-y: auto;
    box-shadow: 0 0 40px #ff00ff;
    color: #fff;
    display: flex;
    flex-direction: column;
    transform: translateY(100%);
    opacity: 0;
    transition: transform 0.5s ease, opacity 0.5s ease;
}
.ai-chat-panel.show {
    transform: translateY(0);
    opacity: 1;
}

.ai-msg { margin: 5px 0; padding: 5px 10px; border-radius: 10px; }
.ai-msg.user { background: #ff00ff33; text-align: right; }
.ai-msg.bot { background: #00ffff33; text-align: left; }
.ai-typing::after {
    content: '';
    display: inline-block;
    width: 10px;
    height: 10px;
    margin-left: 5px;
    border-radius: 50%;
    background: #00ffff;
    animation: blink 1s infinite;
}
@keyframes blink {
    0%,50%,100% { opacity: 0; }
    25%,75% { opacity: 1; }
}
</style>
""", unsafe_allow_html=True)

# ----------------------------
# Welcome card
# ----------------------------
st.markdown(f"""
<div class="glass-card">
    <h1>Welcome, <span style="color:#ff00ff">{username}</span>!</h1>
    <p>This is your intelligence platform dashboard. Use the AI assistant for guidance and support.</p>
</div>
""", unsafe_allow_html=True)

# ----------------------------
# AI Robot Icon
# ----------------------------
st.markdown("""
<div class="ai-robot" id="ai-robot" onclick="toggleChat()"></div>
<div class="ai-chat-panel" id="ai-chat-panel"></div>

<script>
function toggleChat(){
    const panel = document.getElementById('ai-chat-panel');
    panel.classList.toggle('show');
}
</script>
""", unsafe_allow_html=True)

# ----------------------------
# Chat messages container
# ----------------------------
chat_container = st.container()
for msg in st.session_state["chat_history_home"]:
    style = "user" if msg["role"]=="user" else "bot"
    chat_container.markdown(f'<div class="ai-msg {style}">{msg["role"].capitalize()}: {msg["content"]}</div>', unsafe_allow_html=True)


# ----------------------------
# Chat input and Gemini AI response
# ----------------------------
input_text = st.text_input("Type a message:", key="home_ai_input")
if input_text:
    st.session_state["chat_history_home"].append({"role":"user","text":input_text})

    # --- GEMINI AI RESPONSE ---
    if AI_AVAILABLE and gemini_stream_generator:
        reply = ""
        for token in gemini_stream_generator(input_text):
            reply += token
        st.session_state["chat_history_home"].append({"role":"bot","text":reply})
    elif AI_AVAILABLE and gemini_chat_simple:
        reply = gemini_chat_simple(input_text)
        st.session_state["chat_history_home"].append({"role":"bot","text":reply})
    else:
        st.session_state["chat_history_home"].append({"role":"bot","text":"AI not available."})

    st.experimental_rerun()


# AI Chatbot for this dashboard
# Call chatbot without the undefined 'page' variable; pass a page name or context if required by your chatbot implementation
def dashboard_chat(page: str = "home"):
    """Minimal dashboard_chat stub to avoid undefined function errors; replace with your chatbot implementation."""
    if AI_AVAILABLE:
        st.write(f"AI chatbot is available for page: {page}. Use the input box above to send messages.")
    else:
        st.write("AI chatbot is not available. Please configure the Gemini helpers or check your connection.")

# Call the defined chatbot function with an explicit page/context
dashboard_chat()








