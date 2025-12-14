import streamlit as st
from datetime import datetime
from ai_chatbot import dashboard_chat

def ai_sidebar(page_name):
    """
    Floating collapsible AI Assistant in the sidebar
    """
    if "show_ai" not in st.session_state:
        st.session_state["show_ai"] = False

    # Toggle button as floating icon
    st.markdown("""
        <style>
        .ai-btn {
            position: relative;
            display: inline-block;
            cursor: pointer;
            font-size: 1.8em;
            color: #ff69b4;
            margin-bottom: 5px;
        }
        .ai-btn:hover {
            color: #ff1493;
        }
        .ai-container {
            background-color: #1b0f2e;
            padding: 10px;
            border-radius: 10px;
            margin-top: 5px;
        }
        </style>
    """, unsafe_allow_html=True)

    # Button to toggle AI
    if st.button("🤖 AI Assistant"):
        st.session_state["show_ai"] = not st.session_state["show_ai"]

    # Display AI panel if toggled
    if st.session_state["show_ai"]:
        st.markdown('<div class="ai-container">', unsafe_allow_html=True)
        dashboard_chat(page_name)
        st.markdown('</div>', unsafe_allow_html=True)
