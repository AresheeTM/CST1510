# streamlit_app.py
import streamlit as st
import pandas as pd
import bcrypt
import os
import numpy as np
import plotly.express as px
from datetime import datetime, timedelta
from pathlib import Path

# AI helpers (make sure ai_helpers.py is in the same folder)
try:
    from ai_helpers import gemini_chat_simple, gemini_stream_generator
    AI_AVAILABLE = True
except Exception as e:
    gemini_chat_simple = None
    gemini_stream_generator = None
    AI_AVAILABLE = False
    st.warning("ai_helpers import failed. Make sure ai_helpers.py exists and google-genai is installed.")

# ----------------------------
# Config & Paths
# ----------------------------
BASE = Path(__file__).parent
DATA_DIR = BASE / "DATA"
USERS_CSV = BASE / "users.csv"

st.set_page_config(page_title="Intelligence Platform", layout="wide", initial_sidebar_state="expanded")

# ----------------------------
# Dark theme CSS
# ----------------------------
dark_css = """
<style>
.reportview-container, .main, .block-container { background-color: #0f1724 !important; color: #e6eef6 !important; }
.sidebar .sidebar-content { background-color: #071127 !important; }
h1, h2, h3, h4, h5, h6 { color: #e6eef6 !important; }
.stDataFrame table { color: #e6eef6 !important; }
.stButton>button, .stSelectbox, .stTextInput { background-color: #0b1220 !important; color: #e6eef6 !important; }
</style>
"""
st.markdown(dark_css, unsafe_allow_html=True)

# ----------------------------
# User auth helpers
# ----------------------------
def load_users():
    if USERS_CSV.exists():
        try:
            return pd.read_csv(USERS_CSV)
        except Exception:
            return pd.DataFrame(columns=["username", "password", "role"])
    else:
        return pd.DataFrame(columns=["username", "password", "role"])

def save_user(username, password, role):
    users = load_users()
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    new_user = pd.DataFrame([[username, hashed_pw, role]], columns=["username", "password", "role"])
    users = pd.concat([users, new_user], ignore_index=True)
    users.to_csv(USERS_CSV, index=False)

# ----------------------------
# Session defaults
# ----------------------------
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
if "username" not in st.session_state:
    st.session_state["username"] = None
if "show_chat" not in st.session_state:
    st.session_state["show_chat"] = True

# Ensure chat histories exist per dashboard
for k in ("chat_history_cyber", "chat_history_data", "chat_history_it"):
    if k not in st.session_state:
        st.session_state[k] = []

# ----------------------------
# Sidebar Navigation
# ----------------------------
st.sidebar.title("Navigation")
page = st.sidebar.selectbox(
    "Choose page",
    ["Login", "Home", "Tickets", "Datasets", "Cyber Incidents", "Users", "Cyber", "Data", "IT"]
)

# Protect pages behind login (except Login page)
if not st.session_state["logged_in"] and page != "Login":
    st.warning("Please login to access the platform.")
    st.stop()

# ----------------------------
# Login / Register page
# ----------------------------
if page == "Login":
    st.title("User Login")

    menu = ["Login", "Register"]
    choice = st.radio("Select an option:", menu)

    if choice == "Login":
        st.subheader("Login to your account")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            users = load_users()
            if username in users["username"].values:
                stored_pw = users.loc[users["username"] == username, "password"].iloc[0]
                if bcrypt.checkpw(password.encode(), stored_pw.encode()):
                    st.success(f"Logged in successfully as {username}")
                    st.session_state["logged_in"] = True
                    st.session_state["username"] = username
                else:
                    st.error("Incorrect password.")
            else:
                st.error("Username not found.")

    elif choice == "Register":
        st.subheader("Create a new account")
        username = st.text_input("Choose a username")
        password = st.text_input("Choose a password", type="password")
        role = st.selectbox("Register as:", ["Cybersecurity", "Data Science", "IT Operations"])

        if st.button("Register"):
            users = load_users()
            if username in users["username"].values:
                st.error("Username already exists.")
            else:
                save_user(username, password, role)
                st.success("Account created successfully! Please login.")

# ----------------------------
# Home page
# ----------------------------
elif page == "Home":
    st.title("Welcome to the Intelligence Platform")
    st.markdown(f"Hello, **{st.session_state['username']}**!")
    st.markdown("""
    **This platform allows you to:**
    - View and analyze IT Tickets
    - Explore Datasets
    - Monitor Cyber Incidents
    - Manage Users

    Use the sidebar to navigate through pages.
    """)

# ----------------------------
# Tickets / Incidents / Datasets / Users pages (placeholders)
# ----------------------------
elif page == "Tickets":
    st.title("Tickets")
    st.write("Place your tickets dashboard content here.")

elif page == "Datasets":
    st.title("Datasets")
    st.write("Place your datasets exploration UI here.")

elif page == "Cyber Incidents":
    st.title("Cyber Incidents")
    st.write("Place your cyber incidents dashboard here.")

elif page == "Users":
    st.title("User Management")
    st.write("Manage users here.")
    users = load_users()
    st.dataframe(users)

# ----------------------------
# AI Dashboards (Cyber, Data, IT) with chat + Plotly chart
# ----------------------------
else:
    # pages: "Cyber", "Data", "IT"
    st.title(page)

    # Simple Plotly sample chart (replace with your real analytics)
    def show_plotly_chart():
        df = pd.DataFrame({
            "category":["A","B","C","A","B","C"],
            "value":[10,20,30,15,25,35],
            "time":["2025-01-01","2025-01-02","2025-01-03","2025-01-04","2025-01-05","2025-01-06"]
        })
        fig = px.line(df, x="time", y="value", color="category", title="Sample Incident Trend")
        st.plotly_chart(fig, use_container_width=True)

    show_plotly_chart()

    # Robot icon / chat toggle (small column for icon)
    left_col, right_col = st.columns([1, 11])
    with left_col:
        if st.button("🤖"):
            st.session_state["show_chat"] = not st.session_state["show_chat"]

    # Map page to session_state key for chat history
    page_chat_key = {
        "Cyber": "chat_history_cyber",
        "Data": "chat_history_data",
        "IT": "chat_history_it"
    }
    key = page_chat_key.get(page, None)

    # Chat UI
    if key:
        if st.session_state.get("show_chat", True):
            st.markdown("### Assistant")
            # Render existing chat history
            for msg in st.session_state[key]:
                role = msg.get("role", "assistant")
                text = msg.get("text", "")
                with st.chat_message(role):
                    st.write(text)

            # Input + send
            prompt = st.chat_input("Ask the AI about this dashboard (e.g., 'Which incidents are highest severity?')")

            if prompt:
                # Add user message to history and display it
                st.session_state[key].append({"role": "user", "text": prompt, "time": datetime.utcnow().isoformat()})
                with st.chat_message("user"):
                    st.write(prompt)

                # Build system prompt tailored to dashboard
                system_prompt = f"You are a concise analytics/security assistant for the {page} dashboard. Use the dashboard context if possible."

                # Call AI: try streaming if generator available, otherwise do a single non-streaming call
                if AI_AVAILABLE and gemini_stream_generator is not None:
                    # Streamed response
                    with st.chat_message("assistant"):
                        placeholder = st.empty()
                        partial = ""
                        try:
                            # Combine system+user for simple call; adjust to your required message schema
                            ai_prompt = system_prompt + "\nUser: " + prompt
                            for token in gemini_stream_generator(ai_prompt):
                                partial += token
                                placeholder.markdown(partial)
                            # store final reply
                            st.session_state[key].append({"role": "assistant", "text": partial, "time": datetime.utcnow().isoformat()})
                        except Exception as e:
                            err = f"Streaming failed: {e}"
                            placeholder.markdown(err)
                            st.session_state[key].append({"role":"assistant","text":err,"time":datetime.utcnow().isoformat()})
                elif AI_AVAILABLE and gemini_chat_simple is not None:
                    # Non-streaming fallback
                    try:
                        ai_prompt = system_prompt + "\nUser: " + prompt
                        reply = gemini_chat_simple(ai_prompt)
                    except Exception as e:
                        reply = f"Error contacting AI: {e}"
                    st.session_state[key].append({"role": "assistant", "text": reply, "time": datetime.utcnow().isoformat()})
                    with st.chat_message("assistant"):
                        st.write(reply)
                else:
                    # AI not available
                    reply = "AI integration not available (ai_helpers import failed)."
                    st.session_state[key].append({"role": "assistant", "text": reply, "time": datetime.utcnow().isoformat()})
                    with st.chat_message("assistant"):
                        st.write(reply)


