# =========================================================
# streamlit_app.py
# Author: Areshee Marimootoo (M01069426)
# Multi-Domain Intelligence Platform
#=========================================================
# Main entry point for the Streamlit application.
# Handles:
# - Session state management
# - Authentication & registration
# - Role-based navigation
# - UI theming and layout
# - Page routing
# =========================================================
import streamlit as st
import pandas as pd
import bcrypt
import os
import numpy as np
import plotly.express as px
import streamlit.components.v1 as components
from datetime import datetime, timedelta
from pathlib import Path
from utils import load_csv  # Shared CSV loader utility
from sidebar import user_sidebar # Sidebar login/logout logic
from ai_chatbot import dashboard_chat
from ai_sidebar import ai_sidebar
import base64
import ai_helpers

# Debug: confirm AI helpers module is loaded
print(ai_helpers)

# =========================================================
# Forced rerun handler
# (replacement for deprecated st.experimental_rerun)
# =========================================================
if st.session_state.get("force_rerun", False):
    st.session_state["force_rerun"] = False
    st.stop()  # stops current run, Streamlit automatically reruns

# =========================================================
# Initialise required session state keys
# =========================================================
required_keys = [
    "logged_in", "username", "role", "show_chat",
    "page", "force_page_change", "redirect_page",
    "chat_history_cyber", "chat_history_data", "chat_history_it"
]
for k in required_keys:
    if k not in st.session_state:
        # Assign sensible defaults for first run
        if k == "logged_in":
            st.session_state[k] = False
        elif k in ("chat_history_cyber","chat_history_data","chat_history_it"):
            st.session_state[k] = []
        elif k == "page":
            st.session_state[k] = "Login"
        else:
            st.session_state[k] = None

# =========================================================
# Header profile bar (top-right)
# Displays username and profile image
# =========================================================
def header_profile():
    current_user = st.session_state.get("current_user", {})
    username = current_user.get("username", st.session_state.get("username", "Guest"))
    
    # Directory for stored profile images
    profile_dir = Path("app/data/profile_images")
    profile_dir.mkdir(parents=True, exist_ok=True)
    profile_path = profile_dir / f"{username}.png"

    # Load profile image if available
    if profile_path.exists():
        with open(profile_path, "rb") as img:
            encoded = base64.b64encode(img.read()).decode("utf-8")

        profile_img_html = f"""
        <img src="data:image/png;base64,{encoded}" 
             style="width:40px;height:40px;border-radius:50%;border:2px solid #4CAF50;
                    box-shadow:0 0 8px rgba(76,175,80,0.6);margin-right:10px;">
        """
    else:
        # Fallback placeholder avatar
        profile_img_html = """
        <div style="
            width:40px;height:40px;border-radius:50%;background:#bbb;
            display:flex;justify-content:center;align-items:center;
            font-size:20px;color:#555;border:2px solid #4CAF50;
            margin-right:10px;">
            ?
        </div>
        """

    # Render the header bar
    st.markdown(
        f"""
        <div style="
            display:flex;
            justify-content:flex-end;
            align-items:center;
            width:100%;
            padding:10px 20px;
            background-color:#f8f9fa;
            border-bottom:1px solid #e0e0e0;
            position:sticky;
            top:0;
            z-index:1000;
        ">
            {profile_img_html}
            <div style="margin-right:auto;font-weight:600;color:#333;">{username}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# Sidebar with login/logout (this will render sidebar)
user_sidebar()

# =========================================================
# Optional AI helpers (non-fatal import)
# =========================================================
try:
    from ai_helpers import gemini_chat_simple, gemini_stream_generator
    AI_AVAILABLE = True
except Exception:
    # App continues without AI functionality
    gemini_chat_simple = None
    gemini_stream_generator = None
    AI_AVAILABLE = False

# =========================================================
# Paths and configuration
# =========================================================
BASE = Path(__file__).parent
DATA_DIR = BASE / "DATA"
USERS_CSV = BASE / "users.csv"
AVATAR_DIR = BASE / "images/avatars"

st.set_page_config(page_title="Intelligence Platform", layout="wide", initial_sidebar_state="expanded")

# =========================================================
# Global theme (pink / purple / black neon aesthetic)
# =========================================================
theme_css = """
<style>
body {background-color:#0f0a1f;color:#f5c1f5;}
.sidebar .sidebar-content {background-color:#1b0f2e;}
h1,h2,h3,h4,h5,h6 {color:#f5c1f5;}
.stButton>button, .stSelectbox, .stTextInput, .stTextArea {background-color:#2a0f3c;color:#f5c1f5;}
.stDataFrame table {color:#f5c1f5;}
.center-box {max-width:420px;margin:auto;margin-top:80px;padding:30px;border-radius:20px;background:#ffffff10;backdrop-filter:blur(10px);border:1px solid #ffffff30;box-shadow:0px 0px 20px #00000020;}
.title {text-align:center;font-size:32px;font-weight:700;margin-bottom:20px;}
</style>
"""
st.markdown(theme_css, unsafe_allow_html=True)

# =========================================================
# Authentication helper functions
# =========================================================
def load_users():
    # Load registered users from CSV.
    if USERS_CSV.exists():
        try:
            return pd.read_csv(USERS_CSV)
        except Exception:
            return pd.DataFrame(columns=["username","password","role","last_login","avatar"])
    else:
        return pd.DataFrame(columns=["username","password","role","last_login","avatar"])

def save_user(username, password, role, avatar=None):
    # Create and store a new user account.
    users = load_users()
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode() # Secure password hashing
    avatar_file = avatar if avatar else "default.png"
    new_user = pd.DataFrame([[username, hashed_pw, role, datetime.now().isoformat(), avatar_file]],
                            columns=["username","password","role","last_login","avatar"])
    users = pd.concat([users,new_user],ignore_index=True)
    users.to_csv(USERS_CSV,index=False)

def authenticate(username,password):
    # Validate credentials and update session state.
    users = load_users()
    if username in users["username"].values:
        stored_pw = users.loc[users["username"]==username,"password"].iloc[0]
        if bcrypt.checkpw(password.encode(),stored_pw.encode()):
            role = users.loc[users["username"]==username,"role"].iloc[0]
            st.session_state["logged_in"]=True
            st.session_state["username"]=username
            st.session_state["role"]=role
            users.loc[users["username"]==username,"last_login"]=datetime.now().isoformat()
            users.to_csv(USERS_CSV,index=False)
            return {"username":username,"role":role}
    return None

def change_password(username, old_pw, new_pw):
    # Allow authenticated users to change their password.
    users = load_users()
    if username in users["username"].values:
        stored_pw = users.loc[users["username"]==username,"password"].iloc[0]
        if bcrypt.checkpw(old_pw.encode(),stored_pw.encode()):
            hashed = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
            users.loc[users["username"]==username,"password"]=hashed
            users.to_csv(USERS_CSV,index=False)
            return True
    return False

# =========================================================
# Page routing (session-based navigation)
# =========================================================
# Use session_state["page"] (already initialized above). Local alias for convenience:
page = st.session_state.get("page", "Login")

# ----------------------------
# THEME FOR ENTIRE APP (including login)
# ----------------------------
theme_css2 = """
<style>
body {background-color:#0a0a0a;color:#ff69b4;font-family: 'Courier New', monospace;}
.sidebar .sidebar-content {background-color:#1a0a1f;}
h1,h2,h3,h4,h5,h6 {color:#ff69b4;}
.stButton>button, .stSelectbox, .stTextInput, .stTextArea {
    background-color:#1f0a2a;color:#ff69b4;border:1px solid #ff69b4;
    border-radius:8px;
}
.stDataFrame table {color:#ff69b4;}
.center-box {
    max-width:420px;margin:auto;margin-top:80px;padding:30px;
    border-radius:20px;background:#ffffff10;
    backdrop-filter:blur(10px);border:1px solid #ff69b4;
    box-shadow:0px 0px 20px #ff69b480;
}
.title {text-align:center;font-size:32px;font-weight:700;margin-bottom:20px;}
.stRadio > div {color:#ff69b4;}
.stCheckbox>div {color:#ff69b4;}
.stMarkdown h3, .stMarkdown h4 {color:#ff69b4;}
</style>
"""
st.markdown(theme_css2, unsafe_allow_html=True)

# =========================================================
# LOGIN / REGISTER PAGE (NEON STYLE)
# =========================================================
if st.session_state.get("page", "Login") == "Login":

    hide_sidebar_css = """
    <style>
        [data-testid="stSidebar"] {display: none;}
        [data-testid="stSidebarNav"] {display: none;}
    </style>
    """
    st.markdown(hide_sidebar_css, unsafe_allow_html=True)

    st.markdown('<div class="center-box">', unsafe_allow_html=True)

    # Glass panel with animated star constellation
    components.html("""
    <div style="
        width:100%;
        height:180px;
        border-radius:20px;
        background: rgba(0,0,0,0.55);
        backdrop-filter: blur(10px);
        border:2px solid rgba(255,20,147,0.45);
        display:flex;
        justify-content:center;
        align-items:center;
        text-align:center;
        position:relative;
        overflow:hidden;
        margin-bottom:25px;
        box-shadow:0 0 25px rgba(255,20,147,0.4);
    ">
        <h1 style="
            color:#ff69b4;
            font-size:30px;
            font-weight:700;
            text-shadow:0 0 15px #ff69b4, 0 0 30px #ffb6c1;
            z-index:10;
        ">
            Welcome to Intelligence Platform
        </h1>

        <canvas id="login_stars" style="
            position:absolute;
            top:0;
            left:0;
            width:100%;
            height:100%;
            display:block;
            z-index:1;
        "></canvas>
    </div>

    <script>
    const canvas = document.getElementById('login_stars');
    const ctx = canvas.getContext('2d');

    function resize() {
        canvas.width = canvas.offsetWidth;
        canvas.height = canvas.offsetHeight;
    }
    resize();
    window.onresize = resize;

    let stars = [];
    for (let i = 0; i < 120; i++) {
        stars.push({
            x: Math.random() * canvas.width,
            y: Math.random() * canvas.height,
            r: Math.random() * 1.8 + 0.5,
            dx: (Math.random() - 0.5) * 0.6,
            dy: (Math.random() - 0.5) * 0.6
        });
    }

    let sparkles = [];
    let mouse = { x: null, y: null };
    canvas.addEventListener('mousemove', function (e) {
        const rect = canvas.getBoundingClientRect();
        mouse.x = e.clientX - rect.left;
        mouse.y = e.clientY - rect.top;

        for (let i = 0; i < 4; i++) {
            sparkles.push({
                x: mouse.x,
                y: mouse.y,
                size: Math.random() * 2 + 1,
                alpha: 1,
                dx: (Math.random() - 0.5) * 1.2,
                dy: (Math.random() - 0.5) * 1.2
            });
        }
    });

    function animate() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        // Stars
        for (let s of stars) {
            ctx.beginPath();
            ctx.arc(s.x, s.y, s.r, 0, 2 * Math.PI);
            ctx.fillStyle = "#ff69b4";
            ctx.fill();

            s.x += s.dx;
            s.y += s.dy;

            if (s.x < 0 || s.x > canvas.width) s.dx *= -1;
            if (s.y < 0 || s.y > canvas.height) s.dy *= -1;
        }

        // Sparkles
        for (let i = sparkles.length - 1; i >= 0; i--) {
            let p = sparkles[i];
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.size, 0, 2 * Math.PI);
            ctx.fillStyle = "rgba(255,182,193," + p.alpha + ")";
            ctx.fill();

            p.x += p.dx;
            p.y += p.dy;
            p.alpha -= 0.02;

            if (p.alpha <= 0) {
                sparkles.splice(i, 1);
            }
        }

        // Lines between stars
        for (let i = 0; i < stars.length; i++) {
            for (let j = i + 1; j < stars.length; j++) {
                let dx = stars[i].x - stars[j].x;
                let dy = stars[i].y - stars[j].y;
                let dist = Math.sqrt(dx*dx + dy*dy);
                if (dist < 120) {
                    ctx.beginPath();
                    ctx.strokeStyle = "rgba(255,105,180," + (1 - dist/120) + ")";
                    ctx.lineWidth = 1;
                    ctx.moveTo(stars[i].x, stars[i].y);
                    ctx.lineTo(stars[j].x, stars[j].y);
                    ctx.stroke();
                }
            }
        }

        requestAnimationFrame(animate);
    }

    animate();
    </script>
    """, height=200)

# =========================================================
# LOGIN / REGISTER PAGE
# =========================================================
# Radio selector allowing the user to switch between
# login and registration modes
    login_choice = st.radio("Select Option:", ["Login", "Register"], index=0, horizontal=True)

# ----------------------------
# LOGIN FLOW
# ----------------------------
    if login_choice == "Login":
        # Username and password inputs for authentication
        username = st.text_input("Username", key="login_user", placeholder="Enter username")
        password = st.text_input("Password", type="password", key="login_pw", placeholder="Enter password")
        
        # Trigger authentication when login button is clicked
        if st.button("Login"):
            user = authenticate(username, password)
            if user:
                # Successful login: update session state
                st.success(f"Logged in as {username}")
                st.session_state["logged_in"] = True
                st.session_state["username"] = user["username"]
                st.session_state["role"] = user["role"]
                st.session_state["page"] = "Home"  # Redirect to Home page
                st.session_state["force_rerun"] = True
            else:
                st.error("Invalid username or password") # Authentication failure
# ----------------------------
# REGISTRATION FLOW
# ----------------------------
    else:  
        # New user registration inputs
        username = st.text_input("Username", key="reg_user", placeholder="Choose a username")
        password = st.text_input("Password", type="password", key="reg_pw", placeholder="Choose a password")
        role = st.selectbox("Role", ["Admin", "Cybersecurity", "Data Science", "IT Operations"])
        avatar_file = st.file_uploader("Upload profile picture (optional)", type=["png", "jpg"], key="avatar_upload")
        
        # Create new user account
        if st.button("Register"):
            avatar_name = None
            if avatar_file:
                AVATAR_DIR.mkdir(exist_ok=True)
                avatar_name = f"{username}_{avatar_file.name}"
                with open(AVATAR_DIR / avatar_name, "wb") as f:
                    f.write(avatar_file.getbuffer())
            save_user(username, password, role, avatar_name) # Persist user details
            st.success("Account created! Please login.")

    st.markdown("</div>", unsafe_allow_html=True) # Close login container
    st.stop()  # Prevent dashboard content from loading before authentication

# =========================================================
# Redirection after login (handled via session flags)
# =========================================================
if st.session_state.get("force_page_change", False):
    st.session_state["force_page_change"] = False
    if st.session_state.get("redirect_page"): # Optional redirect to a specific page
        st.session_state["page"] = st.session_state["redirect_page"]
    st.session_state["force_rerun"] = True

# Fallback redirect to Home page
if st.session_state.get("force_page_change", False):
    st.session_state["force_page_change"] = False
    st.session_state["page"] = "Home"  # force Home page
    st.session_state["force_rerun"] = True



# =========================================================
# Sidebar Navigation with Role-Based Access
# =========================================================
st.sidebar.title("Navigation")


# Define accessible pages per role
all_pages = {
    "Admin": ["Home","IT Tickets","Datasets","Cyber Incidents","Users","Change Password"],
    "Cybersecurity": ["Home","Cyber Incidents","Change Password"],
    "Data Science": ["Home","Datasets","Change Password"],
    "IT Operations": ["Home","IT Tickets","Change Password"]
}

role = st.session_state.get("role", None)

# Determine available pages based on login status
if st.session_state.get("logged_in", False):
    page_options = all_pages.get(role, ["Home"])
else:
    page_options = ["Login"]


# Ensure current page remains valid for role
current_page = st.session_state.get("page", page_options[0])
if current_page not in page_options:
    current_page = page_options[0]
# Sidebar page selector
page = st.sidebar.selectbox("Choose page", page_options, index=page_options.index(current_page))
st.session_state["page"] = page

# =========================================================
# Logout Button (Neon Power Icon at Sidebar Bottom)
# =========================================================
if st.session_state.get("logged_in", False):
    # Custom CSS to anchor logout button at bottom
    st.sidebar.markdown(
        """
        <style>
        /* Sidebar flex to push logout to bottom */
        [data-testid="stSidebar"] > div:first-child {
            display: flex;
            flex-direction: column;
            height: 100vh;
        }

        /* Logout button styling */
        .logout-btn {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 55px;
            height: 55px;
            border-radius: 50%;
            background: #ff00ff; /* Neon pink */
            box-shadow: 0 0 12px #ff00ff, 0 0 25px #ff33ff;
            cursor: pointer;
            margin-top: auto; /* pushes to bottom */
            margin-bottom: 20px;
            transition: 0.2s ease-in-out;
            font-size: 28px;
            color: white;
            font-weight: bold;
            text-align: center;
            font-family: Arial, sans-serif;
        }

        .logout-btn:hover {
            box-shadow: 0 0 20px #ff00ff, 0 0 35px #ff33ff;
            transform: scale(1.1);
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    # Logout action wrapped in a form
    with st.sidebar.form(key="logout_form", clear_on_submit=False):
        submit_logout = st.form_submit_button(
            label='',
            use_container_width=True,
        )

        # Neon power icon
        st.markdown(
            """
            <div class="logout-btn">&#x23FB;</div>
            """,
            unsafe_allow_html=True
        )

        # Clear session and return to login page
        if submit_logout:
            st.session_state.clear()
            st.session_state["logged_in"] = False
            st.session_state["page"] = "Login"
            st.session_state["force_rerun"] = True


# =========================================================
# Role-Based Page Protection
# =========================================================
if st.session_state.get("logged_in", False):
    allowed_pages = all_pages.get(role, ["Home"])
    if page not in allowed_pages:
        st.warning(f"Access denied: {role} users cannot view this page.")
        st.stop()


# =========================================================
# HOME PAGE
# =========================================================
if page == "Home":
    st.markdown(" ")  # small spacing

    components.html("""
    <div style="
        width:100%;
        height:260px;
        border-radius:20px;
        background: rgba(0,0,0,0.55);
        backdrop-filter: blur(10px);
        border:2px solid rgba(255,20,147,0.45);
        display:flex;
        justify-content:center;
        align-items:center;
        text-align:center;
        position:relative;
        overflow:hidden;
        margin-bottom:25px;
        box-shadow:0 0 25px rgba(255,20,147,0.4);
    ">
        <h1 style="
            color:#ff69b4;
            font-size:38px;
            font-weight:700;
            text-shadow:0 0 15px #ff69b4, 0 0 30px #ffb6c1;
            z-index:10;
        ">
            Welcome to Intelligence Platform
        </h1>

        <canvas id="stars" style="
            position:absolute;
            top:0;
            left:0;
            width:100%;
            height:100%;
            display:block;
            z-index:1;
        "></canvas>
    </div>

    <script>
    const canvas = document.getElementById('stars');
    const ctx = canvas.getContext('2d');

    function resize() {
        canvas.width = canvas.offsetWidth;
        canvas.height = canvas.offsetHeight;
    }

    resize();
    window.onresize = resize;

    let stars = [];
    for (let i = 0; i < 120; i++) {
        stars.push({
            x: Math.random() * canvas.width,
            y: Math.random() * canvas.height,
            r: Math.random() * 1.8 + 0.6,
            dx: (Math.random() - 0.5) * 0.3,
            dy: (Math.random() - 0.5) * 0.3
        });
    }

    function animate() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        for (let s of stars) {
            ctx.beginPath();
            ctx.arc(s.x, s.y, s.r, 0, 2 * Math.PI);
            ctx.fillStyle = "#ff69b4";
            ctx.fill();

            s.x += s.dx;
            s.y += s.dy;

            if (s.x < 0 || s.x > canvas.width) s.dx *= -1;
            if (s.y < 0 || s.y > canvas.height) s.dy *= -1;
        }
        requestAnimationFrame(animate);
    }

    animate();
    </script>
    """, height=280)



# =========================================================
# Authentication Enforcement
# =========================================================
if not st.session_state.get("logged_in", False) and page != "Login":
    st.warning("Please login to access the platform.")
    st.stop()

# =========================================================
# Change Password Page
# =========================================================
if page == "Change Password":
    st.title("Change Password")
    old_pw = st.text_input("Current Password",type="password",key="old_pw")
    new_pw = st.text_input("New Password",type="password",key="new_pw")
    if st.button("Change Password"):
        if change_password(st.session_state["username"],old_pw,new_pw):
            st.success("Password updated successfully!")
        else:
            st.error("Incorrect current password.")

# =========================================================
# Admin Page – User Management
# =========================================================
elif page == "Users":
    if st.session_state["role"]!="Admin":
        st.warning("Access denied: Admins only.")
        st.stop()
    st.title("Admin Dashboard - User Management")
    # Display all registered users
    users = load_users()
    st.dataframe(users)

    # User deletion feature
    delete_user = st.text_input("Delete username")
    if st.button("Delete User"):
        if delete_user in users["username"].values:
            users = users[users["username"]!=delete_user]
            users.to_csv(USERS_CSV,index=False)
            st.success(f"Deleted {delete_user}")
        else:
            st.error("Username not found.")

