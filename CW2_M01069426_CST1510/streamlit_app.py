# streamlit_app.py
import streamlit as st
import pandas as pd
import bcrypt
import os
import numpy as np
import plotly.express as px
import streamlit.components.v1 as components
from datetime import datetime, timedelta
from pathlib import Path
from utils import load_csv  # your existing utils.py loader
from sidebar import user_sidebar
from ai_chatbot import dashboard_chat
from ai_sidebar import ai_sidebar

# =====================================================
# HEADER PROFILE BAR (TOP RIGHT)
# =====================================================

import streamlit as st
import base64
from pathlib import Path

def header_profile():
    current_user = st.session_state.get("current_user", {})
    username = current_user.get("username", "Guest")

    profile_dir = Path("app/data/profile_images")
    profile_dir.mkdir(parents=True, exist_ok=True)
    profile_path = profile_dir / f"{username}.png"

    # Load profile image
    if profile_path.exists():
        with open(profile_path, "rb") as img:
            encoded = base64.b64encode(img.read()).decode("utf-8")

        profile_img_html = f"""
        <img src="data:image/png;base64,{encoded}" 
             style="width:40px;height:40px;border-radius:50%;border:2px solid #4CAF50;
                    box-shadow:0 0 8px rgba(76,175,80,0.6);margin-right:10px;">
        """
    else:
        # Default grey placeholder
        profile_img_html = """
        <div style="
            width:40px;height:40px;border-radius:50%;background:#bbb;
            display:flex;justify-content:center;align-items:center;
            font-size:20px;color:#555;border:2px solid #4CAF50;
            margin-right:10px;">
            ?
        </div>
        """

    # Render header bar
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

# Sidebar with login/logout
user_sidebar()
# Ensure 'username' exists in session state (avoid referencing undefined variable)
if "username" not in st.session_state:
    st.session_state["username"] = None

# AI helpers
try:
    from ai_helpers import gemini_chat_simple, gemini_stream_generator
    AI_AVAILABLE = True
except Exception:
    gemini_chat_simple = None
    gemini_stream_generator = None
    AI_AVAILABLE = False

# ----------------------------
# Paths & Config
# ----------------------------
BASE = Path(__file__).parent
DATA_DIR = BASE / "DATA"
USERS_CSV = BASE / "users.csv"
AVATAR_DIR = BASE / "images/avatars"

st.set_page_config(page_title="Intelligence Platform", layout="wide", initial_sidebar_state="expanded")

# ----------------------------
# Theme: Pink, Purple, Black
# ----------------------------
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

# ----------------------------
# User Authentication
# ----------------------------
def load_users():
    if USERS_CSV.exists():
        try:
            return pd.read_csv(USERS_CSV)
        except Exception:
            return pd.DataFrame(columns=["username","password","role","last_login","avatar"])
    else:
        return pd.DataFrame(columns=["username","password","role","last_login","avatar"])

def save_user(username, password, role, avatar=None):
    users = load_users()
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    avatar_file = avatar if avatar else "default.png"
    new_user = pd.DataFrame([[username, hashed_pw, role, datetime.now().isoformat(), avatar_file]],
                            columns=["username","password","role","last_login","avatar"])
    users = pd.concat([users,new_user],ignore_index=True)
    users.to_csv(USERS_CSV,index=False)

def authenticate(username,password):
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
    users = load_users()
    if username in users["username"].values:
        stored_pw = users.loc[users["username"]==username,"password"].iloc[0]
        if bcrypt.checkpw(old_pw.encode(),stored_pw.encode()):
            hashed = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
            users.loc[users["username"]==username,"password"]=hashed
            users.to_csv(USERS_CSV,index=False)
            return True
    return False

# ----------------------------
# Session defaults
# ----------------------------
for key in ["logged_in","username","role","show_chat"]:
    if key not in st.session_state:
        st.session_state[key]=False if key=="logged_in" else None

for k in ("chat_history_cyber","chat_history_data","chat_history_it"):
    if k not in st.session_state:
        st.session_state[k]=[]

# ----------------------------
# THEME FOR ENTIRE APP (including login)
# ----------------------------
theme_css = """
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
st.markdown(theme_css, unsafe_allow_html=True)


# ----------------------------
# LOGIN / REGISTER PAGE (NEON STYLE)
# ----------------------------
page = st.session_state.get("page", "Login")
if page == "Login":
    hide_sidebar_css = """
    <style>
        [data-testid="stSidebar"] {display: none;}
        [data-testid="stSidebarNav"] {display: none;}
        body {
            background: linear-gradient(135deg, #0a0a0a, #1a001a, #ff69b4);
            background-size: 400% 400%;
            animation: gradientBG 15s ease infinite;
            color: #ff69b4;
            font-family: 'Courier New', monospace;
        }
        @keyframes gradientBG {
            0% {background-position:0% 50%;}
            50% {background-position:100% 50%;}
            100% {background-position:0% 50%;}
        }
        .center-box {
            max-width: 420px;
            margin:auto;
            margin-top:80px;
            padding:30px;
            border-radius:20px;
            background: rgba(0,0,0,0.7);
            border: 2px solid #ff69b4;
            box-shadow: 0 0 30px #ff69b4;
        }
        .title {
            text-align:center;
            font-size:32px;
            font-weight:700;
            margin-bottom:20px;
            color: #ff69b4;
            text-shadow: 0 0 10px #ff69b4, 0 0 20px #ffb6c1;
        }
        .stTextInput>div>div>input, .stTextInput>div>div>textarea, .stSelectbox>div>div>div {
            background-color: #1b001b !important;
            color: #ffb6c1 !important;
        }
        .stButton>button {
            background-color: #ff69b4;
            color: #0a0a0a;
            font-weight: bold;
        }
    </style>
    """
    st.markdown(hide_sidebar_css, unsafe_allow_html=True)


    st.markdown('<div class="center-box">', unsafe_allow_html=True)
    # Glass panel with animated star constellation on Login page
st.components.v1.html("""
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

// -----------------------------
// STAR FIELD
// -----------------------------
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

// -----------------------------
// SPARKLE TRAIL PARTICLES
// -----------------------------
let sparkles = [];
let mouse = { x: null, y: null };

canvas.addEventListener('mousemove', function (e) {
    const rect = canvas.getBoundingClientRect();
    mouse.x = e.clientX - rect.left;
    mouse.y = e.clientY - rect.top;

    // Create sparkle particles
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

// -----------------------------
// DRAW ANIMATION
// -----------------------------
function animate() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // 1. Stars movement
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

    // 2. Connecting lines
    for (let i = 0; i < stars.length; i++) {
        for (let j = i + 1; j < stars.length; j++) {
            let dx = stars[i].x - stars[j].x;
            let dy = stars[i].y - stars[j].y;
            let dist = Math.sqrt(dx * dx + dy * dy);

            if (dist < 120) {
                ctx.beginPath();
                ctx.strokeStyle = "rgba(255,105,180," + (1 - dist / 120) + ")";
                ctx.lineWidth = 1;
                ctx.moveTo(stars[i].x, stars[i].y);
                ctx.lineTo(stars[j].x, stars[j].y);
                ctx.stroke();
            }
        }
    }

    // 3. Sparkle particle trail
    for (let i = sparkles.length - 1; i >= 0; i--) {
        let p = sparkles[i];
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, 2 * Math.PI);
        ctx.fillStyle = "rgba(255,182,193," + p.alpha + ")";
        ctx.fill();

        p.x += p.dx;
        p.y += p.dy;
        p.alpha -= 0.02;  // fade out

        if (p.alpha <= 0) {
            sparkles.splice(i, 1);
        }
    }

    requestAnimationFrame(animate);
}

animate();
</script>
""", height=200)



login_choice = st.radio("Select Option:", ["Login", "Register"], index=0, horizontal=True)

    # ----------------------------
    # LOGIN
    # ----------------------------
if login_choice == "Login":
        username = st.text_input("Username", key="login_user", placeholder="Enter username")
        password = st.text_input("Password", type="password", key="login_pw", placeholder="Enter password")

        if st.button("Login"):
            user = authenticate(username, password)
            if user:
                st.success(f"Logged in as {username}")
                role = user["role"]
                # auto-redirect to dashboard
                if role == "Cybersecurity":
                    st.session_state["redirect_page"] = "Cyber Incidents"
                elif role == "Data Science":
                    st.session_state["redirect_page"] = "Datasets"
                elif role == "IT Operations":
                    st.session_state["redirect_page"] = "IT Tickets"
                else:  # Admin
                    st.session_state["redirect_page"] = "Home"
                st.session_state["force_page_change"] = True
                st.rerun()
            else:
                st.error("Invalid username or password")

    # ----------------------------
    # REGISTER
    # ----------------------------
else:
        username = st.text_input("Username", key="reg_user", placeholder="Choose a username")
        password = st.text_input("Password", type="password", key="reg_pw", placeholder="Choose a password")
        role = st.selectbox("Role", ["Admin", "Cybersecurity", "Data Science", "IT Operations"])
        avatar_file = st.file_uploader("Upload profile picture (optional)", type=["png", "jpg"], key="avatar_upload")

        if st.button("Register"):
            avatar_name = None
            if avatar_file:
                AVATAR_DIR.mkdir(exist_ok=True)
                avatar_name = f"{username}_{avatar_file.name}"
                with open(AVATAR_DIR / avatar_name, "wb") as f:
                    f.write(avatar_file.getbuffer())
            save_user(username, password, role, avatar_name)
            st.success("Account created! Please login.")

st.markdown("</div>", unsafe_allow_html=True)
st.stop()  # prevent other dashboards from showing

# ----------------------------
# Sidebar Navigation with Role-Based Access
# ----------------------------
st.sidebar.title("Navigation")

# Default page options
all_pages = {
    "Admin": ["Home","IT Tickets","Datasets","Cyber Incidents","Users","Change Password"],
    "Cybersecurity": ["Cyber Incidents","Change Password"],
    "Data Science": ["Datasets","Change Password"],
    "IT Operations": ["IT Tickets","Change Password"]
}

# Determine allowed pages
if st.session_state.get("logged_in", False):
    role = st.session_state.get("role", None)
    page_options = all_pages.get(role, ["Home","Change Password"])
else:
    page_options = ["Login"]

# Sidebar selectbox
page = st.sidebar.selectbox("Choose page", page_options)

# ----------------------------
# Role-Based Page Protection
# ----------------------------
if st.session_state.get("logged_in", False):
    role = st.session_state.get("role")
    allowed_pages = all_pages.get(role, [])
    if page not in allowed_pages:
        st.warning(f"Access denied: {role} users cannot view this page.")
        st.stop()

# ----------------------------
# HOME PAGE
# ----------------------------
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


    # Add your dashboard content below the glass panel
    st.markdown("### Quick Stats / Dashboard Overview", unsafe_allow_html=True)

    # Example placeholders for charts or data
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Users", len(load_users()))
    with col2:
        tickets_df = load_csv("it_tickets.csv")
        st.metric("Open Tickets", 0 if tickets_df.empty else len(tickets_df))
    with col3:
        incidents_df = load_csv("cyber_incidents.csv")
        st.metric("Cyber Incidents", 0 if incidents_df.empty else len(incidents_df))

    # Example chart below
    st.subheader("Sample Analytics")
    df = pd.DataFrame({
        "Category": ["A", "B", "C"],
        "Value": [10, 20, 30]
    })
    fig = px.bar(df, x="Category", y="Value", title="Sample Dashboard Chart")
    st.plotly_chart(fig, use_container_width=True)


    

# ----------------------------
# Login Protection
# ----------------------------
if not st.session_state["logged_in"] and page != "Login":
    st.warning("Please login to access the platform.")
    st.stop()

# ----------------------------
# Login / Register UI (Updated)
# ----------------------------
# Hide sidebar on login page
if page == "Login":
    hide_sidebar_css = """
    <style>
        [data-testid="stSidebar"] {display: none;}
        [data-testid="stSidebarNav"] {display: none;}
    </style>
    """
    st.markdown(hide_sidebar_css, unsafe_allow_html=True)


    st.markdown('<div class="center-box">', unsafe_allow_html=True)
    st.markdown('<div class="title">Sign In</div>', unsafe_allow_html=True)

    login_choice = st.radio("Select Option:", ["Login", "Register"])


    # ----------------------------
    # LOGIN PROCESS
    # ----------------------------
    if login_choice == "Login":
        username = st.text_input("Username", key="login_user")
        password = st.text_input("Password", type="password", key="login_pw")

        if st.button("Login"):
            user = authenticate(username, password)
            if user:
                st.success(f"Logged in as {username}")
                st.markdown("</div>", unsafe_allow_html=True)

  


                # ==========================================
                # ROLE → AUTO-REDIRECT TO ASSIGNED DASHBOARD
                # ==========================================
                role = user["role"]

                if role == "Cybersecurity":
                    st.session_state["redirect_page"] = "Cyber Incidents"
                elif role == "Data Science":
                    st.session_state["redirect_page"] = "Datasets"
                elif role == "IT Operations":
                    st.session_state["redirect_page"] = "IT Tickets"
                else:  # Admin
                    st.session_state["redirect_page"] = "Home"

                # Apply redirect
                st.session_state["force_page_change"] = True
                st.rerun()

            else:
                st.error("Invalid credentials")

    # ----------------------------
    # REGISTRATION PROCESS
    # ----------------------------
    else:
        st.subheader("Register")
        username = st.text_input("Username", key="reg_user")
        password = st.text_input("Password", type="password", key="reg_pw")
        role = st.selectbox("Role", ["Admin", "Cybersecurity", "Data Science", "IT Operations"])
        avatar_file = st.file_uploader("Upload profile picture", type=["png", "jpg"], key="avatar_upload")

        if st.button("Register"):
            avatar_name = None
            if avatar_file:
                AVATAR_DIR.mkdir(exist_ok=True)
                avatar_name = f"{username}_{avatar_file.name}"
                with open(AVATAR_DIR / avatar_name, "wb") as f:
                    f.write(avatar_file.getbuffer())

            save_user(username, password, role, avatar_name)
            st.success("Account created. Please login.")

        st.markdown("</div>", unsafe_allow_html=True)

    # Prevent ANY dashboard elements from showing on Login page
    st.stop()

# ----------------------------
# APPLY REDIRECTION TO DASHBOARD AFTER LOGIN
# ----------------------------
if st.session_state.get("force_page_change", False):
    # Update sidebar page based on redirect_page
    st.session_state["force_page_change"] = False
    if "redirect_page" in st.session_state:
        st.session_state["page"] = st.session_state["redirect_page"]
    st.rerun()

# ----------------------------
# Sidebar Navigation with Role-Based Access
# ----------------------------
st.sidebar.title("Navigation")

all_pages = {
    "Admin": ["Home","IT Tickets","Datasets","Cyber Incidents","Users","Change Password"],
    "Cybersecurity": ["Cyber Incidents","Change Password"],
    "Data Science": ["Datasets","Change Password"],
    "IT Operations": ["IT Tickets","Change Password"]
}

# Determine allowed pages based on login
role = st.session_state.get("role", None)
if st.session_state.get("logged_in", False):
    page_options = all_pages.get(role, ["Home","Change Password"])
else:
    page_options = ["Login"]

# Ensure sidebar selection is synced with session state
current_page = st.session_state.get("page", page_options[0])
page = st.sidebar.selectbox("Choose page", page_options, index=page_options.index(current_page))
st.session_state["page"] = page

# ----------------------------
# Role-Based Page Protection
# ----------------------------
if st.session_state.get("logged_in", False):
    allowed_pages = all_pages.get(role, [])
    if page not in allowed_pages:
        st.warning(f"Access denied: {role} users cannot view this page.")
        st.stop()



# ----------------------------
# Change Password
# ----------------------------
elif page=="Change Password":
    st.title("Change Password")
    old_pw = st.text_input("Current Password",type="password",key="old_pw")
    new_pw = st.text_input("New Password",type="password",key="new_pw")
    if st.button("Change Password"):
        if change_password(st.session_state["username"],old_pw,new_pw):
            st.success("Password updated successfully!")
        else:
            st.error("Incorrect current password.")

# ----------------------------
# Admin User Management
# ----------------------------
elif page=="Users":
    if st.session_state["role"]!="Admin":
        st.warning("Access denied: Admins only.")
        st.stop()
    st.title("Admin Dashboard - User Management")
    users = load_users()
    st.dataframe(users)

    # Delete user
    delete_user = st.text_input("Delete username")
    if st.button("Delete User"):
        if delete_user in users["username"].values:
            users = users[users["username"]!=delete_user]
            users.to_csv(USERS_CSV,index=False)
            st.success(f"Deleted {delete_user}")
        else:
            st.error("Username not found.")

# ----------------------------
# Tickets / Datasets / Cyber Incidents placeholders
# ----------------------------

elif page=="Tickets":
    st.title("Tickets Dashboard")
    tickets_df = load_csv("it_tickets.csv")
    if tickets_df.empty:
        st.info("No ticket data.")
    else:
        st.dataframe(tickets_df)
        st.subheader("Tickets by Status")
        st.bar_chart(tickets_df["status"].value_counts())

elif page=="Datasets":
    st.title("Datasets Dashboard")
    datasets_df = load_csv("datasets_metadata.csv")
    if datasets_df.empty:
        st.info("No dataset metadata.")
    else:
        st.dataframe(datasets_df)
        if "name" in datasets_df.columns:
            st.subheader("Datasets by Name")
            st.bar_chart(datasets_df["name"].value_counts())

elif page=="Cyber Incidents":
    st.title("Cyber Incidents Dashboard")
    incidents_df = load_csv("cyber_incidents.csv")
    if incidents_df.empty:
        st.info("No incidents data.")
    else:
        st.dataframe(incidents_df)
        if "severity" in incidents_df.columns:
            st.subheader("Incidents by Severity")
            st.bar_chart(incidents_df["severity"].value_counts())

# ----------------------------
# AI Dashboards (Cyber, Data, IT)
# ----------------------------
else:
    st.title(page + " Dashboard")
    # Sample Plotly chart
    df = pd.DataFrame({"category":["A","B","C"],"value":[10,20,30]})
    fig = px.bar(df,x="category",y="value",title=f"{page} Sample Chart")
    st.plotly_chart(fig,use_container_width=True)

    # AI chat
    left_col,right_col = st.columns([1,11])
    with left_col:
        if st.button("🤖"):
            st.session_state["show_chat"]=not st.session_state["show_chat"]

    chat_key = {"Cyber":"chat_history_cyber","Data":"chat_history_data","IT":"chat_history_it"}.get(page)
    if chat_key and st.session_state.get("show_chat",True):
        st.markdown("### Assistant")
        for msg in st.session_state[chat_key]:
            role = msg.get("role","assistant")
            text = msg.get("text","")
            with st.chat_message(role):
                st.write(text)
        prompt = st.chat_input("Ask AI about this dashboard")
        if prompt:
            st.session_state[chat_key].append({"role":"user","text":prompt,"time":datetime.utcnow().isoformat()})
            with st.chat_message("user"): st.write(prompt)
            sys_prompt=f"You are a concise analytics/security assistant for {page}."
            if AI_AVAILABLE and gemini_stream_generator:
                with st.chat_message("assistant"):
                    placeholder=st.empty()
                    partial=""
                    for token in gemini_stream_generator(sys_prompt+"\nUser: "+prompt):
                        partial+=token
                        placeholder.markdown(partial)
                    st.session_state[chat_key].append({"role":"assistant","text":partial,"time":datetime.utcnow().isoformat()})
            elif AI_AVAILABLE and gemini_chat_simple:
                reply=gemini_chat_simple(sys_prompt+"\nUser: "+prompt)
                st.session_state[chat_key].append({"role":"assistant","text":reply,"time":datetime.utcnow().isoformat()})
                with st.chat_message("assistant"): st.write(reply)
            else:
                reply="AI not available."
                st.session_state[chat_key].append({"role":"assistant","text":reply,"time":datetime.utcnow().isoformat()})
                with st.chat_message("assistant"): st.write(reply)
