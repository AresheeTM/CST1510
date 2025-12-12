# =========================================================
# utils.py - Shared helper functions for the Streamlit app
# Author: Areshee Marimootoo (M01069426)
# Multi-Domain Intelligence Platform
# =========================================================

import os
from pathlib import Path
import pandas as pd
import bcrypt
import streamlit as st
from fpdf import FPDF
from PIL import Image, ImageDraw
import hashlib

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
USERS_CSV = DATA_DIR / "users.csv"
AVATAR_DIR = BASE_DIR / "images" / "avatars"
AVATAR_DIR.mkdir(parents=True, exist_ok=True)

# -------------------------
# File helpers
# -------------------------
def load_csv(path_or_name: str) -> pd.DataFrame:
    """
    Load CSV given either a path relative to project root or a file in data/.
    """
    p = Path(path_or_name)
    if not p.exists():
        # try data folder
        p = DATA_DIR / path_or_name
    if not p.exists():
        st.warning(f"[utils] File not found: {p}")
        return pd.DataFrame()
    try:
        return pd.read_csv(p)
    except Exception as e:
        st.error(f"[utils] Error reading CSV {p}: {e}")
        return pd.DataFrame()

def save_csv(df: pd.DataFrame, path_or_name: str):
    p = Path(path_or_name)
    if not p.exists():
        p = DATA_DIR / path_or_name
    p.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(p, index=False)

# -------------------------
# Users & Auth
# -------------------------
def ensure_users_file():
    if not USERS_CSV.exists():
        USERS_CSV.parent.mkdir(parents=True, exist_ok=True)
        df = pd.DataFrame(columns=["username","password","role","profile_picture"])
        df.to_csv(USERS_CSV,index=False)

def load_users():
    ensure_users_file()
    try:
        return pd.read_csv(USERS_CSV)
    except Exception:
        return pd.DataFrame(columns=["username","password","role","profile_picture"])

def create_user(username: str, raw_password: str, role: str="Dataset User", profile_picture: str=None):
    users = load_users()
    if username in users["username"].values:
        raise ValueError("Username exists")
    hashed = bcrypt.hashpw(raw_password.encode(), bcrypt.gensalt()).decode()
    pic = profile_picture or generate_avatar(username)
    new = pd.DataFrame([[username, hashed, role, pic]], columns=["username","password","role","profile_picture"])
    users = pd.concat([users, new], ignore_index=True)
    save_csv(users, USERS_CSV)
    return True

def authenticate_user(username: str, raw_password: str):
    users = load_users()
    if username not in users["username"].values:
        return None
    row = users[users["username"]==username].iloc[0]
    if bcrypt.checkpw(raw_password.encode(), row["password"].encode()):
        return {"username": row["username"], "role": row.get("role",""), "profile_picture": row.get("profile_picture", "")}
    return None

def update_user_password(username: str, new_password: str):
    users = load_users()
    if username not in users["username"].values:
        raise ValueError("User not found")
    users.loc[users["username"]==username, "password"] = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    save_csv(users, USERS_CSV)
    return True

def delete_user(username: str):
    users = load_users()
    users = users[users["username"] != username]
    save_csv(users, USERS_CSV)
    return True

# -------------------------
# Avatars (identicon)
# -------------------------
def generate_avatar(username: str) -> str:
    avatar_path = AVATAR_DIR / f"{username}.png"
    if avatar_path.exists():
        return str(avatar_path)
    # identicon generation
    size = 5
    square = 40
    img_size = size * square
    image = Image.new("RGB", (img_size, img_size), (10,10,10))
    draw = ImageDraw.Draw(image)
    hash_val = hashlib.md5(username.encode()).hexdigest()
    color = tuple(int(hash_val[i:i+2],16) for i in (0,2,4))
    for y in range(size):
        for x in range(size//2 + 1):
            idx = (y*size + x) % len(hash_val)
            if int(hash_val[idx], 16) % 2 == 0:
                x0, y0 = x*square, y*square
                draw.rectangle([x0,y0,x0+square,y0+square], fill=color)
                # mirror
                mx = size - 1 - x
                draw.rectangle([mx*square,y0,mx*square+square,y0+square], fill=color)
    avatar_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(avatar_path)
    return str(avatar_path)

# -------------------------
# Role enforcement helper for pages
# -------------------------
def require_role(allowed_roles):
    user = st.session_state.get("user") or {"role": None}
    if user.get("role") not in allowed_roles:
        st.error("Access denied: you do not have permission to view this page.")
        st.stop()

# -------------------------
# PDF report export (simple)
# -------------------------
def create_simple_pdf(title: str, text_blocks: list, out_path: str):
    """
    text_blocks: list of strings (paragraphs). Will combine into a simple PDF.
    """
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.set_text_color(255, 255, 255)
    # set background dark
    pdf.set_fill_color(10, 10, 14)
    pdf.rect(0, 0, 210, 297, style='F')
    pdf.set_text_color(255, 182, 255)
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, title, ln=True)
    pdf.ln(4)
    pdf.set_font("Arial", size=12)
    pdf.set_text_color(230, 230, 230)
    for block in text_blocks:
        pdf.multi_cell(0, 6, block)
        pdf.ln(1)
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(p))
    return str(p)

