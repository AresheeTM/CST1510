# =========================================================
# utils.py - Shared helper functions for the Streamlit app
# Author: Areshee Marimootoo (M01069426)
# Multi-Domain Intelligence Platform
# =========================================================
# This module centralises common utilities used across
# the application, including:
# - File handling (CSV load/save)
# - User authentication and management
# - Role-based access control
# - Avatar generation
# - PDF export
# - CSV uploads
# =========================================================
import os
from pathlib import Path
import pandas as pd
import bcrypt
import streamlit as st
from fpdf import FPDF
from PIL import Image, ImageDraw
import hashlib

# -------------------------
# Base paths and directories
# -------------------------

# Base directory of the project (where utils.py is located)
BASE_DIR = Path(__file__).parent
# Central data directory
DATA_DIR = BASE_DIR / "data"
# User database file
USERS_CSV = DATA_DIR / "users.csv"
# Directory for auto-generated user avatars
AVATAR_DIR = BASE_DIR / "images" / "avatars"
# Ensure avatar directory exists at runtime
AVATAR_DIR.mkdir(parents=True, exist_ok=True)

# -------------------------
# File helpers
# -------------------------
def load_csv(path_or_name: str) -> pd.DataFrame:
    """
    Load CSV given either a path relative to project root or a file in data/.
    """
    p = Path(path_or_name)
     # If file does not exist, attempt to load from data directory
    if not p.exists():
        p = DATA_DIR / path_or_name
    # Handle missing file gracefully
    if not p.exists():
        st.warning(f"[utils] File not found: {p}")
        return pd.DataFrame()
    try:
        return pd.read_csv(p)
    except Exception as e:
        # Streamlit-friendly error reporting
        st.error(f"[utils] Error reading CSV {p}: {e}")
        return pd.DataFrame()

def save_csv(df: pd.DataFrame, path_or_name: str):
    #    Save a DataFrame to CSV; Automatically creates parent directories if required.
    p = Path(path_or_name) # Default to data directory if path does not exist
    if not p.exists():
        p = DATA_DIR / path_or_name
    p.parent.mkdir(parents=True, exist_ok=True) # Ensure directory exists
    df.to_csv(p, index=False) # Save without index for cleaner CSV structure

# -------------------------
# Users & Auth
# -------------------------
def ensure_users_file(): # Ensure that the users.csv file exists; Creates an empty user table if missing.
    if not USERS_CSV.exists():
        USERS_CSV.parent.mkdir(parents=True, exist_ok=True)
        df = pd.DataFrame(columns=["username","password","role","profile_picture"])
        df.to_csv(USERS_CSV,index=False)

def load_users(): # Load all registered users; Always returns a valid DataFrame.
    ensure_users_file()
    try:
        return pd.read_csv(USERS_CSV)
    except Exception:
        return pd.DataFrame(columns=["username","password","role","profile_picture"])

#    Create a new user account with:
#   - hashed password
#   - role-based access
#   - auto-generated avatar if none is provided
def create_user(username: str, raw_password: str, role: str="Dataset User", profile_picture: str=None):
    users = load_users()
    if username in users["username"].values: # Prevent duplicate usernames
        raise ValueError("Username exists")
    hashed = bcrypt.hashpw(raw_password.encode(), bcrypt.gensalt()).decode() # Securely hash the password using bcrypt
    pic = profile_picture or generate_avatar(username) # Generate identicon avatar if not supplied
    new = pd.DataFrame([[username, hashed, role, pic]], columns=["username","password","role","profile_picture"]) # Create new user record
    users = pd.concat([users, new], ignore_index=True) # Append and persist
    save_csv(users, USERS_CSV)
    return True

# Validate user credentials.Returns user session dictionary on success, or None on failure.
def authenticate_user(username: str, raw_password: str):
    users = load_users()
    if username not in users["username"].values: # Check if user exists
        return None
    row = users[users["username"]==username].iloc[0]
    if bcrypt.checkpw(raw_password.encode(), row["password"].encode()): # Verify password hash
        return {"username": row["username"], "role": row.get("role",""), "profile_picture": row.get("profile_picture", "")}
    return None

# Update an existing user's password securely.
def update_user_password(username: str, new_password: str): 
    users = load_users()
    if username not in users["username"].values:
        raise ValueError("User not found")
    users.loc[users["username"]==username, "password"] = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode() # Re-hash the new password
    save_csv(users, USERS_CSV)
    return True

# Permanently remove a user from the system.
def delete_user(username: str): 
    users = load_users()
    users = users[users["username"] != username] # Filter out selected user
    save_csv(users, USERS_CSV)
    return True

# -------------------------
# Avatars (identicon)
# -------------------------
#    Generate a unique identicon-style avatar based on the user's username hash.
def generate_avatar(username: str) -> str:
    avatar_path = AVATAR_DIR / f"{username}.png"
    if avatar_path.exists():  # Reuse existing avatar if already generated
        return str(avatar_path)
    # Grid size and pixel scaling
    size = 5
    square = 40
    img_size = size * square
    image = Image.new("RGB", (img_size, img_size), (10,10,10)) # Create dark background image
    draw = ImageDraw.Draw(image)
    hash_val = hashlib.md5(username.encode()).hexdigest() # Hash username to determine pattern and colour
    color = tuple(int(hash_val[i:i+2],16) for i in (0,2,4))
    # Draw symmetrical pattern
    for y in range(size):
        for x in range(size//2 + 1):
            idx = (y*size + x) % len(hash_val)
            if int(hash_val[idx], 16) % 2 == 0:
                x0, y0 = x*square, y*square
                draw.rectangle([x0,y0,x0+square,y0+square], fill=color)
                # Mirror horizontally for symmetry
                mx = size - 1 - x
                draw.rectangle([mx*square,y0,mx*square+square,y0+square], fill=color)
    # Save avatar to disk
    avatar_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(avatar_path)
    return str(avatar_path)

# -------------------------
# Role enforcement helper for pages
# -------------------------
# Restrict access to Streamlit pages based on user role.
def require_role(allowed_roles):
    user = st.session_state.get("user") or {"role": None}
    if user.get("role") not in allowed_roles:
        st.error("Access denied: you do not have permission to view this page.")
        st.stop()

# -------------------------
# PDF report export (simple)
# -------------------------
# Generate a simple dark-themed PDF report.
#   Args:
#       title (str): Report title
#       text_blocks (list): Paragraphs of content
#       out_path (str): Output file path
def create_simple_pdf(title: str, text_blocks: list, out_path: str):
    """
    text_blocks: list of strings (paragraphs). Will combine into a simple PDF.
    """
    pdf = FPDF()
    pdf.add_page()
    # Title styling
    pdf.set_font("Arial", size=12)
    pdf.set_text_color(255, 255, 255)
    # set background dark
    pdf.set_fill_color(10, 10, 14)
    pdf.rect(0, 0, 210, 297, style='F')
    pdf.set_text_color(255, 182, 255)
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, title, ln=True)
    pdf.ln(4)
    # Body text styling
    pdf.set_font("Arial", size=12)
    pdf.set_text_color(230, 230, 230)
    # Add text blocks
    for block in text_blocks:
        pdf.multi_cell(0, 6, block)
        pdf.ln(1)
    # Ensure output directory existsf
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(p))
    return str(p)

# -------------------------
# CSV uploader
# -------------------------
def upload_csv(label: str, save_path: Path) -> None:
    """
    Shows a drag-and-drop CSV uploader and saves the uploaded file to disk.
    Does not display the dataframe.

    Args:
        label (str): Label for the uploader.
        save_path (Path): Path to save the CSV.
    """
    uploaded_file = st.file_uploader(f"Upload {label} CSV", type="csv", key=f"uploader_{label}")
    
    if uploaded_file:
        try:
            df = pd.read_csv(uploaded_file) # Read uploaded CSV
            save_path.parent.mkdir(parents=True, exist_ok=True)  # Ensure target directory exists
            df.to_csv(save_path, index=False) # Save dataset
            st.success(f"{label} CSV uploaded and saved!")
        except Exception as e:
            st.error(f"Error reading CSV: {e}")



