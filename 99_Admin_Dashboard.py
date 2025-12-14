# =========================================================
# 99_Admin_Dashboard.py
# ============================
# Admin dashboard for managing users.
# Features:
#  - View all users
#  - Add new users (with roles)
#  - Delete existing users (except self)
#  - Upload/update avatars
# Access restricted to Admins only.
# ============================================================
import streamlit as st
from utils import load_users, create_user, delete_user, generate_avatar, save_csv, USERS_CSV
import pandas as pd
import bcrypt

# ----------------------------
# Admin access restriction
# ----------------------------
user = st.session_state.get("user") # Get logged-in user info
if not user or user.get("role") != "Admin":
    st.error("Admins only") # Block non-admins
    st.stop()

# ----------------------------
# Page Title & User Table
# ----------------------------
st.title("Admin Dashboard - Users")
users = load_users() # Load all users from CSV/database
st.dataframe(users) # Display users in interactive table

# ----------------------------
# Add New User Section
# ----------------------------
st.header("Add User")
col1, col2, col3 = st.columns(3)
with col1:
    username = st.text_input("Username", key="admin_new_username")
with col2:
    password = st.text_input("Password", type="password", key="admin_new_pw")
with col3:
    role = st.selectbox("Role", ["Admin", "IT Operations", "Cybersecurity", "Data Science"], key="admin_new_role")

# Button to create new user
if st.button("Create User"):
    if username.strip() and password.strip(): # Basic validation
        try:
            create_user(username, password, role)  # Call helper function to save user
            st.success("User created")
            st.experimental_rerun() # Refresh page to show new user
        except Exception as e:
            st.error(str(e)) # Display error if creation fails

# ----------------------------
# Delete User Section
# ----------------------------
st.header("Delete User")
del_user = st.selectbox("Select user to delete", users["username"].tolist(), key="admin_del_user")
if st.button("Delete"):
    if del_user == user["username"]:
        st.error("Cannot delete yourself") # Prevent self-deletion
    else:
        delete_user(del_user) # Remove user via helper
        st.success("Deleted")
        st.experimental_rerun() # Refresh to update table

# ----------------------------
# Upload / Update Avatar Section
# ----------------------------
st.header("Upload/Update Avatar")
u = st.selectbox("User", users["username"].tolist(), key="admin_avatar_user")
img = st.file_uploader("Avatar PNG/JPG", type=["png","jpg"], key="admin_avatar_upload")
if img and st.button("Upload Avatar"):  # Ensure avatars directory exists
    from pathlib import Path
    save_path = Path("images/avatars") / f"{u}.png"
    save_path.parent.mkdir(parents=True, exist_ok=True)
    with open(save_path, "wb") as f: # Save uploaded avatar
        f.write(img.read())
    st.success("Avatar saved")
    st.experimental_rerun() # Refresh page to reflect new avatar

