# pages/99_Admin_Dashboard.py
import streamlit as st
from utils import load_users, create_user, delete_user, generate_avatar, save_csv, USERS_CSV
import pandas as pd
import bcrypt

# restrict to admins
user = st.session_state.get("user")
if not user or user.get("role") != "Admin":
    st.error("Admins only")
    st.stop()

st.title("Admin Dashboard - Users")
users = load_users()
st.dataframe(users)

st.header("Add User")
col1, col2, col3 = st.columns(3)
with col1:
    username = st.text_input("Username", key="admin_new_username")
with col2:
    password = st.text_input("Password", type="password", key="admin_new_pw")
with col3:
    role = st.selectbox("Role", ["Admin", "IT Operations", "Cybersecurity", "Data Science"], key="admin_new_role")

if st.button("Create User"):
    if username.strip() and password.strip():
        try:
            create_user(username, password, role)
            st.success("User created")
            st.experimental_rerun()
        except Exception as e:
            st.error(str(e))

st.header("Delete User")
del_user = st.selectbox("Select user to delete", users["username"].tolist(), key="admin_del_user")
if st.button("Delete"):
    if del_user == user["username"]:
        st.error("Cannot delete yourself")
    else:
        delete_user(del_user)
        st.success("Deleted")
        st.experimental_rerun()

st.header("Upload/Update Avatar")
u = st.selectbox("User", users["username"].tolist(), key="admin_avatar_user")
img = st.file_uploader("Avatar PNG/JPG", type=["png","jpg"], key="admin_avatar_upload")
if img and st.button("Upload Avatar"):
    from pathlib import Path
    save_path = Path("images/avatars") / f"{u}.png"
    save_path.parent.mkdir(parents=True, exist_ok=True)
    with open(save_path, "wb") as f:
        f.write(img.read())
    st.success("Avatar saved")
    st.experimental_rerun()

