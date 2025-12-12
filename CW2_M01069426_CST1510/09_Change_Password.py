# pages/09_Change_Password.py
import streamlit as st
import bcrypt
from utils import load_users, update_user_password

user = st.session_state.get("user")
if not user:
    st.error("Please login")
    st.stop()

st.title("Change Password")
old = st.text_input("Old password", type="password", key="chg_old")
new = st.text_input("New password", type="password", key="chg_new")
conf = st.text_input("Confirm new", type="password", key="chg_conf")

if st.button("Change Password"):
    users = load_users()
    row = users[users["username"]==user["username"]].iloc[0]
    if not row.empty and bcrypt.checkpw(old.encode(), row["password"].encode()):
        if new == conf:
            update_user_password(user["username"], new)
            st.success("Password changed")
        else:
            st.error("New passwords do not match")
    else:
        st.error("Old password incorrect")

