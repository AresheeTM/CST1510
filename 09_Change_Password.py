# =========================================================
# 09_Change_Password.py
# ============================
# Page for users to change their account password.
# Features:
#  - Verify old password
#  - Confirm new password
#  - Update securely using bcrypt
# ============================================================
import streamlit as st
import bcrypt
from utils import load_users, update_user_password

# ----------------------------
# Ensure user is logged in
# ----------------------------
user = st.session_state.get("user") # Get current session user
if not user:
    st.error("Please login") # Block access if not logged in
    st.stop()

# ----------------------------
# Page title & input fields
# ---------------------------
st.title("Change Password")

# Input: old password
old = st.text_input("Old password", type="password", key="chg_old")
# Input: new password
new = st.text_input("New password", type="password", key="chg_new")
# Input: confirm new password
conf = st.text_input("Confirm new", type="password", key="chg_conf")

# ----------------------------
# Change password button
# ----------------------------
if st.button("Change Password"):
    users = load_users() # Load all users from CSV/database
    row = users[users["username"]==user["username"]].iloc[0] # Find row for current user
    if not row.empty and bcrypt.checkpw(old.encode(), row["password"].encode()):    # Verify old password
        if new == conf: # Check new password confirmation
            update_user_password(user["username"], new)  # Save new password securely
            st.success("Password changed") # Confirmation message
        else:
            st.error("New passwords do not match") # Validation error
    else:
        st.error("Old password incorrect")  # Validation error
