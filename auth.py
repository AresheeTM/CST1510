# =========================================================
# Week 7: Secure Authentication System
# =========================================================
# Author: Areshee Marimootoo
# Student ID: M01069426
# Course: CST1510 - CW2 - Multi-Domain Intelligence Platform
# =========================================================


# Step 3. Import Required Modules
import bcrypt
import os
import secrets
import time

# ============================================
# Step 4. Implement the Password Hashing Function
# ============================================

def hash_password(plain_text_password):
    """
    Hashes a password using bcrypt with automatic salt generation.
    Args:
        plain_text_password (str): The plaintext password to hash
    Returns:
        str: The hashed password as a UTF-8 string
    """
    # Encode password to bytes
    password_bytes = plain_text_password.encode('utf-8')

    # Generate salt
    salt = bcrypt.gensalt()

    # Hash password
    hashed = bcrypt.hashpw(password_bytes, salt)

    # Decode hash to string
    return hashed.decode('utf-8')


# ============================================
# Step 5. Implement the Password Verification Function
# ============================================

def verify_password(plain_text_password, hashed_password):
    """
    Verifies a plaintext password against a stored bcrypt hash.
    Args:
        plain_text_password (str): The password to verify
        hashed_password (str): The stored hash to check against
    Returns:
        bool: True if the password matches, False otherwise
    """
    # Encode both values to bytes
    plain_bytes = plain_text_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')

    # Verify using bcrypt.checkpw()
    return bcrypt.checkpw(plain_bytes, hashed_bytes)


# ============================================
# Step 6. TEMPORARY TEST CODE (remove after testing)
# ============================================

# test_password = "SecurePassword123"
# hashed = hash_password(test_password)
# print(f"Original: {test_password}")
# print(f"Hashed: {hashed}")
# print("Verification:", verify_password(test_password, hashed))


# ============================================
# Step 7. Implement the Registration Function
# ============================================

USER_DATA_FILE = "users.txt"
LOCKOUT_FILE = "failed_attempts.txt"

def register_user(username, password, role="user"):
    """
    Registers a new user by hashing their password and storing credentials.
    Returns:
        bool: True if successful, False if username already exists
    """
    if user_exists(username):
        print(" Username already exists.")
        return False

    hashed_password = hash_password(password)
    with open(USER_DATA_FILE, "a") as file:
        file.write(f"{username},{hashed_password},{role}\n")

    print(f" User '{username}' registered successfully!")
    return True


# ============================================
# Step 8. Implement the User Existence Check
# ============================================

def user_exists(username):
    """
    Checks if a username already exists in the user database.
    Returns:
        bool: True if the user exists, False otherwise
    """
    if not os.path.exists(USER_DATA_FILE):
        return False

    with open(USER_DATA_FILE, "r") as file:
        for line in file:
            existing_user = line.strip().split(",")[0]
            if existing_user == username:
                return True
    return False


# ============================================
# Step 9. Implement the Login Function
# ============================================

def login_user(username, password):
    """
    Authenticates a user by verifying their username and password.
    Returns:
        bool: True if authentication successful, False otherwise
    """
    # Check if users exist
    if not os.path.exists(USER_DATA_FILE):
        print(" No users registered yet.")
        return False

    # Lockout mechanism
    if is_account_locked(username):
        print(" Account locked. Try again later.")
        return False

    # Search user in file
    with open(USER_DATA_FILE, "r") as file:
        for line in file:
            stored_username, stored_hash, role = line.strip().split(",")

            if stored_username == username:
                if verify_password(password, stored_hash):
                    print(" Login successful!")
                    reset_failed_attempts(username)
                    token = create_session(username)
                    print(f"Session token: {token}")
                    return True
                else:
                    print(" Incorrect password.")
                    record_failed_attempt(username)
                    return False

    print(" Username not found.")
    return False


# ============================================
# Step 10. Implement Input Validation
# ============================================

def validate_username(username):
    """
    Validates username format.
    Returns (bool, str)
    """
    if not (3 <= len(username) <= 20):
        return False, "Username must be between 3 and 20 characters."
    if not username.isalnum():
        return False, "Username must contain only letters and numbers."
    return True, ""


def validate_password(password):
    """
    Validates password strength.
    Returns (bool, str)
    """
    if len(password) < 6:
        return False, "Password must be at least 6 characters long."
    return True, ""


# ============================================
# Step 11. Optional Challenge 1: Password Strength Indicator
# ============================================

def check_password_strength(password):
    """
    Evaluates password strength: Weak, Medium, or Strong
    """
    import re
    length = len(password) >= 8
    upper = re.search(r"[A-Z]", password)
    lower = re.search(r"[a-z]", password)
    digit = re.search(r"\d", password)
    special = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)

    score = sum([bool(length), bool(upper), bool(lower), bool(digit), bool(special)])
    if score <= 2:
        return "Weak"
    elif score == 3 or score == 4:
        return "Medium"
    else:
        return "Strong"


# ============================================
# Step 12. Optional Challenge 3: Account Lockout
# ============================================

def record_failed_attempt(username):
    timestamp = time.time()
    failed_attempts = get_failed_attempts(username)
    failed_attempts.append(timestamp)
    with open(LOCKOUT_FILE, "a") as file:
        file.write(f"{username},{timestamp}\n")

def get_failed_attempts(username):
    if not os.path.exists(LOCKOUT_FILE):
        return []
    with open(LOCKOUT_FILE, "r") as file:
        lines = file.readlines()
    return [float(line.strip().split(",")[1]) for line in lines if line.startswith(username + ",")]

def reset_failed_attempts(username):
    if not os.path.exists(LOCKOUT_FILE):
        return
    with open(LOCKOUT_FILE, "r") as file:
        lines = file.readlines()
    with open(LOCKOUT_FILE, "w") as file:
        for line in lines:
            if not line.startswith(username + ","):
                file.write(line)

def is_account_locked(username):
    attempts = get_failed_attempts(username)
    recent_attempts = [t for t in attempts if time.time() - t < 300]
    if len(recent_attempts) >= 3:
        return True
    return False


# ============================================
# Step 13. Optional Challenge 4: Session Management
# ============================================

def create_session(username):
    """
    Creates a session token for a logged-in user.
    """
    token = secrets.token_hex(16)
    return token


# ============================================
# Step 14. Interactive Menu (Main Interface)
# ============================================

def main():
    while True:
        print("\n--- Secure Authentication System ---")
        print("[1] Register User")
        print("[2] Login User")
        print("[3] Exit")

        choice = input("Select an option: ")

        if choice == "1":
            username = input("Enter username: ")
            valid, msg = validate_username(username)
            if not valid:
                print("!!!", msg)
                continue

            password = input("Enter password: ")
            valid, msg = validate_password(password)
            if not valid:
                print("!!!", msg)
                continue

            strength = check_password_strength(password)
            print(f"Password strength: {strength}")

            role = input("Enter role (user/admin/analyst) [default=user]: ") or "user"
            register_user(username, password, role)

        elif choice == "2":
            username = input("Enter username: ")
            password = input("Enter password: ")
            login_user(username, password)

        elif choice == "3":
            print("Exiting program...")
            break
        else:
            print("Invalid option. Please try again.")


if __name__ == "__main__":
    main()
