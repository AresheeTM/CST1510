import bcrypt
import os

USER_DATA_FILE = 'user_data.txt'


def hash_password(plain_text_password):
    # Encode the password to bytes (bcrypt requires byte strings)
    password_bytes = plain_text_password.encode('utf-8')

    # Generate a salt using bcrypt.gensalt()
    salt = bcrypt.gensalt()

    # Hash the password using bcrypt.hashpw()
    hashed = bcrypt.hashpw(password_bytes, salt)

    # Decode the hash back to a string to store in a text file
    return hashed.decode('utf-8')


def verify_password(plain_text_password, hashed_password):
    # Encode both the plaintext password and the stored hash to bytes
    password_bytes = plain_text_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')

    # Use bcrypt.checkpw()verify the password
    # This function extracts the salt from the hash and compares
    return bcrypt.checkpw(password_bytes, hashed_bytes)


def register_user(username, password):
    # TODO: Check if the username already exists
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, 'r') as file:
            for line in file:
                stored_username, _ = line.strip().split(",")
                if stored_username == username:
                    print(f"Error: Username '{username}' already exists.")
                    return False

    # TODO: Hash the password
    hashed_password = hash_password(password)

    # TODO: Append the new user to the file
    # Format: username,hashed_password
    with open(USER_DATA_FILE, 'a') as file:
        file.write(f"{username},{hashed_password}\n")

    print(f"Success: User '{username}' registered successfully!")
    return True


def login_user(username, password):
    # TODO: Handle the case where no users are registered yet
    if not os.path.exists(USER_DATA_FILE):
        print("Error: Username not found.")
        return False

    # TODO: Search for the username in the file
    with open(USER_DATA_FILE, 'r') as file:
        for line in file:
            stored_username, stored_hash = line.strip().split(",")

            # TODO: If username matches, verify the password
            if stored_username == username:
                if verify_password(password, stored_hash):
                    print(f"Success: Welcome, {username}!")
                    return True
                else:
                    print("Error: Invalid password.")
                    return False

    # TODO: If we reach here, the username was not found
    print("Error: Username not found.")
    return False


def validate_username(username):
    # Username must be at least 3 characters
    if len(username) < 3:
        return False, "Username must be at least 3 characters long."

    # Username must not contain spaces
    if " " in username:
        return False, "Username cannot contain spaces."

    # Username must be alphanumeric
    if not username.isalnum():
        return False, "Username must only contain letters and numbers."

    return True, ""


def validate_password(password):
    # Password length check
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    # Uppercase letter check
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."

    # Lowercase letter check
    if not any(c.islower() for c in password):
        return (False, "Password must contain at least one lowercase letter.")

    # Digit check
    if not any(c.isdigit() for c in password):
        return (False, "Password must contain at least one digit.")

    return (True, "")


def display_menu():
    """Displays the main menu options."""
    print("\n" + "=" * 50)
    print("  MULTI-DOMAIN INTELLIGENCE PLATFORM")
    print("  Secure Authentication System")
    print("=" * 50)
    print("\n[1] Register a new user")
    print("[2] Login")
    print("[3] Exit")
    print("-" * 50)


def main():
    """Main program loop."""
    print("\nWelcome to the Week 7 Authentication System!")

    while True:
        display_menu()
        choice = input("\nPlease select an option (1-3): ").strip()

        if choice == '1':
            # Registration flow
            print("\n--- USER REGISTRATION ---")
            username = input("Enter a username: ").strip()

            # Validate username
            is_valid, error_msg = validate_username(username)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            password = input("Enter a password: ").strip()

            # Validate password
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            # Confirm password
            password_confirm = input("Confirm password: ").strip()
            if password != password_confirm:
                print("Error: Passwords do not match.")
                continue

            # Register user
            register_user(username, password)

        elif choice == '2':
            # Login flow
            print("\n--- USER LOGIN ---")
            username = input("Enter your username: ").strip()
            password = input("Enter your password: ").strip()

            # Attempt login
            login_user(username, password)

        elif choice == '3':
            # Exit
            print("\nThank you for using the authentication system.")
            print("Exiting...")
            break

        else:
            print("\nError: Invalid option. Please select 1, 2, or 3.")


if __name__ == "__main__":
    main()
