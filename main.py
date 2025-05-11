import subprocess
import sys
import crypt

def create_users():
    try:
        with open('CommonPasswords.txt', 'r') as password_file:
            passwords = password_file.readlines()

        if len(passwords) < 30:
            print("Error: Not enough passwords in the file.")
            sys.exit(1)

        for i in range(1, 31):
            username = f"user{i}"
            password = passwords[i - 1].strip()
            encrypted_password = crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))
            subprocess.run(['sudo', 'useradd', '-m', '-p', encrypted_password, username], check=True)
            print(f"User {username} created.")
    except Exception as e:
        print(f"Failed to add users: {e}")
        sys.exit(1)
def delete_users():
    try:
        for i in range(1, 31):
            username = f"user{i}"
            subprocess.run(['sudo', 'userdel', '-r', username], check=True)
            print(f"User {username} deleted.")
    except Exception as e:
        print(f"Failed to delete users: {e}")
        sys.exit(1)
def display_files():
    try:
        subprocess.run(['cat', '/etc/passwd'])
        subprocess.run(['sudo', 'cat', '/etc/shadow'])
    except Exception as e:
        print(f"Failed to display files: {e}")
        sys.exit(1)

if __name__ == "__main__":
    delete_users()
    display_files()