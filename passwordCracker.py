import crypt
import time


def read_shadow_file(filename):
    """
    Reads the /etc/shadow file and extracts username, salt, and hashed password.

    :param filename: Path to the shadow file.
    :return: A dictionary with usernames as keys and (salt, hashed_password) as values.
    """
    shadow_data = {}
    try:
        with open(filename, 'r') as file:
            for line in file:
                if ':' in line:
                    parts = line.strip().split(':')
                    if len(parts) >= 2 and parts[1] not in ('*', '!'):  # Skip locked or disabled accounts
                        username = parts[0]
                        hashed_password = parts[1]
                        # Extract the salt (first part of the hashed password)
                        salt = hashed_password[:hashed_password.rfind('$')]
                        shadow_data[username] = (salt, hashed_password)
    except FileNotFoundError:
        print(f"File {filename} not found.")
    except PermissionError:
        print(f"Permission denied. Please run the script with sudo.")
    return shadow_data


def read_common_passwords(filename):
    """
    Reads the common passwords from the given file.

    :param filename: Path to the common passwords file.
    :return: A list of common passwords.
    """
    with open(filename, 'r') as file:
        passwords = [line.strip() for line in file]
    return passwords


def crack_passwords(shadow_data, common_passwords):
    """
    Attempts to crack passwords by comparing hashes.

    :param shadow_data: Dictionary of username: (salt, hashed_password).
    :param common_passwords: List of common passwords to try.
    :return: A dictionary of cracked username: password pairs.
    """
    cracked = {}
    for username, (salt, hashed_password) in shadow_data.items():
        for password in common_passwords:
            # Hash the password with the extracted salt
            computed_hash = crypt.crypt(password, salt)
            if computed_hash == hashed_password:
                cracked[username] = password
                break  # Stop trying passwords for this user once cracked
    return cracked


def main():
    # Read the shadow file
    shadow_data = read_shadow_file('/etc/shadow')
    if not shadow_data:
        print("No shadow data found. Exiting.")
        return

    # Read the common passwords file
    common_passwords = read_common_passwords('CommonPasswords.txt')

    # Crack passwords with salt
    start_time_with_salt = time.time()
    cracked_with_salt = crack_passwords(shadow_data, common_passwords)
    end_time_with_salt = time.time()

    # Crack passwords without salt (for comparison)
    start_time_without_salt = time.time()
    cracked_without_salt = {}
    for username, (_, hashed_password) in shadow_data.items():
        for password in common_passwords:
            # Hash the password without salt (not realistic, just for comparison)
            computed_hash = crypt.crypt(password, '')
            if computed_hash == hashed_password:
                cracked_without_salt[username] = password
                break
    end_time_without_salt = time.time()

    # Output the results
    print("Cracked passwords with salt:")
    for username, password in cracked_with_salt.items():
        print(f"{username}: {password}")
    print(f"Time taken with salt: {end_time_with_salt - start_time_with_salt:.2f} seconds")

    print("\nCracked passwords without salt:")
    for username, password in cracked_without_salt.items():
        print(f"{username}: {password}")
    print(f"Time taken without salt: {end_time_without_salt - start_time_without_salt:.2f} seconds")


if __name__ == "__main__":
    main()