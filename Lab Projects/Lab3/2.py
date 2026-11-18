from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher = Fernet(key)
print("Secret Key:", key.decode())

message = input("\nEnter confidential message: ").encode()

encrypted_message = cipher.encrypt(message)
print("\nEncrypted Message:", encrypted_message.decode())

print("\n--- Decryption Phase ---")
user_key = input("Enter the secret key to decrypt: ").encode()

try:
    decrypt_cipher = Fernet(user_key)
    decrypted_message = decrypt_cipher.decrypt(encrypted_message)
    print("\nDecrypted Message:", decrypted_message.decode())
    print("\nData confidentiality verified successfully!")
except Exception as e:
    print("\nDecryption failed! Invalid or incorrect key provided.")
    print(f"Error details: {e}")
