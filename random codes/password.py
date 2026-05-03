import math
import string

def password_strength(password):
    length = len(password)
    if length == 0:
        print("Password cannot be empty!")
        return

    # Calculate Character Set Size (R)
    charset_size = 0
    if any(c in string.ascii_lowercase for c in password):
        charset_size += 26
    if any(c in string.ascii_uppercase for c in password):
        charset_size += 26
    if any(c in string.digits for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += 32

    # Entropy Formula: E = L * log2(R)
    # Using math.pow can cause OverflowErrors for very long passwords; 
    # math.log2(charset_size) * length is more stable.
    bits = math.log2(charset_size) * length
    combinations = math.pow(charset_size, length)

    # Crack Time Calculation
    guesses_per_second = 1_000_000_000  # 1 Billion guesses/sec
    seconds = combinations / guesses_per_second
    years = seconds / (60 * 60 * 24 * 365)

    print("\n--- Password Strength Analysis ---")
    print(f"Length of Password: {length} characters")
    print(f"Total Combinations: {combinations:,.2f}")
    print(f"Entropy Bits: {bits:.2f} bits")
    print(f"Crack time (seconds): {seconds:,.2f}s")
    
    if years < 1:
        print(f"Crack time (days): {(seconds / 86400):.2f} days")
    else:
        print(f"Crack time (years): {years:,.2f} years")

    # Strength Thresholds
    if bits < 36:
        print("Verdict: VERY WEAK (Can be cracked instantly)")
    elif 36 <= bits < 60:
        print("Verdict: REASONABLE (Better to change it)")
    elif 60 <= bits < 80:
        print("Verdict: STRONG")
    elif 80 <= bits < 128:
        print("Verdict: VERY STRONG")
    else:
        print("Verdict: EXCELLENT (Fully Secure)")

# Main Loop
while True:
    user_pwd = input("\nEnter the password to check (or type 'exit'): ")
    if user_pwd.lower() == 'exit':
        print("Program Exited.")
        break
    
    password_strength(user_pwd)
    print("-" * 40)
