import hashlib
import time
import pyotp

# PART 2: Functions
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, stored_hash: str) -> bool:
    return hash_password(password) == stored_hash

# PART 6: OTP Verification Function
def verify_otp(secret: str, otp: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(otp)


# PARTS 3 & 7: Setup User Database with a Fixed Secret
alice_secret = pyotp.random_base32()

users = {
    "alice": {
        "password_hash": hash_password("Cyber123!"),
        "totp_secret": alice_secret  # Secret is saved into the user record
    }
}

print("--- PARTS 3 & 7: User Record Created ---")
print("User: alice")
print("Password Hash:", users["alice"]["password_hash"])
print("Static TOTP Secret:", users["alice"]["totp_secret"])
print("-" * 45)


# PARTS 5 & 6: Test OTP Generation & Verification

# Retrieve the secret directly from the user dictionary
user_secret = users["alice"]["totp_secret"]

# Generate current 6-digit code from that stored secret
totp = pyotp.TOTP(user_secret)
current_otp = totp.now()

print("--- PART 6: Testing OTP Verification ---")
print("Current Valid OTP:", current_otp)

# Test 1: Valid OTP
is_valid = verify_otp(user_secret, current_otp)
print(f"1. Test Current OTP ({current_otp}): {is_valid}")

# Test 2: Invalid 6-Digit Code
is_invalid = verify_otp(user_secret, "000000")
print(f"2. Test Incorrect OTP ('000000'): {is_invalid}")

# Test 3: Expired OTP
print("\nWaiting 35 seconds for the OTP to expire...")
time.sleep(35)  # Pauses execution so the 30-second TOTP window rolls over

is_expired = verify_otp(user_secret, current_otp)
print(f"3. Test Expired OTP ({current_otp}): {is_expired}")