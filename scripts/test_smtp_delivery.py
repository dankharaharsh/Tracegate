#!/usr/bin/env python3
"""
Tracegate Email Delivery & SMTP Diagnostic Tool
Tests SMTP / email delivery configuration and dispatches a test verification OTP
to any specified email address.
"""

import sys
import os
import argparse
from pathlib import Path

# Add project root to sys.path
root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root))

from backend.config import (
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USER,
    SMTP_PASSWORD,
    SMTP_FROM_EMAIL,
    SMTP_FROM_NAME,
    SMTP_USE_TLS,
    SMTP_USE_SSL,
    RESEND_API_KEY,
    EMAIL_DEV_MODE,
)
from backend import email_service


def mask_secret(secret: str) -> str:
    if not secret:
        return "[NOT SET]"
    if len(secret) <= 4:
        return "***"
    return secret[:2] + "*" * (len(secret) - 4) + secret[-2:]


def print_status():
    print("=" * 60)
    print(" Tracegate Email Delivery Configuration Status")
    print("=" * 60)
    print(f"  SMTP_HOST:       {SMTP_HOST or '[NOT SET]'}")
    print(f"  SMTP_PORT:       {SMTP_PORT}")
    print(f"  SMTP_USER:       {SMTP_USER or '[NOT SET]'}")
    print(f"  SMTP_PASSWORD:   {mask_secret(SMTP_PASSWORD)}")
    print(f"  SMTP_FROM_EMAIL: {SMTP_FROM_EMAIL}")
    print(f"  SMTP_FROM_NAME:  {SMTP_FROM_NAME}")
    print(f"  SMTP_USE_TLS:    {SMTP_USE_TLS}")
    print(f"  SMTP_USE_SSL:    {SMTP_USE_SSL}")
    print(f"  RESEND_API_KEY:  {mask_secret(RESEND_API_KEY)}")
    print(f"  EMAIL_DEV_MODE:  {EMAIL_DEV_MODE}")
    print("-" * 60)
    configured = email_service.is_email_configured()
    print(f"  Configured:      {'YES (Ready for delivery)' if configured else 'NO (Unconfigured)'}")
    print("=" * 60)
    return configured


def check_connection():
    print("\nTesting connection to email provider...")
    if RESEND_API_KEY and not SMTP_HOST:
        print("[+] Resend API key is configured. (Connection tested upon send)")
        return True

    success, msg = email_service.verify_smtp_connection()
    if success:
        print(f"[SUCCESS] {msg}")
    else:
        print(f"[ERROR] {msg}")
    return success


def send_test_otp(target_email: str):
    print(f"\nSending test verification OTP to recipient: {target_email}")
    test_otp = "849201"
    success = email_service.send_password_reset_email(target_email, test_otp)
    if success:
        if os.getenv("TESTING") == "1" or EMAIL_DEV_MODE:
            print("[NOTICE] Email captured in test/dev outbox (EMAIL_DEV_MODE is enabled).")
        else:
            print(f"[SUCCESS] Verification OTP successfully sent to {target_email}!")
            print(f"[+] Please check the inbox (and spam folder) of {target_email}.")
    else:
        print(f"[ERROR] Failed to send verification OTP to {target_email}.")
        print("[!] Please verify your SMTP settings in .env or server environment variables.")
    return success


def main():
    parser = argparse.ArgumentParser(description="Tracegate Email Delivery Diagnostic Tool")
    parser.add_argument("--check", action="store_true", help="Check configuration and test SMTP handshake")
    parser.add_argument("--send", type=str, metavar="EMAIL", help="Send a test verification OTP to any target email")
    args = parser.parse_args()

    print_status()

    if args.check:
        check_connection()

    if args.send:
        send_test_otp(args.send)

    if not args.check and not args.send:
        print("\nUsage:")
        print("  python scripts/test_smtp_delivery.py --check")
        print("  python scripts/test_smtp_delivery.py --send user@example.com")


if __name__ == "__main__":
    main()
