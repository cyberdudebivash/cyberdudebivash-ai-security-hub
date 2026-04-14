#!/usr/bin/env python3
"""
CYBERDUDEBIVASH AI — LOCAL DEVELOPMENT STARTUP
Usage: python start.py [--check-only]
"""

import os
import sys
import subprocess
import secrets

def banner():
    print("\n" + "="*60)
    print("  ⚔️  CYBERDUDEBIVASH AI SYSTEM v2.0.0")
    print("  Autonomous Cybersecurity Intelligence Platform")
    print("="*60 + "\n")

def check_env():
    banner()
    if not os.path.exists(".env"):
        print("⚠️  .env not found — creating from .env.example...")
        if os.path.exists(".env.example"):
            import shutil
            shutil.copy(".env.example", ".env")
            # Generate a real secret key
            new_key = secrets.token_hex(32)
            with open(".env", "r") as f:
                content = f.read()
            content = content.replace(
                "replace_with_64_char_random_hex_string_do_not_use_default",
                new_key
            )
            with open(".env", "w") as f:
                f.write(content)
            print(f"✅ .env created with generated SECRET_KEY")
        else:
            print("❌ .env.example missing. Create .env manually.")
            sys.exit(1)

    from dotenv import load_dotenv
    load_dotenv()

    errors = []
    warnings = []

    key = os.getenv("OPENAI_API_KEY", "")
    if not key or key == "your_openai_api_key_here":
        errors.append("OPENAI_API_KEY is not set (AI features will be disabled)")

    secret = os.getenv("SECRET_KEY", "")
    if "CHANGE_ME" in secret or "replace_with" in secret.lower():
        warnings.append("SECRET_KEY is using an insecure default — change before production use")

    if errors:
        for e in errors:
            print(f"  ⚠️  {e}")
    if warnings:
        for w in warnings:
            print(f"  ⚠️  {w}")

    print("✅ Environment loaded\n")

def init_db():
    print("🗄  Initializing database...")
    try:
        from core.database.db_engine import init_db as _init
        _init()
        print("✅ Database ready\n")
    except Exception as e:
        print(f"❌ Database init failed: {e}")
        sys.exit(1)

def start_api():
    print("🚀 Starting CYBERDUDEBIVASH AI...")
    print("   API:       http://localhost:8000")
    print("   Docs:      http://localhost:8000/docs")
    print("   Dashboard: http://localhost:8000/dashboard")
    print("   Health:    http://localhost:8000/health\n")
    print("   Press Ctrl+C to stop\n")
    subprocess.run([
        sys.executable, "-m", "uvicorn",
        "generated_app.main:app",
        "--host", "0.0.0.0",
        "--port", "8000",
        "--reload",
        "--log-level", "info",
    ])

if __name__ == "__main__":
    check_only = "--check-only" in sys.argv
    check_env()
    if not check_only:
        init_db()
        start_api()
    else:
        print("✅ Check complete — system configuration looks good")
