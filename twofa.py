import os
import json
import time
import random
import threading

CODES_FILE = os.path.expanduser("~/.tui_codes.json")
lock = threading.Lock()
codes = {}

def save_codes():
    with lock:
        with open(CODES_FILE, "w") as f:
            json.dump(codes, f)

def load_codes():
    if os.path.exists(CODES_FILE):
        with open(CODES_FILE, "r") as f:
            try:
                data = json.load(f)
                with lock:
                    codes.clear()
                    codes.update(data)
            except json.JSONDecodeError:
                pass

def generate_codes():
    """Refresh all codes every 30 seconds."""
    while True:
        with lock:
            for name in codes:
                codes[name] = random.randint(100000, 999999)
        save_codes()
        time.sleep(30)

def register_credential(name):
    load_codes()
    with lock:
        codes[name] = random.randint(100000, 999999)
    save_codes()

def remove_credential(name):
    load_codes()
    with lock:
        if name in codes:
            del codes[name]
    save_codes()

def get_current_code(name):
    load_codes()
    with lock:
        return codes.get(name)

def verify_code(name, user_input):
    load_codes()
    with lock:
        return str(user_input) == str(codes.get(name))

def display_loop():
    """Show live-updating codes, auto-reloading new credentials."""
    while True:
        load_codes() 
        os.system('cls' if os.name == 'nt' else 'clear')
        print("=== Live 2FA Codes ===")
        with lock:
            if not codes:
                print("(No credentials registered)")
            else:
                for name, code in codes.items():
                    print(f"{name}: {code}")
        print("\n(Refreshing every 30 seconds, auto-updating new creds)")
        time.sleep(1)

if __name__ == "__main__":
    load_codes()
    threading.Thread(target=generate_codes, daemon=True).start()
    display_loop()
