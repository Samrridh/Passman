import os
import json
import base64
import getpass
import secrets
import string
import pyotp
import qrcode
import pyperclip
from typing import Dict


from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich import box
from PIL import Image

console = Console()
VAULT_FILE = "vault.json"

def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def load_vault(master_password: str) -> Dict:
    if not os.path.exists(VAULT_FILE):
        return {}

    with open(VAULT_FILE, "rb") as f:
        data = f.read()

    salt, encrypted_data = data[:16], data[16:]
    key = derive_key(master_password, salt)
    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(encrypted_data)
    except InvalidToken:
        console.print("[red]Invalid master password![/red]")
        return None
    return json.loads(decrypted.decode())

def save_vault(vault: Dict, master_password: str):
    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(json.dumps(vault).encode())
    with open(VAULT_FILE, "wb") as f:
        f.write(salt + encrypted)

def generate_totp_qr(name: str, secret: str):
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=name, issuer_name="TUI Password Manager")
    img = qrcode.make(uri)
    file_path = f"./QR/{name}_qr.png"
    img.save(file_path)
    img_obj = Image.open(file_path)
    img_obj.show()
    console.print(f"[green]QR code saved as [bold]{file_path}[/bold]. Scan it with Google Authenticator.[/green]")

def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def pretty_list(vault: Dict[str, dict]):
    table = Table(title="Saved Credentials", box=box.ROUNDED)
    table.add_column("Service", style="cyan", no_wrap=True)
    table.add_column("Username/Email", style="magenta")
    table.add_column("Has 2FA?", style="green")
    for name, creds in vault.items():
        has_2fa = "✅" if "totp_secret" in creds else "❌"
        table.add_row(name, creds["username"], has_2fa)
    console.print(table)


def main():
    console.print(Panel("🔐 [bold cyan]TUI Password Manager[/bold cyan]", expand=False))
    
    if not os.path.exists(VAULT_FILE):
        console.print("[yellow]No vault found. Let's create one![/yellow]")
        while True:
            master_password = getpass.getpass("Create a new master password: ")
            confirm_password = getpass.getpass("Confirm master password: ")
            if master_password == confirm_password and master_password.strip():
                save_vault({}, master_password)  
                console.print("[green]Vault created successfully![/green]")
                break
            else:
                console.print("[red]Passwords do not match or are empty. Try again.[/red]")
    else:
        master_password = getpass.getpass("Enter master password: ")

    vault = load_vault(master_password)
    if vault is None:
        return

    while True:
        console.print("\n[bold yellow]Options:[/bold yellow] (list, add, view, delete, demo, exit)")
        choice = Prompt.ask("What do you want to do?").strip().lower()

        if choice == "list":
            if vault:
                pretty_list(vault)
            else:
                console.print("[red]Vault is empty.[/red]")

        elif choice == "add":
            name = Prompt.ask("Service name")
            username = Prompt.ask("Username/Email")
            password = Prompt.ask("Password (leave blank to generate)")
            if not password:
                password = generate_password()
                console.print(f"[green]Generated password:[/green] {password}")

            enable_2fa = Confirm.ask("Enable Google Authenticator 2FA?")
            totp_secret = None
            if enable_2fa:
                totp_secret = pyotp.random_base32()
                generate_totp_qr(name, totp_secret)

            vault[name] = {
                "username": username,
                "password": password,
                **({"totp_secret": totp_secret} if totp_secret else {})
            }
            save_vault(vault, master_password)
            console.print("[green]Credential added successfully![/green]")

        elif choice == "view":
            pretty_list(vault)
            name = Prompt.ask("Enter Service name")
            if name not in vault:
                console.print("[red]No such credential found.[/red]")
                continue

            cred = vault[name]
            console.print(f"[cyan]Username:[/cyan] {cred['username']}")
            console.print(f"[cyan]Password:[/cyan] {cred['password']}")
            pyperclip.copy(cred['password'])
            console.print("[green]Password copied![/green]")

        elif choice == "delete":
            pretty_list(vault)
            name = Prompt.ask("Enter Service name to delete")
            if name in vault:
                vault.pop(name)
                save_vault(vault, master_password)
                console.print("[green]Deleted successfully.[/green]")
            else:
                console.print("[red]No such credential found.[/red]")

        elif choice == "demo":
            pretty_list(vault)
            name = Prompt.ask("Enter Service name")
            if name not in vault:
                console.print("[red]No such credential found.[/red]")
                continue

            cred = vault[name]
            username_input = Prompt.ask("Enter username/email")
            password_input = getpass.getpass("Enter password: ")

            if username_input != cred["username"] or password_input != cred["password"]:
                console.print("[red]Invalid username or password![/red]")
                continue

            if "totp_secret" in cred:
                totp = pyotp.TOTP(cred["totp_secret"])
                code = Prompt.ask("Enter Google Authenticator code")
                if not totp.verify(code):
                    console.print("[red]Invalid 2FA code![/red]")
                    continue

            console.print("[green bold]✅ Demo successful![/green bold]")

        elif choice == "exit":
            console.print("[yellow]Exiting...[/yellow]")
            break

        else:
            console.print("[red]Invalid option![/red]")


if __name__ == "__main__":
    main()
