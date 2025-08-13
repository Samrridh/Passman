import os
import json
import base64
import getpass
import secrets
import string
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

from twofa import register_credential, remove_credential, get_current_code, verify_code


console = Console()

VAULT_PATH = os.path.expanduser("~/.tui_vault.bin")
SALT_SIZE = 16
KDF_ITERS = 390000

try:
    import pyperclip
    CLIP_AVAILABLE = True
except Exception:
    CLIP_AVAILABLE = False


def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def init_vault(master_password: str) -> Dict:
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(master_password, salt)
    f = Fernet(key)
    token = f.encrypt(json.dumps({}).encode())
    with open(VAULT_PATH, "wb") as fh:
        fh.write(salt + token)
    return {}


def load_vault(master_password: str) -> Dict:
    if not os.path.exists(VAULT_PATH):
        return init_vault(master_password)
    with open(VAULT_PATH, "rb") as fh:
        data = fh.read()
    salt = data[:SALT_SIZE]
    token = data[SALT_SIZE:]
    key = derive_key(master_password, salt)
    try:
        return json.loads(Fernet(key).decrypt(token).decode())
    except InvalidToken:
        raise


def save_vault(vault: Dict, master_password: str) -> None:
    if os.path.exists(VAULT_PATH):
        with open(VAULT_PATH, "rb") as fh:
            salt = fh.read()[:SALT_SIZE]
    else:
        salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(master_password, salt)
    token = Fernet(key).encrypt(json.dumps(vault).encode())
    with open(VAULT_PATH, "wb") as fh:
        fh.write(salt + token)


def prompt_master(new=False) -> str:
    if new:
        while True:
            m = getpass.getpass("Create master password: ")
            if len(m) < 8:
                console.print("[red]Use at least 8 characters[/red]")
                continue
            if m != getpass.getpass("Confirm master password: "):
                console.print("[red]Passwords do not match[/red]")
                continue
            return m
    else:
        return getpass.getpass("Master password: ")


def generate_password(length=16) -> str:
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def pretty_list(vault: Dict):
    if not vault:
        console.print("[yellow](Vault empty)[/yellow]")
        return
    table = Table(title="Vault Entries", box=box.SIMPLE, header_style="bold cyan")
    table.add_column("#")
    table.add_column("Name")
    for i, name in enumerate(sorted(vault.keys()), 1):
        table.add_row(str(i), name)
    console.print(table)


def main():
    console.print(Panel("[bold cyan]TUI Password Manager[/bold cyan]", expand=False))
    if not os.path.exists(VAULT_PATH):
        console.print("[yellow]No vault found — creating new one[/yellow]")
        master = prompt_master(new=True)
        vault = init_vault(master)
    else:
        master = prompt_master()
        try:
            vault = load_vault(master)
            console.print("[green]Vault unlocked[/green]")
        except InvalidToken:
            console.print("[red]Wrong master password[/red]")
            return

    while True:
        console.print("\n[bold]Menu:[/bold] [cyan]L[/cyan]ist  [cyan]A[/cyan]dd  [cyan]V[/cyan]iew  [cyan]D[/cyan]elete  [cyan]G[/cyan]enerate  [cyan]C[/cyan]hange Master  [cyan]Q[/cyan]uit")
        choice = Prompt.ask(">", default="L").lower()

        if choice.startswith("l"):
            pretty_list(vault)
        elif choice.startswith("a"):
            name = Prompt.ask("Name")
            user = Prompt.ask("Username/email")
            if Confirm.ask("Generate password?", default=True):
                length = Prompt.ask("Length", default="16")
                try:
                    length = int(length)
                except ValueError:
                    length = 16
                password = generate_password(length)
                console.print(f"Generated: [bold yellow]{password}[/bold yellow]")
            else:
                password = getpass.getpass("Password: ")
            notes = Prompt.ask("Notes", default="")
            vault[name] = {"username": user, "password": password, "notes": notes}
            
            register_credential(name)

            save_vault(vault, master)
            console.print("[green]Saved[/green]")
        elif choice.startswith("v"):
            if not vault:
                console.print("[yellow]Vault empty[/yellow]")
                continue
            pretty_list(vault)
            sel = Prompt.ask("Name or number")
            if sel.isdigit():
                idx = int(sel) - 1
                keys = sorted(vault.keys())
                if idx < 0 or idx >= len(keys):
                    console.print("[red]Invalid selection[/red]")
                    continue
                key = keys[idx]
            else:
                key = sel
            if key not in vault:
                console.print("[red]No such entry[/red]")
                continue

            code = get_current_code(key)
            if code is None:
                register_credential(key)
                code = get_current_code(key)
            # console.print(f"[dim]2FA code for {key}: [bold magenta]{code}[/bold magenta][/dim]")
            console.print(f"2FA code for {key}: [bold magenta]Check in twofa.py terminal[/bold magenta]")
            user_code = Prompt.ask("Enter 2FA code")
            if not verify_code(key, user_code):
                console.print("[red]Invalid 2FA code. Access denied.[/red]")
                continue

            entry = vault[key]
            console.print(Panel(f"[bold]{key}[/bold]\nUser: {entry['username']}\nPass: {entry['password']}\nNotes: {entry['notes']}", title="Entry"))
            if CLIP_AVAILABLE and Confirm.ask("Copy password to clipboard?", default=False):
                pyperclip.copy(entry['password'])
                console.print("[green]Copied to clipboard[/green]")
        elif choice.startswith("d"):
            pretty_list(vault)
            sel = Prompt.ask("Name or number")
            if sel.isdigit():
                idx = int(sel) - 1
                keys = sorted(vault.keys())
                if idx < 0 or idx >= len(keys):
                    console.print("[red]Invalid selection[/red]")
                    continue
                key = keys[idx]
            else:
                key = sel
            if key not in vault:
                console.print("[red]No such entry[/red]")
                continue
            if Confirm.ask(f"Delete {key}?", default=False):
                del vault[key]
                save_vault(vault, master)
                remove_credential(key)
                console.print("[green]Deleted[/green]")
        elif choice.startswith("g"):
            length = Prompt.ask("Length", default="16")
            try:
                length = int(length)
            except ValueError:
                length = 16
            console.print(f"Generated: [bold yellow]{generate_password(length)}[/bold yellow]")
        elif choice.startswith("c"):
            current = getpass.getpass("Current master password: ")
            try:
                _ = load_vault(current)
            except InvalidToken:
                console.print("[red]Wrong password[/red]")
                continue
            newpw = prompt_master(new=True)
            salt = secrets.token_bytes(SALT_SIZE)
            key = derive_key(newpw, salt)
            token = Fernet(key).encrypt(json.dumps(vault).encode())
            with open(VAULT_PATH, "wb") as fh:
                fh.write(salt + token)
            master = newpw
            console.print("[green]Master password changed[/green]")
        elif choice.startswith("q"):
            save_vault(vault, master)
            console.print("[green]Vault saved. Bye![/green]")
            break
        else:
            console.print("[red]Unknown choice[/red]")

if __name__ == "__main__":
    main()
