#!/usr/bin/env python
"""Bootstrap del administrador de la consola de auditoria sin clave en claro.

Problema: AUDIT_ADMIN_PASSWORD guarda la contraseña en claro en el entorno del
usuario (HKCU\\Environment), donde cualquier proceso, volcado de logs o backup la
puede leer. La alternativa es guardar solo el digest scrypt, que no se puede
invertir.

Uso:

  # 1. Generar el hash (pide la contraseña, no la escribe en ningun sitio)
  python ui/bootstrap_admin.py --hash
  # imprime: scrypt$<salt>$<hash>  y el comando setx para aplicarlo

  # 2. Aplicarlo en el entorno del usuario
  setx AUDIT_ADMIN_USER "sammi"
  setx AUDIT_ADMIN_PASSWORD_HASH "scrypt$<salt>$<hash>"

  # 3. Arrancar la consola: bootstrap_admin() crea el usuario desde el hash

  # Comprobar que una contraseña dada corresponde al hash guardado
  python ui/bootstrap_admin.py --verify "la-contraseña" --hash-string "scrypt$..."

La utilidad no escribe secretos en el entorno: solo imprime el comando. La
decision de ejecutarlo es del operador.
"""

from __future__ import annotations

import argparse
import getpass
import os
import secrets
import sys

import auth


def _user_env(name: str) -> str:
    """Leer una variable de entorno del usuario desde el registro.

    setx no afecta a la sesion actual y el proceso en curso tampoco ve lo que se
    acaba de escribir. Leer HKCU\\Environment es la unica forma de saber el estado
    real del entorno.
    """
    import subprocess
    result = subprocess.run(
        ["reg", "query", "HKCU\\Environment", "/v", name],
        capture_output=True,
        text=True,
        encoding="cp850",
        errors="replace",
    )
    if result.returncode != 0:
        return ""
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == name:
            return " ".join(parts[2:]).strip()
    return ""


def _set_user_env(name: str, value: str) -> None:
    """Escribir en HKCU\\Environment sin pasar por el shell.

    `reg` se invoca como lista de argumentos: el hash contiene '$' y el shell lo
    expandiria. Con subprocess sin shell no se toca.
    """
    import subprocess
    result = subprocess.run(
        ["reg", "add", "HKCU\\Environment", "/v", name, "/d", value, "/f"],
        capture_output=True,
        text=True,
        encoding="cp850",
        errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "reg add fallo")


def _delete_user_env(name: str) -> bool:
    import subprocess
    result = subprocess.run(
        ["reg", "delete", "HKCU\\Environment", "/v", name, "/f"],
        capture_output=True,
        text=True,
        encoding="cp850",
        errors="replace",
    )
    return result.returncode == 0


def cmd_sign_key() -> int:
    """Generar AUDIT_SIGN_KEY y escribirla en el entorno del usuario.

    Sin esta clave los exports se firman como 'no firmado'. La clave se crea aqui
    y va directa al registro; no se imprime ni se guarda en ningun fichero.
    """
    if _user_env("AUDIT_SIGN_KEY"):
        print("AUDIT_SIGN_KEY ya existe. Use --sign-key --force para rotarla.")
        return 0
    key = secrets.token_urlsafe(48)
    _set_user_env("AUDIT_SIGN_KEY", key)
    print(f"AUDIT_SIGN_KEY generada ({len(key)} caracteres). No se imprime.")
    print("Abre una ventana nueva de PowerShell para que surta efecto.")
    return 0


def cmd_rotate(user: str) -> int:
    """Migrar AUDIT_ADMIN_PASSWORD (en claro) a AUDIT_ADMIN_PASSWORD_HASH.

    Hace lo que se rompe si se hace a mano: genera el scrypt sin imprimir la clave,
    lo escribe directo en HKCU (el shell trunca el valor en 'scrypt' cuando el hash
    va entre comillas dobles) y sincroniza la cuenta existente, porque
    bootstrap_admin() solo crea el admin si no hay ninguno.
    """
    password = _user_env("AUDIT_ADMIN_PASSWORD")
    if not password:
        print("AUDIT_ADMIN_PASSWORD no esta definida en el entorno del usuario: no hay nada que rotar.")
        return 1

    digest = auth.password_hash_string(password)
    if not auth.verify_hash_string(password, digest):
        print("El hash generado no verifica la clave: no se toca nada.", file=sys.stderr)
        return 1

    _set_user_env("AUDIT_ADMIN_PASSWORD_HASH", digest)
    print(f"AUDIT_ADMIN_PASSWORD_HASH escrita ({len(digest)} caracteres, prefijo {digest[:7]}...).")

    auth.init_auth()
    try:
        auth.reset_password(user, password)
        print(f"Cuenta '{user}' sincronizada con el hash (sesiones activas revocadas).")
    except ValueError as exc:
        print(f"No se pudo sincronizar la cuenta: {exc}", file=sys.stderr)
        return 1

    if _delete_user_env("AUDIT_ADMIN_PASSWORD"):
        print("AUDIT_ADMIN_PASSWORD eliminada del entorno del usuario.")
    else:
        print("AUDIT_ADMIN_PASSWORD ya no existia.")

    print("Abre una ventana nueva de PowerShell para que el cambio surta efecto.")
    return 0


def cmd_hash() -> int:
    password = getpass.getpass("Contraseña del administrador (no se guarda en claro): ")
    if len(password) < 8:
        print("La contraseña debe tener al menos 8 caracteres.", file=sys.stderr)
        return 1
    digest = auth.password_hash_string(password)
    print(digest)
    print()
    print("Aplicar en el entorno del usuario (PowerShell):")
    print(f'  setx AUDIT_ADMIN_USER "{os.environ.get("AUDIT_ADMIN_USER", "sammi")}"')
    print(f'  setx AUDIT_ADMIN_PASSWORD_HASH "{digest}"')
    print()
    print("Una vez aplicado, se puede borrar la variable en claro:")
    print("  setx AUDIT_ADMIN_PASSWORD \"\"   (o Remove-Variable en la sesion actual)")
    return 0


def cmd_verify(hash_string: str, password: str) -> int:
    if auth.verify_hash_string(password, hash_string):
        print("La contraseña coincide con el hash.")
        return 0
    print("La contraseña NO coincide con el hash.")
    return 1


def cmd_posture() -> int:
    """Postura real del entorno: HKCU, no la sesion actual.

    setx escribe en el registro y no se hereda al proceso en curso, asi que leer
    os.environ engana: dice 'none' cuando la variable si existe.
    """
    user = _user_env("AUDIT_ADMIN_USER") or os.environ.get("AUDIT_ADMIN_USER", "")
    hash_string = _user_env("AUDIT_ADMIN_PASSWORD_HASH") or os.environ.get("AUDIT_ADMIN_PASSWORD_HASH", "")
    clear = _user_env("AUDIT_ADMIN_PASSWORD") or os.environ.get("AUDIT_ADMIN_PASSWORD", "")
    sign_key = _user_env("AUDIT_SIGN_KEY") or os.environ.get("AUDIT_SIGN_KEY", "")

    print(f"admin_user: {user or None}")
    print("admin_password_source:", "hash" if hash_string.strip() else "claro" if clear.strip() else "none")
    print("sign_key_defined:", bool(sign_key.strip()))
    if clear.strip():
        print("Aviso: AUDIT_ADMIN_PASSWORD sigue en claro. Ejecuta --rotate para migrarla a hash.")
    elif not hash_string.strip():
        print("Aviso: no hay clave de administrador en el entorno.")
    if not sign_key.strip():
        print("Aviso: AUDIT_SIGN_KEY no definida: los exports se firman como 'no firmado'.")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Bootstrap del administrador sin clave en claro")
    parser.add_argument("--hash", action="store_true", help="Generar el hash scrypt de una contraseña")
    parser.add_argument("--verify", help="Comprobar una contraseña contra un hash")
    parser.add_argument("--hash-string", help="Hash a comprobar (formato scrypt$<salt>$<hash>)")
    parser.add_argument("--posture", action="store_true", help="Mostrar la postura de secretos del entorno")
    parser.add_argument("--rotate", action="store_true", help="Migrar la clave en claro a hash y borrarla")
    parser.add_argument("--sign-key", action="store_true", help="Generar AUDIT_SIGN_KEY si no existe")
    parser.add_argument("--user", default="", help="Usuario a sincronizar (por defecto AUDIT_ADMIN_USER)")
    args = parser.parse_args(argv)

    if args.sign_key:
        return cmd_sign_key()
    if args.rotate:
        return cmd_rotate(args.user or _user_env("AUDIT_ADMIN_USER") or "sammi")
    if args.hash:
        return cmd_hash()
    if args.verify:
        hash_string = args.hash_string or os.environ.get("AUDIT_ADMIN_PASSWORD_HASH", "")
        if not hash_string:
            print("Falta --hash-string y AUDIT_ADMIN_PASSWORD_HASH no esta definida.", file=sys.stderr)
            return 1
        return cmd_verify(hash_string, args.verify)
    if args.posture:
        return cmd_posture()
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
