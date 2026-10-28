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
import sys

import auth


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
    posture = auth.secret_posture()
    for key, value in posture.items():
        print(f"{key}: {value}")
    if posture["admin_password_source"] == "claro":
        print(
            "Aviso: AUDIT_ADMIN_PASSWORD esta en claro. Generar el hash con "
            "--hash y migrar a AUDIT_ADMIN_PASSWORD_HASH."
        )
    if not posture["sign_key_defined"]:
        print("Aviso: AUDIT_SIGN_KEY no definida: los exports se firman como 'no firmado'.")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Bootstrap del administrador sin clave en claro")
    parser.add_argument("--hash", action="store_true", help="Generar el hash scrypt de una contraseña")
    parser.add_argument("--verify", help="Comprobar una contraseña contra un hash")
    parser.add_argument("--hash-string", help="Hash a comprobar (formato scrypt$<salt>$<hash>)")
    parser.add_argument("--posture", action="store_true", help="Mostrar la postura de secretos del entorno")
    args = parser.parse_args(argv)

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
