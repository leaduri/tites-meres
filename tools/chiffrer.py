"""Chiffre les statistiques du site des Tites mères.

Usage :
    TM_MOT_DE_PASSE='...' python3 tools/chiffrer.py <dossier_json> <fichier_sortie>

<dossier_json> contient joueuses.json, gardiennes.json, matchs.json, classement.json,
adversaires.json, gardiennes_adverses.json et meta.json.
La sortie (data/stats.chiffre.json) est déchiffrée dans le navigateur avec le mot de passe
(PBKDF2-SHA256, 600 000 itérations, puis AES-256-GCM).
"""
import base64
import json
import os
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

IDS = ["joueuses", "gardiennes", "matchs", "classement", "adversaires", "gardiennes_adverses", "meta"]
ITERATIONS = 600_000


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    src, out = sys.argv[1], sys.argv[2]
    password = os.environ.get("TM_MOT_DE_PASSE")
    if not password:
        sys.exit("Variable TM_MOT_DE_PASSE manquante.")
    bundle = {}
    for name in IDS:
        with open(os.path.join(src, name + ".json"), encoding="utf-8") as f:
            bundle[name] = json.load(f)
    plain = json.dumps(bundle, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS).derive(password.encode("utf-8"))
    ct = AESGCM(key).encrypt(iv, plain, None)
    b64 = lambda b: base64.b64encode(b).decode("ascii")
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"v": 1, "kdf": "PBKDF2-SHA256", "iter": ITERATIONS, "salt": b64(salt), "iv": b64(iv), "data": b64(ct)}, f)
    print(f"OK : {len(IDS)} jeux de données chiffrés dans {out}")


if __name__ == "__main__":
    main()
