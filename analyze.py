import sys
import math
import hashlib
import re

# Analyse STATIQUE d'un fichier : on ne l'execute jamais, on le lit comme
# des octets. Hash, entropie (indice d'un binaire packe/chiffre), chaines de
# caracteres lisibles, et quelques magic bytes pour deviner le type.
# Approche classique pour un premier triage de malware, sans rien lancer.

MAGIC = {
    b"MZ": "exe/dll Windows (PE)",
    b"\x7fELF": "binaire Linux (ELF)",
    b"PK": "archive zip (ou docx/jar/apk)",
    b"%PDF": "PDF",
    b"\xff\xd8\xff": "image JPEG",
}


def hashes(data):
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def shannon_entropy(data):
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    e = 0.0
    for count in freq:
        if count:
            p = count / len(data)
            e -= p * math.log2(p)
    return round(e, 2)


def detect_type(data):
    for sig, label in MAGIC.items():
        if data.startswith(sig):
            return label
    return "inconnu"


def strings(data, minlen=5):
    # suites de caracteres ASCII imprimables
    pattern = rb"[\x20-\x7e]{%d,}" % minlen
    return [m.decode() for m in re.findall(pattern, data)]


SUSPECT = ["http://", "https://", "cmd.exe", "powershell", "CreateProcess",
           "RegSetValue", "WScript", "/bin/sh", "socket", "base64"]


def main():
    if len(sys.argv) < 2:
        print("usage: python analyze.py <fichier>")
        return

    data = open(sys.argv[1], "rb").read()

    print(f"fichier : {sys.argv[1]}  ({len(data)} octets)")
    print(f"type    : {detect_type(data)}")
    for algo, h in hashes(data).items():
        print(f"{algo}  : {h}")

    ent = shannon_entropy(data)
    note = " (eleve -> possiblement packe/chiffre)" if ent > 7.2 else ""
    print(f"entropie: {ent}/8{note}")

    found = strings(data)
    print(f"\nchaines lisibles: {len(found)}")

    flagged = [s for s in found if any(k.lower() in s.lower() for k in SUSPECT)]
    if flagged:
        print("\nchaines qui attirent l'oeil:")
        for s in flagged[:20]:
            print(f"  {s}")


if __name__ == "__main__":
    main()
