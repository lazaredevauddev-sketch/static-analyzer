# static-analyzer

Fait un premier triage statique d'un fichier binaire, sans jamais l'exécuter.
Il sort :

- le type de fichier (via les magic bytes)
- les hashs MD5 et SHA256 (pour chercher le fichier sur VirusTotal par exemple)
- l'entropie de Shannon : une entropie proche de 8 indique souvent un binaire
  compressé ou chiffré, ce qui est typique des malwares packés
- les chaînes de caractères lisibles, en mettant en avant celles qui sont
  intéressantes (URLs, appels système, powershell, base64...)

Tout se fait en lecture seule. On n'exécute rien, c'est justement l'intérêt de
l'analyse statique : on peut regarder un échantillon sans risque.

## Utilisation

```
python analyze.py /bin/ls
python analyze.py un_binaire_quelconque
```

Pour s'entraîner proprement sans vrai malware : analyser n'importe quel exe ou
binaire système, ou récupérer des échantillons inoffensifs comme le fichier de
test EICAR. Ne pas exécuter ce qu'on analyse.

## Suite logique

- parser les sections PE avec la lib `pefile` (imports, timestamp de compilation)
- calculer l'entropie section par section, pas sur tout le fichier
- envoyer le hash à l'API VirusTotal pour voir s'il est déjà connu
