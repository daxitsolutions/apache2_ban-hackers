# apache2_ban-hackers

## Language / Langue

- [Français](#français)
- [English](#english)

---

## Français

Collection de scripts shell pour la sécurité et l'observabilité Apache.

### Clonage du repository

Voici les étapes exactes pour cloner le repo `https://github.com/daxitsolutions/apache2_ban-hackers` :

1. Installer Git (si ce n'est pas déjà fait) :

```bash
sudo apt update
sudo apt install git -y
```

2. Cloner le repository :

```bash
git clone https://github.com/daxitsolutions/apache2_ban-hackers.git
```

3. Aller dans le dossier cloné :

```bash
cd apache2_ban-hackers
```

4. Voir ce qu'il contient :

```bash
ls -l scripts/
```

Tu verras notamment :

- `ban-path-explorer.sh`
- `test-ban-path-explorer.sh`
- `safe-ips.txt`

### Commandes utiles une fois cloné

```bash
# Voir l'aide du script principal
./scripts/ban-path-explorer.sh --help

# Lancer le test (recommandé)
./scripts/test-ban-path-explorer.sh

# Exemple d'utilisation du script de ban
./scripts/ban-path-explorer.sh --log-dir /var/log/apache2 --threshold 20 --window 30
```

### Mise à jour du repository

Une fois dans le dossier du repo :

```bash
cd ~/apache2_ban-hackers   # ou le chemin où tu l'as cloné
git pull
```

`git pull` récupère les dernières modifications (nouveaux scripts, corrections, mises à jour de `ban-path-explorer.sh`, etc.).

Commandes pratiques pour l'update :

```bash
# 1. Aller dans le dossier
cd apache2_ban-hackers

# 2. Mettre à jour
git pull

# 3. (Optionnel) Voir ce qui a changé
git log --oneline -5
```

Astuce : alias rapide

```bash
echo 'alias update-ban="cd ~/apache2_ban-hackers && git pull"' >> ~/.bashrc
source ~/.bashrc
```

Ensuite, tu peux lancer `update-ban` depuis n'importe où.

### Structure du projet

Tous les scripts sont centralisés dans `scripts/` pour faciliter l'ajout de nouveaux outils.

- `scripts/ban-path-explorer.sh` : détection de scans de chemins dans les logs Apache
- `scripts/test-ban-path-explorer.sh` : tests du script principal
- `scripts/safe-ips.txt` : whitelist d'IPs utilisée par les scripts qui en ont besoin

### Usage générique (plusieurs scripts)

Lister les scripts disponibles :

```bash
ls -1 ./scripts/*.sh
```

Aide d'un script :

```bash
./scripts/<nom-script>.sh --help
```

Exécution d'un script en arrière-plan :

```bash
nohup ./scripts/<nom-script>.sh > /tmp/<nom-script>.out 2>&1 &
```

### Usage actuel

Script principal :

```bash
./scripts/ban-path-explorer.sh --help
./scripts/ban-path-explorer.sh --log-dir /var/log/apache2
```

Tests :

```bash
./scripts/test-ban-path-explorer.sh
```

---

## English

Shell script collection for Apache security and observability tasks.

### Project structure

All scripts are grouped under `scripts/` so new tools can be added consistently.

- `scripts/ban-path-explorer.sh`: detects path-scanning behavior in Apache logs
- `scripts/test-ban-path-explorer.sh`: test runner for the main script
- `scripts/safe-ips.txt`: IP whitelist used by scripts that require it

### Generic usage (multiple scripts)

List available scripts:

```bash
ls -1 ./scripts/*.sh
```

Show help for any script:

```bash
./scripts/<script-name>.sh --help
```

Run any script in background:

```bash
nohup ./scripts/<script-name>.sh > /tmp/<script-name>.out 2>&1 &
```

### Current usage

Main script:

```bash
./scripts/ban-path-explorer.sh --help
./scripts/ban-path-explorer.sh --log-dir /var/log/apache2
```

Tests:

```bash
./scripts/test-ban-path-explorer.sh
```
