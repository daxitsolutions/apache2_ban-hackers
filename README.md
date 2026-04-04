# apache2_ban-hackers

## Language / Langue

- [Français](#français)
- [English](#english)

---

## Français

Collection de scripts shell pour la sécurité et l'observabilité Apache.

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
