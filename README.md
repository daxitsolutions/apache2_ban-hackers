# apache2_ban-hackers

Scripts de détection d'exploration de chemins Apache et tests associés.

## Arborescence

- `scripts/ban-path-explorer.sh` : script principal (détection + dry-run/ban)
- `scripts/test-ban-path-explorer.sh` : script de test
- `scripts/safe-ips.txt` : whitelist d'IPs (obligatoire pour lancer le script principal)

## Usage rapide

```bash
./scripts/ban-path-explorer.sh --help
```

```bash
./scripts/ban-path-explorer.sh --log-dir /var/log/apache2
```

## Exécution en arrière-plan

```bash
nohup ./scripts/ban-path-explorer.sh --log-dir /var/log/apache2 > /tmp/ban-path-explorer.out 2>&1 &
```

## Lancer les tests

```bash
./scripts/test-ban-path-explorer.sh
```
