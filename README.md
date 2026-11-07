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
- `safe-ips.example.txt`

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

> ⚠️ **Mise à jour depuis une version antérieure à #11** : `scripts/safe-ips.txt` n'est plus versionné. **Avant** `git pull`, sauvegardez votre whitelist :
>
> ```bash
> sudo install -D -m 600 scripts/safe-ips.txt /etc/ban-path-explorer/safe-ips.txt
> git checkout -- scripts/safe-ips.txt && git pull
> ```

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
- `scripts/safe-ips.example.txt` : modèle de whitelist. La vraie whitelist est dans `/etc/ban-path-explorer/safe-ips.txt`, **hors du repo** pour ne pas publier vos IPs. Elle accepte les IPs, les plages CIDR (`198.51.100.0/24`, `2001:db8::/48`) et les commentaires `#`
- `scripts/bad-patterns.txt` : signatures d'attaque (`/.env`, `../`, `${jndi:`, `union select`…) qui déclenchent un ban dès la première requête

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


### Service permanent (bans conservés après redémarrage)

Les bans actifs sont stockés dans `/var/lib/ban-path-explorer/state`. À chaque cycle avec `--ban`, les règles absentes (après un redémarrage ou un flush) sont réappliquées. Une IP ajoutée à `/etc/ban-path-explorer/safe-ips.txt` est débloquée au cycle suivant.

```bash
sudo git clone https://github.com/daxitsolutions/apache2_ban-hackers.git /opt/apache2_ban-hackers
sudo cp /opt/apache2_ban-hackers/scripts/ban-path-explorer.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now ban-path-explorer
sudo cp /opt/apache2_ban-hackers/config/logrotate.d/ban-path-explorer /etc/logrotate.d/
```

Seuls les événements des `--window` dernières minutes sont pris en compte. Pour analyser après coup tout l'historique d'une attaque passée, utilisez `--history` (sans `--ban`).


### Derrière un reverse proxy / CDN (important)

Si Apache est derrière nginx, HAProxy, un load balancer ou Cloudflare, les logs contiennent **l'IP du proxy**, pas celle de l'attaquant. Par sécurité, le script refuse de bannir les IPs privées (10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16, fc00::/7, fe80::/10) et le journalise (`Ban refusé: IP privée`). Si ce message apparaît, activez `mod_remoteip` pour que les logs contiennent la vraie IP du client :

```bash
sudo a2enmod remoteip
sudo tee /etc/apache2/conf-available/remoteip.conf >/dev/null <<'CONF'
RemoteIPHeader X-Forwarded-For
# IP(s) de vos proxys de confiance uniquement (sinon l'en-tête est falsifiable)
RemoteIPTrustedProxy 10.0.0.0/8
CONF
sudo a2enconf remoteip
```

Dans les `LogFormat`, remplacez `%h` par `%a` pour l'access log ; l'error log utilise déjà l'IP corrigée. Rechargez ensuite Apache avec `sudo systemctl reload apache2`.

Avec un **CDN public** (Cloudflare…), utilisez `RemoteIPTrustedProxyList` avec la liste des IPs du CDN. Attention : bannir avec iptables n'a alors **aucun effet**, puisque le trafic arrive depuis le CDN. Il faut bloquer au niveau du CDN, ou n'accepter sur 80/443 que les IPs du CDN.


### Protection proactive : fail2ban, ModSecurity, CrowdSec

`ban-path-explorer.sh` réagit aux attaques déjà subies. Ces trois outils complètent la protection : ils couvrent SSH, bloquent l'exploit dès la première requête, et bloquent les IPs connues comme malveillantes avant même qu'elles n'arrivent.

**1. fail2ban** : brute force SSH/HTTP, bots, Shellshock, récidive (configuration testée : `config/fail2ban/jail.d/ban-hackers.local`)

```bash
sudo apt install fail2ban
sudo cp config/fail2ban/jail.d/ban-hackers.local /etc/fail2ban/jail.d/
sudo nano /etc/fail2ban/jail.d/ban-hackers.local   # ignoreip = vos IPs d'administration
sudo fail2ban-client -t && sudo systemctl restart fail2ban
sudo fail2ban-client status
```

**2. ModSecurity + OWASP CRS** (pare-feu applicatif) : bloque SQLi, XSS, LFI et RCE même depuis une IP inconnue. Chaque requête bloquée (`ModSecurity: Access denied`) déclenche aussi un ban par `ban-path-explorer.sh`.

```bash
sudo apt install libapache2-mod-security2 modsecurity-crs
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sudo apache2ctl configtest && sudo systemctl reload apache2
```

Le moteur démarre en `SecRuleEngine DetectionOnly` : il journalise sans bloquer. Laissez-le ainsi **1 à 2 semaines** et cherchez les faux positifs avec `grep ModSecurity /var/log/apache2/*error.log`. Ensuite, activez le blocage :

```bash
sudo sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
sudo systemctl reload apache2
```

**3. CrowdSec** : blocklist communautaire. Les IPs vues en train d'attaquer d'autres serveurs sont bloquées chez vous **avant leur première requête**. C'est la seule protection contre les scans distribués.

```bash
curl -s https://install.crowdsec.net | sudo sh       # dépôt officiel CrowdSec
sudo apt install crowdsec crowdsec-firewall-bouncer-iptables
sudo cscli collections install crowdsecurity/apache2 crowdsecurity/sshd
sudo systemctl reload crowdsec
sudo cscli metrics && sudo cscli decisions list
```

Pensez à déclarer vos IPs d'administration dans une whitelist CrowdSec (`/etc/crowdsec/parsers/s02-enrich/`, voir la documentation CrowdSec).

---

## English

Shell script collection for Apache security and observability tasks.

### Project structure

All scripts are grouped under `scripts/` so new tools can be added consistently.

- `scripts/ban-path-explorer.sh`: detects path-scanning behavior in Apache logs
- `scripts/test-ban-path-explorer.sh`: test runner for the main script
- `scripts/safe-ips.example.txt`: whitelist template. The real whitelist lives in `/etc/ban-path-explorer/safe-ips.txt`, **outside the repo**, so your IPs are not published. Supports IPs, CIDR ranges and `#` comments
- `scripts/bad-patterns.txt`: attack signatures (`/.env`, `../`, `${jndi:`, `union select`…) that trigger a ban on the very first request

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

### Permanent service (bans survive reboots)

Active bans are stored in `/var/lib/ban-path-explorer/state`. On every `--ban` cycle, missing rules (after a reboot or flush) are re-applied. An IP added to `/etc/ban-path-explorer/safe-ips.txt` is unbanned on the next cycle.

```bash
sudo git clone https://github.com/daxitsolutions/apache2_ban-hackers.git /opt/apache2_ban-hackers
sudo cp /opt/apache2_ban-hackers/scripts/ban-path-explorer.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now ban-path-explorer
sudo cp /opt/apache2_ban-hackers/config/logrotate.d/ban-path-explorer /etc/logrotate.d/
```

Only events from the last `--window` minutes are considered. To investigate a past attack across the whole log history, use `--history` (without `--ban`).

### Behind a reverse proxy / CDN (important)

Behind nginx, HAProxy, a load balancer or Cloudflare, logs show the **proxy IP**, not the attacker's. As a safety net the script refuses to ban private IPs (10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16, fc00::/7, fe80::/10) and logs `Ban refusé: IP privée`. If you see it, enable `mod_remoteip` (`RemoteIPHeader X-Forwarded-For` + `RemoteIPTrustedProxy <your proxies>`) and use `%a` instead of `%h` in `LogFormat`. With a public CDN, iptables bans are useless (traffic comes from the CDN): block at the CDN level.

### Proactive protection: fail2ban, ModSecurity, CrowdSec

- **fail2ban** (tested config): `sudo apt install fail2ban && sudo cp config/fail2ban/jail.d/ban-hackers.local /etc/fail2ban/jail.d/ && sudo systemctl restart fail2ban`. Set `ignoreip` first.
- **ModSecurity + OWASP CRS**: `sudo apt install libapache2-mod-security2 modsecurity-crs`, copy `modsecurity.conf-recommended` to `modsecurity.conf`, run in `DetectionOnly` for 1–2 weeks, then `SecRuleEngine On`. Every block (`ModSecurity: Access denied`) also triggers a `ban-path-explorer.sh` ban.
- **CrowdSec** (community blocklist, blocks known-bad IPs before their first request): `curl -s https://install.crowdsec.net | sudo sh && sudo apt install crowdsec crowdsec-firewall-bouncer-iptables && sudo cscli collections install crowdsecurity/apache2 crowdsecurity/sshd`.
