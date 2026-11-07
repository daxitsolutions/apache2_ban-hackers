# apache2_ban-hackers

Boîte à outils shell pour protéger un serveur web Apache (Debian/Ubuntu, compatible RHEL) : détection et blocage automatique des attaquants à partir des logs, configurations de durcissement prêtes à l'emploi et audits de sécurité.

- [Français](#français)
- [English](#english)

---

## Français

### Ce que fait le projet

| Outil | Rôle |
|---|---|
| `scripts/ban-path-explorer.sh` | Analyse les logs Apache (error + access) et **bannit** via iptables/ip6tables les IPs qui scannent le site, font du brute force ou envoient une requête d'attaque connue |
| `scripts/audit-compromise.sh` | Après une attaque : recherche les traces de compromission (comptes, clés SSH, webshells, processus suspects…), **en lecture seule** |
| `scripts/audit-email-problems.sh` | Vérifie la protection anti-usurpation d'un domaine : SPF, DMARC, DKIM, MTA-STS, TLS-RPT |
| `config/` | Configurations testées : fail2ban, durcissement Apache et SSH, logrotate |

Les scripts qui touchent au système (`ban-path-explorer.sh`, `audit-compromise.sh` et les tests) **doivent être lancés avec `sudo`** ; ils refusent de démarrer sinon. `audit-email-problems.sh` ne fait que des requêtes DNS et se lance sans sudo.

---

### Démarrage rapide (10 minutes)

**1. Installer** (dans `/opt`, emplacement attendu par le service systemd)

```bash
sudo apt update && sudo apt install -y git iptables iproute2
sudo git clone https://github.com/daxitsolutions/apache2_ban-hackers.git /opt/apache2_ban-hackers
cd /opt/apache2_ban-hackers
```

**2. Ajouter l'IP de l'administrateur dans la whitelist : obligatoire avant tout lancement**

> ⚠️ **Avant le premier lancement**, ajoutez votre IP publique d'administration dans `scripts/data/safe-ips.txt`. Le fichier ne contient au départ que `127.0.0.1`. Sans votre IP, une erreur de votre part (une URL mal tapée, un test de scan, un accès à `/.env`) peut **vous bannir de votre propre serveur**, SSH compris. Le script affiche un avertissement tant qu'aucune IP d'administration n'est déclarée.

```bash
echo $SSH_CLIENT | cut -d' ' -f1                 # votre IP actuelle, si vous êtes connecté en SSH
sudo nano scripts/data/safe-ips.txt
```

Une IP ou une plage par ligne (`203.0.113.10`, `198.51.100.0/24`, `2001:db8::/48`), `#` pour les commentaires. Les adresses du serveur lui-même sont toujours protégées. Ne poussez pas ce fichier complété sur un dépôt public : il révèle vos IPs d'administration.

**3. Vérifier que le serveur n'est pas déjà compromis**

```bash
sudo ./scripts/audit-compromise.sh --days 60
```

**4. Premier essai, sans rien bloquer** (dry-run)

```bash
sudo ./scripts/ban-path-explorer.sh
```

Le script affiche les IPs qu'il aurait bannies et pourquoi. Vérifiez qu'aucune n'est légitime (sinon : whitelist, `--ignore-paths`, ou ajustez `scripts/bad-patterns.txt`). Pour remonter tout l'historique des logs (enquête sur une attaque passée) : `sudo ./scripts/ban-path-explorer.sh --history`.

**5. Activer la protection permanente**

```bash
sudo cp scripts/ban-path-explorer.service /etc/systemd/system/
sudo cp config/logrotate.d/ban-path-explorer /etc/logrotate.d/
sudo systemctl daemon-reload && sudo systemctl enable --now ban-path-explorer
sudo systemctl status ban-path-explorer
```

**6. Suivre l'activité**

```bash
sudo tail -f /var/log/ban-path-explorer.log      # bans, déblocages, avertissements
sudo iptables -S BAN-PATH-EXPLORER               # IPv4 bannies
sudo ip6tables -S BAN-PATH-EXPLORER              # IPv6 bannies
sudo cat /var/lib/ban-path-explorer/state        # ip|expiration|nombre de bans|début
```

Étapes suivantes recommandées : [protection proactive](#protection-proactive--fail2ban-modsecurity-crowdsec) et [durcissement](#durcissement-du-serveur).

---

### ban-path-explorer.sh : fonctionnement

**Ce qui déclenche un ban**

1. **Scan** : au moins `--threshold` (20) chemins différents en erreur pour une même IP dans une fenêtre de `--window` (30) minutes. Sont comptés :
   - error log : `File does not exist`, `script not found`, `AH01276` ;
   - access log : réponses 400, 403, 404, 405 (query string ignorée) ;
   - access log : chaque `POST` sur `wp-login.php` ou `xmlrpc.php` (brute force WordPress).
2. **Signature d'attaque** : **une seule requête** contenant un motif de `scripts/bad-patterns.txt` (`/.env`, `/.git/`, `../`, `union select`, `${jndi:`, `() {`…), cherché dans l'URL, le referer et le user-agent, quel que soit le code HTTP.
3. **Blocage ModSecurity** : toute requête refusée par le WAF (`ModSecurity: Access denied`).

**Durée des bans (récidive)** : 1er ban `--ban-duration` (60 min), 2e : 24 h, 3e : 7 jours, puis 30 jours. Un ban expiré est retenu 30 jours pour compter les récidives.

**Garde-fous** : jamais de ban pour une IP de la whitelist, une adresse du serveur, une IP privée (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7… : souvent un reverse proxy) ou une valeur qui n'est pas une IP unique valide.

**Logs analysés par défaut** : dans `--log-dir` (`/var/log/apache2`), les fichiers `*error*.log`, `*access*.log` (Debian) et `*error_log`, `*access_log` (RHEL). Un avertissement s'affiche si un `ErrorLog`/`CustomLog` de la configuration Apache n'est pas couvert.

**Options**

| Option | Défaut | Rôle |
|---|---|---|
| `--ban` | désactivé | Applique réellement les bans (sinon dry-run) |
| `--follow` | | Analyse en boucle (utilisé par le service) |
| `--follow-interval SEC` | 5 | Intervalle entre deux analyses en `--follow` |
| `--threshold N` | 20 | Chemins différents en erreur avant ban |
| `--window MIN` | 30 | Fenêtre de détection (seuls ces événements récents comptent) |
| `--ban-duration MIN` | 60 | Durée du premier ban |
| `--history` | | Analyse tout l'historique lu, pas seulement la fenêtre (enquête, sans `--ban`) |
| `--log-dir DIR` | `/var/log/apache2` | Dossier des logs |
| `--log-files "F1 F2"` | | Liste explicite de fichiers (relatifs à `--log-dir` ou absolus) |
| `--ignore-paths "a,b"` | | Ignore les chemins contenant ces motifs (ex. `favicon.ico,robots.txt`) |
| `--max-log-lines N` | 20000 | Lignes lues à la fin de chaque fichier |
| `--max-events N` | 200000 | Événements traités au maximum par analyse |
| `--lock-dir DIR` | `/run/ban-path-explorer.lock` | Verrou d'instance unique |
| `--quiet` | | Aucune sortie écran |

**Fichiers**

| Fichier | Contenu |
|---|---|
| `scripts/data/safe-ips.txt` | Whitelist : `127.0.0.1` par défaut, **ajoutez l'IP de l'administrateur avant le lancement** |
| `scripts/bad-patterns.txt` | Signatures à ban immédiat : à adapter à vos sites |
| `/var/lib/ban-path-explorer/state` | Bans actifs et historique des récidives |
| `/var/log/ban-path-explorer.log` | Journal des bans, déblocages et avertissements |

**Débloquer une IP** : ajoutez-la à `scripts/data/safe-ips.txt` ; elle est débloquée au cycle suivant (≤ 5 s avec le service).

**Après un redémarrage** : les bans encore valides sont réappliqués automatiquement depuis le fichier d'état.

### Derrière un reverse proxy / CDN (important)

Si Apache est derrière nginx, HAProxy, un load balancer ou Cloudflare, les logs contiennent **l'IP du proxy**. Le script refuse alors de bannir (IP privée) et journalise `Ban refusé: IP privée … (reverse proxy ?)`. Si ce message apparaît, activez `mod_remoteip` pour que les logs contiennent la vraie IP du client :

```bash
sudo a2enmod remoteip
sudo tee /etc/apache2/conf-available/remoteip.conf >/dev/null <<'CONF'
RemoteIPHeader X-Forwarded-For
# IP(s) de vos proxys de confiance uniquement (sinon l'en-tête est falsifiable)
RemoteIPTrustedProxy 10.0.0.0/8
CONF
sudo a2enconf remoteip
```

Remplacez ensuite `%h` par `%a` dans les `LogFormat`, puis `sudo systemctl reload apache2`. Avec un **CDN public**, bannir avec iptables n'a aucun effet (le trafic arrive depuis le CDN) : bloquez au niveau du CDN, ou n'acceptez sur 80/443 que les IPs du CDN.

---

### Lancer les tests

Les tests ne modifient **aucun fichier permanent** du serveur : le script testé est copié dans un dossier temporaire avec ses propres journal, état, whitelist et verrou, puis supprimé à la fin.

**Tests de ban-path-explorer.sh** (sur le serveur)

```bash
sudo ./scripts/test-ban-path-explorer.sh
```

- tests 1 à 4 : exécution sur une copie des 15 000 dernières lignes de vos vrais logs (`/var/log/apache2` ou `/var/log/httpd`), sautés s'il n'y en a pas ;
- test 5 : vérifie que le vrai journal `/var/log/ban-path-explorer.log` n'a pas été modifié ;
- tests « Access », « Signature », « Whitelist » : logs synthétiques (scans, brute force, signatures, ModSecurity, plages CIDR).

Le code de retour vaut 0 si tout passe, 1 sinon.

**Tests iptables complets** (bans IPv4/IPv6, récidive, restauration après redémarrage, IP privées refusées…) : ils créent et vident de vraies règles, donc **à lancer uniquement dans un conteneur jetable**, jamais sur un serveur en production :

```bash
docker run --rm --cap-add NET_ADMIN -e BAN_TESTS=1 -v "$PWD":/repo -w /repo debian:stable-slim \
  bash -c 'apt-get update -qq && apt-get install -y -qq iptables iproute2 procps >/dev/null && ./scripts/test-ban-path-explorer.sh'
```

**Tests de l'audit email** (aucune requête DNS réelle, un faux `dig` est utilisé ; sans sudo) :

```bash
./scripts/test-audit-email-problems.sh
```

**Mode essai du script de ban** : sans `--ban`, `ban-path-explorer.sh` ne bloque rien et affiche seulement ce qu'il ferait. C'est la façon sûre de tester un réglage (`--threshold`, `bad-patterns.txt`…) sur un serveur réel.

---

### Protection proactive : fail2ban, ModSecurity, CrowdSec

`ban-path-explorer.sh` réagit à ce qui arrive sur vos logs Apache. Ces outils le complètent (SSH, exploit bloqué dès la 1re requête, IPs malveillantes connues bloquées avant d'arriver). Ils cohabitent sans conflit (chaînes iptables séparées) ; reportez vos IPs d'administration dans chacun.

**fail2ban** : SSH, brute force HTTP, bots, Shellshock, récidive (config testée avec fail2ban 1.1)

```bash
sudo apt install fail2ban
sudo cp config/fail2ban/jail.d/ban-hackers.local /etc/fail2ban/jail.d/
sudo nano /etc/fail2ban/jail.d/ban-hackers.local   # ignoreip = vos IPs d'administration
sudo fail2ban-client -t && sudo systemctl restart fail2ban
sudo fail2ban-client status
```

**ModSecurity + OWASP CRS** (pare-feu applicatif) : bloque SQLi, XSS, LFI, RCE même depuis une IP inconnue ; chaque blocage déclenche aussi un ban par `ban-path-explorer.sh`.

```bash
sudo apt install libapache2-mod-security2 modsecurity-crs
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sudo apache2ctl configtest && sudo systemctl reload apache2
```

Le moteur démarre en `SecRuleEngine DetectionOnly` (journalise sans bloquer). Après **1 à 2 semaines** sans faux positif (`grep ModSecurity /var/log/apache2/*error.log`), activez le blocage :

```bash
sudo sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
sudo systemctl reload apache2
```

**CrowdSec** : liste de blocage communautaire, seule protection contre les scans distribués (non testé dans ce projet).

```bash
curl -s https://install.crowdsec.net | sudo sh
sudo apt install crowdsec crowdsec-firewall-bouncer-iptables
sudo cscli collections install crowdsecurity/apache2 crowdsecurity/sshd
sudo systemctl reload crowdsec
sudo cscli metrics && sudo cscli decisions list
```

---

### Durcissement du serveur

**Apache** : version masquée, pas de listing de répertoires, `.env`/`.git`/`.sql`/`.bak` interdits (sauf `/.well-known/` pour Let's Encrypt), en-têtes de sécurité.

```bash
sudo cp config/apache/zz-ban-hackers-hardening.conf /etc/apache2/conf-available/
sudo a2enmod headers && sudo a2enconf zz-ban-hackers-hardening
sudo apache2ctl configtest && sudo systemctl reload apache2
```

**SSH** : connexion par clé uniquement, 3 essais maximum. ⚠️ Vérifiez d'abord que vous vous connectez **par clé**, et gardez une session ouverte pendant le test.

```bash
sudo cp config/ssh/99-ban-hackers.conf /etc/ssh/sshd_config.d/
sudo sshd -t && sudo systemctl reload ssh
```

**Mises à jour de sécurité automatiques**

```bash
sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades
```

**Pare-feu par défaut en refus** : n'ouvrez que 80, 443 et SSH (idéalement limité à vos IPs), par exemple avec ufw :

```bash
sudo ufw default deny incoming && sudo ufw allow 80,443/tcp
sudo ufw allow from <IP_ADMIN> to any port 22 && sudo ufw enable
```

---

### Audit après une attaque

```bash
sudo ./scripts/audit-compromise.sh --days 30 --www /var/www
```

Lecture seule. Liste : comptes UID 0 et comptes avec shell, fichiers `passwd`/`shadow`/`sudoers` modifiés, clés SSH autorisées, crontabs et services systemd récents, `ld.so.preload`, webshells PHP, PHP récents ou dans des dossiers d'upload, exécutables et processus lancés depuis `/tmp`/`/dev/shm`, ports en écoute, connexions sortantes, SUID récents, intégrité des paquets (`debsums`). Toute ligne inattendue dans « UID 0 », « Clés SSH », « Webshells » ou « Processus » doit être traitée comme une compromission : changez tous les secrets et, idéalement, réinstallez le serveur.

### Audit de sécurité email

```bash
./scripts/audit-email-problems.sh
```

Le domaine est demandé au lancement, puis d'éventuels sélecteurs DKIM supplémentaires (visibles dans l'en-tête `DKIM-Signature: … s=XXX` d'un mail envoyé). En une ligne : `./scripts/audit-email-problems.sh exemple.com s1 s2`. Nécessite `dig` (`sudo apt install dnsutils`).

---

### Mise à jour

```bash
cd /opt/apache2_ban-hackers
sudo git pull --autostash          # --autostash conserve vos IPs ajoutées dans scripts/data/safe-ips.txt
sudo systemctl restart ban-path-explorer
```

> ⚠️ **Si vous venez d'une version précédente** : la whitelist était dans `scripts/safe-ips.txt` ou dans `/etc/ban-path-explorer/safe-ips.txt`. Ces anciens fichiers sont **encore lus** s'ils existent, donc aucune IP n'est perdue, et un avertissement le signale. Recopiez leurs IPs dans `scripts/data/safe-ips.txt`, puis supprimez-les.
>
> Le fichier d'état passe aussi de `/var/log/ban-path-explorer.state` à `/var/lib/ban-path-explorer/state` (migration automatique).

### Dépannage

| Symptôme | Cause / solution |
|---|---|
| `Erreur : ce script doit être lancé avec sudo` | Relancez la même commande précédée de `sudo` |
| `Ban refusé: IP privée` dans le journal | Apache est derrière un proxy : configurez `mod_remoteip` (voir plus haut) |
| `Avertissement : log Apache non analysé` | Un vhost écrit ailleurs : ajoutez `--log-files` ou `--log-dir` dans le service |
| Une IP légitime est bannie | Ajoutez-la à `scripts/data/safe-ips.txt` ; si c'est une signature, retirez le motif de `bad-patterns.txt` |
| `Aucune IP d'administration dans …safe-ips.txt` | Ajoutez votre IP d'administration dans `scripts/data/safe-ips.txt` |
| `whitelist recréée` | `scripts/data/safe-ips.txt` était absent : il a été recréé avec `127.0.0.1`, ajoutez votre IP |
| `ancienne whitelist encore lue` | Recopiez ses IPs dans `scripts/data/safe-ips.txt`, puis supprimez l'ancien fichier |
| Le service ne démarre pas | `sudo journalctl -u ban-path-explorer -n 50` ; vérifiez le chemin `ExecStart` si le repo n'est pas dans `/opt` |

---

## English

Shell toolkit to protect an Apache web server (Debian/Ubuntu, RHEL-compatible): automatic attacker detection and banning from logs, ready-to-use hardening configs, and security audits.

| Tool | Purpose |
|---|---|
| `scripts/ban-path-explorer.sh` | Parses Apache error + access logs and **bans** (iptables/ip6tables) IPs that scan, brute-force, or send a known attack request |
| `scripts/audit-compromise.sh` | Post-attack compromise indicators (accounts, SSH keys, webshells, suspicious processes…), **read-only** |
| `scripts/audit-email-problems.sh` | Domain anti-spoofing check: SPF, DMARC, DKIM, MTA-STS, TLS-RPT |
| `config/` | Tested configs: fail2ban, Apache and SSH hardening, logrotate |

> ⚠️ **Before the first run, add the administrator's IP to `scripts/data/safe-ips.txt`** (it only contains `127.0.0.1`). Otherwise a mistake on your side can ban you from your own server, SSH included. Do not push the completed file to a public repository.

`ban-path-explorer.sh`, `audit-compromise.sh` and the test suite **must run with `sudo`** and refuse to start otherwise. `audit-email-problems.sh` only does DNS lookups and runs without sudo.

### Quick start

```bash
# 1. Install
sudo apt update && sudo apt install -y git iptables iproute2
sudo git clone https://github.com/daxitsolutions/apache2_ban-hackers.git /opt/apache2_ban-hackers
cd /opt/apache2_ban-hackers

# 2. MANDATORY before the first run: add the administrator's public IP to the whitelist
echo $SSH_CLIENT | cut -d' ' -f1            # your current IP when connected over SSH
sudo nano scripts/data/safe-ips.txt         # contains only 127.0.0.1 by default

# 3. Check the server is not already compromised
sudo ./scripts/audit-compromise.sh --days 60

# 4. Dry run: shows what would be banned, blocks nothing
sudo ./scripts/ban-path-explorer.sh

# 5. Permanent protection
sudo cp scripts/ban-path-explorer.service /etc/systemd/system/
sudo cp config/logrotate.d/ban-path-explorer /etc/logrotate.d/
sudo systemctl daemon-reload && sudo systemctl enable --now ban-path-explorer

# 6. Monitor
sudo tail -f /var/log/ban-path-explorer.log
sudo iptables -S BAN-PATH-EXPLORER; sudo ip6tables -S BAN-PATH-EXPLORER
```

### How ban-path-explorer works

- **Ban triggers**:
  - scan: ≥ `--threshold` (20) distinct failing paths in `--window` (30) minutes, counting error-log "file not found" lines, access-log 400/403/404/405 responses, and POSTs to `wp-login.php`/`xmlrpc.php`;
  - **one** request matching `scripts/bad-patterns.txt`, searched in the URL, referer and user-agent;
  - any request blocked by ModSecurity.
- **Ban durations**: `--ban-duration` (60 min), then 24 h, 7 days, then 30 days for repeat offenders (remembered for 30 days).
- **Never banned**: whitelisted IPs/ranges, the server's own addresses, private IPs (likely a reverse proxy), invalid values.
- **Bans survive reboots**: they are re-applied from `/var/lib/ban-path-explorer/state`.
- **Whitelist**: `scripts/data/safe-ips.txt` (IPs, CIDR ranges, `#` comments). **Unban an IP**: add it there.
- **Default logs**: `*error*.log`, `*access*.log`, `*error_log`, `*access_log` in `--log-dir`. A warning is shown for Apache logs that are configured but not covered.
- **Main options**:
  - `--ban` (without it: dry run);
  - `--follow`, `--threshold`, `--window`, `--ban-duration`;
  - `--history` (whole log history, for investigations);
  - `--log-dir`, `--log-files`, `--ignore-paths`, `--quiet`.

  See `sudo ./scripts/ban-path-explorer.sh --help`.
- **Behind a reverse proxy/CDN**: enable `mod_remoteip` (`RemoteIPHeader X-Forwarded-For` + `RemoteIPTrustedProxy <your proxies>`) and use `%a` instead of `%h` in `LogFormat`. With a public CDN, iptables bans have no effect: block at the CDN level.

### Running the tests

The tests never modify permanent files: the script under test runs from a temporary copy with its own log, state, whitelist and lock.

```bash
sudo ./scripts/test-ban-path-explorer.sh        # on the server: real logs (copied) + synthetic logs
./scripts/test-audit-email-problems.sh          # fake dig, no real DNS queries
```

Full iptables tests (IPv4/IPv6 bans, repeat offenders, restore after reboot…) create real firewall rules. Run them **only in a disposable container**:

```bash
docker run --rm --cap-add NET_ADMIN -e BAN_TESTS=1 -v "$PWD":/repo -w /repo debian:stable-slim \
  bash -c 'apt-get update -qq && apt-get install -y -qq iptables iproute2 procps >/dev/null && ./scripts/test-ban-path-explorer.sh'
```

Running `ban-path-explorer.sh` without `--ban` is the safe way to try settings on a live server.

### Proactive protection and hardening

- **fail2ban** (tested): `sudo apt install fail2ban && sudo cp config/fail2ban/jail.d/ban-hackers.local /etc/fail2ban/jail.d/`. Set `ignoreip`, then `sudo fail2ban-client -t && sudo systemctl restart fail2ban`.
- **ModSecurity + OWASP CRS**:
  1. `sudo apt install libapache2-mod-security2 modsecurity-crs`;
  2. copy `modsecurity.conf-recommended` to `modsecurity.conf`;
  3. run in `DetectionOnly` for 1–2 weeks;
  4. switch to `SecRuleEngine On`.
- **CrowdSec** (community blocklist, not tested here):
  ```bash
  curl -s https://install.crowdsec.net | sudo sh
  sudo apt install crowdsec crowdsec-firewall-bouncer-iptables
  sudo cscli collections install crowdsecurity/apache2 crowdsecurity/sshd
  ```
- **Apache**: `config/apache/zz-ban-hackers-hardening.conf`, enabled with `a2enmod headers && a2enconf zz-ban-hackers-hardening`.
- **SSH**: `config/ssh/99-ban-hackers.conf` (key-only login). Check that key login works first, then run `sshd -t`.
- **Automatic security updates**: `unattended-upgrades`. **Firewall**: default deny incoming.

### Audits

```bash
sudo ./scripts/audit-compromise.sh --days 30 --www /var/www   # read-only
./scripts/audit-email-problems.sh                             # asks for the domain
```

### Updating

```bash
cd /opt/apache2_ban-hackers && sudo git pull --autostash && sudo systemctl restart ban-path-explorer
```

`--autostash` keeps the IPs you added to `scripts/data/safe-ips.txt`. Older whitelist locations (`scripts/safe-ips.txt`, `/etc/ban-path-explorer/safe-ips.txt`) are still read if present: copy their IPs into `scripts/data/safe-ips.txt`, then delete them.
