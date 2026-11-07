#!/usr/bin/env bash
#
# Usage : sudo ./scripts/audit-compromise.sh [--days N] [--www DIR]
# Recherche de traces de compromission après une attaque (issue #14).
# LECTURE SEULE : ne modifie, ne supprime et ne bloque rien.
# Chaque section liste des éléments à vérifier à la main ; une ligne n'est pas forcément malveillante.

set -u

DAYS=30
WWW_DIR="/var/www"
while [ $# -gt 0 ]; do
  case "$1" in
    --days) shift; DAYS="${1:?--days N}" ;;
    --www) shift; WWW_DIR="${1:?--www DIR}" ;;
    -h|--help) sed -n '3,6p' "$0"; exit 0 ;;
    *) echo "Option inconnue: $1" >&2; exit 1 ;;
  esac
  shift
done
case "$DAYS" in ''|*[!0-9]*) echo "--days doit être un entier" >&2; exit 1 ;; esac
if [ "$(id -u)" -ne 0 ]; then
  echo "Erreur : ce script doit être lancé avec sudo (lecture de /etc/shadow, /root, /proc des autres utilisateurs)." >&2
  echo "  sudo $0 $*" >&2
  exit 1
fi

section() { printf '\n=== %s ===\n' "$1"; }
# Affiche la sortie, ou "(rien)" si vide
show() { local out; out="$("$@" 2>/dev/null)"; [ -n "$out" ] && printf '%s\n' "$out" || echo "(rien)"; }

echo "Audit de compromission - $(hostname) - $(date '+%Y-%m-%d %H:%M') - fenêtre : $DAYS jours"

section "Comptes avec UID 0 (seul root attendu)"
show awk -F: '$3 == 0 { print $1 }' /etc/passwd

section "Comptes avec un shell de connexion"
show awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ { print $1 " (uid " $3 ", " $7 ")" }' /etc/passwd

section "Fichiers d'identité modifiés depuis $DAYS jours"
show find /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/sudoers.d -mtime "-$DAYS" -printf '%TY-%Tm-%Td %TH:%TM  %p\n'

section "Clés SSH autorisées (toute clé inconnue = accès de l'attaquant)"
for f in /root/.ssh/authorized_keys* /home/*/.ssh/authorized_keys*; do
  [ -f "$f" ] || continue
  printf '%s (modifié %s)\n' "$f" "$(date -r "$f" '+%Y-%m-%d %H:%M')"
  awk '!/^#/ && NF { print "   " $1 " ..." substr($2, length($2) - 11) " " $3 }' "$f"
done

section "Tâches planifiées modifiées depuis $DAYS jours"
show find /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron -type f -mtime "-$DAYS" -printf '%TY-%Tm-%Td %TH:%TM  %p\n'

section "Services systemd ajoutés/modifiés depuis $DAYS jours"
show find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -name '*.service' -mtime "-$DAYS" -printf '%TY-%Tm-%Td %TH:%TM  %p\n'

section "Démarrage automatique (rc.local, profile, ld.so.preload)"
show find /etc/rc.local /etc/profile /etc/profile.d /etc/bash.bashrc /root/.bashrc /etc/ld.so.preload -mtime "-$DAYS" -printf '%TY-%Tm-%Td %TH:%TM  %p\n'
[ -s /etc/ld.so.preload ] && echo "⚠️  /etc/ld.so.preload non vide (technique de rootkit) :" && cat /etc/ld.so.preload

section "Webshells probables dans $WWW_DIR"
show grep -rlE --include='*.php' --include='*.phtml' --include='*.php[0-9]' \
  'eval[[:space:]]*\([[:space:]]*(\$_(POST|GET|REQUEST|COOKIE)|base64_decode|gzinflate|str_rot13)|(system|shell_exec|passthru|exec|popen|proc_open|assert)[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE)|preg_replace[[:space:]]*\(.*/e' \
  "$WWW_DIR"

section "Fichiers PHP modifiés depuis 7 jours dans $WWW_DIR"
show find "$WWW_DIR" -type f \( -name '*.php' -o -name '*.phtml' \) -mtime -7 -printf '%TY-%Tm-%Td %TH:%TM  %p\n'

section "Fichiers PHP dans des dossiers d'upload"
show find "$WWW_DIR" -type f -name '*.php*' -path '*upload*'

section "Exécutables dans /tmp, /var/tmp, /dev/shm"
show find /tmp /var/tmp /dev/shm -type f -perm -u+x

section "Processus lancés depuis un dossier temporaire ou supprimé"
for p in /proc/[0-9]*; do
  exe="$(readlink "$p/exe" 2>/dev/null)" || continue
  case "$exe" in
    /tmp/*|/var/tmp/*|/dev/shm/*|*" (deleted)") echo "PID ${p#/proc/} : $exe  ($(tr '\0' ' ' < "$p/cmdline" | cut -c1-120))" ;;
  esac
done

section "Ports en écoute"
show ss -tulpn

section "Connexions sortantes établies (mineurs, reverse shells ?)"
show ss -tnp state established

section "Binaires SUID modifiés depuis $DAYS jours"
show find / -xdev -perm -4000 -type f -mtime "-$DAYS" -printf '%TY-%Tm-%Td %TH:%TM  %p\n'

section "Intégrité des paquets (debsums)"
if command -v debsums >/dev/null 2>&1; then
  show debsums -c
else
  echo "debsums absent : sudo apt install debsums && sudo debsums -c"
fi

section "Pour aller plus loin"
echo "- sudo apt install rkhunter chkrootkit && sudo rkhunter --check --sk && sudo chkrootkit"
echo "- last -n 30 ; lastb -n 30   (connexions réussies / échouées)"
echo "- En cas de doute sérieux : changer tous les secrets (SSH, BDD, .env, API) et réinstaller le serveur."
