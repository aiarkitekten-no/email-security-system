#!/usr/bin/env bash
# liste_spam_mapper.sh
# Finn alle spam/søppelpost-mapper på Plesk Obsidian med Dovecot.
# Kjør som root.

set -Eeuo pipefail

# Vanlige Plesk/Dovecot mail-roots:
ROOTS=(
  /var/qmail/mailnames        # Plesk standard (uansett Postfix/Qmail)
  /var/vmail                  # Noen installasjoner bruker denne
  /var/www/vhosts/*/mail      # Eldre/varianter
)

# Kandidatnavn for spam/junk-mapper (case-insensitive sjekk ved sammenligning)
CANDIDATES=(
  ".Spam" ".Junk" "Spam" "Junk"
  ".Søppelpost" "Søppelpost"
  ".Trash" "Trash"    # noen klienter dumper spam her (ikke ideelt)
  ".Uønsket" "Uønsket"
)

shopt -s nullglob dotglob extglob

is_maildir_folder() {
  # Sann hvis $1 er en Maildir-mappe (har cur/new/tmp)
  local d="$1"
  [[ -d "$d/cur" && -d "$d/new" && -d "$d/tmp" ]]
}

guess_email_from_path() {
  local p="$1"
  # /var/qmail/mailnames/<domene>/<bruker>/...
  if [[ "$p" =~ /mailnames/([^/]+)/([^/]+)/ ]]; then
    printf "%s@%s" "${BASH_REMATCH[2]}" "${BASH_REMATCH[1]}"
    return 0
  fi
  # /var/vmail/<domene>/<bruker>/...
  if [[ "$p" =~ /vmail/([^/]+)/([^/]+)/ ]]; then
    printf "%s@%s" "${BASH_REMATCH[2]}" "${BASH_REMATCH[1]}"
    return 0
  fi
  # /var/www/vhosts/<domene>/mail/<bruker>/...
  if [[ "$p" =~ /vhosts/([^/]+)/mail/([^/]+)/ ]]; then
    printf "%s@%s" "${BASH_REMATCH[2]}" "${BASH_REMATCH[1]}"
    return 0
  fi
  printf "ukjent"
  return 1
}

printf "Starter skann av spam/søppelpost-mapper (Plesk/Dovecot)\n\n"

found=0

for root in "${ROOTS[@]}"; do
  for base in $root/*/*; do
    # base blir f.eks: /var/qmail/mailnames/example.com/user
    [[ -d "$base" ]] || continue

    # Typisk Maildir-plasseringer vi vil sjekke
    maildirs=()
    [[ -d "$base/Maildir" ]] && maildirs+=("$base/Maildir")
    [[ -d "$base" ]] && maildirs+=("$base")  # dekke /var/vmail/<domene>/<bruker> direkte layout

    for md in "${maildirs[@]}"; do
      # Sjekk kandidater både med og uten leading dot (noen klienter lager begge varianter)
      for name in "${CANDIDATES[@]}"; do
        # To varianter: ".Spam" og "Spam" kan finnes side om side
        for candidate in "$md/$name" "$md/.${name#.}"; do
          [[ -d "$candidate" ]] || continue
          # Maildir under-mapper har egen cur/new/tmp
          if is_maildir_folder "$candidate"; then
            email="$(guess_email_from_path "$base")"
            printf "%s | %s | epost: %s\n" "$candidate" "Maildir-mappe" "$email"
            ((found++))
          fi
          # Noen klienter lager “folder directory” som selve kandidatmappen,
          # men selve Maildir-data ligger i underkatalog (f.eks. candidate/cur osv).
          # Dette er allerede dekket av is_maildir_folder over.
        done
      done
    done
  done
done

printf "\n"
if (( found == 0 )); then
  printf "Ingen spam-/junk-mapper funnet i kjente stier.\n"
  printf "Tips:\n"
  printf " - Kjør som root (sudo) – du gjorde trolig det allerede.\n"
  printf " - Sjekk at post ligger i Plesk-standard: /var/qmail/mailnames/<domene>/<bruker>/Maildir\n"
  printf " - Har du custom-lagring? Legg til root i ROOTS-arrayen i toppen av scriptet.\n"
  printf " - Dypere skann? Bytt ut glob-løkka med 'find' uten -maxdepth, men det blir tregere.\n"
else
  printf "Ferdig. Fant %d spam-/junk-mapper.\n" "$found"
fi
