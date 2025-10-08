#!/bin/bash

ATTEMPTS_FILE="/home/ubuntu/ssh_honeypot/logs/attempts.json"
BLACKLIST="/home/ubuntu/ssh_honeypot/logs/blacklist.txt"
THRESHOLD=10  # Bloquer après X tentatives
WHITELIST="METTRE VOTRE IP ICI"

echo "🔍 Analyse des IPs avec plus de $THRESHOLD tentatives..."

# Extraire les IPs avec beaucoup de tentatives
cat "$ATTEMPTS_FILE" | jq -r '.ip' | sort | uniq -c | sort -rn | while read count ip; do
    # Skip whitelist
    if [[ "$ip" == "$WHITELIST" ]]; then
        continue
    fi
    
    if [ "$count" -ge "$THRESHOLD" ]; then
        # Vérifier si déjà dans la blacklist
        if ! grep -q "^$ip$" "$BLACKLIST" 2>/dev/null; then
            echo "$ip" >> "$BLACKLIST"
            echo "🚫 $ip ajoutée à la blacklist ($count tentatives)"
        fi
    fi
done

echo ""
echo "📊 Statistiques:"
echo "Total IPs: $(cat "$ATTEMPTS_FILE" | jq -r '.ip' | sort -u | wc -l)"
echo "IPs bloquées: $(grep -v "^#" "$BLACKLIST" | grep -v "^$" | wc -l)"

docker restart ssh_honeypot
