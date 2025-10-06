#!/bin/bash

# Vérifier que le script est lancé en root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Ce script doit être exécuté en root"
    echo "Utilisez: sudo ./auto_ban.sh"
    exit 1
fi

# IP à ne jamais bannir (whitelist)
WHITELIST="VOTRE IP ICI"
LOG="/home/ubuntu/ssh_honeypot/logs/attempts.json"
THRESHOLD=3

echo "🔍 Analyse des IPs..."
echo "🛡️  IP whitelistée : $WHITELIST"
echo ""

# Lire le fichier JSON et extraire les IPs
cat "$LOG" | jq -r '.ip' 2>/dev/null | sort | uniq -c | sort -rn | \
while read count ip; do
    # Skip whitelist
    if [[ "$ip" == "$WHITELIST" ]]; then
        echo "✅ $ip whitelistée - $count tentatives (ignorée)"
        continue
    fi
    
    if [ "$count" -ge "$THRESHOLD" ]; then
        if ! iptables -L INPUT -n | grep -q "$ip"; then
            echo "🚫 Bannissement: $ip ($count tentatives)"
            iptables -I INPUT -s "$ip" -j DROP
        else
            echo "✓ $ip déjà bannie ($count tentatives)"
        fi
    fi
done

echo ""
echo "📊 Top 10 des attaquants:"
cat "$LOG" | jq -r '.ip' 2>/dev/null | sort | uniq -c | sort -rn | head -10

echo ""
echo "🔒 IPs actuellement bannies:"
iptables -L INPUT -n | grep DROP | awk '{print $4}' | grep -v "0.0.0.0/0"
