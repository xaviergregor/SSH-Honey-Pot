#!/bin/bash

# Vérifier que le script est lancé en root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Ce script doit être exécuté en root"
    echo "Utilisez: sudo ./toggle_telegram.sh"
    exit 1
fi

PAUSE_FILE="logs/.telegram_paused"

if [ -f "$PAUSE_FILE" ]; then
    rm "$PAUSE_FILE"
    echo "🔔 ✅ Notifications Telegram ACTIVÉES"
else
    touch "$PAUSE_FILE"
    echo "🔕 ⏸️  Notifications Telegram DÉSACTIVÉES"
fi

# Afficher le statut
echo ""
if [ -f "$PAUSE_FILE" ]; then
    echo "📱 Statut actuel: EN PAUSE"
else
    echo "📱 Statut actuel: ACTIF"
fi
