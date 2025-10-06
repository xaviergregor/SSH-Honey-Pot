# 🍯 SSH HONEYPOT
A simple SSH Honey Pot with Telegram notifications

# Pour supprimer le conteneur
docker compose down

# Remplacer les valeurs

* TELEGRAM_BOT_TOKEN=
* TELEGRAM_CHAT_ID=

# Pour builder le conteneur
docker compose build --no-cache

# Pour lancer le contenenur
docker compose up -d

# Pour voir les logs
docker compose logs -f

# Pour bannir les IP
⚠️ Modifier le fichier pour mettre votre IP 😜\
auto_ban.sh

# Pour suspendre les notifications Telegram
toggle_telegram.sh


# OPTION

Pour fail2ban\

* Mettre le fichier ssh-honeypot.local dans /etc/fail2ban/jail.d/
* Mettre le fichier ssh-honeypot.conf dans /etc/fail2ban/filter.d/

# Pour avoir le DashBoard Web

# Installer nginx et htpasswd
sudo apt install nginx apache2-utils -y

# Créer un utilisateur/mot de passe
sudo htpasswd -c /etc/nginx/.htpasswd admin

# Configuration nginx
sudo vim /etc/nginx/sites-available/honeypot

# Coller ceci
```
server {
    listen 8080;
    server_name _;

    root /var/www/honeypot;
    index dashboard.html;

    auth_basic "Honeypot Dashboard";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        try_files $uri $uri/ =404;
    }

    location ~* \.(json)$ {
        add_header Cache-Control "no-store, no-cache, must-revalidate";
    }
}
```
# Activer NGINX

sudo ln -s /etc/nginx/sites-available/honeypot /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx

# Créer le dossier
sudo mkdir -p /var/www/honeypot

# Copier le dashboard
sudo cp /home/ubuntu/ssh_honeypot/logs/dashboard.html /var/www/honeypot/

# Créer des liens symboliques pour les JSON
sudo ln -sf /home/ubuntu/ssh_honeypot/logs/attempts.json /var/www/honeypot/attempts.json
sudo ln -sf /home/ubuntu/ssh_honeypot/logs/commands.json /var/www/honeypot/commands.json

# Permissions correctes
sudo chown -R www-data:www-data /var/www/honeypot
sudo chmod 755 /var/www/honeypot
sudo chmod 644 /var/www/honeypot/*
