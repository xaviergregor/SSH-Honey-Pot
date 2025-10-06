#!/usr/bin/env python3
"""
SSH Honeypot interactif avec logging des commandes
"""
import socket
import paramiko
import threading
import logging
import json
import requests
import os
import sys
from datetime import datetime

# Configuration
PORT = 2222
HOST = '0.0.0.0'
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', 'VOTRE_TOKEN_ICI')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID', 'VOTRE_CHAT_ID_ICI')
TELEGRAM_ENABLED = os.getenv('TELEGRAM_ENABLED', 'true').lower() == 'true'
KEY_PATH = '/app/keys/ssh_host_rsa_key'
TELEGRAM_PAUSE_FILE = '/app/logs/.telegram_paused'

# Créer les dossiers
os.makedirs('/app/keys', exist_ok=True)
os.makedirs('/app/logs', exist_ok=True)

# Génération de la clé SSH
def generate_ssh_key():
    if not os.path.exists(KEY_PATH):
        print(f"Génération de la clé SSH dans {KEY_PATH}...")
        try:
            key = paramiko.RSAKey.generate(2048)
            key.write_private_key_file(KEY_PATH)
            print(f"✓ Clé SSH générée avec succès")
        except Exception as e:
            print(f"✗ Erreur lors de la génération de la clé: {e}")
            sys.exit(1)
    else:
        print(f"✓ Clé SSH existante trouvée")
    
    if os.path.exists(KEY_PATH):
        print(f"✓ Vérification: {KEY_PATH} existe")
    else:
        print(f"✗ ERREUR: {KEY_PATH} n'existe pas!")
        sys.exit(1)

generate_ssh_key()

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/honeypot.log'),
        logging.StreamHandler()
    ]
)

# Faux système de fichiers pour simuler un environnement réel
FAKE_FS = {
    '/': ['bin', 'etc', 'home', 'root', 'tmp', 'usr', 'var'],
    '/home': ['user', 'admin', 'ubuntu'],
    '/etc': ['passwd', 'shadow', 'hosts', 'ssh'],
    '/root': ['.bash_history', '.ssh'],
    '/tmp': []
}

class SSHServerHandler(paramiko.ServerInterface):
    def __init__(self, client_address):
        self.event = threading.Event()
        self.client_address = client_address
        self.username = None
        self.password = None
        
    def check_auth_password(self, username, password):
        # Sauvegarder les infos
        self.username = username
        self.password = password
        
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'ip': self.client_address[0],
            'port': self.client_address[1],
            'username': username,
            'password': password,
            'auth_type': 'password'
        }
        
        # Si username ou password est vide, refuser
        if not username or not password:
            return paramiko.AUTH_FAILED
        
        logging.warning(f"Connexion acceptée - IP: {self.client_address[0]}, User: {username}, Pass: {password}")
        
        with open('/app/logs/attempts.json', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
        
        send_telegram_notification(log_entry, "🔓 Connexion acceptée")
        
        # ACCEPTER toute connexion avec username ET password non vides
        return paramiko.AUTH_SUCCESSFUL
    
    def check_auth_publickey(self, username, key):
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'ip': self.client_address[0],
            'port': self.client_address[1],
            'username': username,
            'key_type': key.get_name(),
            'auth_type': 'publickey'
        }
        
        logging.warning(f"Connexion par clé publique - IP: {self.client_address[0]}, User: {username}")
        
        with open('/app/logs/attempts.json', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
        
        send_telegram_notification(log_entry, "🔑 Connexion par clé publique")
        
        return paramiko.AUTH_SUCCESSFUL
    
    def get_allowed_auths(self, username):
        return 'password,publickey'
    
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True
    
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    
    def check_channel_exec_request(self, channel, command):
        command_str = command.decode('utf-8', errors='ignore')
        log_command(self.client_address[0], self.username, command_str)
        return True

def is_telegram_paused():
    """Vérifie si les notifications Telegram sont en pause"""
    pause_file = '/app/logs/.telegram_paused'
    return os.path.exists(pause_file)

def send_telegram_notification(log_entry, message_type="🚨 Tentative d'intrusion SSH"):
    """Envoie une notification sur Telegram"""
    if not TELEGRAM_ENABLED or is_telegram_paused():
        return
    
    if TELEGRAM_BOT_TOKEN == 'VOTRE_TOKEN_ICI' or TELEGRAM_CHAT_ID == 'VOTRE_CHAT_ID_ICI':
        return
    
    try:
        message = f"{message_type}\n\n"
        message += f"🕐 *Heure:* {log_entry['timestamp']}\n"
        message += f"🌐 *IP:* `{log_entry['ip']}`\n"
        message += f"👤 *Username:* `{log_entry['username']}`\n"
        
        if 'password' in log_entry:
            message += f"🔑 *Password:* `{log_entry['password']}`\n"
        if 'key_type' in log_entry:
            message += f"🔐 *Key Type:* `{log_entry['key_type']}`\n"
        
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        data = {
            'chat_id': TELEGRAM_CHAT_ID,
            'text': message,
            'parse_mode': 'Markdown'
        }
        
        response = requests.post(url, json=data, timeout=5)
        if response.status_code == 200:
            logging.info("Notification Telegram envoyée")
        else:
            logging.error(f"Erreur Telegram: {response.status_code}")
            
    except Exception as e:
        logging.error(f"Erreur Telegram: {e}")

def send_command_notification(ip, username, command):
    """Envoie une notification pour une commande"""
    if not TELEGRAM_ENABLED or is_telegram_paused():
        return
    
    if TELEGRAM_BOT_TOKEN == 'VOTRE_TOKEN_ICI' or TELEGRAM_CHAT_ID == 'VOTRE_CHAT_ID_ICI':
        return
    
    try:
        message = f"⌨️ *Commande exécutée*\n\n"
        message += f"🌐 *IP:* `{ip}`\n"
        message += f"👤 *User:* `{username}`\n"
        message += f"💻 *Commande:* `{command}`\n"
        
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        data = {
            'chat_id': TELEGRAM_CHAT_ID,
            'text': message,
            'parse_mode': 'Markdown'
        }
        
        requests.post(url, json=data, timeout=5)
    except:
        pass

def log_command(ip, username, command):
    """Log une commande exécutée"""
    log_entry = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'ip': ip,
        'username': username,
        'command': command
    }
    
    logging.warning(f"COMMANDE - IP: {ip}, User: {username}, Cmd: {command}")
    
    with open('/app/logs/commands.json', 'a') as f:
        f.write(json.dumps(log_entry) + '\n')
    
    send_command_notification(ip, username, command)

def execute_fake_command(command, cwd='/root'):
    """Simule l'exécution d'une commande"""
    cmd = command.strip().split()
    if not cmd:
        return ""
    
    base_cmd = cmd[0]
    
    # Commandes courantes
    if base_cmd == 'ls':
        path = cwd
        if len(cmd) > 1:
            path = cmd[1] if cmd[1].startswith('/') else f"{cwd}/{cmd[1]}"
        return '\n'.join(FAKE_FS.get(path, ['file1.txt', 'file2.txt']))
    
    elif base_cmd == 'pwd':
        return cwd
    
    elif base_cmd == 'whoami':
        return 'root'
    
    elif base_cmd == 'id':
        return 'uid=0(root) gid=0(root) groups=0(root)'
    
    elif base_cmd == 'uname':
        return 'Linux honeypot 5.15.0-generic #101-Ubuntu SMP x86_64 GNU/Linux'
    
    elif base_cmd == 'cat':
        if len(cmd) > 1 and 'passwd' in cmd[1]:
            return 'root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000::/home/ubuntu:/bin/bash'
        return 'cat: permission denied'
    
    elif base_cmd in ['wget', 'curl']:
        return 'Connecting...\nDownloading...\n100% complete'
    
    elif base_cmd == 'ps':
        return '  PID TTY          TIME CMD\n    1 ?        00:00:00 systemd\n  123 pts/0    00:00:00 bash'
    
    elif base_cmd == 'history':
        return '1  ls\n2  pwd\n3  whoami'
    
    else:
        return f'{base_cmd}: command not found'

def handle_shell(channel, client_address, username):
    """Gère une session shell interactive"""
    cwd = '/root'
    
    try:
        channel.send(f'Welcome to Ubuntu 22.04 LTS\r\n')
        channel.send(f'Last login: {datetime.now().strftime("%a %b %d %H:%M:%S %Y")}\r\n')
        channel.send(f'{username}@honeypot:~$ ')
    except Exception as e:
        logging.error(f"Erreur envoi banner: {e}")
        return
    
    command_buffer = ""
    
    try:
        while True:
            try:
                data = channel.recv(1024)
                if not data:
                    break
                
                char = data.decode('utf-8', errors='ignore')
                
                for c in char:
                    if c == '\r' or c == '\n':
                        if command_buffer.strip():
                            log_command(client_address[0], username, command_buffer)
                            
                            # Exécuter la fausse commande
                            output = execute_fake_command(command_buffer, cwd)
                            if output:
                                channel.send('\r\n' + output + '\r\n')
                            
                            command_buffer = ""
                        
                        channel.send(f'{username}@honeypot:~$ ')
                    
                    elif c == '\x7f':  # Backspace
                        if command_buffer:
                            command_buffer = command_buffer[:-1]
                            channel.send('\b \b')
                    
                    elif c == '\x03':  # Ctrl+C
                        channel.send('^C\r\n')
                        channel.send(f'{username}@honeypot:~$ ')
                        command_buffer = ""
                    
                    elif c == '\x04':  # Ctrl+D (exit)
                        channel.send('logout\r\n')
                        return
                    
                    elif ord(c) >= 32:  # Caractères imprimables
                        command_buffer += c
                        channel.send(c)
            
            except socket.timeout:
                continue
            except EOFError:
                break
                
    except Exception as e:
        logging.error(f"Erreur dans le shell: {e}")
    finally:
        try:
            channel.close()
        except:
            pass

def handle_connection(client_socket, client_address):
    """Gère une connexion SSH entrante"""
    try:
        transport = paramiko.Transport(client_socket)
        
        try:
            host_key = paramiko.RSAKey(filename=KEY_PATH)
            transport.add_server_key(host_key)
        except Exception as e:
            logging.error(f"Impossible de charger la clé SSH: {e}")
            return
        
        server = SSHServerHandler(client_address)
        transport.start_server(server=server)
        
        channel = transport.accept(20)
        if channel is None:
            logging.info(f"Pas de canal ouvert par {client_address[0]}")
            return
        
        # Attendre la requête shell
        server.event.wait(10)
        
        if not server.event.is_set():
            logging.info(f"Pas de shell demandé par {client_address[0]}")
            channel.close()
            return
        
        logging.info(f"Session shell démarrée pour {client_address[0]}")
        
        # Gérer le shell interactif
        handle_shell(channel, client_address, server.username)
        
        logging.info(f"Session terminée pour {client_address[0]}")
        transport.close()
        
    except Exception as e:
        logging.error(f"Erreur avec {client_address[0]}: {e}")
    finally:
        try:
            client_socket.close()
        except:
            pass

def start_honeypot():
    """Démarre le honeypot SSH"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(100)
    
    telegram_status = 'Activées'
    if not TELEGRAM_ENABLED:
        telegram_status = 'Désactivées (TELEGRAM_ENABLED=false)'
    elif is_telegram_paused():
        telegram_status = 'En PAUSE (fichier .telegram_paused existe)'
    elif TELEGRAM_BOT_TOKEN == 'VOTRE_TOKEN_ICI':
        telegram_status = 'Désactivées (pas configuré)'
    
    logging.info(f"🍯 Honeypot SSH INTERACTIF démarré sur {HOST}:{PORT}")
    logging.info(f"📱 Notifications Telegram: {telegram_status}")
    logging.info(f"⌨️  Logging des commandes: Activé")
    
    try:
        while True:
            client_socket, client_address = server_socket.accept()
            logging.info(f"Nouvelle connexion de {client_address[0]}:{client_address[1]}")
            
            client_thread = threading.Thread(
                target=handle_connection,
                args=(client_socket, client_address)
            )
            client_thread.daemon = True
            client_thread.start()
            
    except KeyboardInterrupt:
        logging.info("Arrêt du honeypot...")
    finally:
        server_socket.close()

if __name__ == '__main__':
    start_honeypot()
