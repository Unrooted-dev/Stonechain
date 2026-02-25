#!/usr/bin/env bash
# deploy/setup.sh — Einmaliges Server-Setup
# Getestet auf Ubuntu 22.04 / Debian 12
#
# Usage:
#   sudo bash setup.sh yourdomain.com

set -euo pipefail
DOMAIN="${1:?Usage: sudo bash setup.sh yourdomain.com}"

echo "=== Stone + forge-Nomad Server Setup ==="

# 1. Dependencies
apt-get update -q
apt-get install -y nginx certbot python3-certbot-nginx ufw

# 2. Firewall
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP → Redirect
ufw allow 443/tcp   # HTTPS
ufw deny 8080/tcp   # Stone-Node: KEIN externer Zugriff
ufw --force enable
echo "✅ Firewall konfiguriert (8080 geblockt)"

# 3. forge-Nomad
mkdir -p /opt/forge-nomad
cp -r /tmp/forge-nomad-deploy/* /opt/forge-nomad/
chown -R www-data:www-data /opt/forge-nomad

# .env anpassen
sed -i "s|BLOCKCHAIN_URL=.*|BLOCKCHAIN_URL=http://localhost:8080|" /opt/forge-nomad/.env
sed -i "s|FLASK_ENV=.*|FLASK_ENV=production|" /opt/forge-nomad/.env

# 4. Stone-Node
mkdir -p /opt/stone
cp -r /tmp/stone-deploy/* /opt/stone/
chown -R www-data:www-data /opt/stone

# 5. Systemd Services
cp /opt/stone/deploy/stone-master.service /etc/systemd/system/
cp /opt/stone/deploy/forge-nomad.service  /etc/systemd/system/
systemctl daemon-reload
systemctl enable stone-master forge-nomad
systemctl start  stone-master
sleep 3
systemctl start  forge-nomad
echo "✅ Services gestartet"

# 6. Nginx
cp /opt/stone/deploy/nginx.conf /etc/nginx/sites-available/forge-nomad
sed -i "s|yourdomain.com|$DOMAIN|g" /etc/nginx/sites-available/forge-nomad
ln -sf /etc/nginx/sites-available/forge-nomad /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
echo "✅ Nginx konfiguriert"

# 7. TLS Zertifikat
certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN"
echo "✅ TLS Zertifikat ausgestellt"

echo ""
echo "=== Deployment abgeschlossen ==="
echo "    https://$DOMAIN"
echo ""
echo "BLOCKCHAIN_URL=http://localhost:8080  (intern, nicht exposed)"
echo "Stone-Node API-Key: $(cat /opt/stone/.env | grep STONE_CLUSTER_API_KEY | cut -d= -f2)"
