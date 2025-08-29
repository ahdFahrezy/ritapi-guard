#!/bin/bash
set -e

APP_NAME="ritapi-advance"
VERSION="1.0.0"
ARCH="all"
MAINTAINER="Sydeco <email@example.com>"
DESCRIPTION="Django Project Ritapi Advance
 Ritapi Advance is a Django application. This package installs the app to /opt/${APP_NAME}."

BUILD_DIR="build"
PKG_DIR="$BUILD_DIR/${APP_NAME}_${VERSION}"
DEBIAN_DIR="$PKG_DIR/DEBIAN"

echo "[*] Cleaning build directory..."
rm -rf "$BUILD_DIR"
mkdir -p "$DEBIAN_DIR"
mkdir -p "$PKG_DIR/opt/$APP_NAME"
mkdir -p "$PKG_DIR/lib/systemd/system"

echo "[*] Copying project to /opt/$APP_NAME..."
rsync -a \
  --exclude 'build' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  --exclude '*.db' \
  --exclude '*.log' \
  --exclude 'venv' \
  --exclude '.env' \
  ./ "$PKG_DIR/opt/$APP_NAME/"

# Ensure setup script is executable
if [ -f "$PKG_DIR/opt/$APP_NAME/setup_ritapi.sh" ]; then
    chmod +x "$PKG_DIR/opt/$APP_NAME/setup_ritapi.sh"
fi

# --- CONTROL file ---
cat > "$DEBIAN_DIR/control" <<EOF
Package: $APP_NAME
Version: $VERSION
Section: web
Priority: optional
Architecture: $ARCH
Maintainer: $MAINTAINER
Depends: python3, python3-venv, python3-pip
Description: $DESCRIPTION
EOF

# --- POSTINST ---
cat > "$DEBIAN_DIR/postinst" <<'EOF'
#!/bin/sh
set -eu

APP_NAME="ritapi-advance"
APP_DIR="/opt/${APP_NAME}"
SETUP="${APP_DIR}/setup_ritapi.sh"
STAMP_DIR="/var/lib/${APP_NAME}"
STAMP_FILE="${STAMP_DIR}/postinst_setup_done"
SERVICE_FILE="/lib/systemd/system/${APP_NAME}.service"

mkdir -p "${STAMP_DIR}"

if [ "${1:-configure}" = "configure" ]; then
  if [ -x "${SETUP}" ]; then
    if [ ! -f "${STAMP_FILE}" ]; then
      echo "Running setup_ritapi.sh..."
      chmod +x "${SETUP}"
      cd "${APP_DIR}"
      "${SETUP}" setup
      touch "${STAMP_FILE}"
      echo "Setup completed."
    else
      echo "Setup already executed, skipping."
    fi
  else
    echo "setup_ritapi.sh is missing or not executable."
  fi

  # --- Systemd service setup ---
  if [ -f "${SERVICE_FILE}" ]; then
    echo "Installing systemd service..."
    chmod 644 "${SERVICE_FILE}"
    systemctl daemon-reload
    systemctl enable "${APP_NAME}.service"
    systemctl restart "${APP_NAME}.service" || true
    echo "Service ${APP_NAME} is now running (if no errors)."
  else
    echo "Systemd service file ${APP_NAME}.service not found in /lib/systemd/system/"
  fi
fi

exit 0
EOF
chmod 755 "$DEBIAN_DIR/postinst"

# --- PRERM ---
cat > "$DEBIAN_DIR/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "upgrade" ]; then
    systemctl stop ritapi-advance || true
    systemctl disable ritapi-advance || true
fi
exit 0
EOF
chmod 755 "$DEBIAN_DIR/prerm"

# --- POSTRM ---
cat > "$DEBIAN_DIR/postrm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "purge" ]; then
    rm -f /lib/systemd/system/ritapi-advance.service
    systemctl daemon-reload
fi
exit 0
EOF
chmod 755 "$DEBIAN_DIR/postrm"

# --- SERVICE ---
cat > "$PKG_DIR/lib/systemd/system/ritapi-advance.service" <<EOF
[Unit]
Description=RitAPI Advance Django Service
After=network.target postgresql.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/opt/ritapi-advance
ExecStart=/opt/ritapi-advance/venv/bin/gunicorn \\
  --workers 3 \\
  --bind 0.0.0.0:8004 \\
  ritapi_advance.wsgi:application
Restart=always
Environment="DJANGO_SETTINGS_MODULE=ritapi_advance.settings"
EnvironmentFile=-/opt/ritapi-advance/.env

[Install]
WantedBy=multi-user.target
EOF


echo "[*] Building Debian package..."
dpkg-deb --build "$PKG_DIR"

echo "[+] Done: $PKG_DIR.deb"
echo "[*] You can install it using: sudo dpkg -i $PKG_DIR.deb"