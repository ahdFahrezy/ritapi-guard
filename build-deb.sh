#!/bin/bash
set -e

APP_NAME="ritapi-guard"
VERSION="1.0.0"
DEFAULT_PORT="8008"
ARCH="all"
MAINTAINER="Sydeco <email@example.com>"
DESCRIPTION="Django Project Ritapi Guard
 Ritapi Guard is a Django application. This package installs the app to /opt/${APP_NAME}."

BUILD_DIR="build"
PKG_DIR="$BUILD_DIR/${APP_NAME}_${VERSION}"
DEBIAN_DIR="$PKG_DIR/DEBIAN"
SRC_DIR="$(pwd)"

echo "[*] Cleaning build directory..."
rm -rf "$BUILD_DIR"
mkdir -p "$DEBIAN_DIR"
mkdir -p "$PKG_DIR/opt/$APP_NAME"
mkdir -p "$PKG_DIR/lib/systemd/system"

# --- Prepare temporary venv for PyArmor ---
if [ ! -d ".build_venv" ]; then
    echo "[*] Creating temporary build venv..."
    python3 -m venv .build_venv
    source .build_venv/bin/activate
    pip install --upgrade pip
    pip install pyarmor
else
    source .build_venv/bin/activate
fi

# --- Run PyArmor obfuscation (only project source, not venv) ---
echo "[*] Running PyArmor obfuscation..."
OBFUSCATED_DIR="$BUILD_DIR/obf_project"
rm -rf "$OBFUSCATED_DIR"

pyarmor gen --recursive \
    --exclude venv \
    -O "$OBFUSCATED_DIR" \
    "$SRC_DIR/manage.py" \
    "$SRC_DIR/ritapi_guard" \
    "$SRC_DIR/ai_behaviour" \
    "$SRC_DIR/alert_blocking" \
    "$SRC_DIR/asn_score" \
    "$SRC_DIR/decision_engine" \
    "$SRC_DIR/ip_reputation" \
    "$SRC_DIR/json_enforcer" \
    "$SRC_DIR/tls_analyzer"\
    "$SRC_DIR/middlewares"\
    "$SRC_DIR/demo"\
    "$SRC_DIR/ops"

# --- Copy obfuscated project into package ---
echo "[*] Copying obfuscated project to /opt/$APP_NAME..."
rsync -a "$OBFUSCATED_DIR/" "$PKG_DIR/opt/$APP_NAME/"

# Copy other non-source files (requirements, setup scripts, etc.)
rsync -a \
  --exclude 'build' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  --exclude '*.db' \
  --exclude '*.log' \
  --exclude 'venv' \
  --exclude '.env' \
  --exclude 'ritapi_guard' \
  --exclude 'ai_behaviour' \
  --exclude 'alert_blocking' \
  --exclude 'asn_score' \
  --exclude 'decision_engine' \
  --exclude 'ip_reputation' \
  --exclude 'json_enforcer' \
  --exclude 'tls_analyzer' \
  --exclude 'ops' \
  --exclude 'demo' \
  --exclude 'middlewares' \
  --exclude 'manage.py' \
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

APP_NAME="ritapi-guard"
APP_DIR="/opt/${APP_NAME}"
SETUP="${APP_DIR}/setup_ritapi.sh"
SERVICE_FILE="/lib/systemd/system/${APP_NAME}.service"

configure_service() {
    # Port configuration
    DEFAULT_PORT="8008"
    printf "Enter port number for Gunicorn [default=${DEFAULT_PORT}]: "
    read -r port_number

    if [ -n "$port_number" ] && [ "$port_number" -eq "$port_number" ] 2>/dev/null; then
        sed -i "s/--bind 0.0.0.0:[0-9]\+/--bind 0.0.0.0:${port_number}/" "${SERVICE_FILE}"
        echo "Port set to: $port_number"
    else
        echo "Using default port: ${DEFAULT_PORT}"
        sed -i "s/--bind 0.0.0.0:[0-9]\+/--bind 0.0.0.0:${DEFAULT_PORT}/" "${SERVICE_FILE}"
    fi

    # Workers configuration
    DEFAULT_WORKERS="5"
    printf "Enter number of workers [default=${DEFAULT_WORKERS}]: "
    read -r workers

    if [ -n "$workers" ] && [ "$workers" -eq "$workers" ] 2>/dev/null; then
        sed -i "s/--workers [0-9]\+/--workers ${workers}/" "${SERVICE_FILE}"
        echo "Workers set to: $workers"
    else
        echo "Using default workers: ${DEFAULT_WORKERS}"
    fi

    # Threads configuration
    DEFAULT_THREADS="2"
    printf "Enter number of threads [default=${DEFAULT_THREADS}]: "
    read -r threads

    if [ -n "$threads" ] && [ "$threads" -eq "$threads" ] 2>/dev/null; then
        sed -i "s/--threads [0-9]\+/--threads ${threads}/" "${SERVICE_FILE}"
        echo "Threads set to: $threads"
    else
        echo "Using default threads: ${DEFAULT_THREADS}"
    fi
}

if [ "${1:-configure}" = "configure" ]; then
    # Configure service
    configure_service
    
    if [ -x "${SETUP}" ]; then
        echo "Running setup_ritapi.sh..."
        chmod +x "${SETUP}"
        cd "${APP_DIR}"
        "${SETUP}" setup
        echo "Setup completed."
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
    systemctl stop ritapi-guard || true
    systemctl disable ritapi-guard || true
fi
exit 0
EOF
chmod 755 "$DEBIAN_DIR/prerm"

# --- POSTRM ---
cat > "$DEBIAN_DIR/postrm" <<'EOF'
#!/bin/sh
set -e
APP_NAME="ritapi-guard"
APP_DIR="/opt/${APP_NAME}"
STAMP_DIR="/var/lib/${APP_NAME}"

if [ "$1" = "purge" ]; then
    # Remove systemd service
    rm -f /lib/systemd/system/${APP_NAME}.service
    systemctl daemon-reload

    # Remove application directory
    rm -rf "${APP_DIR}"
    
    # Remove stamp directory
    rm -rf "${STAMP_DIR}"
    
    # Remove any related files
    rm -rf /var/log/${APP_NAME}
    rm -rf /var/run/${APP_NAME}
    
    # Remove any remaining configuration
    rm -rf /etc/${APP_NAME}
    
    echo "Complete removal of ${APP_NAME} finished."
fi

exit 0
EOF
chmod 755 "$DEBIAN_DIR/postrm"

# --- SERVICE ---
cat > "$PKG_DIR/lib/systemd/system/ritapi-guard.service" <<EOF
[Unit]
Description=RitAPI guard Django Service
After=network.target postgresql.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/opt/ritapi-guard
ExecStart=/opt/ritapi-guard/venv/bin/gunicorn \\
  --workers 5 \
  --threads 2 \
  --timeout 60 \
  --keep-alive 30 \
  --bind 0.0.0.0:8008 \\
  ritapi_guard.wsgi:application
Restart=always
Environment="DJANGO_SETTINGS_MODULE=ritapi_guard.settings"
EnvironmentFile=-/opt/ritapi-guard/.env

[Install]
WantedBy=multi-user.target
EOF


echo "[*] Building Debian package..."
dpkg-deb --build "$PKG_DIR"

echo "[+] Done: $PKG_DIR.deb"
echo "[*] You can install it using: sudo dpkg -i $PKG_DIR.deb"