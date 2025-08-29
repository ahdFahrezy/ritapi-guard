#!/bin/bash

# RitAPI Advance Setup Script
# This script sets up and runs the RitAPI Advance Django project

set -e  # Exit on any error

APP_NAME="ritapi-advance"
APP_DIR="/opt/${APP_NAME}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check Python version
check_python_version() {
    if command_exists python3; then
        PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
        PYTHON_CMD="python3"
    elif command_exists python; then
        PYTHON_VERSION=$(python --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
        PYTHON_CMD="python"
    else
        print_error "Python is not installed. Please install Python 3.8 or higher."
        exit 1
    fi
    
    # Check if Python version is 3.8 or higher
    if [[ $(echo "$PYTHON_VERSION >= 3.8" | bc -l 2>/dev/null) -eq 1 ]] || [[ "$PYTHON_VERSION" == "3.8"* ]] || [[ "$PYTHON_VERSION" == "3.9"* ]] || [[ "$PYTHON_VERSION" == "3.10"* ]] || [[ "$PYTHON_VERSION" == "3.11"* ]] || [[ "$PYTHON_VERSION" == "3.12"* ]]; then
        print_success "Python $PYTHON_VERSION found"
    else
        print_error "Python $PYTHON_VERSION found, but Python 3.8 or higher is required"
        exit 1
    fi
}

# Function to check if virtual environment exists
check_venv() {
    if [[ -d "venv" ]]; then
        print_status "Virtual environment found"
        return 0
    else
        print_status "Virtual environment not found, will create one"
        return 1
    fi
}

# Function to create virtual environment
create_venv() {
    print_status "Creating virtual environment..."
    $PYTHON_CMD -m venv venv
    print_success "Virtual environment created"
}

# Function to activate virtual environment
activate_venv() {
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        # Windows
        source venv/Scripts/activate
    else
        # Linux/Mac
        source venv/bin/activate
    fi
    print_success "Virtual environment activated"
}

# Function to install dependencies
install_dependencies() {
    print_status "Installing Python dependencies..."
    
    # Upgrade pip
    $PYTHON_CMD -m pip install --upgrade pip
    
    # Install requirements
    if [[ -f "requirements.txt" ]]; then
        $PYTHON_CMD -m pip install -r requirements.txt
        print_success "Dependencies installed from requirements.txt"
    else
        print_error "requirements.txt not found"
        exit 1
    fi
}

# Function to check database
check_database() {
    print_status "Checking PostgreSQL database..."
    
    DB_NAME=${POSTGRES_DB:-ritapi_advance_test_2}
    DB_USER=${POSTGRES_USER:-postgres}
    DB_HOST=${POSTGRES_HOST:-127.0.0.1}
    DB_PORT=${POSTGRES_PORT:-5432}
    DB_PASS=${POSTGRES_PASSWORD:-admin}

    if ! command_exists psql; then
        print_error "psql command not found. Please install PostgreSQL client tools."
        exit 1
    fi

    # Cek apakah bisa connect ke PostgreSQL
    if PGPASSWORD=$DB_PASS psql -U "$DB_USER" -h "$DB_HOST" -p "$DB_PORT" -lqt 2>/dev/null | cut -d \| -f1 | grep -qw "$DB_NAME"; then
        print_status "PostgreSQL database '$DB_NAME' found"
    else
        print_warning "PostgreSQL database '$DB_NAME' not found, creating..."
        if PGPASSWORD=$DB_PASS createdb -U "$DB_USER" -h "$DB_HOST" -p "$DB_PORT" "$DB_NAME" 2>/dev/null; then
            print_success "PostgreSQL database '$DB_NAME' created"
        else
            print_error "Failed to create database '$DB_NAME'. Please check PostgreSQL user/password/permissions."
            exit 1
        fi
    fi
}

# Function to run database migrations
run_migrations() {
    print_status "Running database migrations..."
    $PYTHON_CMD manage.py makemigrations
    $PYTHON_CMD manage.py migrate
    print_success "Database migrations completed"
}

# Function to create superuser
create_superuser() {
    print_status "Checking if superuser exists..."
    
    # Check if superuser exists
    if $PYTHON_CMD manage.py shell -c "from django.contrib.auth import get_user_model; User = get_user_model(); print('Superuser exists' if User.objects.filter(is_superuser=True).exists() else 'No superuser found')" 2>/dev/null | grep -q "Superuser exists"; then
        print_status "Superuser already exists"
    else
        print_warning "No superuser found. Creating default superuser: admin/admin"
        $PYTHON_CMD manage.py shell -c "
from django.contrib.auth import get_user_model;
User = get_user_model();
User.objects.create_superuser('admin', 'admin@example.com', 'admin')
"
    fi
}

# Function to collect static files
collect_static() {
    print_status "Collecting static files..."
    $PYTHON_CMD manage.py collectstatic --noinput
    print_success "Static files collected"
}

# Setup logs directory
setup_logs() {
    print_status "Setting up logs directory..."
    LOG_DIR="$APP_DIR/logs"

    sudo mkdir -p "$LOG_DIR"
    LOG_FILES=("cron_ai.log" "decision_engine.log" "tls_analyzer.log" "train_iforest.log")

    for LOGFILE in "${LOG_FILES[@]}"; do
        sudo touch "$LOG_DIR/$LOGFILE"
    done

    OWNER=www-data
    sudo chown -R "$OWNER:$OWNER" "$LOG_DIR"
    sudo chmod 664 "$LOG_DIR"/*.log

    print_success "Logs directory ready at $LOG_DIR"
}

# Function to check environment file
check_env_file() {
    if [[ ! -f ".env" ]]; then
        print_status "Creating .env file from template..."
        cat > .env << EOF
# Django Settings
SECRET_KEY=your-secret-key-here-change-in-production
DEBUG=1
ALLOWED_HOSTS=127.0.0.1,localhost
ALLOW_IPS=127.0.0.1
DJANGO_ENV=prod

# Database (for production, uncomment and configure PostgreSQL)
# DATABASE_URL=postgres://postgres:@localhost:5432/ritapi_advance
POSTGRES_DB=ritapi_advance_test_2
POSTGRES_USER=postgres
POSTGRES_PASSWORD=admin
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
MAX_SERVICES=10

# Security
# CSRF_TRUSTED_ORIGINS=https://yourdomain.com
# SECURE_SSL_REDIRECT=False
# SESSION_COOKIE_SECURE=False
# CSRF_COOKIE_SECURE=False
EOF
        print_success ".env file created. Please review and update the values."
    else
        print_status ".env file already exists"
    fi
}

find_free_port() {
    local PORT=8000
    while ss -tuln | grep -q ":$PORT "; do
        ((PORT++))
    done
    echo $PORT
}

# Function to run development server
run_dev_server() {
    PORT=$(find_free_port)
    print_status "Starting Django development server..."
    print_status "Server will be available at: http://127.0.0.1:$PORT"
    print_status "Press Ctrl+C to stop the server"
    
    $PYTHON_CMD manage.py runserver 127.0.0.1:$PORT
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  setup     - Set up the project (install dependencies, run migrations)"
    echo "  run       - Run the development server"
    echo "  full      - Full setup and run (setup + run server)"
    echo "  help      - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 setup    # Only setup the project"
    echo "  $0 run      # Only run the server (assumes setup is done)"
    echo "  $0 full     # Setup and run the server"
}

# Main function
main() {
    case "${1:-full}" in
        "setup")
            print_status "Starting RitAPI Advance setup..."
            check_python_version
            if ! check_venv; then
                create_venv
            fi
            activate_venv
            install_dependencies
            check_env_file
            check_database
            setup_logs
            run_migrations
            create_superuser
            collect_static
            print_success "Setup completed successfully!"
            ;;
        "run")
            print_status "Starting RitAPI Advance..."
            check_python_version
            if ! check_venv; then
                print_error "Virtual environment not found. Please run setup first: $0 setup"
                exit 1
            fi
            activate_venv
            run_dev_server
            ;;
        "full")
            print_status "Starting full RitAPI Advance setup and run..."
            check_python_version
            if ! check_venv; then
                create_venv
            fi
            activate_venv
            install_dependencies
            check_env_file
            check_database
            setup_logs
            run_migrations
            create_superuser
            collect_static
            print_success "Setup completed successfully!"
            echo ""
            run_dev_server
            ;;
        "help"|"-h"|"--help")
            show_usage
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
}

# Check if script is run from the correct directory
if [[ ! -f "manage.py" ]]; then
    print_error "This script must be run from the project root directory (where manage.py is located)"
    exit 1
fi

# Run main function with all arguments
main "$@"
