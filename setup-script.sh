#!/bin/bash

# SecureArch Platform Setup Script
# By Justin Weaver

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║               SecureArch Platform Setup Script                ║"
echo "║                     By Justin Weaver                          ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Check if running on supported OS
check_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]] || [[ "$OSTYPE" == "darwin"* ]]; then
        print_success "Operating system supported: $OSTYPE"
    else
        print_error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check Docker
    if command -v docker &> /dev/null; then
        print_success "Docker installed: $(docker --version)"
    else
        print_error "Docker not installed. Please install Docker first."
        exit 1
    fi
    
    # Check Docker Compose
    if command -v docker-compose &> /dev/null; then
        print_success "Docker Compose installed: $(docker-compose --version)"
    else
        print_error "Docker Compose not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check Git
    if command -v git &> /dev/null; then
        print_success "Git installed: $(git --version)"
    else
        print_error "Git not installed. Please install Git first."
        exit 1
    fi
    
    # Check Python
    if command -v python3 &> /dev/null; then
        print_success "Python installed: $(python3 --version)"
    else
        print_warning "Python not installed. Some features may not work."
    fi
    
    # Check Node.js
    if command -v node &> /dev/null; then
        print_success "Node.js installed: $(node --version)"
    else
        print_warning "Node.js not installed. Frontend development will require Node.js."
    fi
}

# Create necessary directories
create_directories() {
    print_status "Creating project directories..."
    
    directories=(
        "logs"
        "backups"
        "uploads"
        "infrastructure/nginx/ssl"
        "tests/performance"
        "tests/results"
        "models"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        print_success "Created directory: $dir"
    done
}

# Setup environment file
setup_environment() {
    print_status "Setting up environment configuration..."
    
    if [ -f .env ]; then
        print_warning ".env file already exists. Backing up to .env.backup"
        cp .env .env.backup
    fi
    
    # Copy example environment file
    cp .env.example .env
    
    # Generate secret keys
    print_status "Generating secure secret keys..."
    
    # Generate SECRET_KEY
    SECRET_KEY=$(openssl rand -hex 32)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/your-secret-key-here-generate-with-openssl-rand-hex-32/$SECRET_KEY/" .env
    else
        sed -i "s/your-secret-key-here-generate-with-openssl-rand-hex-32/$SECRET_KEY/" .env
    fi
    
    print_success "Environment file created with secure keys"
}

# Generate SSL certificates for local development
generate_ssl_certificates() {
    print_status "Generating self-signed SSL certificates for local development..."
    
    if [ -f infrastructure/nginx/ssl/securearch.crt ]; then
        print_warning "SSL certificates already exist. Skipping..."
    else
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout infrastructure/nginx/ssl/securearch.key \
            -out infrastructure/nginx/ssl/securearch.crt \
            -subj "/C=US/ST=Georgia/L=Atlanta/O=SecureArch/CN=localhost" \
            2>/dev/null
        
        print_success "SSL certificates generated"
    fi
}

# Initialize Git repository
init_git() {
    print_status "Initializing Git repository..."
    
    if [ -d .git ]; then
        print_warning "Git repository already initialized"
    else
        git init
        git add .
        git commit -m "Initial commit - SecureArch Platform" || true
        print_success "Git repository initialized"
    fi
}

# Install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."
    
    if command -v python3 &> /dev/null; then
        cd backend
        python3 -m venv venv || true
        
        if [ -f venv/bin/activate ]; then
            source venv/bin/activate
            pip install --upgrade pip
            pip install -r requirements.txt
            deactivate
            print_success "Python dependencies installed"
        else
            print_warning "Could not create Python virtual environment"
        fi
        cd ..
    else
        print_warning "Python not installed. Skipping Python dependencies."
    fi
}

# Install Node.js dependencies
install_node_deps() {
    print_status "Installing Node.js dependencies..."
    
    if command -v npm &> /dev/null; then
        cd frontend
        npm install
        print_success "Node.js dependencies installed"
        cd ..
    else
        print_warning "Node.js not installed. Skipping Node dependencies."
    fi
}

# Start Docker services
start_services() {
    print_status "Starting Docker services..."
    
    docker-compose up -d
    
    print_status "Waiting for services to be ready..."
    sleep 30
    
    # Check service health
    if curl -f http://localhost:8000/api/v1/health &> /dev/null; then
        print_success "Backend API is healthy"
    else
        print_warning "Backend API might not be ready yet"
    fi
    
    if curl -f http://localhost:3000 &> /dev/null; then
        print_success "Frontend is accessible"
    else
        print_warning "Frontend might not be ready yet"
    fi
    
    print_success "Services started"
}

# Run database migrations
run_migrations() {
    print_status "Running database migrations..."
    
    docker-compose exec backend alembic upgrade head || print_warning "Could not run migrations automatically"
    
    print_success "Database migrations completed"
}

# Create initial admin user
create_admin_user() {
    print_status "Creating initial admin user..."
    
    # This would typically be done through a management command
    # For now, we'll provide instructions
    print_warning "To create an admin user, run: docker-compose exec backend python create_admin.py"
}

# Display summary
display_summary() {
    echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║            SecureArch Platform Setup Complete! 🎉             ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}\n"
    
    echo -e "${BLUE}Access Points:${NC}"
    echo -e "  • Frontend:        ${GREEN}http://localhost:3000${NC}"
    echo -e "  • Backend API:     ${GREEN}http://localhost:8000${NC}"
    echo -e "  • API Docs:        ${GREEN}http://localhost:8000/docs${NC}"
    echo -e "  • Kibana:          ${GREEN}http://localhost:5601${NC}"
    echo -e "  • Grafana:         ${GREEN}http://localhost:3001${NC} (admin/admin)"
    echo -e "  • Prometheus:      ${GREEN}http://localhost:9090${NC}"
    
    echo -e "\n${BLUE}Useful Commands:${NC}"
    echo -e "  • View logs:       ${YELLOW}make logs${NC}"
    echo -e "  • Stop services:   ${YELLOW}make stop${NC}"
    echo -e "  • Run tests:       ${YELLOW}make test${NC}"
    echo -e "  • Security scan:   ${YELLOW}make security-scan${NC}"
    
    echo -e "\n${BLUE}Next Steps:${NC}"
    echo -e "  1. Create an admin user"
    echo -e "  2. Configure your security policies"
    echo -e "  3. Add assets to monitor"
    echo -e "  4. Run your first security scan"
    
    echo -e "\n${GREEN}Happy securing! 🔐${NC}\n"
}

# Main execution
main() {
    echo -e "${BLUE}Starting SecureArch Platform setup...${NC}\n"
    
    check_os
    check_prerequisites
    create_directories
    setup_environment
    generate_ssl_certificates
    init_git
    
    # Ask if user wants to install dependencies
    read -p "Install Python and Node.js dependencies? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_python_deps
        install_node_deps
    fi
    
    # Ask if user wants to start services
    read -p "Start Docker services now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        start_services
        run_migrations
        create_admin_user
        display_summary
    else
        echo -e "\n${YELLOW}To start services later, run: ${NC}make dev"
    fi
}

# Run main function
main