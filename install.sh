#!/bin/bash

# Dolutech Security Automate System (DSAS) - Installation Script
# Version: 0.0.5
# This script safely installs DSAS with all necessary checks

set -e  # Exit on error
set -o pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Installation settings
INSTALL_DIR="/opt/DSAS"
BIN_LINK="/usr/local/bin/dsas"
CONFIG_DIR="/etc/dsas"
GITHUB_REPO="https://raw.githubusercontent.com/dolutech/Dolutech-Security-Automate-System/main"

# Print colored messages
print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_info() {
    echo -e "[i] $1"
}

# Check if running as root or with sudo
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Este script precisa ser executado como root ou com sudo"
        exit 1
    fi
    print_success "Verificacao de privilegios OK"
}

# Check system compatibility
check_system() {
    print_info "Verificando compatibilidade do sistema..."

    if [ -f /etc/debian_version ]; then
        DISTRO="debian"
        print_success "Sistema Debian/Ubuntu detectado"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
        print_success "Sistema RHEL/CentOS detectado"
    else
        print_error "Sistema operacional nao suportado"
        print_info "DSAS suporta apenas sistemas Debian/Ubuntu e RHEL/CentOS"
        exit 1
    fi
}

# Check for required commands
check_dependencies() {
    print_info "Verificando dependencias..."

    local missing_deps=()

    for cmd in curl wget systemctl; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done

    if [ ${#missing_deps[@]} -gt 0 ]; then
        print_error "Comandos faltando: ${missing_deps[*]}"
        print_info "Por favor, instale as dependencias necessarias"
        exit 1
    fi

    print_success "Todas as dependencias estao presentes"
}

# Backup existing installation
backup_existing() {
    if [ -d "$INSTALL_DIR" ]; then
        print_warning "Instalacao existente detectada em $INSTALL_DIR"
        local backup_dir="${INSTALL_DIR}.backup.$(date +%Y%m%d_%H%M%S)"

        read -p "Deseja fazer backup da instalacao existente? (s/n): " -n 1 -r
        echo

        if [[ $REPLY =~ ^[Ss]$ ]]; then
            print_info "Criando backup em $backup_dir..."
            cp -r "$INSTALL_DIR" "$backup_dir"
            print_success "Backup criado com sucesso"
        fi
    fi
}

# Create necessary directories
create_directories() {
    print_info "Criando diretorios necessarios..."

    mkdir -p "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR/logs"
    mkdir -p "$INSTALL_DIR/version"
    mkdir -p "$INSTALL_DIR/backups"
    mkdir -p "$CONFIG_DIR"

    print_success "Diretorios criados"
}

# Download and install main script
install_script() {
    print_info "Baixando script principal do DSAS..."

    local temp_file="/tmp/dsas.sh"

    if curl -fsSL "$GITHUB_REPO/dsas.sh" -o "$temp_file"; then
        # Verify the downloaded file is valid bash
        if bash -n "$temp_file" 2>/dev/null; then
            mv "$temp_file" "$INSTALL_DIR/dsas.sh"
            chmod +x "$INSTALL_DIR/dsas.sh"
            print_success "Script principal instalado"
        else
            print_error "Script baixado esta corrompido ou invalido"
            rm -f "$temp_file"
            exit 1
        fi
    else
        print_error "Falha ao baixar script do GitHub"
        exit 1
    fi
}

# Download version file
install_version() {
    print_info "Baixando arquivo de versao..."

    if curl -fsSL "$GITHUB_REPO/version.txt" -o "$INSTALL_DIR/version/version.txt"; then
        print_success "Arquivo de versao instalado"
    else
        print_warning "Falha ao baixar arquivo de versao (continuando...)"
    fi
}

# Install configuration file
install_config() {
    print_info "Instalando arquivo de configuracao..."

    if [ ! -f "$CONFIG_DIR/dsas.conf" ]; then
        if curl -fsSL "$GITHUB_REPO/dsas.conf.example" -o "$CONFIG_DIR/dsas.conf"; then
            print_success "Arquivo de configuracao instalado"
        else
            print_warning "Falha ao baixar arquivo de configuracao (continuando...)"
        fi
    else
        print_info "Arquivo de configuracao ja existe, mantendo versao atual"
    fi
}

# Create symlink
create_symlink() {
    print_info "Criando link simbolico em $BIN_LINK..."

    if [ -L "$BIN_LINK" ]; then
        rm -f "$BIN_LINK"
    fi

    ln -sf "$INSTALL_DIR/dsas.sh" "$BIN_LINK"
    print_success "Link simbolico criado"
}

# Set proper permissions
set_permissions() {
    print_info "Configurando permissoes..."

    chown -R root:root "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR/dsas.sh"
    chmod 644 "$INSTALL_DIR/version/version.txt" 2>/dev/null || true

    print_success "Permissoes configuradas"
}

# Display completion message
show_completion() {
    echo ""
    echo "============================================"
    print_success "DSAS instalado com sucesso!"
    echo "============================================"
    echo ""
    print_info "Para executar o DSAS, digite: dsas"
    print_info "Localizacao da instalacao: $INSTALL_DIR"
    print_info "Arquivo de configuracao: $CONFIG_DIR/dsas.conf"
    print_info "Logs: $INSTALL_DIR/logs/dsas.log"
    echo ""
    print_warning "IMPORTANTE: Recomendamos revisar o arquivo de configuracao antes do primeiro uso"
    echo ""
}

# Main installation flow
main() {
    echo "============================================"
    echo " DSAS - Instalador"
    echo " Dolutech Security Automate System"
    echo "============================================"
    echo ""

    check_root
    check_system
    check_dependencies
    backup_existing
    create_directories
    install_script
    install_version
    install_config
    create_symlink
    set_permissions
    show_completion
}

# Run main installation
main
