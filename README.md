# 🛡️ Dolutech Security Automate System (DSAS)

[![CI/CD Pipeline](https://github.com/dolutech/Dolutech-Security-Automate-System/actions/workflows/ci.yml/badge.svg)](https://github.com/dolutech/Dolutech-Security-Automate-System/actions)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Version](https://img.shields.io/badge/version-0.0.5-green.svg)](https://github.com/dolutech/Dolutech-Security-Automate-System)

[English](#english) | [Português](#português)

---

## Português

### 📋 Sobre o Projeto

O **Dolutech Security Automate System (DSAS)** é uma ferramenta de linha de comando projetada para simplificar e automatizar a administração de segurança em servidores Linux. Com uma interface intuitiva baseada em menus, o DSAS oferece gerenciamento abrangente de SSH, firewall, antivírus, pilha LAMP e muito mais.

### ✨ Recursos Principais

#### 🔐 Gerenciamento de SSH
- Alteração de porta SSH com validação
- Configuração de autenticação de dois fatores (2FA)
- Reinicialização segura do serviço SSH
- Avisos de segurança para portas críticas

#### 🛡️ Gerenciamento de Firewall
- Bloqueio/desbloqueio de portas com validação
- Bloqueio/desbloqueio de endereços IP (IPv4/IPv6)
- Liberação de portas específicas para IPs
- **Persistência automática de regras iptables**
- Visualização de regras ativas
- Limpeza segura de todas as regras

#### 🦠 Antivírus (ClamAV)
- Instalação automática do ClamAV
- Verificação completa do sistema
- Verificação personalizada de diretórios
- Atualização automática da base de dados

#### 🌐 Instalação LAMP
- Instalação completa do pacote LAMP
- Apache, MySQL, PHP 8.3, phpMyAdmin
- Configuração segura de senha MySQL
- Instalação modular de componentes individuais

#### 🔧 Administração do Sistema
- Alteração de hostname com validação
- Configuração de servidores DNS (IPv4/IPv6)
- Agendamento de tarefas de automação (cron)
- Visualização e limpeza de logs
- Reinicialização segura do servidor

### 🚀 Instalação

#### Método 1: Script de Instalação Automatizado (Recomendado)

```bash
# Baixar e executar o instalador
curl -fsSL https://raw.githubusercontent.com/dolutech/Dolutech-Security-Automate-System/main/install.sh | sudo bash
```

#### Método 2: Instalação Manual

```bash
# Clonar o repositório
git clone https://github.com/dolutech/Dolutech-Security-Automate-System.git
cd Dolutech-Security-Automate-System

# Executar instalador
sudo bash install.sh
```

### 📖 Uso

```bash
# Executar DSAS
sudo dsas
```

### 🔄 Atualização

O DSAS verifica automaticamente por atualizações ao iniciar. Para forçar uma atualização:

```bash
sudo dsas
# Selecione a opção: 12) Forçar Atualização do DSAS
```

### ⚙️ Configuração

O arquivo de configuração está localizado em `/etc/dsas/dsas.conf`:

```bash
# Editar configuração
sudo nano /etc/dsas/dsas.conf
```

Configurações disponíveis:
- Diretórios de instalação e logs
- Auto-atualização
- Requisitos de senha
- Comportamento do firewall
- Configurações do ClamAV
- Rotação de logs

### 🧪 Testes

Execute os testes automatizados:

```bash
# Instalar BATS
sudo apt-get install bats  # Debian/Ubuntu
sudo yum install bats      # RHEL/CentOS

# Executar testes
cd tests
bats *.bats
```

### 📁 Estrutura do Projeto

```
Dolutech-Security-Automate-System/
├── dsas.sh                 # Script principal
├── install.sh              # Script de instalação
├── dsas.conf.example       # Exemplo de configuração
├── version.txt             # Informação de versão
├── LICENSE.md              # Licença GPL v3
├── README.md               # Esta documentação
├── CHANGELOG.md            # Histórico de mudanças
├── .github/
│   └── workflows/
│       └── ci.yml          # Pipeline CI/CD
└── tests/
    ├── validation.bats     # Testes de validação
    └── README.md           # Documentação de testes
```

### 🔒 Recursos de Segurança

#### Validação de Entrada
- Validação de portas (1-65535)
- Validação de endereços IPv4 e IPv6
- Validação de hostname
- Prevenção de injeção de comandos em caminhos

#### Tratamento Seguro de Senhas
- Mínimo de 8 caracteres
- Senhas passadas via stdin (não visíveis no histórico de processos)
- Limpeza automática de senhas da memória

#### Proteção de Firewall
- Avisos para portas críticas (SSH)
- Persistência automática de regras
- Confirmação para operações destrutivas

#### Logging e Auditoria
- Registro timestamped de todas as operações
- Níveis de log (INFO, ERROR, SUCCESS)
- Rotação automática de logs

### 🤝 Contribuindo

Contribuições são bem-vindas! Por favor:

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

### 📝 Changelog

Veja [CHANGELOG.md](CHANGELOG.md) para um histórico completo de mudanças.

### 📄 Licença

Este projeto está licenciado sob a GNU General Public License v3.0 - veja [LICENSE.md](LICENSE.md) para detalhes.

### 🌐 Suporte

- Website: [https://dolutech.com](https://dolutech.com)
- GitHub Issues: [Reportar um problema](https://github.com/dolutech/Dolutech-Security-Automate-System/issues)

### 👥 Autores

- **Dolutech** - [GitHub](https://github.com/dolutech)

### 🙏 Agradecimentos

- Comunidade Open Source
- Contribuidores do projeto
- Usuários e testadores

---

## English

### 📋 About the Project

**Dolutech Security Automate System (DSAS)** is a command-line tool designed to simplify and automate security administration on Linux servers. With an intuitive menu-based interface, DSAS offers comprehensive management of SSH, firewall, antivirus, LAMP stack, and more.

### ✨ Key Features

#### 🔐 SSH Management
- SSH port change with validation
- Two-factor authentication (2FA) setup
- Secure SSH service restart
- Security warnings for critical ports

#### 🛡️ Firewall Management
- Block/unblock ports with validation
- Block/unblock IP addresses (IPv4/IPv6)
- Allow specific ports for IPs
- **Automatic iptables rules persistence**
- View active rules
- Safe clearing of all rules

#### 🦠 Antivirus (ClamAV)
- Automatic ClamAV installation
- Full system scan
- Custom directory scan
- Automatic database updates

#### 🌐 LAMP Installation
- Complete LAMP stack installation
- Apache, MySQL, PHP 8.3, phpMyAdmin
- Secure MySQL password configuration
- Modular installation of individual components

#### 🔧 System Administration
- Hostname change with validation
- DNS server configuration (IPv4/IPv6)
- Automation task scheduling (cron)
- Log viewing and clearing
- Safe server reboot

### 🚀 Installation

#### Method 1: Automated Installation Script (Recommended)

```bash
# Download and run installer
curl -fsSL https://raw.githubusercontent.com/dolutech/Dolutech-Security-Automate-System/main/install.sh | sudo bash
```

#### Method 2: Manual Installation

```bash
# Clone repository
git clone https://github.com/dolutech/Dolutech-Security-Automate-System.git
cd Dolutech-Security-Automate-System

# Run installer
sudo bash install.sh
```

### 📖 Usage

```bash
# Run DSAS
sudo dsas
```

### 🔄 Updates

DSAS automatically checks for updates on startup. To force an update:

```bash
sudo dsas
# Select option: 12) Force DSAS Update
```

### ⚙️ Configuration

Configuration file is located at `/etc/dsas/dsas.conf`:

```bash
# Edit configuration
sudo nano /etc/dsas/dsas.conf
```

Available settings:
- Installation and log directories
- Auto-update
- Password requirements
- Firewall behavior
- ClamAV settings
- Log rotation

### 🧪 Tests

Run automated tests:

```bash
# Install BATS
sudo apt-get install bats  # Debian/Ubuntu
sudo yum install bats      # RHEL/CentOS

# Run tests
cd tests
bats *.bats
```

### 📁 Project Structure

```
Dolutech-Security-Automate-System/
├── dsas.sh                 # Main script
├── install.sh              # Installation script
├── dsas.conf.example       # Configuration example
├── version.txt             # Version information
├── LICENSE.md              # GPL v3 License
├── README.md               # This documentation
├── CHANGELOG.md            # Change history
├── .github/
│   └── workflows/
│       └── ci.yml          # CI/CD pipeline
└── tests/
    ├── validation.bats     # Validation tests
    └── README.md           # Test documentation
```

### 🔒 Security Features

#### Input Validation
- Port validation (1-65535)
- IPv4 and IPv6 address validation
- Hostname validation
- Command injection prevention in paths

#### Secure Password Handling
- Minimum 8 characters
- Passwords passed via stdin (not visible in process history)
- Automatic password cleanup from memory

#### Firewall Protection
- Warnings for critical ports (SSH)
- Automatic rules persistence
- Confirmation for destructive operations

#### Logging and Auditing
- Timestamped logging of all operations
- Log levels (INFO, ERROR, SUCCESS)
- Automatic log rotation

### 🤝 Contributing

Contributions are welcome! Please:

1. Fork the project
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md) for a complete change history.

### 📄 License

This project is licensed under the GNU General Public License v3.0 - see [LICENSE.md](LICENSE.md) for details.

### 🌐 Support

- Website: [https://dolutech.com](https://dolutech.com)
- GitHub Issues: [Report an issue](https://github.com/dolutech/Dolutech-Security-Automate-System/issues)

### 👥 Authors

- **Dolutech** - [GitHub](https://github.com/dolutech)

### 🙏 Acknowledgments

- Open Source Community
- Project contributors
- Users and testers

---

**Made with ❤️ by Dolutech**
