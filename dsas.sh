#!/bin/bash

# Enable error handling
set -o pipefail

# Nome e versao do sistema
SYSTEM_NAME="Dolutech Security Automate System (DSAS)"
VERSION="0.0.5"
DSAS_DIR="/opt/DSAS"
LOG_DIR="$DSAS_DIR/logs"
VERSION_DIR="$DSAS_DIR/version"
LOG_FILE="$LOG_DIR/dsas.log"
VERSION_FILE="$VERSION_DIR/version.txt"
SCRIPT_NAME="dsas.sh"
SCRIPT_PATH="$DSAS_DIR/$SCRIPT_NAME"
GITHUB_REPO_RAW="https://raw.githubusercontent.com/dolutech/Dolutech-Security-Automate-System/main"

# Funcoes de validacao de entrada

# Valida numero de porta (1-65535)
validate_port() {
    local port=$1
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        return 1
    fi
    return 0
}

# Valida endereco IPv4
validate_ipv4() {
    local ip=$1
    local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'

    if [[ ! $ip =~ $regex ]]; then
        return 1
    fi

    # Verificar se cada octeto esta entre 0-255
    IFS='.' read -ra OCTETS <<< "$ip"
    for octet in "${OCTETS[@]}"; do
        if [ "$octet" -gt 255 ]; then
            return 1
        fi
    done
    return 0
}

# Valida endereco IPv6
validate_ipv6() {
    local ip=$1
    # Regex simples para IPv6
    local regex='^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'

    if [[ $ip =~ $regex ]]; then
        return 0
    fi
    return 1
}

# Valida caminho de arquivo/diretorio
validate_path() {
    local path=$1
    # Impedir caracteres perigosos em caminhos
    if [[ "$path" =~ [;\|\&\$\`] ]]; then
        return 1
    fi
    return 0
}

# Valida hostname
validate_hostname() {
    local hostname=$1
    local regex='^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'

    if [[ $hostname =~ $regex ]]; then
        return 0
    fi
    return 1
}

# Funcao para log de erro
log_error() {
    local message="$1"
    echo "[ERRO $(date '+%Y-%m-%d %H:%M:%S')] $message" | tee -a $LOG_FILE >&2
}

# Funcao para log de informacao
log_info() {
    local message="$1"
    echo "[INFO $(date '+%Y-%m-%d %H:%M:%S')] $message" | tee -a $LOG_FILE
}

# Funcao para log de sucesso
log_success() {
    local message="$1"
    echo "[SUCESSO $(date '+%Y-%m-%d %H:%M:%S')] $message" | tee -a $LOG_FILE
}

# Funcao para verificar se comando foi bem-sucedido
check_command() {
    if [ $? -ne 0 ]; then
        log_error "$1"
        return 1
    fi
    return 0
}

# Funcao para detectar a distribuicao
detect_distro() {
    if [ -f /etc/debian_version ]; then
        DISTRO="debian"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
    else
        echo "Sistema operacional nao suportado." | tee -a $LOG_FILE
        exit 1
    fi
}

# Funcao para garantir que o script pode ser executado de qualquer lugar
setup_path() {
    ln -sf $SCRIPT_PATH /usr/local/bin/dsas
}

# Funcao para criar o diretorio do sistema e os arquivos necessarios
setup_environment() {
    if [ ! -d "$DSAS_DIR" ]; then
        mkdir -p $DSAS_DIR
    fi

    if [ ! -d "$LOG_DIR" ]; then
        mkdir -p $LOG_DIR
    fi

    if [ ! -d "$VERSION_DIR" ]; then
        mkdir -p $VERSION_DIR
    fi

    if [ ! -f "$LOG_FILE" ]; then
        touch $LOG_FILE
    fi

    if [ ! -f "$SCRIPT_PATH" ]; then
        mv "$0" "$SCRIPT_PATH"
    fi

    if [ ! -f "$VERSION_FILE" ]; then
        curl -o "$VERSION_FILE" "$GITHUB_REPO_RAW/version.txt"
    fi
}

# Funcao para verificar e baixar a versao mais recente do script
check_for_updates() {
    local new_version_file="/tmp/version.txt"
    curl -o "$new_version_file" "$GITHUB_REPO_RAW/version.txt"

    if ! diff "$VERSION_FILE" "$new_version_file" > /dev/null; then
        echo "Foi encontrada uma nova versao do Dolutech Security Automate System. Iremos efetuar a atualizacao."
        read -p "Pressione Enter para atualizar..."

        # Baixar o novo script
        curl -o "$SCRIPT_PATH" "$GITHUB_REPO_RAW/$SCRIPT_NAME"

        # Dar permissao de execucao ao novo script
        chmod +x "$SCRIPT_PATH"

        # Substituir o arquivo version.txt
        mv "$new_version_file" "$VERSION_FILE"

        # Reiniciar o script
        exec "$SCRIPT_PATH"
    else
        rm "$new_version_file"
    fi
}

# Funcao para forcar a atualizacao do DSAS
force_update() {
    echo "Forcando atualizacao do DSAS..."
    curl -o "$SCRIPT_PATH" "$GITHUB_REPO_RAW/$SCRIPT_NAME"
    chmod +x "$SCRIPT_PATH"
    echo "Atualizacao concluida. Reiniciando o script..."
    exec "$SCRIPT_PATH"
}

# Funcao para instalar ClamAV
install_clamav() {
    echo "Verificando instalacao do ClamAV..." | tee -a $LOG_FILE
    if ! command -v clamscan &> /dev/null; then
        echo "ClamAV nao encontrado, instalando..." | tee -a $LOG_FILE
        if [ "$DISTRO" = "debian" ]; then
            sudo apt-get update && sudo apt-get install -y clamav clamav-daemon
        elif [ "$DISTRO" = "rhel" ]; then
            sudo yum install -y epel-release && sudo yum install -y clamav clamav-update
        fi
    else
        echo "ClamAV ja esta instalado." | tee -a $LOG_FILE
    fi
}

# Funcao para alterar a porta SSH
change_ssh_port() {
    read -p "Digite a nova porta SSH: " new_port

    # Validar porta
    if ! validate_port "$new_port"; then
        log_error "Porta invalida. Por favor, digite um numero entre 1 e 65535."
        read -p "Pressione Enter para voltar ao menu..."
        return 1
    fi

    # Avisar sobre portas bem conhecidas
    if [ "$new_port" -lt 1024 ] && [ "$new_port" -ne 22 ]; then
        echo "AVISO: Porta $new_port esta na faixa de portas privilegiadas (1-1023)."
        read -p "Tem certeza que deseja continuar? (s/n): " confirm
        if [[ ! $confirm =~ ^[Ss]$ ]]; then
            log_info "Alteracao de porta SSH cancelada pelo usuario."
            read -p "Pressione Enter para voltar ao menu..."
            return 0
        fi
    fi

    log_info "Alterando porta SSH para $new_port"

    # Substituindo a linha Port independentemente do valor atual
    if grep -q "^#Port" /etc/ssh/sshd_config; then
        sudo sed -i "s/^#Port.*/Port $new_port/" /etc/ssh/sshd_config
    elif grep -q "^Port" /etc/ssh/sshd_config; then
        sudo sed -i "s/^Port.*/Port $new_port/" /etc/ssh/sshd_config
    else
        echo "Port $new_port" | sudo tee -a /etc/ssh/sshd_config > /dev/null
    fi

    if check_command "Erro ao alterar porta SSH"; then
        log_success "Porta SSH alterada com sucesso para $new_port."
        restart_ssh
    fi
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para configurar 2FA no SSH
setup_2fa() {
    sudo apt-get install -y libpam-google-authenticator
    echo "Iniciando a configuracao do 2FA..."
    sudo google-authenticator

    # Verifica se a linha do 2FA ja existe no arquivo pam.d/sshd
    if ! grep -q "auth required pam_google_authenticator.so" /etc/pam.d/sshd; then
        sudo sed -i '/@include common-auth/a auth required pam_google_authenticator.so' /etc/pam.d/sshd
        echo "Configuracao do 2FA adicionada no arquivo /etc/pam.d/sshd." | tee -a $LOG_FILE
    else
        echo "Configuracao do 2FA ja estava presente no arquivo /etc/pam.d/sshd." | tee -a $LOG_FILE
    fi

    # Adicionando ou substituindo a linha ChallengeResponseAuthentication no sshd_config
    if grep -q "^# Change to yes to enable challenge-response passwords" /etc/ssh/sshd_config; then
        sudo sed -i "/^# Change to yes to enable challenge-response passwords/a ChallengeResponseAuthentication yes" /etc/ssh/sshd_config
    elif grep -q "^ChallengeResponseAuthentication" /etc/ssh/sshd_config; then
        sudo sed -i "s/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/" /etc/ssh/sshd_config
    else
        echo "ChallengeResponseAuthentication yes" | sudo tee -a /etc/ssh/sshd_config
    fi

    # Comentando a linha KbdInteractiveAuthentication
    if grep -q "^KbdInteractiveAuthentication" /etc/ssh/sshd_config; then
        sudo sed -i "s/^KbdInteractiveAuthentication.*/#&/" /etc/ssh/sshd_config
    fi

    echo "Configuracao do 2FA concluida com sucesso." | tee -a $LOG_FILE
    restart_ssh
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para remover 2FA do SSH
remove_2fa() {
    echo "Removendo configuracoes do 2FA..."

    # Removendo a linha do 2FA no arquivo pam.d/sshd
    sudo sed -i '/auth required pam_google_authenticator.so/d' /etc/pam.d/sshd

    # Revertendo a linha ChallengeResponseAuthentication para no
    if grep -q "^ChallengeResponseAuthentication yes" /etc/ssh/sshd_config; then
        sudo sed -i "s/^ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/" /etc/ssh/sshd_config
    fi

    # Desinstalando o google-authenticator
    if [ "$DISTRO" = "debian" ]; then
        sudo apt-get remove --purge -y libpam-google-authenticator
    elif [ "$DISTRO" = "rhel" ]; then
        sudo yum remove -y google-authenticator
    fi

    echo "2FA removido com sucesso." | tee -a $LOG_FILE
    restart_ssh
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para corrigir CVEs
fix_cve_menu() {
    clear
    echo "============================================"
    echo " Correcao de CVEs"
    echo "============================================"
    echo "Em breve disponibilizaremos diversas correcoes de CVE no nosso sistema."
    echo "============================================"
    echo "1) Voltar ao Menu Principal"
    echo "============================================"
    read -p "Escolha uma opcao: " cve_option

    case $cve_option in
        1) return ;;
        *) echo "Opcao invalida. Tente novamente." ;;
    esac
}

# Funcao para alterar o hostname do servidor
change_hostname() {
    read -p "Digite o novo hostname do servidor: " new_hostname

    # Validar hostname
    if ! validate_hostname "$new_hostname"; then
        log_error "Hostname invalido. Use apenas letras, numeros e hifens."
        read -p "Pressione Enter para voltar ao menu..."
        return 1
    fi

    local old_hostname
    old_hostname=$(hostname)

    log_info "Alterando hostname de '$old_hostname' para '$new_hostname'"

    # Alterando o hostname atual
    sudo hostnamectl set-hostname "$new_hostname"
    if ! check_command "Erro ao alterar hostname"; then
        read -p "Pressione Enter para voltar ao menu..."
        return 1
    fi

    # Alterando o hostname no arquivo /etc/hosts de forma segura
    sudo sed -i "s/\b${old_hostname}\b/${new_hostname}/g" /etc/hosts

    log_success "Hostname alterado com sucesso para $new_hostname."
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para alterar servidores DNS
change_dns() {
    while true; do
        clear
        echo "============================================"
        echo " Alterar Servidores DNS"
        echo "============================================"
        echo "1) DNS IPv4"
        echo "2) DNS IPv6"
        echo "3) Voltar ao Menu Principal"
        echo "============================================"
        read -p "Escolha uma opcao: " dns_option

        case $dns_option in
            1) configure_dns "IPv4" ;;
            2) configure_dns "IPv6" ;;
            3) return ;;
            *) echo "Opcao invalida. Tente novamente." ;;
        esac
    done
}

# Funcao para configurar servidores DNS
configure_dns() {
    local dns_type=$1
    local dns_file

    if [ "$dns_type" = "IPv4" ]; then
        dns_file="/etc/resolv.conf"
    else
        dns_file="/etc/resolv.conf"
    fi

    echo "Configurando servidores DNS $dns_type..."
    for i in {1..3}; do
        read -p "Digite o endereco DNS $dns_type ($i): " dns_address
        if [ -n "$dns_address" ]; then
            echo "nameserver $dns_address" | sudo tee -a $dns_file
        fi
    done

    echo "Servidores DNS $dns_type configurados com sucesso." | tee -a $LOG_FILE
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para agendar rotina de automacao
schedule_automation() {
    read -p "Digite o comando da rotina de automacao que deseja agendar: " automation_command

    echo "Com que frequencia deseja executar esta rotina?"
    echo "1) A cada X minutos"
    echo "2) A cada X horas"
    echo "3) A cada X dias"
    read -p "Escolha uma opcao: " schedule_option

    case $schedule_option in
        1) 
            read -p "Digite o intervalo em minutos: " interval
            cron_time="*/$interval * * * *"
            ;;
        2) 
            read -p "Digite o intervalo em horas: " interval
            cron_time="0 */$interval * * *"
            ;;
        3) 
            read -p "Digite o intervalo em dias: " interval
            cron_time="0 0 */$interval * *"
            ;;
        *) 
            echo "Opcao invalida. Retornando ao menu principal."
            return
            ;;
    esac

    # Adiciona a rotina ao crontab
    (crontab -l 2>/dev/null; echo "$cron_time $automation_command") | crontab -
    echo "Rotina de automacao agendada com sucesso." | tee -a $LOG_FILE
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para verificar e gerenciar agendamentos de automacao
view_automation_schedule() {
    crontab -l > /tmp/current_cron
    if [ ! -s /tmp/current_cron ]; then
        echo "Nao ha agendamentos de automacao no momento." | tee -a $LOG_FILE
    else
        echo "Agendamentos de automacao atuais:"
        nl -s ") " /tmp/current_cron
        read -p "Deseja remover algum agendamento (s/n)? " remove_option

        if [[ $remove_option =~ ^[Ss]$ ]]; then
            read -p "Digite o numero do agendamento que deseja remover: " line_number
            sed -i "${line_number}d" /tmp/current_cron
            crontab /tmp/current_cron
            echo "Agendamento removido com sucesso." | tee -a $LOG_FILE
        else
            echo "Nenhum agendamento foi removido." | tee -a $LOG_FILE
        fi
    fi
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para reiniciar o SSH
restart_ssh() {
    if [ "$DISTRO" = "debian" ]; then
        sudo systemctl restart ssh
    elif [ "$DISTRO" = "rhel" ]; then
        sudo systemctl restart sshd
    fi
    
    if [ $? -eq 0 ]; then
        echo "Servico SSH reiniciado com sucesso." | tee -a $LOG_FILE
    else
        echo "Erro ao reiniciar o servico SSH." | tee -a $LOG_FILE
    fi
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para reiniciar o servidor
reboot_server() {
    read -p "Tem certeza que deseja reiniciar o servidor? (s/n): " confirm
    if [[ $confirm =~ ^[Ss]$ ]]; then
        read -p "Pressione Enter novamente para confirmar o reinicio do servidor..."
        sudo reboot
    else
        echo "Reinicio do servidor cancelado." | tee -a $LOG_FILE
        read -p "Pressione Enter para voltar ao menu..."
    fi
}

# Funcao para bloquear porta no servidor
block_port() {
    read -p "Digite a porta que deseja bloquear: " port

    # Validar porta
    if ! validate_port "$port"; then
        log_error "Porta invalida. Por favor, digite um numero entre 1 e 65535."
        read -p "Pressione Enter para voltar ao menu..."
        return 1
    fi

    # Avisar sobre portas criticas
    if [ "$port" -eq 22 ] || [ "$port" -eq "$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')" ]; then
        echo "AVISO: Bloquear a porta SSH pode resultar em perda de acesso remoto!"
        read -p "Tem certeza que deseja continuar? (s/n): " confirm
        if [[ ! $confirm =~ ^[Ss]$ ]]; then
            log_info "Bloqueio de porta $port cancelado pelo usuario."
            read -p "Pressione Enter para voltar ao menu..."
            return 0
        fi
    fi

    log_info "Bloqueando porta $port"
    sudo iptables -A INPUT -p tcp --dport "$port" -j DROP

    if check_command "Erro ao bloquear porta"; then
        log_success "Porta $port bloqueada com sucesso."
        save_iptables_rules
    fi
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para desbloquear porta no servidor
unblock_port() {
    sudo iptables -L INPUT -v -n --line-numbers | grep DROP
    read -p "Digite o numero da linha que deseja desbloquear: " line
    sudo iptables -D INPUT $line
    echo "Porta desbloqueada com sucesso." | tee -a $LOG_FILE
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para bloquear IP
block_ip() {
    read -p "Digite o IP que deseja bloquear: " ip

    # Validar IP (IPv4 ou IPv6)
    if ! validate_ipv4 "$ip" && ! validate_ipv6 "$ip"; then
        log_error "Endereco IP invalido."
        read -p "Pressione Enter para voltar ao menu..."
        return 1
    fi

    log_info "Bloqueando IP $ip"
    sudo iptables -A INPUT -s "$ip" -j DROP

    if check_command "Erro ao bloquear IP"; then
        log_success "IP $ip bloqueado com sucesso."
        save_iptables_rules
    fi
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para desbloquear IP
unblock_ip() {
    sudo iptables -L INPUT -v -n --line-numbers | grep DROP
    read -p "Digite o numero da linha que deseja desbloquear: " line
    sudo iptables -D INPUT $line
    echo "IP desbloqueado com sucesso." | tee -a $LOG_FILE
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para liberar porta para IP especifico
allow_ip_port() {
    read -p "Digite o IP que deseja liberar: " ip

    # Validar IP
    if ! validate_ipv4 "$ip" && ! validate_ipv6 "$ip"; then
        log_error "Endereco IP invalido."
        read -p "Pressione Enter para voltar ao menu..."
        return 1
    fi

    read -p "Digite a porta que deseja liberar: " port

    # Validar porta
    if ! validate_port "$port"; then
        log_error "Porta invalida. Por favor, digite um numero entre 1 e 65535."
        read -p "Pressione Enter para voltar ao menu..."
        return 1
    fi

    log_info "Liberando porta $port para IP $ip"
    sudo iptables -A INPUT -p tcp -s "$ip" --dport "$port" -j ACCEPT

    if check_command "Erro ao liberar porta para IP"; then
        log_success "Porta $port liberada para o IP $ip."
        save_iptables_rules
    fi
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para remover liberacao de porta para IP especifico
remove_allow_ip_port() {
    sudo iptables -L INPUT -v -n --line-numbers | grep ACCEPT
    read -p "Digite o numero da linha que deseja remover: " line
    sudo iptables -D INPUT $line
    echo "Liberacao de porta removida com sucesso." | tee -a $LOG_FILE
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para salvar regras do iptables
save_iptables_rules() {
    log_info "Salvando regras do iptables..."

    if [ "$DISTRO" = "debian" ]; then
        # Instalar iptables-persistent se necessario
        if ! dpkg -l | grep -q iptables-persistent; then
            echo "Instalando iptables-persistent para persistir regras..."
            echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
            echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
            sudo apt-get install -y iptables-persistent
        fi
        sudo netfilter-persistent save
    elif [ "$DISTRO" = "rhel" ]; then
        sudo service iptables save
    fi

    if check_command "Erro ao salvar regras do iptables"; then
        log_success "Regras do iptables salvas com sucesso."
    fi
}

# Funcao para limpar todas as regras do IPTables
clear_all_rules() {
    read -p "Tem certeza que deseja limpar TODAS as regras do iptables? (s/n): " confirm
    if [[ ! $confirm =~ ^[Ss]$ ]]; then
        log_info "Limpeza de regras cancelada pelo usuario."
        read -p "Pressione Enter para voltar ao menu..."
        return 0
    fi

    log_info "Limpando todas as regras do iptables"
    sudo iptables -F
    sudo iptables -X
    sudo iptables -t nat -F
    sudo iptables -t nat -X
    sudo iptables -t mangle -F
    sudo iptables -t mangle -X

    if check_command "Erro ao limpar regras"; then
        log_success "Todas as regras do IPTables foram limpas."
        save_iptables_rules
    fi
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para visualizar logs do sistema
view_logs() {
    clear
    echo "============================================"
    echo " Visualizacao de Logs do Sistema"
    echo "============================================"
    echo ""

    if [ ! -f "$LOG_FILE" ]; then
        echo "Arquivo de log nao encontrado." | tee -a $LOG_FILE
        read -p "Pressione Enter para voltar ao menu..."
        return
    fi

    echo "Ultimas 50 linhas do log do DSAS:"
    echo "============================================"
    tail -n 50 "$LOG_FILE"
    echo "============================================"
    echo ""
    echo "Para ver o log completo, acesse: $LOG_FILE"
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para limpar logs do sistema
clear_logs() {
    clear
    echo "============================================"
    echo " Limpeza de Logs do Sistema"
    echo "============================================"

    read -p "Tem certeza que deseja limpar todos os logs? (s/n): " confirm
    if [[ $confirm =~ ^[Ss]$ ]]; then
        if [ -f "$LOG_FILE" ]; then
            echo "Limpando logs do DSAS..." | tee -a $LOG_FILE
            > "$LOG_FILE"
            echo "Logs limpos com sucesso em $(date)" | tee -a $LOG_FILE
        else
            echo "Arquivo de log nao encontrado."
        fi
    else
        echo "Limpeza de logs cancelada." | tee -a $LOG_FILE
    fi
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para fazer verificacao completa do antivirus
full_scan() {
    clear
    echo "============================================"
    echo " Verificacao Completa do Antivirus"
    echo "============================================"
    echo ""

    # Atualizar base de dados do ClamAV
    echo "Atualizando base de dados do ClamAV..." | tee -a $LOG_FILE
    sudo freshclam

    echo ""
    echo "Iniciando verificacao completa do sistema..."
    echo "AVISO: Esta operacao pode levar muito tempo."
    echo "Os resultados serao salvos em: $LOG_DIR/clamav_full_scan.log"
    echo ""

    read -p "Pressione Enter para iniciar a verificacao..."

    # Executar scan completo
    sudo clamscan -r -i --log="$LOG_DIR/clamav_full_scan.log" / 2>&1 | tee -a $LOG_FILE

    echo ""
    echo "Verificacao completa concluida." | tee -a $LOG_FILE
    echo "Resultados salvos em: $LOG_DIR/clamav_full_scan.log"
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para fazer verificacao personalizada do antivirus
custom_scan() {
    clear
    echo "============================================"
    echo " Verificacao Personalizada do Antivirus"
    echo "============================================"
    echo ""

    read -p "Digite o caminho do diretorio que deseja verificar: " scan_path

    if [ ! -d "$scan_path" ]; then
        echo "Erro: O diretorio '$scan_path' nao existe." | tee -a $LOG_FILE
        read -p "Pressione Enter para voltar ao menu..."
        return
    fi

    # Atualizar base de dados do ClamAV
    echo "Atualizando base de dados do ClamAV..." | tee -a $LOG_FILE
    sudo freshclam

    echo ""
    echo "Iniciando verificacao de: $scan_path"
    echo "Os resultados serao salvos em: $LOG_DIR/clamav_custom_scan.log"
    echo ""

    # Executar scan personalizado
    sudo clamscan -r -i --log="$LOG_DIR/clamav_custom_scan.log" "$scan_path" 2>&1 | tee -a $LOG_FILE

    echo ""
    echo "Verificacao concluida." | tee -a $LOG_FILE
    echo "Resultados salvos em: $LOG_DIR/clamav_custom_scan.log"
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para instalar o pacote LAMP completo
install_lamp_complete() {
    echo "Instalando Apache, MySQL, PHP e PhpMyAdmin..." | tee -a $LOG_FILE
    
    # Instalar Apache
    if [ "$DISTRO" = "debian" ]; then
        sudo apt-get update
        sudo apt-get install -y apache2
    elif [ "$DISTRO" = "rhel" ]; then
        sudo yum install -y httpd
        sudo systemctl enable httpd
        sudo systemctl start httpd
    fi

    # Instalar MySQL
    if [ "$DISTRO" = "debian" ]; then
        sudo apt-get install -y mysql-server
    elif [ "$DISTRO" = "rhel" ]; then
        sudo yum install -y mariadb-server mariadb
        sudo systemctl enable mariadb
        sudo systemctl start mariadb
    fi
    
    # Definir senha do MySQL de forma segura
    read -sp "Digite a senha root para o MySQL: " mysql_root_password
    echo

    # Validar senha (minimo 8 caracteres)
    if [ ${#mysql_root_password} -lt 8 ]; then
        log_error "A senha deve ter pelo menos 8 caracteres."
        read -p "Pressione Enter para voltar ao menu..."
        return 1
    fi

    # Usar pipe para passar senha de forma segura
    echo "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$mysql_root_password';" | sudo mysql
    echo "FLUSH PRIVILEGES;" | sudo mysql

    unset mysql_root_password  # Limpar senha da memoria

    # Instalar PHP
    if [ "$DISTRO" = "debian" ]; then
        sudo apt-get install -y lsb-release apt-transport-https ca-certificates
        sudo wget -qO /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg
        sudo sh -c 'echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" > /etc/apt/sources.list.d/php.list'
        sudo apt-get update
        sudo apt-get install -y php8.3 libapache2-mod-php8.3 php8.3-mysql
    elif [ "$DISTRO" = "rhel" ]; then
        sudo yum install -y epel-release
        sudo yum install -y https://rpms.remirepo.net/enterprise/remi-release-8.rpm
        sudo yum module reset php
        sudo yum module enable php:remi-8.3
        sudo yum install -y php php-mysqlnd
    fi

    # Instalar PhpMyAdmin
    if [ "$DISTRO" = "debian" ]; then
        sudo apt-get install -y phpmyadmin
        sudo ln -s /usr/share/phpmyadmin /var/www/html/phpmyadmin
    elif [ "$DISTRO" = "rhel" ]; then
        sudo yum install -y epel-release
        sudo yum install -y phpmyadmin
        sudo ln -s /usr/share/phpmyadmin /var/www/html/phpmyadmin
    fi

    echo "Instalacao do pacote LAMP completo concluida." | tee -a $LOG_FILE
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para instalar Apache
install_apache() {
    echo "Instalando Apache..." | tee -a $LOG_FILE
    if [ "$DISTRO" = "debian" ]; then
        sudo apt-get update
        sudo apt-get install -y apache2
    elif [ "$DISTRO" = "rhel" ]; then
        sudo yum install -y httpd
        sudo systemctl enable httpd
        sudo systemctl start httpd
    fi
    echo "Instalacao do Apache concluida." | tee -a $LOG_FILE
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para instalar MySQL
install_mysql() {
    echo "Instalando MySQL..." | tee -a $LOG_FILE
    if [ "$DISTRO" = "debian" ]; then
        sudo apt-get update
        sudo apt-get install -y mysql-server
    elif [ "$DISTRO" = "rhel" ]; then
        sudo yum install -y mariadb-server mariadb
        sudo systemctl enable mariadb
        sudo systemctl start mariadb
    fi

    read -sp "Digite a senha root para o MySQL: " mysql_root_password
    echo

    # Validar senha (minimo 8 caracteres)
    if [ ${#mysql_root_password} -lt 8 ]; then
        log_error "A senha deve ter pelo menos 8 caracteres."
        read -p "Pressione Enter para voltar ao menu..."
        return 1
    fi

    # Usar pipe para passar senha de forma segura
    echo "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$mysql_root_password';" | sudo mysql
    echo "FLUSH PRIVILEGES;" | sudo mysql

    unset mysql_root_password  # Limpar senha da memoria

    echo "Instalacao do MySQL concluida." | tee -a $LOG_FILE
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para instalar PHP
install_php() {
    echo "Instalando PHP 8.3..." | tee -a $LOG_FILE
    if [ "$DISTRO" = "debian" ]; then
        sudo apt-get install -y lsb-release apt-transport-https ca-certificates
        sudo wget -qO /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg
        sudo sh -c 'echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" > /etc/apt/sources.list.d/php.list'
        sudo apt-get update
        sudo apt-get install -y php8.3 libapache2-mod-php8.3 php8.3-mysql
    elif [ "$DISTRO" = "rhel" ]; then
        sudo yum install -y epel-release
        sudo yum install -y https://rpms.remirepo.net/enterprise/remi-release-8.rpm
        sudo yum module reset php
        sudo yum module enable php:remi-8.3
        sudo yum install -y php php-mysqlnd
    fi
    echo "Instalacao do PHP 8.3 concluida." | tee -a $LOG_FILE
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para instalar PhpMyAdmin
install_phpmyadmin() {
    echo "Instalando PhpMyAdmin..." | tee -a $LOG_FILE
    if [ "$DISTRO" = "debian" ]; then
        sudo apt-get update
        sudo apt-get install -y phpmyadmin
        sudo ln -s /usr/share/phpmyadmin /var/www/html/phpmyadmin
    elif [ "$DISTRO" = "rhel" ]; then
        sudo yum install -y epel-release
        sudo yum install -y phpmyadmin
        sudo ln -s /usr/share/phpmyadmin /var/www/html/phpmyadmin
    fi
    echo "Instalacao do PhpMyAdmin concluida." | tee -a $LOG_FILE
    read -p "Pressione Enter para voltar ao menu..."
}

# Menu de gerenciamento do SSH
ssh_management_menu() {
    while true; do
        clear
        echo "============================================"
        echo " Gerenciamento do SSH"
        echo "============================================"
        echo "1) Alterar porta SSH"
        echo "2) Configurar 2FA no SSH"
        echo "3) Remover 2FA no SSH"
        echo "4) Reiniciar SSH"
        echo "5) Voltar ao Menu Principal"
        echo "============================================"
        read -p "Escolha uma opcao: " ssh_option

        case $ssh_option in
            1) change_ssh_port ;;
            2) setup_2fa ;;
            3) remove_2fa ;;
            4) restart_ssh ;;
            5) return ;;
            *) echo "Opcao invalida. Tente novamente." ;;
        esac
    done
}

# Menu de gerenciamento do firewall
firewall_management_menu() {
    while true; do
        clear
        echo "============================================"
        echo " Gerenciamento de Firewall"
        echo "============================================"
        echo "1) Bloqueio de Portas do Servidor"
        echo "2) Desbloqueio de Porta no Servidor"
        echo "3) Bloqueio de IP"
        echo "4) Desbloqueio de IP"
        echo "5) Liberar Porta para um IP Especifico"
        echo "6) Remover Liberacao de Porta para um IP Especifico"
        echo "7) Visualizar Regras Atuais"
        echo "8) Salvar Regras do Firewall"
        echo "9) Limpar Todas as Regras Criadas"
        echo "10) Voltar ao Menu Principal"
        echo "============================================"
        read -p "Escolha uma opcao: " firewall_option

        case $firewall_option in
            1) block_port ;;
            2) unblock_port ;;
            3) block_ip ;;
            4) unblock_ip ;;
            5) allow_ip_port ;;
            6) remove_allow_ip_port ;;
            7) sudo iptables -L -v -n --line-numbers; read -p "Pressione Enter para continuar..." ;;
            8) save_iptables_rules; read -p "Pressione Enter para continuar..." ;;
            9) clear_all_rules ;;
            10) return ;;
            *) echo "Opcao invalida. Tente novamente." ;;
        esac
    done
}

# Menu de gerenciamento do antivirus
antivirus_management_menu() {
    while true; do
        clear
        echo "============================================"
        echo " Gerenciamento de Antivirus"
        echo "============================================"
        echo "1) Fazer Verificacao Completa do Antivirus"
        echo "2) Verificacao Personalizada do Antivirus"
        echo "3) Voltar ao Menu Principal"
        echo "============================================"
        read -p "Escolha uma opcao: " antivirus_option

        case $antivirus_option in
            1) full_scan ;;
            2) custom_scan ;;
            3) return ;;
            *) echo "Opcao invalida. Tente novamente." ;;
        esac
    done
}

# Menu de gerenciamento de automacao de sistema
automation_management_menu() {
    while true; do
        clear
        echo "============================================"
        echo " Gerir Automacao de Sistema"
        echo "============================================"
        echo "1) Agendar Rotina de Automacao"
        echo "2) Verificar Agendamentos Automatizados"
        echo "3) Voltar ao Menu Principal"
        echo "============================================"
        read -p "Escolha uma opcao: " automation_option

        case $automation_option in
            1) schedule_automation ;;
            2) view_automation_schedule ;;
            3) return ;;
            *) echo "Opcao invalida. Tente novamente." ;;
        esac
    done
}

# Menu de instalacao do pacote LAMP
lamp_install_menu() {
    while true; do
        clear
        echo "============================================"
        echo " Instalar Pacotes LAMP"
        echo "============================================"
        echo "1) Instalar Pacote LAMP Completo"
        echo "2) Instalar Apache"
        echo "3) Instalar MySQL"
        echo "4) Instalar PHP"
        echo "5) Instalar PhpMyAdmin"
        echo "6) Voltar ao Menu Principal"
        echo "============================================"
        read -p "Escolha uma opcao: " lamp_option

        case $lamp_option in
            1) install_lamp_complete ;;
            2) install_apache ;;
            3) install_mysql ;;
            4) install_php ;;
            5) install_phpmyadmin ;;
            6) return ;;
            *) echo "Opcao invalida. Tente novamente." ;;
        esac
    done
}

# Menu principal
main_menu() {
    while true; do
        clear
        echo "============================================"
        echo " $SYSTEM_NAME - Versao $VERSION"
        echo "============================================"
        echo "1) Gerenciamento do SSH"
        echo "2) Corrigir CVEs"
        echo "3) Alterar Hostname do Servidor"
        echo "4) Alterar Servidores DNS"
        echo "5) Gerir Automacao de Sistema"
        echo "6) Gerenciamento de Firewall"
        echo "7) Gerenciamento de Antivirus"
        echo "8) Instalar Pacotes LAMP"
        echo "9) Reiniciar Servidor"
        echo "10) Ver Logs"
        echo "11) Limpar Logs"
        echo "12) Forcar Atualizacao do DSAS"
        echo "13) Sair"
        echo "============================================"
        read -p "Escolha uma opcao: " option

        case $option in
            1) ssh_management_menu ;;
            2) fix_cve_menu ;;
            3) change_hostname ;;
            4) change_dns ;;
            5) automation_management_menu ;;
            6) firewall_management_menu ;;
            7) antivirus_management_menu ;;
            8) lamp_install_menu ;;
            9) reboot_server ;;
            10) view_logs ;;
            11) clear_logs ;;
            12) force_update ;;
            13) 
                echo "Voce acabou de sair do $SYSTEM_NAME"
                echo "Caso precise de suporte e ajuda acesse nosso site https://dolutech.com"
                exit 0
                ;;
            *) echo "Opcao invalida. Tente novamente." ;;
        esac
    done
}

# Executando as funcoes de inicializacao
detect_distro
setup_environment
check_for_updates
install_clamav
setup_path

# Iniciando o menu principal
main_menu
