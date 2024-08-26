#!/bin/bash

# Nome e versao do sistema
SYSTEM_NAME="Dolutech Security Automate System (DSAS)"
VERSION="0.0.3"
DSAS_DIR="/opt/DSAS"
LOG_DIR="$DSAS_DIR/logs"
VERSION_DIR="$DSAS_DIR/version"
LOG_FILE="$LOG_DIR/dsas.log"
VERSION_FILE="$VERSION_DIR/version.txt"
SCRIPT_NAME="dsas.sh"
SCRIPT_PATH="$DSAS_DIR/$SCRIPT_NAME"
GITHUB_REPO_RAW="https://raw.githubusercontent.com/dolutech/Dolutech-Security-Automate-System/main"

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

    # Substituindo a linha Port independentemente do valor atual
    if grep -q "^#Port" /etc/ssh/sshd_config; then
        sudo sed -i "s/^#Port.*/Port $new_port/" /etc/ssh/sshd_config
    elif grep -q "^Port" /etc/ssh/sshd_config; then
        sudo sed -i "s/^Port.*/Port $new_port/" /etc/ssh/sshd_config
    else
        echo "Port $new_port" | sudo tee -a /etc/ssh/sshd_config
    fi

    restart_ssh
    echo "Porta SSH alterada com sucesso para $new_port." | tee -a $LOG_FILE
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

    restart_ssh
    echo "Configuracao do 2FA concluida com sucesso." | tee -a $LOG_FILE
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

    restart_ssh
    echo "2FA removido com sucesso." | tee -a $LOG_FILE
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para corrigir CVEs
fix_cve_menu() {
    while true; do
        clear
        echo "============================================"
        echo " Correção de CVEs"
        echo "============================================"
        echo "1) Corrigir CVE-2024-6387 e CVE-2024-6409"
        echo "2) Voltar ao Menu Principal"
        echo "============================================"
        read -p "Escolha uma opção: " cve_option

        case $cve_option in
            1) fix_cves ;;
            2) return ;;
            *) echo "Opção inválida. Tente novamente." ;;
        esac
    done
}

# Funcao para corrigir CVEs especificas
fix_cves() {
    echo "Corrigindo CVEs CVE-2024-6387 e CVE-2024-6409..."
    echo "Esta operação pode demorar um pouco. Por favor, aguarde."

    # Passo 1: Baixar e preparar a compilacao
    sudo apt update
    sudo apt install build-essential zlib1g-dev libssl-dev libpam0g-dev libselinux1-dev wget -y

    cd /usr/local/src
    sudo wget https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-9.8p1.tar.gz
    sudo tar -xzf openssh-9.8p1.tar.gz
    cd openssh-9.8p1

    # Perguntar ao usuário se ele possui 2FA configurado
    read -p "Você usa 2FA no SSH (s/n)? " use_2fa

    if [[ $use_2fa =~ ^[Ss]$ ]]; then
        sudo ./configure --with-pam
    else
        sudo ./configure
    fi

    sudo make
    sudo make install

    # Passo 3: Verificar a versão atualizada
    /usr/local/bin/ssh -V

    # Passo 4: Atualizar o PATH
    export PATH=/usr/local/bin:$PATH
    echo 'export PATH=/usr/local/bin:$PATH' >> ~/.bashrc
    source ~/.bashrc

    # Passo 5: Reiniciar o serviço SSH
    sudo systemctl restart ssh

    # Passo 6: Verificar se o serviço está usando a versão nova
    if ps aux | grep sshd | grep -q "/usr/sbin/sshd"; then
        if /usr/sbin/sshd -v | grep -q "OpenSSH_9.8p1"; then
            echo "O SSH está usando a versão atualizada."
        else
            sudo ln -sf /usr/local/sbin/sshd /usr/sbin/sshd
            sudo systemctl restart ssh
        fi
    fi

    # Verificar novamente a versão para confirmar
    /usr/sbin/sshd -v

    # Corrigir o arquivo sshd.service se necessário
    sudo sed -i 's|ExecStart=.*|ExecStart=/usr/local/sbin/sshd -D -f /etc/ssh/sshd_config|' /etc/systemd/system/sshd.service

    sudo systemctl daemon-reload
    sudo systemctl restart sshd
    sudo systemctl status sshd

    echo "Correção de CVEs concluída com sucesso." | tee -a $LOG_FILE
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
    sudo iptables -A INPUT -p tcp --dport $port -j DROP
    echo "Porta $port bloqueada com sucesso." | tee -a $LOG_FILE
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
    sudo iptables -A INPUT -s $ip -j DROP
    echo "IP $ip bloqueado com sucesso." | tee -a $LOG_FILE
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
    read -p "Digite a porta que deseja liberar: " port
    sudo iptables -A INPUT -p tcp -s $ip --dport $port -j ACCEPT
    echo "Porta $port liberada para o IP $ip." | tee -a $LOG_FILE
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

# Funcao para limpar todas as regras do IPTables
clear_all_rules() {
    sudo iptables -F
    echo "Todas as regras do IPTables foram limpas." | tee -a $LOG_FILE
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para fazer verificacao completa do antivirus
full_scan() {
    sudo clamscan -r /
    echo "Verificacao completa do sistema realizada." | tee -a $LOG_FILE
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para fazer verificacao personalizada do antivirus
custom_scan() {
    read -p "Digite o caminho que deseja verificar: " path
    sudo clamscan -r $path
    echo "Verificacao personalizada do caminho $path realizada." | tee -a $LOG_FILE
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para ver os logs
view_logs() {
    cat $LOG_FILE
    read -p "Pressione Enter para voltar ao menu..."
}

# Funcao para limpar os logs
clear_logs() {
    > $LOG_FILE
    echo "Logs limpos com sucesso." | tee -a $LOG_FILE
    read -p "Pressione Enter para voltar ao menu..."
}

# Menu principal
main_menu() {
    while true; do
        clear
        echo "============================================"
        echo " $SYSTEM_NAME - Versao $VERSION"
        echo "============================================"
        echo "1) Alterar porta SSH"
        echo "2) Configurar 2FA no SSH"
        echo "3) Remover 2FA no SSH"
        echo "4) Corrigir CVEs"
        echo "5) Reiniciar SSH"
        echo "6) Bloqueio de Portas do Servidor"
        echo "7) Desbloqueio de Porta no Servidor"
        echo "8) Bloqueio de IP"
        echo "9) Desbloqueio de IP"
        echo "10) Liberar Porta para um IP Especifico"
        echo "11) Remover Liberacao de Porta para um IP Especifico"
        echo "12) Limpar Todas as Regras Criadas"
        echo "13) Fazer Verificacao Completa do Antivirus"
        echo "14) Verificacao Personalizada do Antivirus"
        echo "15) Reiniciar Servidor"
        echo "16) Ver Logs"
        echo "17) Limpar Logs"
        echo "18) Sair"
        echo "============================================"
        read -p "Escolha uma opcao: " option

        case $option in
            1) change_ssh_port ;;
            2) setup_2fa ;;
            3) remove_2fa ;;
            4) fix_cve_menu ;;
            5) restart_ssh ;;
            6) block_port ;;
            7) unblock_port ;;
            8) block_ip ;;
            9) unblock_ip ;;
            10) allow_ip_port ;;
            11) remove_allow_ip_port ;;
            12) clear_all_rules ;;
            13) full_scan ;;
            14) custom_scan ;;
            15) reboot_server ;;
            16) view_logs ;;
            17) clear_logs ;;
            18) 
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
