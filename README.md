# Dolutech Security Automate System (DSAS)

![Dolutech Logo](https://dolutech.com/wp-content/uploads/2023/02/dolutech-new-logo.png)

Bem-vindo ao **Dolutech Security Automate System (DSAS)**, uma ferramenta poderosa projetada para automatizar e facilitar a administração de servidores Linux. Este sistema foi criado para melhorar a segurança e simplificar a gestão de servidores, oferecendo uma série de funcionalidades automatizadas.

### **Versão Estável: 0.0.4**

## Funcionalidades Principais

- **Gerenciamento do SSH**
  - Alterar porta SSH
  - Configurar 2FA no SSH
  - Remover 2FA no SSH
  - Reiniciar o serviço SSH

- **Corrigir CVEs**
  - Em breve, disponibilizaremos diversas correções de CVEs diretamente através do sistema.

- **Alterar Hostname do Servidor**
  - Altere facilmente o hostname do servidor com apenas alguns comandos.

- **Alterar Servidores DNS**
  - Configure servidores DNS IPv4 e IPv6 para seu servidor.

- **Gerir Automação de Sistema**
  - **Agendar Rotina de Automação**: Agende comandos para serem executados automaticamente em intervalos específicos.
  - **Verificar Agendamentos Automatizados**: Visualize, gerencie e remova agendamentos de automação existentes.

- **Gerenciamento de Firewall**
  - Bloqueio de Portas do Servidor
  - Desbloqueio de Porta no Servidor
  - Bloqueio de IP
  - Desbloqueio de IP
  - Liberar Porta para um IP Específico
  - Remover Liberação de Porta para um IP Específico
  - Limpar Todas as Regras Criadas

- **Gerenciamento de Antivírus**
  - Fazer Verificação Completa do Antivírus
  - Verificação Personalizada do Antivírus

- **Reiniciar Servidor**
  - Reinicie o servidor de forma segura através do sistema.

- **Logs**
  - Ver Logs: Visualize os logs de atividades do sistema.
  - Limpar Logs: Limpe os logs armazenados.
 
 - **Instalação do pacote LAMP**
  - Instalar pacote LAMP completo: Instala automaticamente Apache,PHP,Mysql e phpmyAdmin.
  - Instalar Apache: instala o apache individual.
  - Instalar php: instala o php individual.
  - Instalar Mysql: instala o mysql com opção de senha diferente da Root server.
  - Instalar phpmyAdmin: instala individual o phpMyadmin

- **Forçar Atualização do DSAS**
  - Atualize o DSAS manualmente a qualquer momento para garantir que está usando a versão mais recente.

## Instalação

Para instalar o DSAS em seu servidor, siga os passos abaixo:

### Passo 1: Baixar o Script

Use o seguinte comando para baixar o script diretamente do GitHub:

```bash
curl -o dsas.sh https://raw.githubusercontent.com/dolutech/Dolutech-Security-Automate-System/main/dsas.sh
```
## Passo 2: Dar Permissão de Execução ao Script

Após o download, é necessário dar permissão de execução ao script:

```bash
chmod +x dsas.sh
```

## Passo 3: Executar o Script pela Primeira Vez

Execute o script para inicializar a configuração:

```bash
./dsas.sh
```

## Passo 4: Ativar o Sistema

Depois da configuração inicial, você pode ativar o sistema a qualquer momento usando o comando:

```bash
dsas start
```

## Atualizações Automáticas
O DSAS verifica automaticamente se há uma nova versão disponível toda vez que é iniciado. Se uma nova versão for encontrada, o sistema solicitará a atualização antes de continuar. Isso garante que você esteja sempre utilizando a versão mais segura e atualizada.

## Manutenção

Para garantir que as funcionalidades funcionem corretamente, o script atualiza e configura automaticamente. Recomenda-se verificar os logs periodicamente para garantir que tudo está funcionando conforme o esperado.

## Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou enviar pull requests no repositório do GitHub.

## Licença

Este projeto está licenciado sob a Licença GPL.

## Créditos
- Lucas Catão de Moraes: - https://cataodemoraes.com
- Dolutech: - https://dolutech.com

Agradecemos por utilizar o Dolutech Security Automate System. Se tiver sugestões, problemas ou precisar de suporte, entre em contato conosco através dos links acima.
