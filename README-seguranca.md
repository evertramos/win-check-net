# diagnostico-seguranca.ps1

Script PowerShell de análise forense/segurança para Windows. Detecta indicadores de comprometimento (IoC), malware, backdoors e mecanismos de persistência. Projetado para análise inicial de uma máquina suspeita.

> **Execute sempre como Administrador** — algumas seções (WMI, logs de segurança, cache DNS) requerem privilégios elevados.

## Como usar

```powershell
# Abra o PowerShell como Administrador e execute:
.\diagnostico-seguranca.ps1

# Salvar resultado em arquivo para análise posterior:
.\diagnostico-seguranca.ps1 | Tee-Object -FilePath "resultado-seguranca.txt"
```

Se a política de execução bloquear o script:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\diagnostico-seguranca.ps1
```

## O que o script verifica

| Seção | O que analisa |
|-------|---------------|
| **1. Adaptadores de rede** | Detecta adaptadores virtuais/loopback de terceiros inesperados |
| **2. Conexões TCP ativas** | Lista conexões em andamento com o processo responsável; alerta portas de backdoor conhecidas |
| **3. Portas em escuta** | Identifica portas incomuns abertas em todas as interfaces |
| **4. Processos suspeitos** | Detecta ferramentas maliciosas conhecidas, processos em diretórios temporários e binários sem assinatura digital |
| **5. Registro (Run/RunOnce)** | Varredura nas chaves de inicialização automática mais usadas por malware |
| **6. Tarefas agendadas** | Detecta tarefas com scripts, paths temporários ou PowerShell codificado/oculto |
| **7. Serviços** | Lista serviços não-Microsoft em execução; alerta serviços em paths suspeitos |
| **8. WMI subscriptions** | Detecta Event Filters/Consumers do WMI — técnica avançada usada por APTs e malware sofisticado |
| **9. Contas de usuário** | Lista usuários, datas de acesso, membros do grupo Administradores, contas sem senha |
| **10. Cache DNS** | Analisa domínios recentemente acessados buscando TLDs suspeitos (.ru, .tk, .xyz) e serviços de C2 comuns (ngrok, no-ip, dyndns) |
| **11. Logs de segurança** | Eventos das últimas 24h: falhas de logon, criação de contas, instalação de serviços, limpeza de logs |
| **12. Executáveis recentes** | Arquivos .exe/.dll/.ps1/.bat criados nos últimos 7 dias em diretórios temporários |

## Legenda de saída

```
[OK]  Sem problemas detectados neste item
[AV]  Aviso — merece atenção mas não necessariamente malicioso
[ER]  Erro de verificação
[--]  Informação
[!!]  SUSPEITO — indicador de comprometimento potencial
[FW]  Status do Firewall
[AD]  Adaptador de rede
[US]  Conta de usuário
```

## Sobre o "Topaz Loopback"

O adaptador **Topaz Loopback** é instalado por produtos da **Topaz Labs** (Topaz Photo AI, Video AI, DeNoise AI etc.). Eles usam um servidor local (loopback) para processar imagens com IA. **É legítimo se o cliente usa esses softwares.**

Para confirmar:

```powershell
# Verificar qual processo está usando o adaptador
Get-NetAdapter | Where-Object { $_.InterfaceDescription -match "Topaz" }

# Verificar serviços relacionados
Get-Service | Where-Object { $_.DisplayName -match "Topaz" }

# Verificar instalação nos programas
Get-WmiObject Win32_Product | Where-Object { $_.Name -match "Topaz" }
```

Se **nenhum software Topaz estiver instalado**, o adaptador é suspeito e deve ser investigado.

## Portas de backdoor monitoradas

O script alerta automaticamente conexões nessas portas:

| Porta | Associação comum |
|-------|-----------------|
| 4444  | Metasploit/Meterpreter padrão |
| 1337  | Ferramentas hacking genéricas |
| 31337 | Back Orifice / ferramentas antigas |
| 5554  | Sasser worm |
| 9001 / 9030 | Tor relay |
| 6666  | IRC bots / botnets |
| 8080  | Proxy reverso / C2 via HTTP |

## Resumo de risco

Ao final o script exibe todos os itens `[!!]` agrupados com contagem total. Use como base para decidir os próximos passos:

- **0 alertas**: nenhum IoC óbvio — recomenda-se confirmação com antivírus
- **1-3 alertas**: investigar cada item individualmente antes de concluir
- **4+ alertas**: alto risco de comprometimento — isolar a máquina e fazer análise forense completa

## Ferramentas complementares recomendadas

| Ferramenta | Para que serve |
|------------|----------------|
| **Autoruns** (Sysinternals) | Visão completa de todos os pontos de persistência |
| **Process Explorer** (Sysinternals) | Árvore de processos com verificação de assinatura e VirusTotal |
| **TCPView** (Sysinternals) | Conexões de rede em tempo real por processo |
| **Malwarebytes Free** | Scan de malware complementar |
| **Windows Defender Offline Scan** | Scan antes do boot do sistema (detecta rootkits) |

### Executar Windows Defender Offline Scan

```powershell
# Agenda um scan offline no próximo boot
Start-MpScan -ScanType OfflineScan
```

## Limitações

- O script faz análise **estática e comportamental básica** — não substitui um EDR ou análise forense profissional
- Malware sofisticado pode ocultar processos e conexões de APIs do Windows (rootkits)
- Alguns alertas podem ser falsos positivos — cada item `[!!]` exige julgamento humano
- Requer execução como Administrador para acesso a WMI subscriptions, logs de segurança e cache DNS
