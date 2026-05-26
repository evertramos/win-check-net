# diagnostico-rede.ps1

Script PowerShell para diagnóstico completo de rede no Windows. Identifica problemas de conectividade, DNS, latência, MTU e firewall com saída colorida e níveis de severidade.

## Requisitos

- Windows 10 / 11 ou Windows Server 2016+
- PowerShell 5.1 ou superior (PS 7+ suportado)
- Execução como **Administrador** para resultados completos

## Como usar

```powershell
# Abra o PowerShell como Administrador e execute:
.\diagnostico-rede.ps1
```

Se a política de execução bloquear o script:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\diagnostico-rede.ps1
```

## O que o script verifica

| Seção | O que faz |
|-------|-----------|
| **1. Adaptadores de rede** | Lista adaptadores ativos, endereço IP, MAC e gateway |
| **2. Configuração de DNS** | Exibe os servidores DNS configurados por interface |
| **3. Conectividade básica** | Ping para IPs e domínios públicos (Google, Cloudflare, Microsoft) |
| **4. Resolução de DNS** | Resolve domínios e exibe os IPs retornados |
| **5. Latência e perda de pacotes** | 10 pings por destino — mín/máx/média e % de perda |
| **6. Teste de MTU** | Detecta problemas de fragmentação de pacotes |
| **7. Traceroute** | Exibe a rota completa até o destino (requer Admin) |
| **8. Portas e firewall** | Status do Windows Firewall e teste de portas TCP externas |

## Legenda de saída

```
[OK]  Resultado dentro do esperado
[AV]  Aviso — situação que merece atenção
[ER]  Erro — problema identificado
[--]  Informação
[FW]  Status do Firewall
```

## Thresholds de latência (Seção 5)

| Condição | Classificação |
|----------|---------------|
| Média ≤ 80ms | OK |
| Média entre 80ms e 150ms | Aviso |
| Média > 150ms | Erro |
| Perda entre 1% e 20% | Aviso |
| Perda > 20% | Erro |

## Compatibilidade PowerShell

O script detecta automaticamente a versão do PowerShell para ler a propriedade de latência correta:

- **PS 5.1**: usa `ResponseTime`
- **PS 7+**: usa `Latency`

## Exemplo de saída

```
============================================================
  1. ADAPTADORES DE REDE
============================================================
  [--]  Ethernet | Intel(R) Ethernet Connection
  [--]    Status    : Up
  [--]    MAC       : AA-BB-CC-DD-EE-FF
  [--]    Velocidade: 1000 Mbps
  [OK]    IP        : 192.168.1.100/24
  [OK]    Gateway   : 192.168.1.1

============================================================
  5. LATÊNCIA E PERDA DE PACOTES
============================================================
  [--]  8.8.8.8  —  Min: 12ms  |  Máx: 18ms  |  Média: 14.3ms  |  Perda: 0%
  [OK]    Nenhuma perda de pacotes
  [OK]    Latência dentro do normal
```
