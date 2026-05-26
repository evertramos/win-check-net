# ============================================================
#  diagnostico-rede.ps1
#  Diagnóstico completo de rede para Windows
#  Uso: Execute como Administrador para resultados completos
# ============================================================

$Linha     = "=" * 60
$Separador = "-" * 60

function Titulo($texto) {
    Write-Host ""
    Write-Host $Linha -ForegroundColor Cyan
    Write-Host "  $texto" -ForegroundColor Cyan
    Write-Host $Linha -ForegroundColor Cyan
}

function OK($msg)   { Write-Host "  [OK]  $msg" -ForegroundColor Green }
function WARN($msg) { Write-Host "  [AV]  $msg" -ForegroundColor Yellow }
function ERRO($msg) { Write-Host "  [ER]  $msg" -ForegroundColor Red }
function INFO($msg) { Write-Host "  [--]  $msg" -ForegroundColor Gray }

function Get-Latencia($resultados) {
    # Compatível com Windows PowerShell 5.1 (ResponseTime) e PS 7+ (Latency)
    if ($resultados[0].PSObject.Properties["Latency"]) {
        return $resultados.Latency
    }
    return $resultados.ResponseTime
}

# ----------------------------------------------------------
# 1. CONFIGURAÇÕES DE IP E ADAPTADORES
# ----------------------------------------------------------
Titulo "1. ADAPTADORES DE REDE"

$adaptadores = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

if ($adaptadores.Count -eq 0) {
    ERRO "Nenhum adaptador de rede ativo encontrado."
} else {
    foreach ($ad in $adaptadores) {
        INFO "$($ad.Name) | $($ad.InterfaceDescription)"
        INFO "  Status    : $($ad.Status)"
        INFO "  MAC       : $($ad.MacAddress)"

        $mbps = [math]::Round($ad.LinkSpeed / 1000000, 0)
        INFO "  Velocidade: ${mbps} Mbps"

        $ip = Get-NetIPAddress -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($ip) {
            OK  "  IP        : $($ip.IPAddress)/$($ip.PrefixLength)"
        } else {
            WARN "  IP        : Nenhum endereço IPv4 atribuído"
        }

        $gw = Get-NetRoute -InterfaceIndex $ad.ifIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
        if ($gw) {
            OK  "  Gateway   : $($gw.NextHop)"
        } else {
            WARN "  Gateway   : Não encontrado"
        }

        Write-Host ""
    }
}

# ----------------------------------------------------------
# 2. CONFIGURAÇÃO DE DNS
# ----------------------------------------------------------
Titulo "2. CONFIGURAÇÃO DE DNS"

$dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 |
              Where-Object { $_.ServerAddresses.Count -gt 0 }

if ($dnsServers) {
    foreach ($d in $dnsServers) {
        INFO "Interface : $($d.InterfaceAlias)"
        OK  "  DNS     : $($d.ServerAddresses -join ', ')"
    }
} else {
    ERRO "Nenhum servidor DNS configurado."
}

# ----------------------------------------------------------
# 3. CONECTIVIDADE BÁSICA (PING)
# ----------------------------------------------------------
Titulo "3. CONECTIVIDADE BÁSICA — PING"

$alvos = @(
    @{ Host = "8.8.8.8";        Desc = "Google DNS (IPv4)" },
    @{ Host = "1.1.1.1";        Desc = "Cloudflare DNS (IPv4)" },
    @{ Host = "google.com";      Desc = "google.com" },
    @{ Host = "microsoft.com";   Desc = "microsoft.com" }
)

foreach ($alvo in $alvos) {
    $ping = Test-Connection -ComputerName $alvo.Host -Count 3 -ErrorAction SilentlyContinue
    if ($ping) {
        $tempos = Get-Latencia $ping
        $media  = [math]::Round(($tempos | Measure-Object -Average).Average, 1)
        OK  "$($alvo.Desc) — $($alvo.Host) | Média: ${media}ms"
    } else {
        ERRO "$($alvo.Desc) — $($alvo.Host) | SEM RESPOSTA"
    }
}

# ----------------------------------------------------------
# 4. RESOLUÇÃO DNS
# ----------------------------------------------------------
Titulo "4. RESOLUÇÃO DE DNS"

$dominios = @("google.com", "microsoft.com", "cloudflare.com")

foreach ($dom in $dominios) {
    try {
        $res = Resolve-DnsName $dom -ErrorAction Stop | Where-Object { $_.Type -eq "A" }
        OK  "$dom → $($res.IPAddress -join ', ')"
    } catch {
        ERRO "$dom → Falha na resolução"
    }
}

# ----------------------------------------------------------
# 5. LATÊNCIA E PERDA DE PACOTES
# ----------------------------------------------------------
Titulo "5. LATÊNCIA E PERDA DE PACOTES"

$testLatencia = @("8.8.8.8", "1.1.1.1")

foreach ($destino in $testLatencia) {
    $resultados = Test-Connection -ComputerName $destino -Count 10 -ErrorAction SilentlyContinue
    if ($resultados) {
        $enviados  = 10
        $recebidos = $resultados.Count
        $perda     = [math]::Round((($enviados - $recebidos) / $enviados) * 100, 0)
        $tempos    = Get-Latencia $resultados
        $min       = ($tempos | Measure-Object -Minimum).Minimum
        $max       = ($tempos | Measure-Object -Maximum).Maximum
        $media     = [math]::Round(($tempos | Measure-Object -Average).Average, 1)

        INFO "$destino  —  Min: ${min}ms  |  Máx: ${max}ms  |  Média: ${media}ms  |  Perda: ${perda}%"

        if ($perda -gt 20) {
            ERRO "  Alta perda de pacotes detectada: ${perda}%"
        } elseif ($perda -gt 0) {
            WARN "  Perda leve de pacotes: ${perda}%"
        } else {
            OK  "  Nenhuma perda de pacotes"
        }

        if ($media -gt 150) {
            ERRO "  Latência muito alta: ${media}ms"
        } elseif ($media -gt 80) {
            WARN "  Latência elevada: ${media}ms"
        } else {
            OK  "  Latência dentro do normal"
        }
    } else {
        ERRO "$destino — Sem resposta"
    }
    Write-Host ""
}

# ----------------------------------------------------------
# 6. TESTE DE MTU
# ----------------------------------------------------------
Titulo "6. TESTE DE MTU"

INFO "Testando MTU com pacotes de 1472 bytes (1500 - 28 cabeçalho IP/ICMP)..."

$mtuAlvo = "8.8.8.8"
$mtuOk   = $false

# Test-Connection com BufferSize equivale ao -l do ping clássico
$mtuTeste = Test-Connection -ComputerName $mtuAlvo -Count 2 -BufferSize 1472 -ErrorAction SilentlyContinue

if ($mtuTeste) {
    OK  "MTU padrão (1500) está funcionando corretamente"
    $mtuOk = $true
} else {
    WARN "Possível problema de MTU detectado — pacotes grandes estão sendo descartados"
    INFO "Isso pode causar lentidão em conexões HTTPS, VPN ou streaming"
}

# ----------------------------------------------------------
# 7. TRACEROUTE (ROTA ATÉ O DESTINO)
# ----------------------------------------------------------
Titulo "7. ROTA DE REDE (TRACEROUTE)"

INFO "Rastreando rota até 8.8.8.8 (máx. 15 saltos)..."
Write-Host ""

try {
    $trace = Test-NetConnection -ComputerName "8.8.8.8" -TraceRoute -Hops 15 -WarningAction SilentlyContinue
    if ($trace.TraceRoute) {
        $salto = 1
        foreach ($hop in $trace.TraceRoute) {
            INFO "  Salto $salto : $hop"
            $salto++
        }
        if ($trace.PingSucceeded) {
            OK  "Destino alcançado com $($trace.PingReplyDetails.RoundtripTime)ms"
        } else {
            WARN "Destino não respondeu ao ping final (pode ser filtro ICMP no destino)"
        }
    } else {
        WARN "Nenhum salto retornado — execute como Administrador para traceroute completo"
    }
} catch {
    WARN "Traceroute não disponível neste ambiente"
}

# ----------------------------------------------------------
# 8. PORTAS E FIREWALL
# ----------------------------------------------------------
Titulo "8. PORTAS E FIREWALL"

try {
    $fw = Get-NetFirewallProfile -ErrorAction Stop
    foreach ($perfil in $fw) {
        $estado = if ($perfil.Enabled) { "ATIVO" } else { "INATIVO" }
        $cor    = if ($perfil.Enabled) { "Green" } else { "Yellow" }
        Write-Host "  [FW]  Firewall $($perfil.Name): $estado" -ForegroundColor $cor
    }
} catch {
    WARN "Não foi possível verificar o status do Firewall (execute como Administrador)."
}

Write-Host ""
INFO "Testando portas externas (TCP)..."

$portasTeste = @(
    @{ Host = "8.8.8.8";          Porta = 53;  Desc = "DNS (TCP)" },
    @{ Host = "google.com";        Porta = 80;  Desc = "HTTP" },
    @{ Host = "google.com";        Porta = 443; Desc = "HTTPS" },
    @{ Host = "smtp.gmail.com";    Porta = 587; Desc = "SMTP (e-mail)" }
)

foreach ($p in $portasTeste) {
    $teste = Test-NetConnection -ComputerName $p.Host -Port $p.Porta -WarningAction SilentlyContinue
    if ($teste.TcpTestSucceeded) {
        OK  "$($p.Desc) → $($p.Host):$($p.Porta) aberta"
    } else {
        ERRO "$($p.Desc) → $($p.Host):$($p.Porta) BLOQUEADA ou inacessível"
    }
}

# ----------------------------------------------------------
# RESUMO FINAL
# ----------------------------------------------------------
Titulo "DIAGNÓSTICO CONCLUÍDO"
INFO "Verifique os itens marcados com [ER] (erro) ou [AV] (aviso)."
INFO "Execute como Administrador para resultados completos do Firewall e Traceroute."
Write-Host ""
