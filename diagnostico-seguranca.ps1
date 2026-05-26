# ============================================================
#  diagnostico-seguranca.ps1
#  Análise forense de segurança para Windows
#  Detecta malware, backdoors e persistência
#  Uso: Execute como Administrador para resultados completos
# ============================================================

$Linha     = "=" * 60
$Separador = "-" * 60

$riscos = [System.Collections.Generic.List[string]]::new()

function Titulo($texto) {
    Write-Host ""
    Write-Host $Linha -ForegroundColor Cyan
    Write-Host "  $texto" -ForegroundColor Cyan
    Write-Host $Linha -ForegroundColor Cyan
}

function OK($msg)      { Write-Host "  [OK]  $msg" -ForegroundColor Green }
function WARN($msg)    { Write-Host "  [AV]  $msg" -ForegroundColor Yellow }
function ERRO($msg)    { Write-Host "  [ER]  $msg" -ForegroundColor Red }
function INFO($msg)    { Write-Host "  [--]  $msg" -ForegroundColor Gray }
function SUSPEITO($msg) {
    Write-Host "  [!!]  $msg" -ForegroundColor Magenta
    $riscos.Add($msg)
}

function Get-VelocidadeMbps($linkSpeed) {
    if ($linkSpeed -is [string]) {
        if ($linkSpeed -match "([\d\.]+)\s*(G|M|K)?bps") {
            $valor = [double]$Matches[1]
            return switch ($Matches[2]) {
                "G" { [math]::Round($valor * 1000, 0) }
                "M" { [math]::Round($valor, 0) }
                "K" { [math]::Round($valor / 1000, 1) }
                default { [math]::Round($valor / 1000000, 0) }
            }
        }
        return $linkSpeed
    }
    return [math]::Round($linkSpeed / 1000000, 0)
}

# ----------------------------------------------------------
# 1. ADAPTADORES DE REDE — FOCO EM VIRTUAIS E LOOPBACK
# ----------------------------------------------------------
Titulo "1. ADAPTADORES DE REDE (INCLUINDO VIRTUAIS E LOOPBACK)"

$todosAdaptadores = Get-NetAdapter | Sort-Object Status

foreach ($ad in $todosAdaptadores) {
    $status = $ad.Status
    $cor    = switch ($status) {
        "Up"           { "Green" }
        "Disconnected" { "Gray" }
        default        { "Yellow" }
    }

    $tipo = ""
    $nomeUpper = $ad.InterfaceDescription.ToUpper()

    if ($nomeUpper -match "LOOPBACK|VIRTUAL|TAP|TUN|VPN|PSEUDO|MINIPORT") {
        $tipo = " [VIRTUAL/LOOPBACK]"
    }

    Write-Host "  [AD]  $($ad.Name)$tipo" -ForegroundColor $cor
    INFO "        Desc   : $($ad.InterfaceDescription)"
    INFO "        Status : $status"
    INFO "        MAC    : $($ad.MacAddress)"

    # Adaptadores loopback/virtuais não esperados merecem atenção
    if ($tipo -ne "" -and $nomeUpper -notmatch "MICROSOFT|HYPER-V|VIRTUALBOX|VMWARE") {
        $vendor = $ad.InterfaceDescription -replace "\(.*\)", "" -replace "Virtual.*", "" | ForEach-Object { $_.Trim() }
        WARN "        Adaptador virtual/loopback de terceiro detectado: $($ad.InterfaceDescription)"
        INFO "        Verifique se '$vendor' é um software conhecido e instalado intencionalmente."
    }

    Write-Host ""
}

# ----------------------------------------------------------
# 2. CONEXÕES DE REDE ATIVAS COM PROCESSO ASSOCIADO
# ----------------------------------------------------------
Titulo "2. CONEXÕES ATIVAS (TCP) COM PROCESSO"

$conexoes = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" } |
            Sort-Object RemoteAddress

if ($conexoes.Count -eq 0) {
    INFO "Nenhuma conexão TCP estabelecida no momento."
} else {
    foreach ($c in $conexoes) {
        try {
            $proc = Get-Process -Id $c.OwningProcess -ErrorAction Stop
            $nome = $proc.Name
            $path = $proc.Path
        } catch {
            $nome = "PID $($c.OwningProcess)"
            $path = "(sem acesso)"
        }

        $linha = "$($c.LocalAddress):$($c.LocalPort) → $($c.RemoteAddress):$($c.RemotePort)  |  $nome"

        # Portas incomuns ou processos de sistema com conexões externas
        $portasAlerta = @(4444, 1337, 31337, 5554, 9001, 9030, 6666, 8080)
        $processosSistema = @("svchost", "lsass", "csrss", "winlogon", "explorer")

        if ($c.RemotePort -in $portasAlerta) {
            SUSPEITO "Porta suspeita de backdoor/C2: $linha"
        } elseif ($nome -in $processosSistema -and $c.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)") {
            SUSPEITO "Processo de sistema com conexão externa: $linha"
            INFO "        Path: $path"
        } else {
            INFO "$linha"
            if ($path) { INFO "        Path: $path" }
        }
    }
}

# ----------------------------------------------------------
# 3. PORTAS ABERTAS EM ESCUTA (BACKDOORS POTENCIAIS)
# ----------------------------------------------------------
Titulo "3. PORTAS EM ESCUTA (LISTENING)"

$escuta = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } |
          Sort-Object LocalPort

$portasComuns = @(80, 135, 139, 443, 445, 3389, 5040, 5357, 7680, 49664..49670)

foreach ($p in $escuta) {
    try {
        $proc = Get-Process -Id $p.OwningProcess -ErrorAction Stop
        $nome = $proc.Name
        $path = $proc.Path
    } catch {
        $nome = "PID $($p.OwningProcess)"
        $path = "(sem acesso)"
    }

    $incomum = ($p.LocalPort -notin $portasComuns) -and ($p.LocalPort -lt 49664 -or $p.LocalPort -gt 65535)

    if ($incomum -and $p.LocalAddress -eq "0.0.0.0") {
        SUSPEITO "Porta $($p.LocalPort) aberta em TODAS as interfaces — processo: $nome"
        if ($path) { INFO "        Path: $path" }
    } elseif ($incomum) {
        WARN "Porta incomum $($p.LocalPort) em escuta — processo: $nome"
    } else {
        INFO "Porta $($p.LocalPort) ($($p.LocalAddress)) — $nome"
    }
}

# ----------------------------------------------------------
# 4. PROCESSOS SUSPEITOS
# ----------------------------------------------------------
Titulo "4. PROCESSOS SUSPEITOS"

$processos = Get-Process | Where-Object { $_.Path -ne $null }

$pathsSuspeitos = @(
    "\\Temp\\", "\\tmp\\", "\\AppData\\Local\\Temp\\",
    "\\Downloads\\", "\\Public\\", "\\ProgramData\\"
)

$nomesAlerta = @(
    "nc", "ncat", "netcat", "mimikatz", "meterpreter",
    "psexec", "pwdump", "fgdump", "wce", "xmrig", "minerd"
)

$countSuspeitos = 0

foreach ($proc in $processos) {
    $alertaNome = $proc.Name.ToLower() -in $nomesAlerta
    $alertaPath = $pathsSuspeitos | Where-Object { $proc.Path -match [regex]::Escape($_) }

    # Verifica assinatura digital
    $assinado = $true
    try {
        $sig = Get-AuthenticodeSignature -FilePath $proc.Path -ErrorAction Stop
        if ($sig.Status -ne "Valid") { $assinado = $false }
    } catch {
        $assinado = $false
    }

    if ($alertaNome) {
        SUSPEITO "Nome de ferramenta maliciosa conhecida: $($proc.Name) (PID $($proc.Id))"
        INFO "        Path: $($proc.Path)"
        $countSuspeitos++
    } elseif ($alertaPath) {
        SUSPEITO "Processo executando de diretório temporário/suspeito:"
        INFO "        Nome: $($proc.Name) (PID $($proc.Id))"
        INFO "        Path: $($proc.Path)"
        $countSuspeitos++
    } elseif (-not $assinado -and $proc.Path -notmatch "\\WindowsApps\\") {
        WARN "Processo sem assinatura digital válida: $($proc.Name)"
        INFO "        Path: $($proc.Path)"
    }
}

if ($countSuspeitos -eq 0) {
    OK "Nenhum processo de nome malicioso conhecido encontrado"
}

# ----------------------------------------------------------
# 5. PERSISTÊNCIA — CHAVES DE REGISTRO (RUN / RUNONCE)
# ----------------------------------------------------------
Titulo "5. PERSISTÊNCIA — REGISTRO (RUN / RUNONCE)"

$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($key in $runKeys) {
    try {
        $entradas = Get-ItemProperty -Path $key -ErrorAction Stop
        $entradas.PSObject.Properties |
            Where-Object { $_.Name -notmatch "^PS" } |
            ForEach-Object {
                $val = $_.Value
                $alertaPath = $pathsSuspeitos | Where-Object { $val -match [regex]::Escape($_) }
                if ($alertaPath) {
                    SUSPEITO "Run key em path suspeito: $($_.Name) → $val"
                    INFO "        Chave: $key"
                } else {
                    INFO "$($_.Name) → $val"
                }
            }
    } catch {
        INFO "$key — sem entradas ou sem acesso"
    }
}

# ----------------------------------------------------------
# 6. PERSISTÊNCIA — TAREFAS AGENDADAS SUSPEITAS
# ----------------------------------------------------------
Titulo "6. PERSISTÊNCIA — TAREFAS AGENDADAS"

try {
    $tarefas = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }

    foreach ($tarefa in $tarefas) {
        $acoes = $tarefa.Actions | Where-Object { $_.Execute -ne $null }
        foreach ($acao in $acoes) {
            $exe = $acao.Execute
            $args = $acao.Arguments

            $alertaPath = $pathsSuspeitos | Where-Object { $exe -match [regex]::Escape($_) }
            $alertaExt  = $exe -match "\.(vbs|bat|cmd|ps1|js|hta|scr|pif)$"
            $powershellEnc = $args -match "-enc|-encodedcommand|-w hidden|-windowstyle h"

            if ($alertaPath) {
                SUSPEITO "Tarefa agendada com path suspeito: '$($tarefa.TaskName)'"
                INFO "        Ação: $exe $args"
            } elseif ($powershellEnc) {
                SUSPEITO "Tarefa agendada com PowerShell codificado/oculto: '$($tarefa.TaskName)'"
                INFO "        Ação: $exe $args"
            } elseif ($alertaExt -and $exe -notmatch "\\Windows\\|\\Microsoft\\") {
                WARN "Tarefa agendada com script: '$($tarefa.TaskName)'"
                INFO "        Ação: $exe $args"
            }
        }
    }

    OK "Varredura de tarefas agendadas concluída"
} catch {
    WARN "Não foi possível listar tarefas agendadas (execute como Administrador)"
}

# ----------------------------------------------------------
# 7. PERSISTÊNCIA — SERVIÇOS NÃO-MICROSOFT
# ----------------------------------------------------------
Titulo "7. SERVIÇOS NÃO-MICROSOFT / SUSPEITOS"

$servicos = Get-WmiObject Win32_Service | Where-Object {
    $_.State -eq "Running" -and
    $_.PathName -ne $null -and
    $_.PathName -notmatch "\\Windows\\|\\Microsoft\."
} | Sort-Object Name

foreach ($svc in $servicos) {
    $path  = $svc.PathName -replace '"', ''
    $alertaPath = $pathsSuspeitos | Where-Object { $path -match [regex]::Escape($_) }

    if ($alertaPath) {
        SUSPEITO "Serviço rodando de path suspeito: $($svc.Name)"
        INFO "        Path: $path"
    } else {
        INFO "$($svc.Name) | $($svc.DisplayName)"
        INFO "        Path: $path"
    }
}

# ----------------------------------------------------------
# 8. PERSISTÊNCIA — WMI (TÉCNICA AVANÇADA DE MALWARE)
# ----------------------------------------------------------
Titulo "8. PERSISTÊNCIA — WMI EVENT SUBSCRIPTIONS"

try {
    $filtros     = Get-WMIObject -Namespace root\subscription -Class __EventFilter -ErrorAction Stop
    $consumidores = Get-WMIObject -Namespace root\subscription -Class __EventConsumer -ErrorAction Stop
    $bindings    = Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction Stop

    if ($filtros.Count -gt 0) {
        SUSPEITO "WMI Event Filters encontrados (técnica comum de persistência de malware):"
        foreach ($f in $filtros) {
            INFO "        Filtro: $($f.Name) | Query: $($f.Query)"
        }
    } else {
        OK "Nenhum WMI Event Filter encontrado"
    }

    if ($consumidores.Count -gt 0) {
        SUSPEITO "WMI Event Consumers encontrados:"
        foreach ($c in $consumidores) {
            INFO "        Consumer: $($c.Name)"
        }
    } else {
        OK "Nenhum WMI Event Consumer encontrado"
    }
} catch {
    WARN "Não foi possível verificar WMI subscriptions (execute como Administrador)"
}

# ----------------------------------------------------------
# 9. CONTAS DE USUÁRIO E GRUPO ADMINISTRADORES
# ----------------------------------------------------------
Titulo "9. CONTAS DE USUÁRIO E ADMINISTRADORES"

$usuarios = Get-LocalUser | Sort-Object Enabled -Descending

foreach ($u in $usuarios) {
    $status = if ($u.Enabled) { "ATIVA" } else { "inativa" }
    $cor    = if ($u.Enabled) { "White" } else { "Gray" }
    Write-Host "  [US]  $($u.Name) — $status" -ForegroundColor $cor

    if ($u.LastLogon) {
        INFO "        Último acesso: $($u.LastLogon)"
    }
    if ($u.PasswordLastSet) {
        INFO "        Senha alterada: $($u.PasswordLastSet)"
    }
    if (-not $u.PasswordRequired -and $u.Enabled) {
        WARN "        Conta sem senha obrigatória!"
    }
    if ($u.PasswordNeverExpires -and $u.Enabled) {
        WARN "        Senha nunca expira"
    }
}

Write-Host ""
INFO "Membros do grupo Administradores:"
try {
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    foreach ($a in $admins) {
        $tipo = if ($a.ObjectClass -eq "User") { "Usuário" } else { $a.ObjectClass }
        WARN "$($a.Name) ($tipo)"
    }
} catch {
    WARN "Não foi possível listar o grupo Administradores"
}

# ----------------------------------------------------------
# 10. CACHE DNS — DOMÍNIOS RECENTEMENTE ACESSADOS
# ----------------------------------------------------------
Titulo "10. CACHE DNS (DOMÍNIOS RECENTEMENTE ACESSADOS)"

try {
    $cache = Get-DnsClientCache -ErrorAction Stop | Where-Object { $_.Type -eq 1 } |
             Select-Object -ExpandProperty Entry | Sort-Object -Unique

    $dominiosSuspeitos = @(
        "\.ru$", "\.cn$", "\.tk$", "\.xyz$", "\.top$",
        "dyndns\.", "ngrok\.", "no-ip\.", "\.onion\.",
        "pastebin\.com", "raw\.githubusercontent"
    )

    foreach ($dom in $cache) {
        $suspeito = $dominiosSuspeitos | Where-Object { $dom -match $_ }
        if ($suspeito) {
            SUSPEITO "Domínio suspeito no cache DNS: $dom"
        } else {
            INFO $dom
        }
    }

    if ($cache.Count -eq 0) {
        INFO "Cache DNS vazio ou sem permissão para ler"
    }
} catch {
    WARN "Não foi possível ler o cache DNS (execute como Administrador)"
}

# ----------------------------------------------------------
# 11. LOGS DE SEGURANÇA — EVENTOS RECENTES SUSPEITOS
# ----------------------------------------------------------
Titulo "11. EVENTOS DE SEGURANÇA RECENTES (ÚLTIMAS 24H)"

$inicio = (Get-Date).AddHours(-24)

# Event IDs relevantes para segurança
$eventosAlvo = @{
    4625 = "Falha de logon"
    4720 = "Conta de usuário criada"
    4728 = "Membro adicionado ao grupo Administradores"
    4732 = "Membro adicionado a grupo local privilegiado"
    7045 = "Novo serviço instalado"
    1102 = "Log de auditoria limpo (possível cobertura de rastros)"
    4698 = "Tarefa agendada criada"
    4702 = "Tarefa agendada modificada"
}

foreach ($id in $eventosAlvo.Keys) {
    try {
        $eventos = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = $id
            StartTime = $inicio
        } -ErrorAction Stop -MaxEvents 5

        if ($eventos) {
            if ($id -in @(4720, 4728, 4732, 7045, 1102, 4698, 4702)) {
                SUSPEITO "[$id] $($eventosAlvo[$id]) — $($eventos.Count) ocorrência(s) nas últimas 24h"
            } elseif ($id -eq 4625 -and $eventos.Count -gt 10) {
                SUSPEITO "[$id] $($eventosAlvo[$id]) — $($eventos.Count) tentativas (possível brute force)"
            } else {
                WARN "[$id] $($eventosAlvo[$id]) — $($eventos.Count) ocorrência(s)"
            }
            foreach ($ev in $eventos | Select-Object -First 3) {
                INFO "        $($ev.TimeCreated) — $($ev.Message -split "`n" | Select-Object -First 2 | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -First 1)"
            }
        }
    } catch {
        # Sem eventos desse tipo no período ou sem permissão
    }
}

OK "Varredura de eventos concluída"

# ----------------------------------------------------------
# 12. ARQUIVOS EXECUTÁVEIS RECENTEMENTE CRIADOS/MODIFICADOS
# ----------------------------------------------------------
Titulo "12. EXECUTÁVEIS CRIADOS NOS ÚLTIMOS 7 DIAS (PATHS SUSPEITOS)"

$seteDias = (Get-Date).AddDays(-7)

$pathsVerificar = @(
    "$env:TEMP",
    "$env:USERPROFILE\AppData\Local\Temp",
    "$env:USERPROFILE\Downloads",
    "C:\ProgramData",
    "$env:PUBLIC"
)

$extsSuspeitas = @("*.exe", "*.dll", "*.bat", "*.cmd", "*.ps1", "*.vbs", "*.hta", "*.scr")

foreach ($pasta in $pathsVerificar) {
    if (Test-Path $pasta) {
        foreach ($ext in $extsSuspeitas) {
            $arquivos = Get-ChildItem -Path $pasta -Filter $ext -Recurse -ErrorAction SilentlyContinue |
                        Where-Object { $_.LastWriteTime -gt $seteDias }
            foreach ($arq in $arquivos) {
                SUSPEITO "Executável recente em path suspeito: $($arq.FullName)"
                INFO "        Modificado: $($arq.LastWriteTime)  |  Tamanho: $([math]::Round($arq.Length/1KB,1)) KB"
            }
        }
    }
}

OK "Varredura de executáveis recentes concluída"

# ----------------------------------------------------------
# RESUMO DE RISCOS
# ----------------------------------------------------------
Titulo "RESUMO — ITENS SUSPEITOS ENCONTRADOS"

if ($riscos.Count -eq 0) {
    OK "Nenhum indicador de comprometimento (IoC) óbvio detectado."
    INFO "Isso não garante que o sistema está limpo — use um antivírus atualizado para confirmação."
} else {
    Write-Host "  Total de alertas [!!]: $($riscos.Count)" -ForegroundColor Magenta
    Write-Host ""
    $i = 1
    foreach ($r in $riscos) {
        Write-Host "  $i. $r" -ForegroundColor Magenta
        $i++
    }
    Write-Host ""
    WARN "Investigue cada item acima antes de concluir sobre comprometimento."
    WARN "Considere executar Malwarebytes, Windows Defender Offline Scan ou Autoruns (Sysinternals)."
}

Write-Host ""
Titulo "DIAGNÓSTICO CONCLUÍDO"
INFO "Execute como Administrador para acesso completo a todos os dados."
INFO "Ferramentas complementares recomendadas: Autoruns, Process Explorer, TCPView (Sysinternals)"
Write-Host ""
