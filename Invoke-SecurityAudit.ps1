<#

                    SCRIPT DE AUDITORIA DE SEGURIDAD EMPRESARIAL                       
                                VERSION 2.0 - PROFESIONAL                                


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
    Version: 2.0
    Fecha: 2 de noviembre de 2025
    Requisitos: PowerShell 5.1+, Windows 10/Server 2016+
    Privilegios: Se recomienda ejecutar como Administrador para auditoria completa

.EXAMPLE
    .\Auditoria_Empresarial_Completa.ps1
    
    Ejecuta la auditoria completa y crea carpeta con timestamp en el directorio actual

.LINK
    https://docs.microsoft.com/en-us/powershell/
    https://attack.mitre.org/
#>

#Requires -Version 5.1

# 
# SECCION 1: CONFIGURACION INICIAL Y VARIABLES GLOBALES
# 

# Configuracion de ErrorAction por defecto
$ErrorActionPreference = "Continue"

# Variables globales del script
$Global:ScriptVersion = "2.0"
$Global:ScriptStartTime = Get-Date
$Global:TotalModules = 10
$Global:CurrentModule = 0
$Global:WarningsCount = 0
$Global:ErrorsCount = 0
$Global:ThreatsDetected = @()

# Puertos sospechosos comunes (C2, backdoors, malware)
$Global:SuspiciousPorts = @(4444, 5555, 6666, 7777, 8080, 8888, 9999, 31337, 12345, 1337, 6667)

# Extensiones de archivos sospechosos para analisis
$Global:SuspiciousExtensions = @("*.exe", "*.dll", "*.ps1", "*.bat", "*.vbs", "*.js", "*.hta", "*.scr")

# Binarios LOLBAS (Living Off the Land Binaries) frecuentemente abusados
$Global:LOLBASBinaries = @(
    "certutil.exe", "regsvr32.exe", "mshta.exe", "bitsadmin.exe", 
    "regasm.exe", "regsvcs.exe", "msbuild.exe", "installutil.exe", 
    "rundll32.exe", "odbcconf.exe", "wmic.exe", "powershell.exe", "cmd.exe"
)

# Patrones maliciosos comunes en PowerShell
$Global:MaliciousPatterns = @(
    'Invoke-Expression', 'IEX', 'Invoke-Mimikatz', 'Invoke-Obfuscation',
    'Net.WebClient', 'DownloadString', 'DownloadFile', 'EncodedCommand',
    'Hidden', 'New-Object', '-Enc', 'FromBase64String', 'Invoke-Shellcode',
    'Invoke-ReflectivePEInjection', 'Get-GPPPassword', 'mimikatz'
)

# 
# SECCION 2: FUNCIONES AUXILIARES
# 

<#
.SYNOPSIS
    Muestra el banner del script con informacion de version
#>
function Show-Banner {
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
function Add-ThreatDetection {
    param(
        [string]$ThreatType,
        [ValidateSet("LOW", "MEDIUM", "HIGH", "CRITICAL")]
        [string]$Severity,
        [string]$Description,
        $Details
    )
    
    $threat = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ThreatType = $ThreatType
        Severity = $Severity
        Description = $Description
        Details = $Details
    }
    
    $Global:ThreatsDetected += $threat
    
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
        $localUsers | ForEach-Object {
            if (-not $_.PasswordRequired) {
                Add-ThreatDetection -ThreatType "Usuario sin contrasena" -Severity "HIGH" `
                    -Description "Usuario '$($_.Name)' no requiere contrasena" -Details $_
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
        # Procesos en ejecucion
        $processes = Get-Process | Select-Object Name, Id, Path, Company, Product, 
            CPU, @{Name="Memory_MB"; Expression={[math]::Round($_.WorkingSet64/1MB, 2)}},
            StartTime, SessionId,
            @{Name="Signed"; Expression={
                if ($_.Path) {
                    $sig = Get-AuthenticodeSignature $_.Path -ErrorAction SilentlyContinue
                    $sig.Status -eq 'Valid'
                } else {
                    $false
                }
            }}
        
        $outputPath = Join-Path $Global:AuditPath "03_Procesos\procesos_activos"
        Export-MultiFormat -Data $processes -BasePath $outputPath -Title "Procesos en Ejecucion"
        
        # Detectar procesos sin ruta (altamente sospechoso)
        $processesNoPath = Get-Process | Where-Object { 
            $null -eq $_.Path -and $_.Name -ne "Idle" -and $_.Name -ne "System" 
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
            if ($_.CommandLine) {
                $cmdLine = $_.CommandLine.ToLower()
                
                # Detectar comando codificado en Base64
                if ($cmdLine -match "-enc|-encodedcommand") {
                    Add-ThreatDetection -ThreatType "Comando codificado" -Severity "CRITICAL" `
                        -Description "Proceso '$($_.Name)' (PID: $($_.ProcessId)) usando comando codificado" -Details $_
                }
                
                # Detectar patrones maliciosos
                foreach ($pattern in $Global:MaliciousPatterns) {
                    if ($cmdLine -match $pattern.ToLower()) {
                        Add-ThreatDetection -ThreatType "Patron malicioso detectado" -Severity "HIGH" `
                            -Description "Proceso '$($_.Name)' contiene patron '$pattern'" -Details $_
                        break
                    }
                }
            }
        }
        
        # Servicios del sistema
        $services = Get-Service | Select-Object Name, DisplayName, Status, StartType,
            @{Name="BinaryPath"; Expression={
                (Get-WmiObject Win32_Service -Filter "Name='$($_.Name)'" -ErrorAction SilentlyContinue).PathName
            }}
        
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
        # Conexiones TCP activas con informacion de proceso
        $tcpConnections = Get-NetTCPConnection | ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            
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
            if ($_.RemotePort -in $Global:SuspiciousPorts) {
                Add-ThreatDetection -ThreatType "Conexion a puerto sospechoso" -Severity "HIGH" `
                    -Description "Proceso '$($_.ProcessName)' conectado a puerto sospechoso $($_.RemotePort)" -Details $_
            }
            
            # Detectar conexiones externas de procesos del sistema
            if ($_.ProcessName -in @('svchost', 'lsass', 'csrss', 'smss', 'wininit') -and 
                $_.RemoteAddress -notmatch "^(127\.0\.0\.1|::1|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)") {
                Add-ThreatDetection -ThreatType "Proceso del sistema con conexion externa" -Severity "CRITICAL" `
                    -Description "Proceso del sistema '$($_.ProcessName)' conectado a IP externa $($_.RemoteAddress)" -Details $_
            }
        }
        
        # Puertos en escucha (superficie de ataque)
        $listeningPorts = $tcpConnections | Where-Object { $_.State -eq "Listen" }
        $outputPath = Join-Path $Global:AuditPath "04_Red\puertos_escucha"
        Export-MultiFormat -Data $listeningPorts -BasePath $outputPath -Title "Puertos en Escucha"
        
        # Endpoints UDP
        $udpEndpoints = Get-NetUDPEndpoint | ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            
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
            } -MaxEvents 200 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, 
                @{Name="ScriptBlock"; Expression={$_.Properties[2].Value}}
            
            if ($psEvents) {
                $outputPath = Join-Path $Global:AuditPath "05_Eventos\powershell_scriptblock"
                Export-MultiFormat -Data $psEvents -BasePath $outputPath -Title "PowerShell ScriptBlock Logging"
                
                # Detectar comandos codificados o patrones maliciosos
                $psEvents | ForEach-Object {
                    $scriptBlock = $_.ScriptBlock.ToLower()
                    
                    if ($scriptBlock -match "-enc|-encodedcommand") {
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
        $hiddenFiles = Get-ChildItem -Path "C:\Users" -Hidden -Recurse -Force -ErrorAction SilentlyContinue -Include $Global:SuspiciousExtensions |
            Select-Object FullName, Attributes, Length, CreationTime, LastWriteTime
        
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
            $hostsContent | ForEach-Object {
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
            if ($_.Name -match "^[A-Z]\$$" -and $_.Name -ne "ADMIN$" -and $_.Name -ne "IPC$") {
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
        $lolbasProcesses = Get-Process | Where-Object { 
            $_.Name -in $Global:LOLBASBinaries -replace ".exe", ""
        } | Select-Object Name, Id, Path, Company, StartTime,
            @{Name="CommandLine"; Expression={
                (Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine
            }}
        
        if ($lolbasProcesses) {
            $outputPath = Join-Path $Global:AuditPath "08_LOLBAS\procesos_lolbas_activos"
            Export-MultiFormat -Data $lolbasProcesses -BasePath $outputPath -Title "Procesos LOLBAS Activos"
            
            # Analizar lineas de comando sospechosas
            $lolbasProcesses | ForEach-Object {
                $cmdLine = $_.CommandLine
                
                if ($cmdLine -match "-enc|-encodedcommand|-urlcache|-split|-f http") {
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
                    $processName = $_.Properties[5].Value
                    $Global:LOLBASBinaries | ForEach-Object { $processName -match $_ }
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
        # Drivers cargados en el sistema
        $drivers = Get-WindowsDriver -Online -All -ErrorAction SilentlyContinue | 
            Select-Object Driver, OriginalFileName, ProviderName, ClassName, DriverSignature,
                Version, Date
        
        if ($drivers) {
            $outputPath = Join-Path $Global:AuditPath "09_Drivers\drivers_instalados"
            Export-MultiFormat -Data $drivers -BasePath $outputPath -Title "Drivers Instalados en el Sistema"
            
            Write-AuditLog "  -> Total drivers: $($drivers.Count)" -Level INFO
        }
        
        # Drivers sin firma digital (altamente sospechoso)
        $unsignedDrivers = $drivers | Where-Object { $_.DriverSignature -ne "Valid" }
        
        if ($unsignedDrivers) {
            $outputPath = Join-Path $Global:AuditPath "09_Drivers\drivers_sin_firma"
            Export-MultiFormat -Data $unsignedDrivers -BasePath $outputPath -Title "[!] Drivers sin Firma Digital"
            
            $unsignedDrivers | ForEach-Object {
                Add-ThreatDetection -ThreatType "Driver sin firma digital" -Severity "HIGH" `
                    -Description "Driver '$($_.Driver)' no tiene firma digital valida" -Details $_
            }
            
            Write-AuditLog "  -> Drivers sin firma: $($unsignedDrivers.Count)" -Level WARNING
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
        
        # Crear objeto de resumen
        $summary = [PSCustomObject]@{
    # "" = "" # CORREGIDO: Clave duplicada vacia eliminada
            "RESUMEN EJECUTIVO DE AUDITORIA DE SEGURIDAD" = ""
            "`n" = ""
            
            "Informacion General" = ""
    # "" = "" # CORREGIDO: Clave duplicada vacia eliminada
            "Sistema" = $env:COMPUTERNAME
            "Usuario Ejecutor" = $env:USERNAME
            "Privilegios" = if (Test-Administrator) { "Administrador" } else { "Usuario Normal" }
            "Fecha Inicio" = $Global:ScriptStartTime.ToString("yyyy-MM-dd HH:mm:ss")
            "Fecha Fin" = $endTime.ToString("yyyy-MM-dd HH:mm:ss")
            "Duracion Total" = "$($duration.Minutes)m $($duration.Seconds)s"
            "Directorio de Resultados" = $Global:AuditPath
            " " = ""
            
            "Estadisticas de Ejecucion" = ""
    # "" = "" # CORREGIDO: Clave duplicada vacia eliminada
            "Modulos Ejecutados" = "$Global:CurrentModule / $Global:TotalModules"
            "Errores Encontrados" = $Global:ErrorsCount
            "Advertencias" = $Global:WarningsCount
            "Amenazas Detectadas" = $Global:ThreatsDetected.Count
            "  " = ""
            
            "Nivel de Riesgo General" = ""
    # "" = "" # CORREGIDO: Clave duplicada vacia eliminada
            "Amenazas CRITICAS" = ($Global:ThreatsDetected | Where-Object { $_.Severity -eq "CRITICAL" }).Count
            "Amenazas ALTAS" = ($Global:ThreatsDetected | Where-Object { $_.Severity -eq "HIGH" }).Count
            "Amenazas MEDIAS" = ($Global:ThreatsDetected | Where-Object { $_.Severity -eq "MEDIUM" }).Count
            "Amenazas BAJAS" = ($Global:ThreatsDetected | Where-Object { $_.Severity -eq "LOW" }).Count
        }
        
        # Calcular nivel de riesgo general
        $criticalCount = ($Global:ThreatsDetected | Where-Object { $_.Severity -eq "CRITICAL" }).Count
        $highCount = ($Global:ThreatsDetected | Where-Object { $_.Severity -eq "HIGH" }).Count
        
        $riskLevel = if ($criticalCount -gt 0) {
            "[CRITICO] CRITICO"
        } elseif ($highCount -gt 5) {
            "[ALTO] ALTO"
        } elseif ($highCount -gt 0) {
            "[MEDIO] MEDIO"
        } else {
            "[BAJO] BAJO"
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
        "Amenazas ALTAS:       $(($Global:ThreatsDetected | Where-Object { $_.Severity -eq "HIGH" }).Count)" | Out-File $summaryPath -Append -Encoding UTF8
        "Amenazas MEDIAS:      $(($Global:ThreatsDetected | Where-Object { $_.Severity -eq "MEDIUM" }).Count)" | Out-File $summaryPath -Append -Encoding UTF8
        "Amenazas BAJAS:       $(($Global:ThreatsDetected | Where-Object { $_.Severity -eq "LOW" }).Count)" | Out-File $summaryPath -Append -Encoding UTF8
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
function Start-SecurityAudit {
    # Mostrar banner
    Show-Banner
    
    # Crear directorio de auditoria con timestamp
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $auditFolderName = "Auditoria_$timestamp"
    $Global:AuditPath = Join-Path $PSScriptRoot $auditFolderName
    
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
        
        # Preguntar si abrir carpeta de resultados
        Write-Host "¿Desea abrir la carpeta de resultados? (S/N): " -NoNewline -ForegroundColor Cyan
        $response = Read-Host
        
        if ($response -eq "S" -or $response -eq "s") {
            Start-Process explorer.exe $Global:AuditPath
        }
        
        Write-Host ""
        Write-Host "Presione cualquier tecla para salir..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        
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
        
        Write-Host "Presione cualquier tecla para salir..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

# 
# PUNTO DE ENTRADA DEL SCRIPT
# 

# Ejecutar auditoria
Start-SecurityAudit
