# [INFO] INSTRUCCIONES DE USO - Auditoría Empresarial Completa

##  Descripción

Script avanzado de PowerShell para realizar auditorías completas de seguridad empresarial con un solo click. Recopila información crítica del sistema, detecta indicadores de compromiso (IOCs) y genera reportes en múltiples formatos.

---

## [START] Ejecución Rápida (Un Solo Click)

### Método 1: Doble Click (Recomendado)
1. Localizar el archivo `Auditoria_Empresarial_Completa.ps1`
2. **Clic derecho** en el archivo
3. Seleccionar **"Ejecutar con PowerShell"**
4. Si aparece advertencia de seguridad, presionar **"S"** para continuar

### Método 2: Desde PowerShell
```powershell
# Navegar a la carpeta donde está el script
cd C:\ruta\del\script

# Ejecutar el script
.\Auditoria_Empresarial_Completa.ps1
```

### Método 3: Ejecución Remota (Para múltiples servidores)
```powershell
# Ejecutar en servidor remoto
Invoke-Command -ComputerName SERVIDOR01 -FilePath ".\Auditoria_Empresarial_Completa.ps1"

# Ejecutar en múltiples servidores
$servers = Get-Content "servidores.txt"
$servers | ForEach-Object {
    Invoke-Command -ComputerName $_ -FilePath ".\Auditoria_Empresarial_Completa.ps1"
}
```

---

## [PRIV] Requisitos del Sistema

### Requisitos Obligatorios
- **Sistema Operativo:** Windows 10, Windows 11, Windows Server 2016/2019/2022
- **PowerShell:** Versión 5.1 o superior
- **Espacio en Disco:** Mínimo 500 MB libres (para resultados)

### Privilegios Recomendados
| Nivel de Privilegio | Información Disponible |
|---------------------|------------------------|
| **[USER] Usuario Normal** | [OK] Procesos actuales<br>[OK] Conexiones de red<br>[OK] Archivos accesibles<br> Eventos de seguridad (limitado)<br> Configuración del sistema |
| **[PRIV] Administrador** | [OK] **TODO lo anterior +**<br>[OK] Eventos de seguridad completos<br>[OK] Configuración de sistema<br>[OK] Logs de auditoría<br>[OK] Drivers y kernel<br>[OK] Información de todos los usuarios |

**[!] RECOMENDACIÓN:** Ejecutar como **Administrador** para auditoría completa.

---

##  ¿Qué Analiza el Script?

El script ejecuta **10 módulos** de auditoría que cubren todas las áreas críticas:

### 1. [DIR] Información del Sistema
- Sistema operativo y versión
- Hardware (CPU, RAM, discos)
- Fecha de instalación y último reinicio
- Configuración de zona horaria

### 2.  Usuarios y Permisos
- [OK] Usuarios locales y su configuración
- [OK] Cuentas sin contraseña (CRÍTICO)
- [OK] Usuarios con privilegios de administrador
- [OK] Grupos privilegiados (RDP, Backup Operators)
- [OK] Cuentas habilitadas sin uso

### 3.  Procesos y Servicios
- [OK] Procesos en ejecución con firma digital
- [OK] Procesos sin ruta de archivo (MUY SOSPECHOSO)
- [OK] Línea de comandos de todos los procesos
- [OK] Detección de comandos codificados (Base64)
- [OK] Servicios automáticos
- [OK] Patrones maliciosos (Mimikatz, Invoke-Expression, etc.)

### 4.  Red y Conexiones
- [OK] Conexiones TCP/UDP activas
- [OK] Puertos en escucha (superficie de ataque)
- [OK] Conexiones a puertos sospechosos (4444, 8080, etc.)
- [OK] Procesos del sistema con conexiones externas (CRÍTICO)
- [OK] Caché DNS (dominios visitados)
- [OK] Configuración de adaptadores de red

### 5.  Logs y Eventos de Seguridad
- [OK] Intentos de login fallidos (Event ID 4625)
- [OK] Cuentas bloqueadas (Event ID 4740)
- [OK] Eventos de PowerShell (ScriptBlock Logging)
- [OK] Comandos codificados en PowerShell
- [OK] Eventos críticos del sistema y aplicaciones

### 6.  Archivos y Persistencia
- [OK] Archivos modificados en últimas 24 horas
- [OK] Archivos ocultos sospechosos
- [OK] Persistencia en Run Keys del registro
- [OK] Tareas programadas activas
- [OK] Verificación del archivo HOSTS
- [OK] Redirecciones maliciosas en HOSTS

### 7.  Configuraciones de Seguridad
- [OK] Política de ejecución de PowerShell
- [OK] Perfiles del firewall (habilitado/deshabilitado)
- [OK] Reglas del firewall activas
- [OK] Estado de Windows Defender
- [OK] Actualización de firmas de antivirus
- [OK] Recursos compartidos de red
- [OK] Configuración de UAC (User Account Control)

### 8.  Detección de LOLBAS
(Living Off the Land Binaries - Binarios legítimos usados maliciosamente)
- [OK] Uso de certutil, regsvr32, mshta, bitsadmin
- [OK] Uso de rundll32, wmic, PowerShell con argumentos sospechosos
- [OK] Detección de técnicas de evasión

### 9.  Drivers y Módulos del Kernel
- [OK] Drivers instalados en el sistema
- [OK] Drivers sin firma digital (posibles rootkits)
- [OK] Información de proveedor y versión

### 10.  Hardware y Configuración
- [OK] Información del BIOS
- [OK] Discos físicos y su estado de salud
- [OK] Particiones y espacio disponible
- [OK] Adaptadores de red (hardware)
- [OK] Variables de entorno

---

## [DIR] Estructura de Resultados

Al finalizar, el script crea una carpeta con la siguiente estructura:

```
Auditoria_20250102_143022/

  RESUMEN_EJECUTIVO.txt          ←  LEER PRIMERO
  AMENAZAS_DETECTADAS.json/csv/txt
  auditoria.log

 [DIR] 01_Sistema/
    informacion_sistema.[json|csv|txt]

 [DIR] 02_Usuarios/
    usuarios_locales.*
    administradores_locales.*
    grupo_Remote_Desktop_Users.*

 [DIR] 03_Procesos/
    procesos_activos.*
    procesos_sin_ruta.*           ← [!] REVISAR (SOSPECHOSO)
    procesos_con_comandos.*
    servicios.*

 [DIR] 04_Red/
    conexiones_tcp.*
    conexiones_establecidas.*      ← [!] REVISAR conexiones externas
    puertos_escucha.*
    udp_endpoints.*
    dns_cache.*

 [DIR] 05_Eventos/
    logins_fallidos.*              ← [!] REVISAR (Ataques de fuerza bruta)
    cuentas_bloqueadas.*
    powershell_scriptblock.*
    eventos_aplicacion.*
    eventos_sistema.*

 [DIR] 06_Archivos/
    archivos_modificados_24h.*
    archivos_ocultos_sospechosos.* ← [!] REVISAR
    persistencia_run_keys.*        ← [!] REVISAR (Persistencia)
    tareas_programadas.*
    archivo_hosts.*

 [DIR] 07_Configuracion/
    powershell_execution_policy.*
    firewall_perfiles.*
    firewall_reglas.*
    windows_defender.*
    recursos_compartidos.*
    uac_configuracion.*

 [DIR] 08_LOLBAS/
    procesos_lolbas_activos.*      ← [!] REVISAR
    eventos_lolbas.*

 [DIR] 09_Drivers/
    drivers_instalados.*
    drivers_sin_firma.*            ← [!] REVISAR (Posibles rootkits)

 [DIR] 10_Hardware/
     bios_info.*
     discos_fisicos.*
     volumenes.*
     adaptadores_red_hardware.*
     variables_entorno.*
```

### Formatos de Exportación

Cada módulo genera **3 archivos** con la misma información en diferentes formatos:

| Formato | Extensión | Uso Recomendado |
|---------|-----------|-----------------|
| **JSON** | `.json` | [OK] Análisis automatizado<br>[OK] Integración con SIEM<br>[OK] Scripts de procesamiento |
| **CSV** | `.csv` | [OK] Análisis en Excel<br>[OK] Filtrado y ordenamiento<br>[OK] Reportes ejecutivos |
| **TXT** | `.txt` | [OK] Lectura humana<br>[OK] Revisión rápida<br>[OK] Documentación |

---

##  Interpretación de Resultados

### Niveles de Severidad

El script clasifica las amenazas en 4 niveles:

| Nivel | Icono | Significado | Acción Requerida |
|-------|-------|-------------|------------------|
| **CRITICAL** | [CRITICO] | Amenaza crítica confirmada | [!] **INVESTIGAR INMEDIATAMENTE**<br>Posible compromiso activo |
| **HIGH** | [ALTO] | Amenaza de alta prioridad | [!] **INVESTIGAR EN 24 HORAS**<br>Riesgo significativo |
| **MEDIUM** | [MEDIO] | Amenaza moderada | ⏰ **INVESTIGAR EN 1 SEMANA**<br>Configuración insegura |
| **LOW** |  | Amenaza de baja prioridad | [INFO] **DOCUMENTAR**<br>Revisión recomendada |

### Ejemplos de Amenazas Detectadas

#### [CRITICO] CRÍTICAS (Acción Inmediata)
- [OK] **Proceso del sistema con conexión externa**
  - Ejemplo: `svchost.exe` conectado a IP 203.0.113.42
  - **Acción:** Investigar proceso, verificar malware
  
- [OK] **Comando codificado en PowerShell**
  - Ejemplo: `powershell.exe -enc <base64>`
  - **Acción:** Decodificar comando, analizar payload
  
- [OK] **Windows Defender deshabilitado**
  - **Acción:** Verificar si fue deshabilitado por atacante

#### [ALTO] ALTAS (Prioridad)
- [OK] **Conexión a puerto sospechoso**
  - Ejemplo: Conexión a puerto 4444 (Metasploit)
  - **Acción:** Identificar proceso, verificar C2
  
- [OK] **Proceso sin ruta de archivo**
  - Ejemplo: Proceso en memoria sin archivo en disco
  - **Acción:** Posible process injection o hollow
  
- [OK] **Usuario sin contraseña**
  - **Acción:** Establecer contraseña inmediatamente

#### [MEDIO] MEDIAS
- [OK] **Archivo ejecutable oculto**
- [OK] **Run Key con script**
- [OK] **Recurso compartido sin restricciones**

---

##  Respuesta a Amenazas Detectadas

### Workflow de Respuesta a Incidentes

```
1. DETECCIÓN (Script ejecutado)
   ↓
2. TRIAJE (Revisar RESUMEN_EJECUTIVO.txt)
   ↓
3. ANÁLISIS (Revisar AMENAZAS_DETECTADAS.csv)
   ↓
4. CONTENCIÓN (Aislar sistema si es necesario)
   ↓
5. ERRADICACIÓN (Eliminar amenaza)
   ↓
6. RECUPERACIÓN (Restaurar configuración segura)
   ↓
7. LECCIONES APRENDIDAS (Documentar)
```

### Acciones Inmediatas por Tipo de Amenaza

#### Si se detecta: "Conexión a puerto sospechoso"
```powershell
# 1. Identificar proceso
Get-NetTCPConnection -RemotePort 4444

# 2. Ver detalles del proceso
Get-Process -Id <PID> | Select-Object *

# 3. Ver línea de comandos
(Get-WmiObject Win32_Process -Filter "ProcessId=<PID>").CommandLine

# 4. Capturar memoria del proceso (opcional, requiere Procdump)
procdump.exe -ma <PID> proceso_sospechoso.dmp

# 5. Terminar proceso (si se confirma malicioso)
Stop-Process -Id <PID> -Force
```

#### Si se detecta: "Comando codificado en PowerShell"
```powershell
# Decodificar comando Base64
$encodedCommand = "BASE64_STRING_AQUI"
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encodedCommand))

# Analizar contenido decodificado
# Si es malicioso, revisar origen y propagación
```

#### Si se detecta: "Proceso sin ruta de archivo"
```powershell
# ALTAMENTE SOSPECHOSO - Posible process injection

# 1. Listar procesos sin ruta
Get-Process | Where-Object { $_.Path -eq $null -and $_.Name -ne "Idle" -and $_.Name -ne "System" }

# 2. Ver proceso padre
$proc = Get-Process -Id <PID>
$parentPID = (Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)").ParentProcessId
Get-Process -Id $parentPID

# 3. Capturar memoria para análisis forense
# 4. Considerar aislamiento del sistema
```

---

##  Automatización y Programación

### Ejecutar Auditoría Periódica con Tarea Programada

```powershell
# Crear tarea programada que ejecute auditoría semanalmente

$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-ExecutionPolicy Bypass -File C:\Auditoria\Auditoria_Empresarial_Completa.ps1"

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 2:00AM

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "Auditoria_Seguridad_Semanal" `
    -Action $action -Trigger $trigger -Principal $principal `
    -Description "Auditoría de seguridad empresarial automática"
```

### Integración con SIEM (Splunk, ELK, etc.)

Los archivos JSON generados pueden enviarse directamente a SIEM:

```powershell
# Ejemplo: Enviar resultados a Splunk
$splunkUrl = "https://splunk.empresa.com:8088/services/collector"
$splunkToken = "YOUR-HEC-TOKEN"

Get-ChildItem -Path "Auditoria_*" -Filter "*.json" -Recurse | ForEach-Object {
    $jsonContent = Get-Content $_.FullName -Raw
    
    Invoke-RestMethod -Uri $splunkUrl -Method Post `
        -Headers @{"Authorization" = "Splunk $splunkToken"} `
        -Body $jsonContent
}
```

---

##  Solución de Problemas

### Problema: "Script no se ejecuta - Política de ejecución"
**Solución:**
```powershell
# Temporal (solo para sesión actual)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Permanente (requiere admin)
Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned
```

### Problema: "Acceso denegado a logs de seguridad"
**Solución:**
- Ejecutar PowerShell como Administrador
- Clic derecho en PowerShell → "Ejecutar como administrador"

### Problema: "El script tarda mucho tiempo"
**Causas:**
- Sistema con muchos archivos (módulo de archivos modificados)
- Muchas conexiones de red activas

**Solución:**
- Normal: 5-10 minutos en sistemas estándar
- Si >30 minutos, verificar uso de disco/CPU

### Problema: "Algunos módulos fallan"
**Solución:**
- Revisar archivo `auditoria.log` para ver errores específicos
- Verificar requisitos del sistema (PowerShell 5.1+)
- Ejecutar con privilegios de administrador

---

##  Recursos Adicionales

### Documentación de Referencia
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [LOLBAS Project](https://lolbas-project.github.io/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### Herramientas Complementarias
- **Sysinternals Suite** (Microsoft) - Autoruns, Procmon, TCPView
- **VirusTotal** - Verificación de hashes de archivos
- **CyberChef** - Decodificación de comandos ofuscados
- **Splunk/ELK** - Análisis centralizado de logs

### Contacto y Soporte
-  Email: seguridad@empresa.com
-  Portal: https://seguridad.empresa.com
-  Incidentes: +1-800-SECURITY

---

##  Consideraciones Legales

### Uso Autorizado
[OK] **PERMITIDO:**
- Auditorías en sistemas de tu organización
- Análisis de sistemas con permiso explícito
- Evaluaciones de seguridad autorizadas

 **PROHIBIDO:**
- Escanear sistemas sin autorización
- Uso en sistemas de terceros sin consentimiento
- Acceso no autorizado a redes

**Este script es para uso legítimo de seguridad. El uso indebido puede violar leyes.**

---

##  Changelog

### Versión 2.0 (2025-11-03)
- [OK] Detección avanzada de IOCs (Indicadores de Compromiso)
- [OK] Exportación multi-formato (JSON, CSV, TXT)
- [OK] Análisis de LOLBAS (Living Off the Land)
- [OK] Detección de comandos codificados
- [OK] Resumen ejecutivo con nivel de riesgo
- [OK] 10 módulos de auditoría completos
- [OK] Barra de progreso visual
- [OK] Manejo robusto de errores
- [OK] Documentación extensa con comentarios

---

##  Licencia

Este script es propiedad de [Tu Organización] y está destinado únicamente para uso interno.

**Confidencial - No distribuir sin autorización**

---

**¿Preguntas?** Contacta al equipo de Ciberseguridad.


