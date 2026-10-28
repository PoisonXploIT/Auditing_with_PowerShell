![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?style=flat&logo=powershell) ![License](https://img.shields.io/badge/License-MIT-green) ![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?style=flat&logo=windows)

> **Nota:** Los PDFs de documentacion se han movido a [GitHub Releases](https://github.com/PoisonXploIT/Auditing_with_PowerShell/releases) para mantener el repo ligero.

# INSTRUCCIONES DE USO - Auditoría Empresarial Completa

##  Descripción

Script avanzado de PowerShell para realizar auditorías completas de seguridad empresarial con un solo click. Recopila información crítica del sistema, detecta indicadores de compromiso (IOCs) y genera reportes en múltiples formatos.

---

## Ejecución Rápida (Un Solo Click)

### Método 1: Doble Click (Recomendado)
1. Localizar el archivo `Invoke-SecurityAudit.ps1`
2. **Clic derecho** en el archivo
3. Seleccionar **"Ejecutar con PowerShell"**
4. Si aparece advertencia de seguridad, presionar **"S"** para continuar

### Método 2: Desde PowerShell
```powershell
# Navegar a la carpeta donde está el script
cd C:\ruta\del\script

# Ejecutar el script
.\Invoke-SecurityAudit.ps1
```

### Método 3: Ejecución Remota (Para múltiples servidores)
```powershell
# Ejecutar en servidor remoto
Invoke-Command -ComputerName SERVIDOR01 -FilePath ".\Invoke-SecurityAudit.ps1"

# Ejecutar en múltiples servidores
$servers = Get-Content "servidores.txt"
$servers | ForEach-Object {
    Invoke-Command -ComputerName $_ -FilePath ".\Invoke-SecurityAudit.ps1"
}
```

### Método 4: Interfaz Web (v3.0)

La versión 3.0 incluye una interfaz web para visualizar auditorías existentes y ejecutar nuevas auditorías con progreso en vivo.

```powershell
# 1. Crear entorno virtual e instalar dependencias
cd ui
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt

# 2. Arrancar el servidor (puerto fijo 8502: ALLOWED_ORIGINS/CSRF en main.py)
.\.venv\Scripts\python -m uvicorn main:app --host 127.0.0.1 --port 8502

# 3. Abrir http://127.0.0.1:8502 en el navegador
```

La interfaz permite:
- Ver el panel general con nivel de riesgo, KPIs y gráfico de severidades
- Navegar el historial de auditorías generadas
- Explorar los datos de cada módulo (tablas interactivas)
- Ejecutar una nueva auditoría con barra de progreso en vivo
- Ejecutar como administrador (eleva privilegios con UAC)
- Exportar el log unificado (botón **LOG** junto a PDF/JSON/CSV)

#### Log unificado (export JSON Lines)

Cada auditoría puede exportarse como un único archivo `.jsonl` (una línea JSON por evento), pensado para ser ingerido por pipelines de correlación (Visor de Logs Unificado, SIEM, etc.):

```
GET /api/audits/{audit_id}/download/log
```

Contrato de la línea (orden cronológico):

```json
{"ts": "2026-09-16 21:40:41", "level": "ERR", "msg": "[HIGH] Driver sin firma digital - ...", "source": "ps-audit"}
```

| Campo | Valor |
|-------|-------|
| `ts` | Timestamp ISO del evento (inicio, amenaza, fin) |
| `level` | Normalizado: CRIT / ERR / WRN / INF (desde CRITICAL/HIGH/MEDIUM/LOW) |
| `msg` | `[SEVERITY] Tipo - Descripción` de la amenaza, o línea de inicio/resumen final |
| `source` | Siempre `ps-audit` (identificador del emisor en el pipeline) |

#### Ejecución headless (automatización)

El script acepta parámetros para ejecutarse sin interacción, usados internamente por la interfaz web:

```powershell
.\Invoke-SecurityAudit.ps1 -Headless -ResultPath C:\Auditorias -StatusFile C:\Auditorias\status.json
```

`-StatusFile` recibe un JSON de progreso (módulo, porcentaje, amenazas, errores) que la interfaz lee para mostrar el avance en tiempo real.

#### IA: veredictos Jev y explicaciones técnicas (LLM local)

La interfaz incluye una capa IA **opcional y referencial** que enriquece el informe de cada auditoría sin modificar sus datos. En el detalle de la auditoría (Panel General) aparece la tarjeta **IA — Veredictos (Jev) y Explicaciones Técnicas (LLM local)**:

- **Jev (TypeSafe, nube)**: mismo contrato de API que sec-dashboard (`POST {base_url}` con `{model, state, questions}`, modelo pin `jev-1.13.0`). Por cada amenaza calcula veredicto (`true_positive`/`false_positive`/`noise`), confianza, severidad IA (0-3) y urgencia de acción (0-1). De ahí se deriva la **probabilidad de falso positivo** (`true_positive` → 1 − confianza; resto → confianza).
- **LAYA local (segunda opción, opt-in)**: backend `local` contra `laya-serve` (default `http://127.0.0.1:8787`, modelo `multilingual` = FT v4), mismo contrato de salida que Jev (`verdict / confidence / severity_score / immediate_action / prob_false_positive`). POST `{laya_base_url}/batch` con plantilla única y criteria en orden live (`true_positive, false_positive, noise`); `immediate action` = "yes" si P(true) >= 0.5. **Fail-safe**: si el serve local cae, degrada al camino cloud/Jev igual (y si no hay key, devuelve `skipped` con razón); nunca lanza y la auditoría nunca se rompe. Solo instancias locales (loopback validado por el backend).
- **LLM local (técnico)**: servidor OpenAI-compatible **solo loopback** (127.0.0.1/localhost/::1, sin API key). Actúa como técnico de ciberseguridad y produce, en español: por amenaza `{resumen, porque, sugerencia}` y un **resumen ejecutivo** de toda la auditoría (`resumen_ejecutivo`, `riesgo_principal`, `acciones_prioritarias[]`).
- Pulsar **Enriquecer informe con IA** genera todo y persiste dos archivos en la carpeta de la auditoría: `IA_ENRICH.json` (datos) e `IA_RESUMEN_EJECUTIVO.md` (informe legible). Al volver a abrir la auditoría, los resultados guardados se muestran automáticamente.

Configuración (solo memoria; se pierde al reiniciar el servidor):
- **Backend IA** (fila del panel): selector `cloud`/`local` + URL del serve LAYA + modelo → *Guardar*. Default: `cloud`. El modo `local` solo tiene sentido en la instancia local; el despliegue público no puede alcanzar `127.0.0.1:8787` (ahí sigue Jev).
- **Jev**: pegar API key → *Guardar Jev* → *Probar Jev*.
- **LLM local**: base URL loopback + nombre de modelo → *Guardar LLM* → *Probar LLM*. Sin GPU o modelo local: déjelo deshabilitado; nada cambia.

Reglas de seguridad: key Jev solo en memoria (maskeda en lecturas, se envía solo a `api.typesafe.ai`); LLM forzado loopback por el backend; cada fase degrada de forma independiente (ningún error rompe la vista ni el informe); sin dependencias nuevas (solo stdlib).

Endpoints: `GET/POST /api/ai/config`, `POST /api/ai/test` (`{"target": "jev"|"llm"}`; con `backend=local`, `jev` enruta al selftest local), `POST /api/ai/enrich` (`{"audit_id": ...}`), `GET /api/ai/enrich/{audit_id}`.

Tests sin red: desde `ui/` → `python -m unittest tests.test_ai_enrich -v`.

---

## Requisitos del Sistema

### Requisitos Obligatorios
- **Sistema Operativo:** Windows 10, Windows 11, Windows Server 2016/2019/2022
- **PowerShell:** Versión 5.1 o superior
- **Espacio en Disco:** Mínimo 500 MB libres (para resultados)

### Privilegios Recomendados
| Nivel de Privilegio | Información Disponible |
|---------------------|------------------------|
| **Usuario Normal** | Procesos actuales<br> Conexiones de red<br>Archivos accesibles<br> Eventos de seguridad (limitado)<br> Configuración del sistema |
| **Administrador** | **TODO lo anterior +**<br> Eventos de seguridad completos<br> Configuración de sistema<br> Logs de auditoría<br> Drivers y kernel<br> Información de todos los usuarios |

**RECOMENDACIÓN:** Ejecutar como **Administrador** para auditoría completa.

---

##  ¿Qué Analiza el Script?

El script ejecuta **10 módulos** de auditoría que cubren todas las áreas críticas:

### 1.Información del Sistema
- Sistema operativo y versión
- Hardware (CPU, RAM, discos)
- Fecha de instalación y último reinicio
- Configuración de zona horaria

### 2.  Usuarios y Permisos
- Usuarios locales y su configuración
- Cuentas sin contraseña (CRÍTICO)
- Usuarios con privilegios de administrador
- Grupos privilegiados (RDP, Backup Operators)
- Cuentas habilitadas sin uso

### 3.  Procesos y Servicios
- Procesos en ejecución con firma digital
- Procesos sin ruta de archivo (MUY SOSPECHOSO)
- Línea de comandos de todos los procesos
- Detección de comandos codificados (Base64)
- Servicios automáticos
- Patrones maliciosos (Mimikatz, Invoke-Expression, etc.)

### 4.  Red y Conexiones
- Conexiones TCP/UDP activas
- Puertos en escucha (superficie de ataque)
- Conexiones a puertos sospechosos (4444, 8080, etc.)
- Procesos del sistema con conexiones externas (CRÍTICO)
- Caché DNS (dominios visitados)
- Configuración de adaptadores de red

### 5.  Logs y Eventos de Seguridad
- Intentos de login fallidos (Event ID 4625)
- Cuentas bloqueadas (Event ID 4740)
- Eventos de PowerShell (ScriptBlock Logging)
- Comandos codificados en PowerShell
- Eventos críticos del sistema y aplicaciones

### 6.  Archivos y Persistencia
- Archivos modificados en últimas 24 horas
- Archivos ocultos sospechosos
- Persistencia en Run Keys del registro
- Tareas programadas activas
- Verificación del archivo HOSTS
- Redirecciones maliciosas en HOSTS

### 7.  Configuraciones de Seguridad
- Política de ejecución de PowerShell
- Perfiles del firewall (habilitado/deshabilitado)
- Reglas del firewall activas
- Estado de Windows Defender
- Actualización de firmas de antivirus
- Recursos compartidos de red
- Configuración de UAC (User Account Control)

### 8.  Detección de LOLBAS
(Living Off the Land Binaries - Binarios legítimos usados maliciosamente)
- Uso de certutil, regsvr32, mshta, bitsadmin
- Uso de rundll32, wmic, PowerShell con argumentos sospechosos
- Detección de técnicas de evasión

### 9.  Drivers y Módulos del Kernel
- Drivers instalados en el sistema
- Drivers sin firma digital (posibles rootkits)
- Información de proveedor y versión

### 10.  Hardware y Configuración
- Información del BIOS
- Discos físicos y su estado de salud
- Particiones y espacio disponible
- Adaptadores de red (hardware)
- Variables de entorno

---

## Estructura de Resultados

Al finalizar, el script crea una carpeta con la siguiente estructura:

```
Auditoria_fecha

  RESUMEN_EJECUTIVO.txt          ←  LEER PRIMERO
  AMENAZAS_DETECTADAS.json/csv/txt
  auditoria.log

 01_Sistema/
    informacion_sistema.[json|csv|txt]

 02_Usuarios/
    usuarios_locales.*
    administradores_locales.*
    grupo_Remote_Desktop_Users.*

 03_Procesos/
    procesos_activos.*
    procesos_sin_ruta.*           ← [!] REVISAR (SOSPECHOSO)
    procesos_con_comandos.*
    servicios.*

 04_Red/
    conexiones_tcp.*
    conexiones_establecidas.*      ← [!] REVISAR conexiones externas
    puertos_escucha.*
    udp_endpoints.*
    dns_cache.*

 05_Eventos/
    logins_fallidos.*              ← [!] REVISAR (Ataques de fuerza bruta)
    cuentas_bloqueadas.*
    powershell_scriptblock.*
    eventos_aplicacion.*
    eventos_sistema.*

 06_Archivos/
    archivos_modificados_24h.*
    archivos_ocultos_sospechosos.* ← [!] REVISAR
    persistencia_run_keys.*        ← [!] REVISAR (Persistencia)
    tareas_programadas.*
    archivo_hosts.*

 07_Configuracion/
    powershell_execution_policy.*
    firewall_perfiles.*
    firewall_reglas.*
    windows_defender.*
    recursos_compartidos.*
    uac_configuracion.*

 08_LOLBAS/
    procesos_lolbas_activos.*      ← [!] REVISAR
    eventos_lolbas.*

 09_Drivers/
    drivers_instalados.*
    drivers_sin_firma.*            ← [!] REVISAR (Posibles rootkits)

 10_Hardware/
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
| **JSON** | `.json` | Análisis automatizado<br> Integración con SIEM<br> Scripts de procesamiento |
| **CSV** | `.csv` | Análisis en Excel<br>Filtrado y ordenamiento<br> Reportes ejecutivos |
| **TXT** | `.txt` | Lectura humana<br> Revisión rápida<br> Documentación |

---

##  Interpretación de Resultados

### Niveles de Severidad

El script clasifica las amenazas en 4 niveles:

| Nivel | Icono | Significado | Acción Requerida |
|-------|-------|-------------|------------------|
| **CRITICAL** | [CRITICO] | Amenaza crítica confirmada | [!] **INVESTIGAR INMEDIATAMENTE**<br>Posible compromiso activo |
| **HIGH** | [ALTO] | Amenaza de alta prioridad | [!] **INVESTIGAR EN 24 HORAS**<br>Riesgo significativo |
| **MEDIUM** | [MEDIO] | Amenaza moderada |**INVESTIGAR EN 1 SEMANA**<br>Configuración insegura |
| **LOW** |  | Amenaza de baja prioridad | [INFO] **DOCUMENTAR**<br>Revisión recomendada |

### Ejemplos de Amenazas Detectadas

#### [CRITICO] CRÍTICAS (Acción Inmediata)
- **Proceso del sistema con conexión externa**
  - Ejemplo: `svchost.exe` conectado a IP 203.0.113.42
  - **Acción:** Investigar proceso, verificar malware
  
- **Comando codificado en PowerShell**
  - Ejemplo: `powershell.exe -enc <base64>`
  - **Acción:** Decodificar comando, analizar payload
  
- [OK] **Windows Defender deshabilitado**
  - **Acción:** Verificar si fue deshabilitado por atacante

#### [ALTO] ALTAS (Prioridad)
- **Conexión a puerto sospechoso**
  - Ejemplo: Conexión a puerto 4444 (Metasploit)
  - **Acción:** Identificar proceso, verificar C2
  
- **Proceso sin ruta de archivo**
  - Ejemplo: Proceso en memoria sin archivo en disco
  - **Acción:** Posible process injection o hollow
  
  **Usuario sin contraseña**
  - **Acción:** Establecer contraseña inmediatamente

#### [MEDIO] MEDIAS
- **Archivo ejecutable oculto**
- **Run Key con script**
- **Recurso compartido sin restricciones**

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
    -Argument "-ExecutionPolicy Bypass -File C:\Auditoria\Invoke-SecurityAudit.ps1"

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

## Allowlist local, selftest de detección y tendencia

### Allowlist (`-AllowlistPath`)

El ruido hace inservible un informe. El script trae una allowlist built-in con la
justificación de cada entrada (Splunk Web en 9999, Git Bash, Tailscale, syncthing,
Node de desarrollo, PostgreSQL local). Cada supresión se **declara** en el resumen
ejecutivo y en `auditoria.log`; no se silencia.

Una entrada suprime solo los `ThreatTypes` listados, nunca todo lo que haga el proceso:

```json
{
  "entries": [
    {
      "id": "splunk-local",
      "threatTypes": ["Puerto sospechoso en escucha"],
      "ports": [8088, 8089, 9997, 9999],
      "process": "splunkd",
      "reason": "Splunk Web y su API, no un C2"
    }
  ]
}
```

```powershell
.\Invoke-SecurityAudit.ps1 -AllowlistPath C:\audit\allowlist.json
```

La allowlist externa se **fusiona** con la built-in (no la sustituye). Una entrada debe
definir al menos `process` o `ports`.

### Selftest de detección (`-SelfTest`)

102 casos de regex, LOLBAS, direcciones privadas, MITRE, allowlist, deduplicación y
firmas. No audita nada y devuelve 1 si algún caso falla (útil en CI):

```powershell
.\Invoke-SecurityAudit.ps1 -SelfTest
```

Cubre los falsos positivos históricos: `bash -c "grep -E ..."`, `node -e`, `python -c`
no disparan "comando codificado"; solo `powershell`/`pwsh` con `-enc`.

### Tendencia entre auditorías

Cada amenaza lleva una `Signature` (SHA-256 truncada de `ThreatType + descripción sin
PID ni fechas), de modo que dos ejecuciones de la misma detección se comparan aunque
cambie el PID.

- `GET /api/trend` — serie temporal de todas las auditorías (amenazas, riesgo, suprimidas, duración).
- `GET /api/audits/{id}/trend` — diff con la auditoría anterior: amenazas nuevas, resueltas y recurrentes.
- La UI muestra una tarjeta "Tendencia frente a <anterior>" y otra con las suprimidas por allowlist.

### Baseline en SQLite (`audit_baseline.db`)

Las carpetas `Auditoria_*/` son el origen, pero no son memoria. Al arrancar, el backend
indexa todas las auditorías en `audit_baseline.db` (se regenera con el botón "Reconstruir
baseline" o `POST /api/baseline/reingest`):

- `audits`: una fila por ejecución (riesgo, amenazas, suprimidas, duración).
- `threats`: una fila por **firma única** — `first_seen`, `last_seen`, `occurrences`, `status`.
- `audit_threats`: qué firma apareció en qué auditoría.

Lo que la allowlist suprime también se registra (con su motivo) como `false_positive`: una
supresión sin trazabilidad es un hallazgo que nadie revisa.

Triage desde la pestaña **Baseline**:

| Estado | Significado |
|---|---|
| `open` | Detectado y sin revisar |
| `investigating` | Alguien lo está mirando |
| `accepted` | Riesgo conocido, se tolera |
| `false_positive` | Ruido (allowlist o triage manual) |
| `resolved` | Ya no aparece |

```powershell
# API
Invoke-RestMethod -Method Patch -Uri http://127.0.0.1:8502/api/threats/<firma>/status `
  -Body '{"status":"investigating","note":"revisar splunk web"}'
```

Pruebas: `python -m unittest ui.tests.test_baseline` (8 casos, sin dependencias).

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
- Pagina: [sammideblas.com](https://sammideblas.com)
- Email: analista@sammideblas.com


---

##  Consideraciones Legales

### Uso Autorizado
**PERMITIDO:**
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

### Versión 3.0 (2026-09-16)
- Interfaz web (FastAPI + JS vanilla) para visualizar auditorías y ejecutar nuevas con progreso en vivo
- Endpoints API: listado, detalle, módulos, ejecución y cancelación
- Modo headless con `-Headless`, `-ResultPath` y `-StatusFile`
- Archivo de estado de ejecución en `.runs/` para seguimiento en tiempo real
- Detección de severidades y nivel de riesgo en el panel general

### Versión 2.0 (2025-11-03)
- Detección avanzada de IOCs (Indicadores de Compromiso)
- Exportación multi-formato (JSON, CSV, TXT)
- Análisis de LOLBAS (Living Off the Land)
- Detección de comandos codificados
- Resumen ejecutivo con nivel de riesgo
- 10 módulos de auditoría completos
- Barra de progreso visual
- Manejo robusto de errores
- Documentación extensa con comentarios

---

##  Licencia MIT

Este script es propiedad de Sammi De Blas 

**Libre Distribucion**

---

**¿Preguntas?** Contacta al equipo de Ciberseguridad de tu empresa 




## License

MIT License -- see [LICENSE](LICENSE) for details.
