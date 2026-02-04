# Auditoría de Seguridad Windows (Read-Only)

Script PowerShell para auditoría **solo lectura** de servidores Windows, enfocado en seguridad, cumplimiento y visibilidad operativa.

Diseñado para ejecutarse de forma segura en **entornos productivos**, sin modificar el sistema.

---

## 🎯 Objetivo

Proporcionar una visión técnica confiable del estado de seguridad y configuración de servidores Windows para:
- Auditorías internas
- Cumplimiento normativo
- Baselines de seguridad
- Due diligence
- Inventario técnico

---

## 🛡️ Principios de seguridad

- Modo **READ-ONLY (SAFE MODE)**
- Sin modificaciones en:
  - Registro
  - Servicios
  - Políticas
  - Configuración del sistema
- Sin uso de `Invoke-Expression`
- Manejo robusto de errores y timeouts
- Evidencias con metadatos

---

## 🔍 Alcance de la auditoría

- Información del sistema operativo
- Último arranque
- Parches / Hotfixes
- Configuración de Windows Update
- Estado de Microsoft Defender
- Firewall (Domain / Private / Public)
- SMB (incluyendo SMBv1)
- RDP y NLA
- TLS / Schannel
- Políticas de auditoría (`auditpol`)
- Cuentas locales
- Hash SHA256 de los artefactos

---

## ▶️ Ejecución

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `-File "Invoke-WindowsServerAuditoriaReadOnly.ps1"
```

> La política de ejecución no se modifica globalmente.


📂 Salida
Los reportes se generan en:
```makefile
C:\Compliance\Audit\<RunId>\
```

Archivos principales:
- audit_full.json
- summary.html
- transcript.txt
- archivos .sha256

🌐 Reporte HTML
- Interfaz moderna y responsiva
- Charset UTF-8
- Indicadores visuales de estado
- Compatible con navegadores modernos

⚠️ Observaciones
- Ejecutar como Administrador para información completa
- Probar antes en entorno de pruebas
- AppLocker / WDAC puede limitar algunos comandos

📜 Licencia
- Uso interno / corporativo.
- Adaptar según la política de la organización.
