# Iteración: Inyección de Procesos mediante Mapeo de Secciones (Section Mapping Injection)

## Contexto Técnico
En la búsqueda continua por minimizar la huella de detección y evadir las heurísticas modernas de las soluciones EDR/XDR, los métodos clásicos de inyección de código (como los que dependen de `VirtualAllocEx`, `WriteProcessMemory` y `VirtualProtectEx`) se han vuelto altamente detectables. La monitorización en modo usuario y las devoluciones de llamadas (callbacks) en el kernel a menudo se activan mediante secuencias predecibles de lectura/escritura y cambios de protección en la memoria interprocesos.

## Técnica Implementada: Section Mapping Injection
Para mitigar esto, se ha implementado la inyección mediante mapeo de secciones de memoria utilizando System Calls indirectos (Indirect Syscalls) para evitar los hooks en userland (`ntdll.dll`).

Las primitivas utilizadas son:
- `NtCreateSection`: Crea un objeto de sección de memoria respaldado por el archivo de paginación (pagefile).
- `NtMapViewOfSection`: Mapea una vista de esta sección tanto en el proceso local (con permisos de Lectura/Escritura - RW) como en el proceso objetivo (con permisos de Ejecución/Lectura - RX).
- `NtUnmapViewOfSection`: Desmapea la vista local una vez que el payload ha sido copiado.

## Razonamiento y Ventajas de Sigilo
Esta técnica presenta varias ventajas operativas fundamentales:
1. **Ausencia de `WriteProcessMemory`:** Al escribir el shellcode en la vista local de la sección compartida, los cambios se reflejan automáticamente en la memoria del proceso objetivo. Esto omite completamente la necesidad de invocar APIs de escritura interprocesos.
2. **Cumplimiento estricto de W^X:** En ningún momento la memoria tiene permisos simultáneos de Escritura y Ejecución (RWX). El payload se escribe en el proceso local con permisos RW y se ejecuta en el proceso remoto con permisos RX. Esto evade alarmas heurísticas asociadas a transiciones de memoria.
3. **Evasión de Hooks de API:** Utilizando syscalls indirectos (como TartarusGate / Halo's Gate implementado en `killa`), evitamos que los EDR intercepten las llamadas en modo usuario.
4. **Resiliencia Operativa:** La utilización de secciones respaldadas por el archivo de paginación es un comportamiento común y legítimo en el ecosistema Windows (ej. carga de DLLs, comunicación IPC), lo que permite que nuestra actividad se camufle eficientemente.

## Modificaciones en el Código Base
- **Syscalls Indirectos:**
  - Archivo: `Payload_Type/killa/killa/agent_code/pkg/commands/indirect_syscalls_windows.go`
  - Cambios: Se agregaron las definiciones y wrappers para `NtCreateSection`, `NtMapViewOfSection` y `NtUnmapViewOfSection`.
- **Nuevo Comando de Inyección:**
  - Archivo: `Payload_Type/killa/killa/agent_code/pkg/commands/sectioninjection.go`
  - Cambios: Implementación del comando `section-mapping` con toda la lógica de orquestación (crear sección, mapear local RW, copiar payload, desmapear local, mapear remoto RX, crear hilo).
- **Registro del Comando:**
  - Archivo: `Payload_Type/killa/killa/agent_code/pkg/commands/registry_windows.go`
  - Cambios: Registro de la estructura `SectionInjectionCommand`.
- **Función en el Backend de Mythic:**
  - Archivo: `Payload_Type/killa/killa/agentfunctions/sectioninjection.go`
  - Cambios: Creación de la interfaz de usuario y procesamiento de argumentos para el C2.

## Validación del Éxito
- **Métricas:** Compilación exitosa tanto en el agente (`GOOS=windows go build`) como en las funciones del servidor Mythic.
- **Pruebas:** Ejecución exitosa de test sin activar bloqueos o pánicos y validación del paso de los tests definidos en pre-commit.
- **Comportamiento Esperado:** Inyección de shellcode funcional en un PID objetivo sin utilizar `WriteProcessMemory`, verificable mediante instrumentación o análisis dinámico.