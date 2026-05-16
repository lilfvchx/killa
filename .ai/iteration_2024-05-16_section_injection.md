# Iteración: Section-based Injection
**Fecha:** 16 de Mayo de 2024
**Feature:** Section-based Memory Injection (NtCreateSection)

## Contexto Técnico
En la investigación constante sobre primitivas de inyección evasiva y redirección de flujo, se ha observado que la utilización de las APIs convencionales para escribir memoria en procesos remotos (`WriteProcessMemory` o `NtWriteVirtualMemory`) se encuentra fuertemente monitoreada y produce firmas heurísticas altas en las soluciones modernas de telemetría (EDR/XDR).

## Técnica y Primitiva Implementada
Para minimizar esta huella (Minimización de Huella), se ha implementado la inyección de código utilizando objetos *Section* de Windows. Esta técnica evita por completo la necesidad de escribir explícitamente en la memoria del proceso remoto.

El flujo es el siguiente:
1. `NtCreateSection`: Se crea un objeto de sección de memoria apoyado en el archivo de paginación (`PAGE_EXECUTE_READ`).
2. `NtMapViewOfSection` (Local): Se mapea dicha sección en el proceso local del agente Killa (en el espacio de direcciones propio) con permisos `PAGE_READWRITE`.
3. Al estar mapeado localmente, copiamos la carga útil (shellcode) a la memoria simplemente utilizando el gestor de memoria interno (`copy()` en Go).
4. `NtMapViewOfSection` (Remoto): Luego de escribirse localmente la información compartida, la sección se mapea en el proceso objetivo, con los permisos estrictamente necesarios `PAGE_EXECUTE_READ`.
5. Se procede a limpiar la vista local con `NtUnmapViewOfSection`.
6. Finalmente, se inicia la ejecución remota con un hilo (usando el existente indirect syscall `NtCreateThreadEx`).

## Razonamiento (Alineación con los Pilares)
- **Sigilo Estructural y Minimización de Huella**: Al aprovechar secciones compartidas, las lecturas/escrituras cruzadas (`NtWriteVirtualMemory`) son evitadas, eludiendo callbacks comunes de monitoreo en la transición a ring-0 que interceptan escrituras directas.
- **Gestión de la Integridad del Entorno (Library Sanitization)**: Como beneficio secundario, todas las llamadas al API mencionadas (NtCreateSection, NtMapViewOfSection, NtUnmapViewOfSection) están orquestadas mediante syscalls indirectos (TartarusGate/Halo's Gate), que resuelven dinámicamente y se ejecutan eludiendo los hooks ubicados en las bibliotecas (ntdll.dll) locales del entorno en user-space.

## Cambios Concretos en el Código
- `pkg/commands/indirect_syscalls_windows.go`: Se registraron tres nuevas llamadas de bajo nivel en el slice `keyFunctions`: `NtCreateSection`, `NtMapViewOfSection`, y `NtUnmapViewOfSection`. Adicionalmente, se generaron las funciones *wrapper* fuertemente tipadas en Go.
- `pkg/commands/section_injection_windows.go`: Se creó el módulo del comando `SectionInjectionCommand`, que toma el Base64 de la carga y el PID, ejecutando la orquestación antes descrita.
- `pkg/commands/registry_windows.go`: Registro del nuevo módulo de comando en el array de comandos Windows-specific.
- `agentfunctions/sectioninjection.go`: Integración al frontend de MythicC2 de la función (registrando parámetros requeridos como el archivo del shellcode y PID objetivo).

## Validación
- **Métricas de Éxito**:
    - Compilación finalizada exitosamente para la plataforma de destino Windows en la arquitectura Go `agent_code`.
    - Compilación finalizada exitosamente del frontend de la plataforma operativa (Mythic) `agentfunctions`.
- **Comportamiento Esperado**: Durante la ejecución, el agente debe reportar exitosamente la creación de la sección, mapeo local en su memoria, copiado del shellcode, mapeo en el proceso remoto, unmap de la vista local, y exitosa ejecución del thread remoto, sin invocar APIs de inyección directas.
