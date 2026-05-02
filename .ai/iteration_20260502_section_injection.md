# Iteration: Section-Based Remote Process Injection (NtCreateSection / NtMapViewOfSection)

## Contexto Técnico
Actualmente, las técnicas de inyección en el agente (Vanilla, APC, PoolParty) dependen fuertemente de funciones como `NtAllocateVirtualMemory` y `NtWriteVirtualMemory`. Estas llamadas, incluso cuando se ejecutan a través de syscalls indirectos (como ya implementa el agente), suelen dejar artefactos rastreables y pueden ser monitoreadas estrechamente por el subsistema de telemetría del EDR (ej. callbacks `ObRegisterCallbacks` o `PsSetCreateThreadNotifyRoutine` combinados con escaneos de memoria para patrones RWX/RW->RX).

Una alternativa mucho más sigilosa y robusta para la asignación y escritura de memoria entre procesos es el uso de **Section Objects** (Secciones). En Windows, las secciones se utilizan fundamentalmente para la compartición de memoria (shared memory).

## Primitiva y Conceptos de Windows Internals
El enfoque de inyección basado en Secciones funciona de la siguiente manera:
1.  **`NtCreateSection`**: Crea un nuevo objeto de sección respaldado por el archivo de paginación (pagefile) en lugar de un archivo específico.
2.  **`NtMapViewOfSection` (Proceso Local)**: Mapea la sección en el espacio de memoria del proceso del agente (Killa) con permisos RW (Read-Write).
3.  **Escritura (Local)**: Se escribe la shellcode directamente en el mapeo de memoria local (sin usar `NtWriteVirtualMemory` en el proceso remoto). Al estar respaldada por la sección, esta escritura afecta al objeto compartido.
4.  **`NtMapViewOfSection` (Proceso Remoto)**: Mapea *el mismo objeto de sección* en el espacio de memoria del proceso objetivo con permisos RX (Read-Execute). Como el contenido ya fue escrito localmente, el proceso remoto automáticamente ve el shellcode.
5.  **Ejecución**: Se utiliza un mecanismo estándar para la ejecución (ej. `NtCreateThreadEx` apuntando a la dirección base mapeada en el proceso remoto).
6.  **`NtUnmapViewOfSection`**: Se desmapea la vista local.

## Razonamiento
Esta técnica mejora el sigilo y la resiliencia:
*   **Evasión de `NtWriteVirtualMemory`**: Elimina por completo la necesidad de escribir explícitamente en el proceso remoto. El mapeo local y remoto maneja la transferencia a nivel del Kernel/Memory Manager.
*   **W^X Robusto**: La memoria en el proceso remoto *nunca* es RW. Se mapea directamente como RX, lo que evita que los escáneres de EDR detecten la transición sospechosa RW -> RX.

## Cambios en el Código Base
1.  **`indirect_syscalls_windows.go`**:
    *   Agregar `NtCreateSection`, `NtMapViewOfSection`, y `NtUnmapViewOfSection` a `keyFunctions`.
    *   Implementar las funciones wrapper `IndirectNtCreateSection`, `IndirectNtMapViewOfSection`, e `IndirectNtUnmapViewOfSection`.
2.  **`sectioninjection.go`**:
    *   Crear un nuevo comando `section-injection`.
    *   Implementar la lógica descrita para crear la sección, mapear localmente (RW), copiar shellcode, mapear remotamente (RX), crear el hilo remoto (`IndirectNtCreateThreadEx`), y limpiar (desmapear localmente y cerrar handles).
3.  **`registry_windows.go`**:
    *   Registrar el comando `SectionInjectionCommand`.
4.  **`Payload_Type/killa/killa/agentfunctions/sectioninjection.go`**:
    *   Registrar la definición del comando en el framework de Mythic.

## Validación
*   Compilación exitosa (agente y lado de Mythic).
*   Revisión del código para asegurar el uso correcto de indirect syscalls.
