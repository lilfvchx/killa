# Iteración: Implementación de Section Injection a través de llamadas al sistema indirectas (Indirect Syscalls)

## Contexto Técnico
Las técnicas tradicionales de inyección de procesos, como las que utilizan `VirtualAllocEx` y `WriteProcessMemory`, son comúnmente monitoreadas por las soluciones de detección y respuesta de endpoints (EDR). Los ganchos (hooks) en el modo de usuario, comúnmente colocados en las APIs exportadas de bajo nivel (por ejemplo, `NtAllocateVirtualMemory` o `NtWriteVirtualMemory`), son especialmente agresivos para los patrones típicos.

Para mantener la eficacia de la herramienta ofensiva, es fundamental la diversificación de las técnicas de asignación y escritura. El uso de "Section Objects" o asignación de memoria compartida para escribir y ejecutar código malicioso en procesos remotos evade la dependencia directa en escrituras remotas evidentes de procesos que normalmente activan alertas.

## Primitiva Implementada
Esta iteración introduce un módulo de inyección de proceso basado en objetos de sección, utilizando el patrón de Windows Internals de `NtCreateSection` y `NtMapViewOfSection`. Específicamente, este enfoque:

1.  Abre un proceso destino vía `NtOpenProcess`.
2.  Crea un nuevo objeto de sección respaldado por el archivo de paginación (`NtCreateSection`).
3.  Crea una vista (mapping) de esta sección en el propio proceso (con permisos locales Read/Write - `PAGE_READWRITE`).
4.  Crea una segunda vista de la misma sección en el proceso destino remoto (con permisos Execute/Read - `PAGE_EXECUTE_READ`).
5.  Copia la carga útil (shellcode) a la vista mapeada localmente. Esto hace que se refleje inmediatamente en el proceso remoto sin llamar a `WriteProcessMemory`.
6.  Lanza la ejecución de la sección mapeada remotamente (mediante `NtCreateThreadEx` indirecto o con reserva en API estándar).

Además de incorporar esta lógica, las tres primitivas se resolvieron a través de llamadas de sistema indirectas integrándose al mecanismo existente (`SyscallResolver`).

## Razonamiento
El uso de objetos de sección elude detecciones centradas en la API `NtWriteVirtualMemory` ya que la memoria se modifica indirectamente al escribir en un búfer que internamente la administra el sistema operativo.

Al delegar todas estas operaciones a través de syscalls indirectas, se impide que los EDR observen e intercepten el flujo de control, manteniendo un perfil acústico ultrabajo en los procesos host (eludiendo User-land API hooking). Todo fluye como un comportamiento orgánico de llamadas ejecutadas en el contexto nativo.

## Modificaciones del Código Base
-   `indirect_syscalls_windows.go`: Se añadieron los syscalls "NtCreateSection", "NtMapViewOfSection", "NtUnmapViewOfSection" al bloque `keyFunctions` para su carga estática y se programaron las envolturas funcionales (`IndirectNtCreateSection`, etc.).
-   `sectioninjection.go`: Implementación de la nueva función remota del agente `section-injection`. Usa W^X y llamadas al sistema evasivas.
-   `registry_windows.go`: Se registró `SectionInjectionCommand{}`.
-   `agentfunctions/sectioninjection.go`: Creación de la capa para integrar el comando nativamente en la Interfaz de Mythic.

## Validación
-   **Pruebas unitarias/Validación de Compilación**: Se ha compilado correctamente (`go build ./...`) validando la tipificación en Windows (`GOOS=windows go build`).
-   **Metricas Claves**: En la evaluación del flujo, se espera que el agente cree una sección del sistema reflejada sin intercepciones en modo de usuario sobre los métodos de inyección conocidos.
