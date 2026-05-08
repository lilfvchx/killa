## Contexto Técnico
La persistencia en inyección de código es a menudo detectada al inspeccionar llamadas a APIs que escriben de forma directa sobre la memoria de procesos remotos, como `WriteProcessMemory` y `VirtualAllocEx`. Al mapear secciones compartidas (`NtCreateSection`, `NtMapViewOfSection`) en el proceso inyector y remoto, las modificaciones en la vista del inyector se reflejan automáticamente en el objetivo, evadiendo la firma clásica. Además, mediante indirect syscalls eludimos hooks en user-land (ntdll.dll).

## Innovación: Primitiva Section Mapping
Implementaremos un nuevo comando de Mythic (`section-injection`) y su lógica Go utilizando `IndirectNtCreateSection`, `IndirectNtMapViewOfSection`, `IndirectNtUnmapViewOfSection` y ejecución vía `IndirectNtCreateThreadEx`. Es decir, la escritura se hace sobre el proceso propio, lo que se sincroniza al proceso remoto bajo permisos W^X estrictos.

## Archivos
- `Payload_Type/killa/killa/agent_code/pkg/commands/indirect_syscalls_windows.go` (add syscall wrappers)
- `Payload_Type/killa/killa/agent_code/pkg/commands/sectioninjection.go` (new payload logic)
- `Payload_Type/killa/killa/agent_code/pkg/commands/registry_windows.go` (register cmd)
- `Payload_Type/killa/killa/agentfunctions/section_injection.go` (Mythic definition)
