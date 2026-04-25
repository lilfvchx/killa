# Iteración: Early Bird Injection Primitiva

## Contexto Técnico
El agente `killa` actual cuenta con potentes capacidades de inyección como `apc-injection` y `thread-hijack`. Sin embargo, estas implican inyectar en procesos ya en ejecución o hilos alertables (o suspender hilos corriendo). Esto expone la ejecución a detecciones heurísticas o basadas en telemetría en tiempo de ejecución (Ej: EDRs que monitorizan el comportamiento de procesos benignos post-carga).

## La Técnica / Primitiva: Early Bird
La técnica *Early Bird Injection* aprovecha la creación de un nuevo proceso en estado suspendido (`CREATE_SUSPENDED`). Esto es ideal porque:
1. El proceso inicia un entorno de ejecución virgen antes de que bibliotecas maliciosas o hooks dinámicos a nivel usuario tengan la oportunidad de inicializarse completamente.
2. Permite el uso de inyección mediante APC (`QueueUserAPC` o `NtQueueApcThread`) apuntando al hilo principal del proceso que aún no ha arrancado.
3. Se evita el uso de primitivas altamente escaneadas como `CreateRemoteThread`.

## Razonamiento Estratégico
Adoptar "Early Bird" proporciona un nivel avanzado de resiliencia y sigilo en entornos hostiles:
- Minimiza la huella arquitectónica al usar el hilo principal del proceso recién nacido en lugar de inyectar hilos extraños.
- Facilita la adopción del esquema W^X (Write xor Execute) que ya utiliza el agente, apoyado con indirect syscalls (vía `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, y `NtProtectVirtualMemory`).

## Cambios Concretos Implementados
1. Se ha añadido `earlybird_windows.go` en `pkg/commands/`, incorporando la lógica Win32 para crear un proceso (`CreateProcessW`) con la bandera `CREATE_SUSPENDED`.
2. El comando integra el backend de llamadas indirectas de `killa` para alojar memoria, volcar la shellcode, re-asignar protecciones de memoria, y encolar la APC de ejecución en el hilo principal del proceso.
3. Se ha registrado el comando en el framework (`registry_windows.go`).
4. Se agregó la lógica backend para Mythic C2 en `agentfunctions/earlybird.go`.

## Validación
- Compilación cruzada en Windows (`GOOS=windows go build ./...`).
- Análisis de dependencias resueltas, asegurando que se integra nativamente en el resolver de indirect syscalls propio del agente y compila sin errores lógicos.
