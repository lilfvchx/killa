# Iteración: Evasión Avanzada de Hooking en Sleep (NtDelayExecution)

## Contexto Técnico
Muchos productos de seguridad (EDR/AV) instalan hooks en modo usuario en funciones como `Sleep` (en `kernel32.dll`) o `SleepEx`, `NtDelayExecution` en `ntdll.dll`. Monitorear los tiempos de inactividad de un proceso es una heurística clave; si un subproceso duerme sistemáticamente por periodos fijos o anómalos, puede ser catalogado como un beaconing de C2. Adicionalmente, el hooking les permite interceptar estas llamadas para realizar un análisis del Call Stack.

Actualmente, el agente usa `time.Sleep` de Go, que a bajo nivel termina invocando las implementaciones estándar del sistema. Al hacerlo a través del flujo tradicional, queda expuesto a estas métricas heurísticas y hooks.

## Técnica/Primitiva
Se ha introducido el uso de **Indirect Syscalls** para delegar la pausa del hilo. Específicamente, se ha añadido soporte para `NtDelayExecution` mediante una llamada de sistema indirecta (`syscall; ret` gadget).

Al invocar `IndirectNtDelayExecution` desde el resolver de syscalls indirectos (en sistemas Windows), el agente salta directamente al gadget ubicado en la memoria de `ntdll.dll` tras preparar los registros (`r10 = rcx`, `eax = SyscallNumber`).

## Razonamiento
El uso de una llamada indirecta al sistema operativo en lugar de la API Win32 pública:
- Evita la intercepción y logging (user-mode hooks) de los sistemas de seguridad. El salto al gadget `syscall` se realiza en un punto limpio de `ntdll.dll`, después de los hooks insertados comúnmente en el preámbulo de las funciones.
- Protege la latencia y métricas de beaconing del agente; las EDR tendrán más dificultades para reconstruir con precisión el comportamiento temporal y los ciclos de inactividad.
- Refuerza la resiliencia adaptativa al no depender de wrappers en los que puedan inyectarse trampolines para análisis.

## Cambios en el código base
- **`indirect_syscalls_windows.go`**: Se añadió `NtDelayExecution` a la matriz de funciones resolubles (`keyFunctions`) y se generó un wrapper en Go `IndirectNtDelayExecution` que mapea la llamada a sistema a través de las stubs (RX memory) autogeneradas.
- **`agent_sleep_windows.go` / `agent_sleep_other.go`**: Se creó la función centralizada `commands.AgentSleep(d time.Duration)` y las lógicas multi-plataforma. Si las llamadas indirectas están disponibles en Windows, usa `IndirectNtDelayExecution` enviando el tiempo en intervalos de 100 nanosegundos (formato NTSTATUS). Para otros OS, realiza fallback natural a `time.Sleep`.
- **Comandos y Main (`exec_helpers.go`, `main.go`, `spray.go`, `ptrace_inject.go`, `watch_dir.go`)**: Refactorización profunda reemplazando `time.Sleep` nativo con `AgentSleep`.

## Validación
- Pruebas cruzadas usando directivas `GOOS=windows` para verificar que la invocación directa a la syscall respeta los tipos (`int64`, `bool`).
- Verificación de que el resto de plataformas (Linux/Darwin) compilen la versión del wrapper benigno sin problemas (`agent_sleep_other.go`).
- Testing general en binario final asegurando que el C2 duerme en los intervalos correctos definidos por `sleep` y `jitter` en su loop de comunicación primario y secundario.