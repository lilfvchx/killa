# Contexto Técnico
En entornos defensivos avanzados, las soluciones EDR/XDR instalan hooks en user-mode (ej. en `kernel32!Sleep` o `ntdll!NtDelayExecution`) para monitorizar los patrones temporales de ejecución. Llamadas recurrentes o con tiempos específicos pueden ser correlacionadas para detectar comportamientos de balizamiento (beacons) o en técnicas de inyección.

# Primitiva de Innovación
Se implementa una primitiva evasiva para suspender el hilo actual (`AgentSleep`) en la arquitectura base del agente para Windows, utilizando Syscalls Indirectas para llamar a `NtDelayExecution`. La implementación se integra con el `SyscallResolver` (HalosGate) existente, esquivando de esta forma cualquier user-land hook.

# Razonamiento
Reemplazar llamadas estándar de Go como `time.Sleep()` en las ejecuciones de los comandos minimiza significativamente la superficie expuesta a análisis heurístico y profiling. Al realizar el sleep mediante una syscall indirecta, la traza de ejecución aparenta originarse directamente desde la región de memoria de `ntdll`, evadiendo la mayoría de los controles de user-mode que inspeccionan la pila de llamadas. Además, se añade una capa de resiliencia y limpieza del código base al tener una abstracción cruzada (`AgentSleep`) que se degrada de forma segura a `time.Sleep` en otros sistemas operativos.

# Cambios a Introducir
- Agregar `NtDelayExecution` al slice de `keyFunctions` en `indirect_syscalls_windows.go`.
- Implementar el wrapper `IndirectNtDelayExecution` en `indirect_syscalls_windows.go`.
- Crear el archivo `agentsleep_windows.go` y `agentsleep_other.go` con la firma de función `AgentSleep(d time.Duration)`. En Windows usará `NtDelayExecution` a través de syscall indirecta si están habilitadas, de lo contrario un fallback a `time.Sleep`.
- Refactorizar las ocurrencias de `time.Sleep` dentro de `pkg/commands/` para usar nuestra nueva primitiva `AgentSleep`.

# Validación
- Se verificará que el código compile usando `go build ./...`
- Se validarán que los tests existentes para comandos de Windows y UNIX no tengan regresiones, ejecutando `go test ./...`.
- Se revisará manualmente que el uso de `AgentSleep` fue propagado.