# Contexto Técnico
La evasión de análisis de comportamiento (Behavioral Analysis) por parte de soluciones EDR (Endpoint Detection and Response) es fundamental para mantener el sigilo. Una técnica común de los EDR es interceptar funciones API de Windows de bajo nivel (como `Sleep` en `kernel32.dll` o `SleepEx` en `KernelBase.dll`) para identificar patrones temporales, inyecciones en memoria e identificar C2 beacons.

# Técnica Implementada
Se implementó un mecanismo de "Evasive Sleep" o "Sueño Evasivo" utilizando `Indirect Syscalls`. En lugar de llamar a las APIs estándar `Sleep` o `SleepEx`, el agente interactuará directamente con `NtDelayExecution` mediante llamadas al sistema indirectas.
1. Se envuelve la funcionalidad de `time.Sleep` en un nuevo método `AgentSleep` que utiliza las diferentes implementaciones del sistema operativo.
2. En Windows, si `IndirectSyscallsAvailable()` es verdadero, se resuelve y ejecuta `NtDelayExecution` con los parámetros correspondientes en lugar de las llamadas al framework habitual.
3. Se reemplazaron las llamadas directas a `time.Sleep` por `AgentSleep` en todo el flujo de comandos que usan temporizadores para la ejecución y evasión en tiempo de compilación.

# Justificación y Beneficios
Evadir el monitoreo en llamadas base de Windows a través del sistema indirecto garantiza:
*   Evadir el hooking (intercepción) de EDR que analiza las llamadas y tiempos en los sistemas de tiempo de espera (`Sleep`).
*   Desactivar huellas temporales en la capa user-mode estándar.

# Cambios Realizados
*   `sleep_evasion_windows.go`: Implementa `AgentSleep` llamando a `IndirectNtDelayExecution` en Windows.
*   `sleep_evasion_other.go`: Implementa `AgentSleep` usando `time.Sleep` en otros sistemas operativos.
*   `indirect_syscalls_windows.go`: Define la nueva función contenedora `IndirectNtDelayExecution` y añade `NtDelayExecution` a los arreglos de inicialización para resolución indirecta.
*   Se refactorizaron 25+ lugares en `pkg/commands/*.go` que usaban `time.Sleep` para que utilicen la nueva envoltura `AgentSleep`.

# Validación
*   Todos los tests unitarios en Windows y Linux pasan satisfactoriamente.
*   En la carga del agente en sistemas Windows, este bypass de Sleep/SleepEx funcionará cuando la inicialización de indirect syscalls tenga éxito y se logre enlazar con NtDelayExecution.
