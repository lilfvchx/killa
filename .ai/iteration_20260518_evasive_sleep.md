# Iteración: Evasive Sleep via NtDelayExecution

## Contexto Técnico

Las soluciones EDR/XDR modernas hookean de forma agresiva llamadas a la API de usuario relacionadas con pausas o retrasos en la ejecución, en particular `Sleep` y `SleepEx` de `kernel32.dll` (y subyacentemente `NtDelayExecution` de `ntdll.dll`). La monitorización de estos eventos permite a los analistas y a la telemetría detectar patrones rítmicos de beaconing, comportamientos extraños del flujo y aplicar técnicas de aceleración en sandboxes de análisis dinámico.

Actualmente, el agente Killa estaba utilizando `time.Sleep` nativo de Go. Esta función termina invocando las implementaciones dependientes del OS, siendo en Windows una llamada al ring 3 que transita por la API de alto nivel, dejando un gran rastro que compromete el sigilo de la plataforma.

## Técnica y Primitiva Implementada

Para minimizar esta huella (Structural Stealth), se ha incorporado el uso de **Indirect Syscalls** orientados a `NtDelayExecution`. Se ha generado un wrapper denominado `AgentSleep` (implementado en `sleep_evasion_windows.go`).

1. Se agregó `NtDelayExecution` al `SyscallResolver` base, forzando la extracción dinámica del número de syscall e implementando los gadgets de retorno.
2. La nueva función de evasión `IndirectNtDelayExecution` invoca al kernel directamente sin pasar por las funciones monitorizadas en user-land (bypassing the EDR hooks).
3. Como Windows usa un intervalo negativo de tiempo de 100-nanosegundos para retrasos relativos (`int64(-d.Nanoseconds() / 100)`), se respeta la semántica exacta sin introducir anomalías.
4. Para mantener la Resiliencia Adaptativa Multilingüe (Cross-Platform Execution), se usa un build tag para que en sistemas no-Windows el comportamiento retroceda a un `time.Sleep` estándar.

## Razonamiento Estratégico

Al prescindir de `time.Sleep` tradicional y utilizar `NtDelayExecution` mediante llamadas de sistema indirectas, el agente:
* Opera en un espacio fuera del radar de monitoreo (Library Sanitization).
* Protege la integridad de `guardedSleep` y de los chequeos rítmicos anti-sandbox ya que el sistema de detección dinámica no puede engancharse trivialmente a la llamada para acelerar el tiempo de espera y desencadenar el volcado de memoria prematuro.
* El entorno mantiene una huella base ínfima en línea con los pilares de I+D de operaciones ofensivas.

## Modificaciones del Código Base

1. **`Payload_Type/killa/killa/agent_code/pkg/commands/indirect_syscalls_windows.go`**: Inclusión de `NtDelayExecution` en las `keyFunctions` e implementación de la firma `IndirectNtDelayExecution`.
2. **`Payload_Type/killa/killa/agent_code/pkg/commands/sleep_evasion_windows.go`**: Implementación de `AgentSleep` haciendo la traducción a 100-nanosegundos relativos para la llamada a `NtDelayExecution`.
3. **`Payload_Type/killa/killa/agent_code/pkg/commands/sleep_evasion_other.go`**: Fallback nativo usando `time.Sleep` para plataformas distintas a Windows.
4. **`Payload_Type/killa/killa/agent_code/main.go`**: Reemplazo generalizado de las invocaciones a `time.Sleep` por `commands.AgentSleep`.

## Validación

- **Compilación Cruzada:** El cambio se compila exitosamente tanto en Windows (`GOOS=windows`) como en Linux sin errores sintácticos.
- **Flujo de Operación:** Se mantiene el flujo natural en el entry point del agente. La estructura de `guardedSleep` no está penalizada.
- **Verificación Indirect Syscalls:** Se comprueba que si no están disponibles las syscalls indirectas, el código decae suavemente y llama al `time.Sleep` sin causar panic.
