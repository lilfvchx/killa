# Iteración: Evasive Sleep via NtDelayExecution

## Contexto Técnico
El análisis de las soluciones EDR/XDR contemporáneas revela un fuerte enfoque en la telemetría de eventos de ejecución. Las llamadas estándar a la API de Windows para suspender la ejecución (como `Sleep` de `kernel32.dll`) son puntos de monitoreo críticos para el análisis heurístico. Las sandboxes y los mecanismos de análisis dinámico a menudo hookean esta función (y su equivalente de bajo nivel `NtDelayExecution` de `ntdll.dll` a través de transiciones de usermode) para manipular el tiempo percibido (fast-forwarding) y forzar la detonación temprana de los implantes o para crear firmas de comportamiento basadas en los patrones de suspensión prolongada.

## Técnica y Primitiva
Para mitigar la detección basada en hooks de `Sleep`, esta iteración introduce una primitiva de suspensión evasiva para Windows. Reemplaza el uso estándar de `time.Sleep` (el cual el runtime de Go traduce finalmente a llamadas a la API de Windows conocidas y fácilmente detectables) por el uso del mecanismo de **Syscalls Indirectas** del agente, invocando directamente a `NtDelayExecution`.

Al usar syscalls indirectas, la transición al modo kernel ocurre desde el espacio de memoria propio de `ntdll.dll` (utilizando el gadget `syscall; ret`), evadiendo completamente los hooks en modo usuario aplicados tanto en `kernel32.dll` (para `Sleep`) como en `ntdll.dll` (para `NtDelayExecution`).

En sistemas operativos no-Windows, se implementó un fallback transparente usando `time.Sleep` normal, preservando el pilar de Resiliencia Adaptativa Multilingüe y multiplataforma.

## Razonamiento
Esta optimización apunta directamente a los pilares de **Sigilo Estructural y Minimización de Huella** y **Gestión de la Integridad del Entorno**.
Al desviar el flujo de las pausas de ejecución lejos de los flujos del sistema documentados (API hooking estándar del EDR), el agente neutraliza una capa significativa de telemetría de análisis dinámico. Asegura que los retardos programados de la comunicación C2 y los ciclos de inactividad mantengan una huella limpia, no reportable, y previene que soluciones defensivas manipulen efectivamente el reloj interno percibido por el agente a través de user-land hooks simples.

## Cambios en el Código Base
1.  **Creación de abstracción `AgentSleep`**:
    *   Se creó `pkg/commands/agent_sleep_windows.go` (con el build tag `windows`) para usar `IndirectNtDelayExecution` si las syscalls indirectas están habilitadas en el agente, con un fallback a `time.Sleep`.
    *   Se creó `pkg/commands/agent_sleep_other.go` (con el build tag `!windows`) conteniendo un simple `time.Sleep` para compatibilidad cruzada.
2.  **Expansión del resolvedor de Syscalls Indirectas**:
    *   Se actualizó `pkg/commands/indirect_syscalls_windows.go` para añadir `"NtDelayExecution"` al array `keyFunctions`.
    *   Se implementó la función envolvente (wrapper) `IndirectNtDelayExecution` para ejecutar la syscall y pasar la cantidad de tiempo a demorar (calculada en intervalos de 100 nanosegundos y en formato relativo).
3.  **Refactorización global del codebase**:
    *   Se localizó y reemplazó todas las llamadas de suspensión bloqueantes en el código base, enfocándose en la rutina principal de ejecución (`main.go`), rutinas de red y comunicación, la lógica anti-sandbox de `guardedSleep`, inyecciones Ptrace, manipulaciones PTY y lógica de comandos `spray`, para usar el nuevo `AgentSleep`.

## Validación
*   **Compilación**: Verificación cruzada exhaustiva. El código debe compilar exitosamente tanto para `GOOS=windows` (asegurando que los build tags y syscalls funcionan en su entorno objetivo) como para el host (e.g. Linux) confirmando que el agente se mantenga portátil y libre de errores en plataformas secundarias.
*   **Métricas de Evasión (Conceptuales)**: Evaluaciones dinámicas en entornos instrumentados no deberían interceptar las pausas originadas por el ciclo primario del implante una vez activado el switch de indirect syscalls. Las pruebas en sandbox no deberían ser capaces de realizar "time patching" al ignorar los saltos directos al Ring-0 provocados por `NtDelayExecution`.