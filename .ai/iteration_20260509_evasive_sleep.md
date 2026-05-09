# Iteración: Implementación de Sleep Evasivo vía NtDelayExecution (Indirect Syscalls)

**Fecha:** 2026-05-09
**Feature:** Evasive Sleep via NtDelayExecution

## Contexto Técnico
En la arquitectura anterior, el agente `killa` utilizaba la función estándar de Go `time.Sleep` para manejar las pausas y esperas durante el ciclo de vida (beaconing y evasión por sandbox guard). El uso de primitivas estándar expone al agente al monitoreo de las APIs de Windows en modo de usuario (`Sleep`, `SleepEx`), las cuales a menudo están instrumentadas o "enganchadas" (hooked) por las soluciones de EDR/XDR para identificar comportamientos maliciosos (por ejemplo, pausas programadas sospechosas) o realizar el escaneo de memoria tras el regreso de la pausa.

## Técnica y Primitiva Implementada
Para evadir los hooks de modo de usuario y minimizar el riesgo de detección por comportamiento temporal, se ha reemplazado la implementación del Sleep estándar en la plataforma de Windows por un sleep evasivo que hace uso de llamadas al sistema indirectas (Indirect Syscalls) apuntando a `NtDelayExecution`.

### Detalles de Windows Internals
- `NtDelayExecution`: Es la función interna de bajo nivel exportada por ntdll.dll que sirve de base para todas las funciones de suspensión a nivel de usuario (Win32 API `Sleep` y similares).
- Requiere como parámetro un puntero a `LARGE_INTEGER` donde un valor negativo especifica un intervalo de tiempo relativo en unidades de 100 nanosegundos.
- A través del mecanismo existente de `indirect_syscalls_windows.go` (SyscallResolver y llamadas `syscall.SyscallN`), se puede resolver y ejecutar `NtDelayExecution` de forma directa pasando por encima de cualquier hook de EDR en `Sleep`, invocando a la llamada al kernel correspondiente (SYSCALL) sin tocar el código monitoreado a nivel de usuario.
- En la inicialización y uso de la función en la máquina virtual o API de Go en la rama de compilación `windows`, se pasa el tiempo en la unidad requerida multiplicando/dividiendo desde `time.Duration` o `Nanoseconds`.

## Razonamiento
El cambio otorga un beneficio múltiple:
1. **Sigilo de Comportamiento:** Permite que las operaciones temporales se difuminen en llamadas nativas o en los registros puros del kernel, dejando inactivos los medidores basados en la API estándar.
2. **Resiliencia (Cross-platform):** Al implementar el bloque usando los tags de compilación en Go (`//go:build windows` y `//go:build !windows`), la ejecución no cambia ni produce errores en Linux, macOS o sistemas ajenos a las dinámicas de NT.

## Cambios en Código Base
- Modificación en `indirect_syscalls_windows.go` para añadir `"NtDelayExecution"` al registro de resolución dinámica de syscalls.
- Creación de la envoltura de ejecución en Go:
  - `agent_sleep_windows.go`: Llama a `IndirectNtDelayExecution` calculando intervalos de 100ns de forma relativa y manejando los fallos para que haga fallback de manera transparente en un `time.Sleep`.
  - `agent_sleep_other.go`: Sirve a cualquier otro sistema usando `time.Sleep` nativo.
- Modificación de los lugares estratégicos en el corazón del framework (`main.go`) en `guardedSleep` y en el lazo principal de beaconing sustituyendo llamadas estandarizadas con el recién diseñado wrapper `commands.AgentSleep`.

## Validación del Éxito
- **Compilación Correcta:** La compilación y cruzada debe suceder sin problemas tanto en Linux (`GOOS=linux`) como en Windows (`GOOS=windows`).
- **Pass TestSuite:** Ejecutar todo el grupo de pruebas de la arquitectura existente en `pkg/commands/` y en la raíz del entorno sin timeouts o panics de cross-compilación.
- **Funcionamiento Dinámico (Expectativa):** En el ciclo dinámico regular (si se inspecciona bajo EDR), no debe haber llamadas directas por parte del runtime y la telemetría de pausas se observará disipada.