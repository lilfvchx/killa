# Iteration 20260428 - Evasive Sleep

## Contexto Técnico
Actualmente, el agente Killa usa llamadas estándar a `time.Sleep` en todo su ciclo de vida de beaconing y en los mecanismos de retry/checkin (vistos principalmente en `main.go`). En entornos de alto monitoreo, los EDRs y sandboxes monitorizan funciones de API convencionales de sleep (como `Sleep` exportado en `kernel32.dll` que llama internamente a `SleepEx` y luego a `NtDelayExecution`) para hacer fast-forwarding de tiempo, identificar métricas de beaconing rítmicas, e interceptar transiciones de ejecución.

## Técnica Propuesta
Se implementará una primitiva de **Evasive Sleep**. La técnica se basa en eludir las interfaces en espacio de usuario (`time.Sleep` de Go delega a la API del sistema operativo según GOOS) utilizando Syscalls Indirectas (Indirect Syscalls).
En Windows, se resolverá el número de syscall de `NtDelayExecution` mediante las técnicas de resolución de syscall (como TartarusGate / Halo's Gate integradas en el agente) y se invocará vía una instrucción syscall que emula el salto en el binario legítimo (`ntdll.dll`).

## Razonamiento
Esta innovación cumple con el pilar de **Sigilo Estructural y Minimización de Huella**:
1. **Evita User-Mode Hooks**: Al usar la dirección de memoria y el número de syscall nativo para saltar directo a `ntdll.dll`, la llamada no pasa por `kernel32.dll` (ni las funciones empaquetadas por la librería estándar de Go).
2. **Resiliencia Adaptativa**: Se introducirá de manera transparente y fallback (cross-platform). Si la resolución falla, o si se corre en Linux/macOS, se degradará grácilmente hacia el `time.Sleep` normal.
3. **Ofuscación de flujos de control**: Modificar las latencias del agente sin activar las alertas analíticas tradicionales en los sistemas operativos Windows modernos.

## Modificaciones en Código Base
1. **`indirect_syscalls_windows.go`**:
    - Agregar `NtDelayExecution` a la lista de `keyFunctions` a resolver de Ntdll.
    - Exportar el wrapper `IndirectNtDelayExecution` asegurando la manipulación de punteros (`*int64`) correcta para el syscall.
2. **Nuevos módulos `agentsleep_*.go` en `pkg/commands/`**:
    - Centralizarán la función multiplataforma. `AgentSleep` tomará un `time.Duration` y resolverá qué sleep utilizar bajo el hood.
3. **`main.go`**:
    - Reemplazar todas las invocaciones nativas y crudas de `time.Sleep()` en las pausas de checkin y bucles principales con `commands.AgentSleep()`.

## Validación del Éxito
- **Compilación cruzada exitosa**: Ningún error de tipos re-declarados ni dependencias (verificando builds en linux y windows).
- **Ejecución del Unit Test**: Se compilarán los test de la suite de `pkg/commands` para revisar que no haya regresiones de memoria.
- **Validación Lógica**: Ningún `time.Sleep` nativo se invocará en los componentes críticos de latencia en la compilación de Windows cuando `IndirectSyscallsAvailable()` sea cierto.