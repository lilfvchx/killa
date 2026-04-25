1. **Crear `earlybird_windows.go`** en `Payload_Type/killa/killa/agent_code/pkg/commands/`
   - Implementará `EarlyBirdCommand` para la inyección usando la técnica Early Bird.
   - Creará un proceso hijo en estado suspendido (`CREATE_SUSPENDED`), utilizando `CreateProcess` (ya sea por Win32 o usando el wrapper que usa `windows.CreateProcess`).
   - Luego, alojará memoria, escribirá shellcode y cambiará permisos (usando los wrappers de indirect syscalls `injectAllocMemory`, `injectWriteMemory`, `injectProtectMemory`).
   - Añadirá la shellcode al APC del hilo principal usando `IndirectNtQueueApcThread` (o una variante que use apcIndirect / apcStandard).
   - Finalmente, resumirá el hilo con `IndirectNtResumeThread` o `ResumeThread`.

2. **Añadir el registro en `registry_windows.go`**
   - Importar y añadir el `EarlyBirdCommand` a la lista de comandos (si no es autodescubierto, o en su defecto si lo requiere).
   - Vamos a ver cómo se registran los comandos en `registry_windows.go`.

3. **Crear `earlybird.go` y la definición de Mythic en el backend**
   - En `Payload_Type/killa/killa/agentfunctions/earlybird.go`, definir la estructura del comando (nombre "earlybird", descripción de la técnica, y argumentos: "shellcode_b64" y "process_name").

4. **Documentación de la IA (.ai)**
   - Crear el archivo `.ai/iteration_<fecha>_earlybird.md` con la justificación técnica de la primitiva.

5. **Revisar y compilar**
   - Compilar el agente (`GOOS=windows go build` en `agent_code` o la forma en que se prueba).
   - Seguir `pre_commit_instructions`.
