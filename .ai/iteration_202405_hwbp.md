# Iteración: Evasión de ETW y AMSI mediante Hardware Breakpoints (HWBP) y VEH

## Contexto Técnico
Actualmente, el agente Killa neutraliza ETW (`EtwEventWrite`, `EtwEventRegister`) y AMSI (`AmsiScanBuffer`) mediante un parche estático en memoria (escribiendo un byte `0xC3` o instrucción `RET` al inicio de las funciones en `ntdll.dll` y `amsi.dll`).
Esta técnica de "module stomping" o parcheo en memoria `.text` es un vector de visibilidad altísimo. Soluciones modernas de EDR, escáneres de memoria (como pe-sieve o Moneta) y mecanismos de atestación (como NtTraceControl o comprobaciones de integridad del código) detectan fácilmente cualquier alteración en secciones ejecutables respaldadas por imagen (`MEM_IMAGE`).

## Técnica Implementada: HWBP + VEH Hooking
Para lograr **Sigilo Estructural y Minimización de Huella**, reemplazamos el parcheo en memoria estática por un gancho (hook) basado en Hardware Breakpoints (HWBP) orquestado por un Vectored Exception Handler (VEH).

### Funcionamiento:
1. **VEH Registration**: El agente registra un manejador de excepciones vectorial que intercepta excepciones tipo `EXCEPTION_SINGLE_STEP` (0x80000004).
2. **Context Manipulation (HWBP)**: En lugar de sobrescribir el código de AMSI/ETW, el agente configura los registros de depuración del hilo (`Dr0` para `EtwEventWrite`, `Dr1` para `AmsiScanBuffer`) y activa la interrupción local en el registro de control `Dr7`.
3. **Flow Redirection**: Cuando la ejecución del hilo alcanza la dirección de `EtwEventWrite` o `AmsiScanBuffer`, el procesador genera una excepción de single-step (porque el hardware breakpoint ha sido activado).
4. **Library Sanitization**: El VEH captura esta excepción. Verifica que el `ExceptionAddress` coincida con las direcciones de las funciones de ETW/AMSI.
5. **Spoofing**: Si coincide, el VEH simula la ejecución de un `RET` modificando el contexto del hilo en memoria:
   - `RIP = [RSP]` (Lee la dirección de retorno de la pila).
   - `RSP = RSP + 8` (Limpia la dirección de retorno de la pila).
   - `RAX = 0` (Para ETW) o `RAX = 0x80070057` (`E_INVALIDARG` para AMSI) u otro código de error "limpio" que indica éxito al proceso llamador sin ejecutar la lógica interna del escaneo/trazado.
6. El VEH retorna `EXCEPTION_CONTINUE_EXECUTION`, redirigiendo el flujo de ejecución hacia el llamador original sin haber ejecutado la función interceptada ni modificado un solo byte en la sección `.text` de la DLL cargada.

## Razonamiento y Ventajas Tácticas
- **Invisible a Scanners Estáticos**: La memoria de las DLLs (`ntdll.dll`, `amsi.dll`) se mantiene inmaculada. Sus hashes SHA256 y firmas digitales coinciden exactamente con la copia en disco.
- **Evasión de Telemetría**: El EDR no detecta la modificación de la protección de la memoria (`VirtualProtect` a `PAGE_EXECUTE_READWRITE` ya no es necesario).
- **Higienización Dinámica**: La evasión es efímera e intrínseca al contexto de ejecución (Thread Context), lo cual lo hace significativamente más difícil de rastrear post-mortem en análisis forenses.
- **Resiliencia Adaptativa**: Esto aplica las restricciones al thread de ejecución del agente, de forma que el proceso sigue operando "normalmente" sin alertar sobre una manipulación global que podría fallar en entornos inestables.

## Cambios Concretos en el Código Base
1. Se elimina la lógica destructiva de `VirtualProtect` e inyección de `0xC3` en `autopatch_windows.go`.
2. Se introduce la registración del VEH en el ciclo de vida inicial del agente.
3. Se redefine la lógica de parcheo para buscar las direcciones base de `AmsiScanBuffer` y `EtwEventWrite` y registrarlas en las variables globales del manejador VEH.
4. Se introduce un mecanismo para que la ejecución de cada tarea (mediante la modificación en `prepare_execution_windows.go` y la instanciación de los threads de Go) instale el contexto de HWBP (vía `SetThreadContext`) sobre el hilo subyacente que correrá comandos críticos (particularmente ensamblados de .NET y comandos de evasión).

## Validación
- **Métricas:** La sección `.text` de `amsi.dll` y `ntdll.dll` debe permanecer idéntica al archivo en disco (comprobable volcando la memoria y comparando el hash).
- **Pruebas Específicas:** Cargar el agente bajo un EDR activo o escanear su memoria con `pe-sieve` / `Moneta` y validar que no se reporten modificaciones de código (parches / in-line hooks) en AMSI o ETW. Validar adicionalmente que los tests unitarios (`go test`) continúen pasando correctamente.
