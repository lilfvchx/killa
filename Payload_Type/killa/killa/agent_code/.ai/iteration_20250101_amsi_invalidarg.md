# Iteración: Evasión Avanzada de AMSI (E_INVALIDARG)

## Contexto Técnico
En la inicialización del CLR (Command `start-clr`) y en el auto-patching al inicio del agente, se implementa una evasión de telemetría y seguridad mediante la técnica de "Ret Patch" contra `amsi.dll!AmsiScanBuffer` y `ntdll.dll!EtwEventWrite`/`EtwEventRegister`.

La implementación previa para todos los casos usaba la inyección de un único byte `0xC3` (instrucción `ret`). Mientras que esto funciona perfectamente para ETW (`EtwEventWrite` retorna `STATUS_SUCCESS` o `0`), para `AmsiScanBuffer` puede generar inestabilidades. `AmsiScanBuffer` espera retornar un `HRESULT`. Si simplemente se hace un `ret`, el valor de retorno de la función será el valor residual que se encuentre en el registro `RAX`. Si ese valor no es evaluado por el CLR como un éxito (ej. `S_OK`) o un error específico manejado (ej. `E_INVALIDARG`), el CLR podría fallar, abortar la carga del ensamblado y lanzar una excepción de formato inválido (o alertar).

## Técnica/Primitiva
La técnica implementada mejora el "Ret Patch" de `AmsiScanBuffer` para que la función retorne explícitamente `E_INVALIDARG` (`0x80070057`).
La CLR de .NET maneja el error `E_INVALIDARG` devuelto por AMSI asumiendo que el escaneo no se pudo realizar por argumentos inválidos (un comportamiento benigno esperado en ciertos contextos de falla) y permite la carga del ensamblado en memoria, omitiendo silenciosamente el análisis.

El byte pattern inyectado es:
```assembly
mov eax, 0x80070057
ret
```
Opcode: `B8 57 00 07 80 C3` (6 bytes).

## Razonamiento
Devolver un error controlado como `E_INVALIDARG` previene excepciones en tiempo de ejecución (crash de la CLR) y mejora el sigilo al evitar que la falta de un resultado limpio (`AMSI_RESULT_CLEAN`) active detecciones heurísticas en la telemetría del proceso.

## Cambios en el código base
Se han modificado dos archivos principales:
1. `Payload_Type/killa/killa/agent_code/pkg/commands/retpatch.go`: Modificada la función `PerformRetPatch` para soportar la inyección de 6 bytes en lugar de 1, y distinguir la carga útil si el nombre de la función objetivo es `AmsiScanBuffer`.
2. `Payload_Type/killa/killa/agent_code/autopatch_windows.go`: Modificada la función `patchFunctionEntry` de la misma manera para proteger el inicio del agente.

## Validación
- `go build` en entornos Windows para garantizar que la expansión de memoria virtual funciona correctamente sin errores de compilación.
- Pruebas unitarias de Go para verificar que los cambios no rompen las dependencias internas.
- Pruebas de ejecución cruzada para validar la integridad del diseño.