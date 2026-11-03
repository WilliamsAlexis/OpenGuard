# Guía de Contribución para OpenGuard 🛡️

¡Gracias por tu interés en contribuir a **OpenGuard**! Este proyecto tiene como objetivo construir un antivirus moderno, defensivo y transparente para Windows 10 y 11 desarrollado íntegramente en **C++20**.

---

## 1. Principios de Seguridad del Código

OpenGuard es una herramienta de ciberseguridad; por lo tanto, la seguridad de la memoria y la robustez contra vulnerabilidades son la máxima prioridad:

1. **Gestión de Memoria y RAII**:
   - Prohibido el uso de punteros crudos propietarios (`new`/`delete` manuales). Usa siempre `std::unique_ptr` o `std::shared_ptr`.
   - Todos los recursos del sistema operativo (handles de Windows, proveedores BCrypt, conexiones SQLite, archivos abiertos) deben liberarse mediante destructores RAII.
2. **Prevención de Desbordamientos de Búfer**:
   - Usa `std::vector`, `std::string` o `std::array` con verificación de límites en lugar de arreglos C crudos.
   - Prohibidas funciones inseguras de la biblioteca estándar de C como `strcpy`, `sprintf` o `gets`.
3. **Estándar C++20 y Advertencias**:
   - Todo el código debe compilar limpiamente bajo MSVC 2022 con `/W4` y `/permissive-` sin generar advertencias.
4. **Idioma de los Comentarios**:
   - **Obligatorio**: Todos los comentarios, documentación Doxygen (`@brief`, `@param`, `@return`), mensajes de log y cadenas de salida para el usuario deben estar redactados en **español**. Los nombres de identificadores (clases, métodos, variables) se redactan en inglés técnico estándar (camelCase o PascalCase).

---

## 2. Flujo de Desarrollo

1. Realiza un **Fork** del repositorio oficial: `https://github.com/WilliamsAlexis/OpenGuard`.
2. Clona tu bifurcación localmente:
   ```powershell
   git clone https://github.com/TU_USUARIO/OpenGuard.git
   cd OpenGuard
   ```
3. Crea una rama descriptiva para tu característica o corrección:
   ```powershell
   git checkout -b feature/nueva-heuristica
   ```
4. Realiza tus cambios asegurando la inclusión de pruebas unitarias correspondientes en `tests/`.
5. Ejecuta la suite de pruebas unitarias con Google Test:
   ```powershell
   ctest --test-dir build -C Release --output-on-failure
   ```
6. Haz commit de tus cambios con mensajes claros:
   ```powershell
   git commit -m "feat(heuristics): add entropy threshold check for PE overlays"
   ```
7. Envía tus cambios a tu repositorio y abre un **Pull Request** detallando:
   - Descripción de la mejora o vulnerabilidad resuelta.
   - Metodología de prueba aplicada.
   - Confirmación de pase de la suite de pruebas en Windows 10/11.

---

## 3. Reporte de Vulnerabilidades

Si descubres una vulnerabilidad de seguridad en OpenGuard, por favor no abras un issue público. Envía un correo con los detalles técnicos a los mantenedores del proyecto para coordinar una divulgación responsable.

