# Política de Privacidad de OpenGuard 🛡️

**Última actualización:** 2 de Noviembre de 2026  
**Repositorio Oficial:** https://github.com/WilliamsAlexis/OpenGuard

---

## 1. Compromiso de Privacidad Absoluta

OpenGuard es un proyecto de código abierto y gratuito diseñado con el principio fundamental de **Privacidad por Diseño (*Privacy by Design*)**:

1. **Análisis 100% Local**:
   - Todo el cómputo de hashes (SHA-256, SHA-1, MD5), análisis estático de binarios PE, inspección sintáctica de scripts y verificación contra la base de datos de firmas se realiza de forma **exclusivamente local** en la memoria y CPU de tu equipo.
2. **Sin Telemetría ni Rastreo**:
   - OpenGuard no recopila, no registra ni transmite métricas de uso, telemetría, identificadores de hardware, nombres de usuario ni hábitos de navegación.
3. **Sin Envío de Archivos a la Nube**:
   - Los archivos analizados nunca salen de tu ordenador. Ni tus documentos personales, ni ejecutables, ni metadatos son transmitidos a servidores de OpenGuard ni a terceros.
4. **Consultas a Servicios Externos (VirusTotal)**:
   - Cualquier consulta a servicios de terceros (como la API de VirusTotal) es **estrictamente opcional**.
   - Solo se activará si el usuario proporciona voluntariamente su propia clave de API en la configuración. Incluso en dicho caso, solo se consultan hashes criptográficos y jamás el contenido de los archivos.
5. **Aislamiento en Cuarentena**:
   - Los archivos enviados a la bóveda de cuarentena permanecen cifrados localmente en tu disco duro (`quarantine/files/`) bajo el algoritmo militar AES-256 generado con una clave exclusiva de tu instalación.

---

## 2. Descargas de Actualizaciones

Cuando OpenGuard consulta actualizaciones de firmas o reglas YARA:
- La conexión se realiza directamente mediante peticiones HTTPS hacia el repositorio público oficial en GitHub (`https://raw.githubusercontent.com/WilliamsAlexis/OpenGuard`).
- Solo se descargan listas públicas de firmas y reglas; ninguna información de tu equipo es enviada en dichas peticiones más allá del encabezado estándar de agente de usuario.

