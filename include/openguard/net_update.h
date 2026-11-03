/**
 * @file net_update.h
 * @brief Descarga HTTPS de actualizaciones de firmas (WinHTTP). Solo se usa cuando el usuario lo pide.
 * @details No envía información del equipo: únicamente una petición GET con el User-Agent "OpenGuard/<versión>".
 */

#pragma once

#include <cstddef>
#include <string>

namespace openguard::net {

/**
 * @brief Descarga el contenido de una URL HTTPS en memoria.
 * @param url URL completa; se rechaza cualquier esquema distinto de https.
 * @param[out] body Contenido recibido.
 * @param[out] error Descripción del fallo si devuelve false.
 * @param maxBytes Tamaño máximo aceptado (protege contra respuestas desmesuradas).
 * @param authKey Valor opcional del encabezado "Auth-Key" (p. ej. abuse.ch); vacío = no se envía.
 * @return true si la respuesta fue HTTP 200 y cabe en maxBytes.
 */
bool httpsGet(const std::string& url, std::string& body, std::string& error,
              size_t maxBytes = 64u * 1024u * 1024u, const std::string& authKey = {});

} // namespace openguard::net
