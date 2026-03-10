/**
 * http_client.h - Simple HTTP/1.1 Client
 *
 * Provides functions to build HTTP GET requests and parse HTTP responses
 * over an established TCP connection.
 *
 * When used with XFRM IPsec policies in place, the kernel automatically
 * wraps all matching traffic with ESP, making this a transparent
 * IPsec-protected HTTP client.
 */

#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <stdint.h>

typedef struct {
    int    status_code;      /* HTTP status code (200, 404, etc.) */
    char   headers[4096];    /* Response headers */
    char  *body;             /* Response body (dynamically allocated) */
    int    body_len;
} http_response_t;

/**
 * Send an HTTP GET request and receive the response.
 *
 * @param server_ip   Target server IP
 * @param server_port Target server port
 * @param path        HTTP path (e.g., "/" or "/index.html")
 * @param host_header Host header value
 * @param resp        Output: HTTP response (caller must free resp->body)
 * @return            0 on success, -1 on failure
 */
int http_get(const char *server_ip, int server_port,
             const char *path, const char *host_header,
             http_response_t *resp);

/**
 * Free resources allocated in http_response_t.
 */
void http_response_free(http_response_t *resp);

/**
 * Print HTTP response summary.
 */
void http_response_print(const http_response_t *resp);

#endif /* HTTP_CLIENT_H */
