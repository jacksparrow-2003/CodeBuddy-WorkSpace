/**
 * http_client.c - Simple HTTP/1.1 GET Client Implementation
 *
 * Connects to an HTTP server over TCP. When XFRM policies are installed,
 * the Linux kernel transparently applies ESP encapsulation to these packets,
 * providing the IPsec-protected HTTP communication.
 */

#include "http_client.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define HTTP_BUF_SIZE    65536
#define HTTP_RECV_TIMEOUT 15

int http_get(const char *server_ip, int server_port,
             const char *path, const char *host_header,
             http_response_t *resp)
{
    if (!server_ip || !path || !resp) return -1;
    memset(resp, 0, sizeof(*resp));

    /* Create TCP socket */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("[HTTP] socket");
        return -1;
    }

    /* Set receive timeout */
    struct timeval tv = { .tv_sec = HTTP_RECV_TIMEOUT, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Connect to server */
    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port   = htons((uint16_t)server_port),
    };
    inet_pton(AF_INET, server_ip, &dst.sin_addr);

    printf("[HTTP] Connecting to %s:%d\n", server_ip, server_port);
    if (connect(sock, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        perror("[HTTP] connect");
        close(sock);
        return -1;
    }
    printf("[HTTP] Connected\n");

    /* Build HTTP GET request */
    char request[2048];
    int req_len = snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "User-Agent: IPsec-Client/1.0\r\n"
        "Accept: */*\r\n"
        "\r\n",
        path,
        host_header ? host_header : server_ip);

    printf("[HTTP] Sending request:\n%s", request);

    /* Send request */
    ssize_t sent = send(sock, request, req_len, 0);
    if (sent < 0 || sent != req_len) {
        perror("[HTTP] send");
        close(sock);
        return -1;
    }

    /* Receive response */
    char *buf = malloc(HTTP_BUF_SIZE);
    if (!buf) { close(sock); return -1; }

    int total = 0;
    ssize_t n;
    while (total < HTTP_BUF_SIZE - 1) {
        n = recv(sock, buf + total, HTTP_BUF_SIZE - total - 1, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;  /* Timeout */
            perror("[HTTP] recv");
            free(buf);
            close(sock);
            return -1;
        }
        if (n == 0) break;  /* Connection closed */
        total += (int)n;
    }
    buf[total] = '\0';
    close(sock);

    printf("[HTTP] Received %d bytes\n", total);

    /* Parse response */
    if (total < 12) {
        fprintf(stderr, "[HTTP] Response too short\n");
        free(buf);
        return -1;
    }

    /* Parse status line: HTTP/1.x NNN ... */
    if (sscanf(buf, "HTTP/1.%*d %d", &resp->status_code) != 1) {
        fprintf(stderr, "[HTTP] Failed to parse status line\n");
        free(buf);
        return -1;
    }

    /* Find header/body split */
    char *header_end = strstr(buf, "\r\n\r\n");
    if (header_end) {
        int hdr_len = (int)(header_end - buf);
        if (hdr_len < (int)sizeof(resp->headers)) {
            memcpy(resp->headers, buf, hdr_len);
            resp->headers[hdr_len] = '\0';
        }

        /* Body starts after \r\n\r\n */
        char *body_start = header_end + 4;
        int body_len = total - (int)(body_start - buf);
        if (body_len > 0) {
            resp->body = malloc(body_len + 1);
            if (resp->body) {
                memcpy(resp->body, body_start, body_len);
                resp->body[body_len] = '\0';
                resp->body_len = body_len;
            }
        }
    } else {
        /* No body separator found, treat all as headers */
        strncpy(resp->headers, buf, sizeof(resp->headers) - 1);
    }

    free(buf);
    return 0;
}

void http_response_free(http_response_t *resp)
{
    if (resp && resp->body) {
        free(resp->body);
        resp->body = NULL;
        resp->body_len = 0;
    }
}

void http_response_print(const http_response_t *resp)
{
    if (!resp) return;
    printf("\n========================================\n");
    printf("HTTP Response Status: %d\n", resp->status_code);
    printf("----------------------------------------\n");
    printf("Headers:\n%s\n", resp->headers);
    printf("----------------------------------------\n");
    if (resp->body && resp->body_len > 0) {
        printf("Body (%d bytes):\n", resp->body_len);
        /* Print up to 4096 bytes of body */
        int print_len = resp->body_len < 4096 ? resp->body_len : 4096;
        fwrite(resp->body, 1, print_len, stdout);
        if (resp->body_len > 4096) printf("\n... (truncated)\n");
    } else {
        printf("(No body)\n");
    }
    printf("========================================\n\n");
}
