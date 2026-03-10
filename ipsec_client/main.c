/**
 * main.c - IPsec VPN Client Main Entry Point
 *
 * Usage:
 *   sudo ./ipsec_client <server_ip> [http_port] [http_path]
 *
 * This client:
 *   1. Performs IKEv2 IKE_SA_INIT and IKE_AUTH with the server
 *      using Pre-Shared Key (PSK) authentication
 *   2. Installs ESP SA and policies into the Linux kernel XFRM subsystem
 *   3. Sends an HTTP GET request to the server (transparently ESP-protected)
 *   4. Displays the HTTP response
 *   5. Cleans up XFRM SAs and policies on exit
 *
 * Server Requirements:
 *   - strongSwan configured with IKEv2/PSK
 *   - HTTP server running on the server (e.g., nginx, Apache, or Python's http.server)
 *
 * Example strongSwan server config:
 *   See README.md
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>

#include "config.h"
#include "ikev2/ike_types.h"
#include "ikev2/ike_sa_init.h"
#include "ikev2/ike_auth.h"
#include "xfrm/xfrm_api.h"
#include "http/http_client.h"

/* Global IKE SA context for signal handler cleanup */
static ike_sa_ctx_t *g_ike_ctx = NULL;

static void cleanup_handler(int sig)
{
    printf("\n[MAIN] Caught signal %d, cleaning up...\n", sig);
    if (g_ike_ctx) {
        xfrm_uninstall_ipsec(g_ike_ctx);
    }
    exit(0);
}

/* Auto-detect local IP address for a given destination */
static int get_local_ip(const char *dest_ip, char *local_ip, int len)
{
    /* Create a UDP socket and connect to the destination to determine
     * the local interface address that would be used */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port   = htons(IKE_PORT),
    };
    inet_pton(AF_INET, dest_ip, &dst.sin_addr);

    if (connect(sock, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        close(sock);
        return -1;
    }

    struct sockaddr_in local;
    socklen_t local_len = sizeof(local);
    if (getsockname(sock, (struct sockaddr *)&local, &local_len) < 0) {
        close(sock);
        return -1;
    }

    close(sock);
    inet_ntop(AF_INET, &local.sin_addr, local_ip, len);
    return 0;
}

static void print_usage(const char *prog)
{
    printf("Usage: sudo %s <server_ip> [http_port] [http_path]\n\n", prog);
    printf("Arguments:\n");
    printf("  server_ip   IP address of the IPsec/HTTP server\n");
    printf("  http_port   HTTP server port (default: %d)\n", HTTP_SERVER_PORT);
    printf("  http_path   HTTP path to request (default: \"%s\")\n", HTTP_PATH);
    printf("\nExample:\n");
    printf("  sudo %s 10.0.0.1 80 /index.html\n\n", prog);
    printf("Note: Must be run as root (required for XFRM and raw sockets)\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "[MAIN] Error: Must run as root\n");
        return 1;
    }

    const char *server_ip = argv[1];
    int http_port = (argc >= 3) ? atoi(argv[2]) : HTTP_SERVER_PORT;
    const char *http_path = (argc >= 4) ? argv[3] : HTTP_PATH;

    printf("========================================\n");
    printf("  IPsec VPN Client - IKEv2/ESP\n");
    printf("========================================\n");
    printf("Server:    %s\n", server_ip);
    printf("HTTP Port: %d\n", http_port);
    printf("HTTP Path: %s\n", http_path);
    printf("PSK:       %s\n", PSK_VALUE);
    printf("----------------------------------------\n\n");

    /* =========================================================
     * Initialize IKE SA context
     * ========================================================= */
    ike_sa_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    strncpy(ctx.remote_ip, server_ip, sizeof(ctx.remote_ip) - 1);
    strncpy(ctx.local_id, CLIENT_ID, sizeof(ctx.local_id) - 1);
    strncpy(ctx.remote_id, SERVER_ID, sizeof(ctx.remote_id) - 1);
    ctx.local_id_type  = CLIENT_ID_TYPE;
    ctx.remote_id_type = ID_FQDN;

    /* PSK */
    strncpy(ctx.psk, PSK_VALUE, sizeof(ctx.psk) - 1);
    ctx.psk_len = (int)strlen(ctx.psk);

    /* Detect local IP */
    if (get_local_ip(server_ip, ctx.local_ip, sizeof(ctx.local_ip)) != 0) {
        /* Fallback: user must set manually */
        fprintf(stderr, "[MAIN] Warning: Could not detect local IP. "
                        "Using default.\n");
        strncpy(ctx.local_ip, DEFAULT_CLIENT_IP, sizeof(ctx.local_ip) - 1);
    }
    printf("[MAIN] Local IP: %s\n", ctx.local_ip);
    printf("[MAIN] Remote IP: %s\n", ctx.remote_ip);

    /* IKE algorithm suite */
    ctx.ike_alg.encr_id       = IKE_ENCR_ALG;
    ctx.ike_alg.encr_key_bits = IKE_ENCR_KEY_BITS;
    ctx.ike_alg.prf_id        = IKE_PRF_ALG;
    ctx.ike_alg.integ_id      = IKE_INTEG_ALG;
    ctx.ike_alg.dh_group      = IKE_DH_GROUP;
    ctx.ike_alg.is_aead       = (IKE_ENCR_ALG == ENCR_AES_GCM_16);

    /* ESP algorithm suite */
    ctx.esp_alg.encr_id       = ESP_ENCR_ALG;
    ctx.esp_alg.encr_key_bits = ESP_ENCR_KEY_BITS;
    ctx.esp_alg.integ_id      = ESP_INTEG_ALG;
    ctx.esp_alg.is_aead       = (ESP_ENCR_ALG == ENCR_AES_GCM_16);

    printf("[MAIN] IKE: ENCR=%d/%d-bit, PRF=%d, INTEG=%d, DH=%d\n",
           ctx.ike_alg.encr_id, ctx.ike_alg.encr_key_bits,
           ctx.ike_alg.prf_id, ctx.ike_alg.integ_id, ctx.ike_alg.dh_group);

    /* Install signal handlers for cleanup */
    g_ike_ctx = &ctx;
    signal(SIGINT,  cleanup_handler);
    signal(SIGTERM, cleanup_handler);

    /* =========================================================
     * Step 1: Create UDP socket for IKE
     * ========================================================= */
    ctx.udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx.udp_sock < 0) {
        perror("[MAIN] UDP socket");
        return 1;
    }

    /* Bind to IKE port (500) */
    struct sockaddr_in local_addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(IKE_PORT),
        .sin_addr.s_addr = INADDR_ANY,
    };
    if (bind(ctx.udp_sock, (struct sockaddr *)&local_addr,
             sizeof(local_addr)) < 0) {
        perror("[MAIN] bind UDP port 500");
        fprintf(stderr, "[MAIN] Hint: Port 500 may already be in use "
                        "(is strongSwan/racoon running?)\n");
        close(ctx.udp_sock);
        return 1;
    }
    printf("[MAIN] IKE socket bound to UDP port %d\n", IKE_PORT);

    /* =========================================================
     * Step 2: IKE_SA_INIT Exchange
     * ========================================================= */
    printf("\n--- Phase 1: IKE_SA_INIT ---\n");

    int retries = IKE_MAX_RETRANSMIT;
    int sa_init_ok = 0;

    while (retries-- > 0) {
        if (ike_sa_init_send(&ctx) != 0) {
            fprintf(stderr, "[MAIN] IKE_SA_INIT send failed\n");
            break;
        }
        if (ike_sa_init_recv(&ctx) == 0) {
            sa_init_ok = 1;
            break;
        }
        fprintf(stderr, "[MAIN] IKE_SA_INIT attempt failed, retrying...\n");
        /* Reset state for retry */
        if (ctx.dh_pub)    { free(ctx.dh_pub);    ctx.dh_pub = NULL; }
        if (ctx.dh_secret) { free(ctx.dh_secret); ctx.dh_secret = NULL; }
        if (ctx.msg1_raw)  { free(ctx.msg1_raw);  ctx.msg1_raw = NULL; }
        if (ctx.msg2_raw)  { free(ctx.msg2_raw);  ctx.msg2_raw = NULL; }
    }

    if (!sa_init_ok) {
        fprintf(stderr, "[MAIN] IKE_SA_INIT failed after all retries\n");
        close(ctx.udp_sock);
        return 1;
    }

    /* =========================================================
     * Step 3: IKE_AUTH Exchange
     * ========================================================= */
    printf("\n--- Phase 2: IKE_AUTH ---\n");

    if (ike_auth_send(&ctx) != 0) {
        fprintf(stderr, "[MAIN] IKE_AUTH send failed\n");
        close(ctx.udp_sock);
        return 1;
    }

    if (ike_auth_recv(&ctx) != 0) {
        fprintf(stderr, "[MAIN] IKE_AUTH failed\n");
        close(ctx.udp_sock);
        return 1;
    }

    printf("\n[MAIN] IKEv2 negotiation complete!\n");
    printf("[MAIN] Child SA - Local SPI:  0x%08x\n", ntohl(ctx.child_spi_i));
    printf("[MAIN] Child SA - Remote SPI: 0x%08x\n", ntohl(ctx.child_spi_r));

    /* =========================================================
     * Step 4: Install XFRM SA/Policies
     * ========================================================= */
    printf("\n--- Phase 3: XFRM Installation ---\n");

    if (xfrm_install_ipsec(&ctx) != 0) {
        fprintf(stderr, "[MAIN] XFRM installation failed\n");
        close(ctx.udp_sock);
        return 1;
    }

    printf("\n[MAIN] IPsec tunnel established!\n");
    printf("[MAIN] All traffic to %s will be ESP-protected\n", server_ip);

    /* Small delay to let XFRM policies take effect */
    usleep(500000);

    /* =========================================================
     * Step 5: Send ESP-protected HTTP request
     * ========================================================= */
    printf("\n--- Phase 4: ESP-Protected HTTP Request ---\n");

    http_response_t resp;
    if (http_get(server_ip, http_port, http_path, server_ip, &resp) == 0) {
        http_response_print(&resp);
        http_response_free(&resp);
        printf("[MAIN] HTTP request completed successfully via IPsec tunnel\n");
    } else {
        fprintf(stderr, "[MAIN] HTTP request failed\n");
    }

    /* =========================================================
     * Step 6: Cleanup
     * ========================================================= */
    printf("\n--- Cleanup ---\n");
    xfrm_uninstall_ipsec(&ctx);
    close(ctx.udp_sock);

    /* Free allocated buffers */
    if (ctx.dh_pub)    free(ctx.dh_pub);
    if (ctx.dh_secret) free(ctx.dh_secret);
    if (ctx.msg1_raw)  free(ctx.msg1_raw);
    if (ctx.msg2_raw)  free(ctx.msg2_raw);

    g_ike_ctx = NULL;
    printf("[MAIN] Done.\n");
    return 0;
}
