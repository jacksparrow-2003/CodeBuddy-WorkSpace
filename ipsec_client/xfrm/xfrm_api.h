/**
 * xfrm_api.h - Linux XFRM (IPsec) SA and Policy Management via Netlink
 *
 * Provides functions to install ESP SAs and Policies into the Linux kernel
 * using the XFRM netlink interface (NETLINK_XFRM).
 */

#ifndef XFRM_API_H
#define XFRM_API_H

#include "xfrm_types.h"
#include "../ikev2/ike_types.h"
#include <linux/xfrm.h>

/**
 * Open a XFRM netlink socket.
 * @return  Socket fd on success, -1 on failure.
 */
int xfrm_open_socket(void);

/**
 * Close the XFRM netlink socket.
 */
void xfrm_close_socket(int sock);

/**
 * Add an ESP SA to the kernel XFRM database.
 *
 * @param sock   XFRM netlink socket
 * @param params SA parameters
 * @return       0 on success, -1 on failure
 */
int xfrm_add_sa(int sock, const xfrm_sa_params_t *params);

/**
 * Delete an ESP SA from the kernel.
 *
 * @param sock     XFRM netlink socket
 * @param spi      SPI (network byte order)
 * @param dst_ip   SA destination IP
 * @return         0 on success, -1 on failure
 */
int xfrm_del_sa(int sock, uint32_t spi, const char *dst_ip);

/**
 * Add an XFRM Policy (SPD entry).
 *
 * @param sock   XFRM netlink socket
 * @param params Policy parameters
 * @return       0 on success, -1 on failure
 */
int xfrm_add_policy(int sock, const xfrm_policy_params_t *params);

/**
 * Delete an XFRM Policy.
 */
int xfrm_del_policy(int sock, const char *src_net, int src_prefix,
                    const char *dst_net, int dst_prefix, int direction);

/**
 * Install complete IPsec SA pair and policies for a tunnel.
 *
 * Installs:
 *   - Outbound SA (local → remote)
 *   - Inbound  SA (remote → local)
 *   - Outbound Policy
 *   - Inbound  Policy
 *
 * @param ctx   IKE SA context (must have established Child SA keys)
 * @return      0 on success, -1 on failure
 */
int xfrm_install_ipsec(ike_sa_ctx_t *ctx);

/**
 * Remove all IPsec SAs and policies installed for this session.
 */
int xfrm_uninstall_ipsec(ike_sa_ctx_t *ctx);

/**
 * Flush all XFRM SAs.
 */
int xfrm_flush_sa(int sock);

/**
 * Flush all XFRM policies.
 */
int xfrm_flush_policy(int sock);

#endif /* XFRM_API_H */
