/* SPDX-License-Identifier: MIT */
#include "config.h"
#include "session.h"
#include "packet.h"
#include "error.h"

struct ssh_packet_callbacks_struct ssh_ecdh_client_callbacks = {0};

int ssh_ecdh_init(ssh_session session)
{
    ssh_set_error(session, SSH_FATAL, "ECDH is disabled in the bash-os libssh profile");
    return SSH_ERROR;
}

int ssh_client_ecdh_init(ssh_session session)
{
    return ssh_ecdh_init(session);
}

void ssh_client_ecdh_remove_callbacks(ssh_session session)
{
    (void) session;
}

int ecdh_build_k(ssh_session session)
{
    return ssh_ecdh_init(session);
}

#ifdef WITH_SERVER
struct ssh_packet_callbacks_struct ssh_ecdh_server_callbacks = {0};

void ssh_server_ecdh_init(ssh_session session)
{
    (void) ssh_ecdh_init(session);
}

SSH_PACKET_CALLBACK(ssh_packet_server_ecdh_init)
{
    (void) type;
    (void) packet;
    ssh_set_error(session, SSH_FATAL, "ECDH is disabled in the bash-os libssh profile");
    return SSH_PACKET_USED;
}
#endif
