/*
 * This file is part of the tlsserver project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#ifndef _DISPATCH_H_INCLUDED
#define _DISPATCH_H_INCLUDED

typedef struct
{
	int (*tls_server_global_init)(void);
	void (*tls_server_global_fini)(void);
	void *(*tls_server_init)(int tls_version_min,int tls_version_max,
		int ciphers);
	int (*tls_server_add_dhfile)(void *context,char *fn);
	int (*tls_server_set_ticket_lifetime)(void *context,int lifetime);
	int (*tls_server_add_server)(void *context,char *sniname,char *cert,
		char *key,char *ocsp);
	int (*tls_server_add_client_cert_ca)(void *context,int id,char *fn);
	int (*tls_server_add_verify_cafile)(void *context,int id,char *fn);
	int (*tls_server_add_verify_crlfile)(void *context,int id,char *fn);
	int (*tls_server_set_client_cert_resume)(void *context,int id,int mode);
	int (*tls_server_resume_only_for_tls13)(void *context,int id,int mode);
	int (*tls_server_set_alpn)(void *context,int id,int nproto,
		char **proto);
	void (*tls_server_fini)(void *context);
	void *(*tls_server_accept)(void *context,int fd,int timeout);
	void (*tls_server_disconnect)(void *context);
	char *(*tls_server_get_sni_name)(void *context);
	char *(*tls_server_get_alpn)(void *context);
	char *(*tls_server_get_client_cert_cn)(void *context);
	char *(*tls_server_get_client_cert_on)(void *context);
	char *(*tls_server_get_client_cert_ou)(void *context);
	int (*tls_server_get_tls_version)(void *context);
	int (*tls_server_get_resumption_state)(void *context);
	int (*tls_server_write)(void *context,void *data,int len);
	int (*tls_server_read)(void *context,void *data,int len);
} DISPATCH;

extern DISPATCH openssl;
extern DISPATCH gnutls;

#endif
