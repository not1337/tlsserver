/*
 * This file is part of the tlsserver project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#include <stddef.h>
#include "tlsdispatch.h"
#include "tlsserver.h"

#define ALL_LIBS	2

static DISPATCH *lib[ALL_LIBS]=
{
#ifdef USE_OPENSSL
	&openssl,
#else
	NULL,
#endif
#ifdef USE_GNUTLS
	&gnutls,
#else
	NULL,
#endif
};

int tls_server_global_init(void)
{
	int i;

	for(i=0;i<ALL_LIBS;i++)if(lib[i]&&lib[i]->tls_server_global_init())
	{
		while(i-->0)if(lib[i])lib[i]->tls_server_global_fini();
		return -1;
	}
	return 0;
}

void tls_server_global_fini(void)
{
	int i;

	for(i=0;i<ALL_LIBS;i++)if(lib[i])lib[i]->tls_server_global_fini();
}

void *tls_server_init(int library,int tls_version_min,int tls_version_max,
	int ciphers)
{
	void *ctx;

	if(library<0||library>ALL_LIBS)return NULL;

	if(!library)while(library<ALL_LIBS)if(lib[library++])break;
	library--;

	if(!(ctx=lib[library]->tls_server_init(tls_version_min,
		tls_version_max,ciphers)))return NULL;
	*((int *)ctx)=library;
	return ctx;
}

int tls_server_add_dhfile(void *context,char *fn)
{
	return lib[*((int *)context)]->tls_server_add_dhfile(context,fn);
}

int tls_server_set_ticket_lifetime(void *context,int lifetime)
{
	return lib[*((int *)context)]->tls_server_set_ticket_lifetime(context,
		lifetime);
}

int tls_server_add_server(void *context,char *sniname,char *cert,char *key,
	char *ocsp)
{
	return lib[*((int *)context)]->tls_server_add_server(context,sniname,
		cert,key,ocsp);
}

int tls_server_add_client_cert_ca(void *context,int id,char *fn)
{
	return lib[*((int *)context)]->tls_server_add_client_cert_ca(context,
		id,fn);
}

int tls_server_add_verify_cafile(void *context,int id,char *fn)
{
	return lib[*((int *)context)]->tls_server_add_verify_cafile(context,
		id,fn);
}

int tls_server_add_verify_crlfile(void *context,int id,char *fn)
{
	return lib[*((int *)context)]->tls_server_add_verify_crlfile(context,
		id,fn);
}

int tls_server_set_client_cert_resume(void *context,int id,int mode)
{
	return lib[*((int *)context)]->tls_server_set_client_cert_resume(
		context,id,mode);
}

int tls_server_resume_only_for_tls13(void *context,int id,int mode)
{
	return lib[*((int *)context)]->tls_server_resume_only_for_tls13(
		context,id,mode);
}

int tls_server_set_alpn(void *context,int id,int nproto,char **proto)
{
	return lib[*((int *)context)]->tls_server_set_alpn(context,id,nproto,
		proto);
}

void tls_server_fini(void *context)
{
	lib[*((int *)context)]->tls_server_fini(context);
}

void *tls_server_accept(void *context,int fd,int timeout)
{
	return lib[*((int *)context)]->tls_server_accept(context,fd,timeout);
}

void tls_server_disconnect(void *context)
{
	lib[*((int *)context)]->tls_server_disconnect(context);
}

char *tls_server_get_sni_name(void *context)
{
	return lib[*((int *)context)]->tls_server_get_sni_name(context);
}

char *tls_server_get_alpn(void *context)
{
	return lib[*((int *)context)]->tls_server_get_alpn(context);
}

char *tls_server_get_client_cert_cn(void *context)
{
	return lib[*((int *)context)]->tls_server_get_client_cert_cn(context);
}

char *tls_server_get_client_cert_on(void *context)
{
	return lib[*((int *)context)]->tls_server_get_client_cert_on(context);
}

char *tls_server_get_client_cert_ou(void *context)
{
	return lib[*((int *)context)]->tls_server_get_client_cert_ou(context);
}

int tls_server_get_tls_version(void *context)
{
	return lib[*((int *)context)]->tls_server_get_tls_version(context);
}

int tls_server_get_resumption_state(void *context)
{
	return lib[*((int *)context)]->tls_server_get_resumption_state(context);
}

int tls_server_write(void *context,void *data,int len)
{
	return lib[*((int *)context)]->tls_server_write(context,data,len);
}

int tls_server_read(void *context,void *data,int len)
{
	return lib[*((int *)context)]->tls_server_read(context,data,len);
}
