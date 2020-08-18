/*
 * This file is part of the tlsserver project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#if defined(ENABLE_TICKETS) || defined(OCSP_CACHE)
#include <pthread.h>
#endif
#ifdef ENABLE_TICKETS
#include <stdint.h>
#endif
#ifdef OCSP_CACHE
#include <sys/stat.h>
#endif
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>
#include <gnutls/ocsp.h>
#include "tlsdispatch.h"
#include "tlsserver.h"

#if GNUTLS_VERSION_NUMBER < 0x030600
#error need at least GnuTLS 3.6 or later
#endif

#ifdef ENABLE_TICKETS

#if GNUTLS_VERSION_NUMBER > 0x030603 && GNUTLS_VERSION_NUMBER < 0x03060e
#error refusing to use broken GnuTLS version, see CVE-2020-13777
#endif

typedef struct ticket
{
	struct ticket *next;
	struct ticket *prev;
	struct ticket *nxt[2];
	struct ticket *prv[2];
	uint64_t id;
	int namevalid;
	time_t since;
	gnutls_datum_t key;
	unsigned char name[2][16];
} TICKET;

#endif

typedef struct server
{
	struct server *next;
	gnutls_certificate_credentials_t cred;
	gnutls_certificate_credentials_t clncacred;
	gnutls_certificate_credentials_t clnvrycred;
	gnutls_datum_t *alpn;
	char *ocspfn;
	int nalpn;
	int clnca;
#ifdef ENABLE_TICKETS
	int clnresok;
#endif
#ifdef OCSP_CACHE
	time_t stamp;
	time_t otime;
	int osize;
	int olen;
	void *ocsp;
#endif
	char sniname[0];
} SERVER;

typedef struct
{
	int libid;
	gnutls_priority_t prio;
	gnutls_dh_params_t dh;
	SERVER *list;
	int dhloaded;
#ifdef ENABLE_TICKETS
	uint64_t id;
	int tktmax;
	TICKET *first;
	TICKET *last;
	TICKET *lookup[2][256];
#endif
} SERVERCTX;

typedef struct
{
	int libid;
	gnutls_session_t sess;
	char *sniname;
	char *alpn;
	char *cn;
	char *on;
	char *ou;
#ifdef ENABLE_TICKETS
	uint64_t id;
#endif
	int err;
	int fd;
} CONNCTX;

typedef struct
{
	SERVERCTX *ctx;
	CONNCTX *con;
	SERVER *svr;
	int gothello;
#ifdef ENABLE_TICKETS
	int rxfound;
	unsigned char rxname[16];
#endif
} HANDSHAKE;

#ifdef OCSP_CACHE

static pthread_mutex_t otx=PTHREAD_MUTEX_INITIALIZER;

#endif

#ifdef ENABLE_TICKETS

static pthread_mutex_t mtx=PTHREAD_MUTEX_INITIALIZER;

static void purge(SERVERCTX *cfg,time_t now)
{
	int i;
	TICKET *e;
	TICKET *m;
	
	for(e=cfg->last;e;e=e->prev)if(now-e->since<=cfg->tktmax||!e->prev)
	{
		if(now-e->since<=cfg->tktmax)
		{
			if(!(m=e->next))break;
			e->next=NULL;
			cfg->last=e;
		}
		else
		{
			m=e;
			cfg->first=cfg->last=NULL;
		}
		while(m)
		{
			e=m;
			m=e->next;
			for(i=0;i<e->namevalid;i++)
			{
				if(e->prv[i])e->prv[i]->nxt[i]=e->nxt[i];
				else cfg->lookup[i][e->name[i][0]]=e->nxt[i];
				if(e->nxt[i])e->nxt[i]->prv[i]=e->prv[i];
			}
			gnutls_memset(e->key.data,0,e->key.size);
			gnutls_free(e->key.data);
			free(e);
		}
		break;
	}
}

static TICKET *lookup(SERVERCTX *cfg,unsigned char *name)
{
	int i;
	TICKET *e;
	struct timespec now;

	if(clock_gettime(CLOCK_MONOTONIC,&now))return NULL;
	purge(cfg,now.tv_sec);

	for(i=0;i<2;i++)for(e=cfg->lookup[i][name[0]];e;e=e->nxt[i])
		if(!memcmp(name,e->name[i],16))return e;
	return NULL;
}

static void merge(SERVERCTX *cfg,uint64_t id,unsigned char *name)
{
	int i;
	TICKET *e;
	struct timespec now;

	if(clock_gettime(CLOCK_MONOTONIC,&now))return;
	purge(cfg,now.tv_sec);

	for(e=cfg->first;e;e=e->next)if(e->id==id)
	{
		for(i=0;i<e->namevalid;i++)if(!memcmp(name,e->name[i],16))
			return;
		if(e->namevalid==2)return;
		i=e->namevalid++;
		memcpy(e->name[i],name,16);
		if((e->nxt[i]=cfg->lookup[i][e->name[i][0]]))
			e->nxt[i]->prv[i]=e;
		cfg->lookup[i][e->name[i][0]]=e;
		e->prv[i]=NULL;
		return;
	}
}

static TICKET *gen(SERVERCTX *cfg)
{
	TICKET *e;
	TICKET *m;
	struct timespec now;

	if(clock_gettime(CLOCK_MONOTONIC,&now))return NULL;
	purge(cfg,now.tv_sec);

	if(cfg->first&&now.tv_sec-cfg->first->since<60)return cfg->first;

	if(!(m=malloc(sizeof(TICKET))))return NULL;
	while(1)
	{
		memset(m,0,sizeof(TICKET));
		if(gnutls_session_ticket_key_generate(&m->key))
		{
			free(m);
			return NULL;
		}
		for(e=cfg->first;e;e=e->next)if(m->key.size==e->key.size)
			if(!memcmp(m->key.data,e->key.data,m->key.size))break;
		if(!e)break;
		gnutls_memset(m->key.data,0,m->key.size);
		gnutls_free(m->key.data);
	}
	m->since=now.tv_sec;
	m->id=cfg->id++;
	if(!cfg->id)cfg->id++;
	if((m->next=cfg->first))
	{
		m->next->prev=m;
		cfg->first=m;
	}
	else cfg->first=cfg->last=m;
	m->prev=NULL;
	return m;
}

#endif

static int ocsp(gnutls_session_t sess,void *ptr,gnutls_datum_t *resp)
{
	int len;
	HANDSHAKE *h=ptr;
	FILE *fp;
	gnutls_ocsp_resp_t rsp;
	gnutls_datum_t in;
#ifdef OCSP_CACHE
	struct timespec now;
	struct stat stb;
#endif
	unsigned char bfr[8192];

	if(!h->svr->ocspfn)return GNUTLS_E_NO_CERTIFICATE_STATUS;
#ifdef OCSP_CACHE
	pthread_mutex_lock(&otx);
	if(clock_gettime(CLOCK_MONOTONIC,&now))goto err1;
	if(!h->svr->stamp||now.tv_sec-h->svr->stamp>=60)
	{
		h->svr->stamp=now.tv_sec;
		if(!stat(h->svr->ocspfn,&stb))
		{
			if(!h->svr->ocsp||stb.st_mtime!=h->svr->otime||
				stb.st_size!=h->svr->osize)
			{
				h->svr->otime=stb.st_mtime;
				h->svr->osize=stb.st_size;
				if(h->svr->ocsp)
				{
					gnutls_free(h->svr->ocsp);
					h->svr->ocsp=NULL;
				}
				if(!(fp=fopen(h->svr->ocspfn,"re")))goto err1;
				len=fread(bfr,1,sizeof(bfr),fp);
				fclose(fp);
				if(len<=0)goto err1;
				if(gnutls_ocsp_resp_init(&rsp))goto err1;
				in.data=bfr;
				in.size=len;
				if(gnutls_ocsp_resp_import(rsp,&in))goto err2;
				if(gnutls_ocsp_resp_export(rsp,&in))
				{
err2:					gnutls_ocsp_resp_deinit(rsp);
err1:					pthread_mutex_unlock(&otx);
					return GNUTLS_E_NO_CERTIFICATE_STATUS;
				}
				h->svr->olen=in.size;
				h->svr->ocsp=in.data;
			}
		}
		else if(h->svr->ocsp)
		{
			gnutls_free(h->svr->ocsp);
			h->svr->ocsp=NULL;
		}
	}
	if(!h->svr->ocsp||!(resp->data=gnutls_malloc(h->svr->olen)))goto err1;
	memcpy(resp->data,h->svr->ocsp,h->svr->olen);
	resp->size=h->svr->olen;
	pthread_mutex_unlock(&otx);
	return GNUTLS_E_SUCCESS;
#else
	if(!(fp=fopen(h->svr->ocspfn,"re")))
		return GNUTLS_E_NO_CERTIFICATE_STATUS;
	len=fread(bfr,1,sizeof(bfr),fp);
	fclose(fp);
	if(len<=0)return GNUTLS_E_NO_CERTIFICATE_STATUS;
	if(gnutls_ocsp_resp_init(&rsp))
		return GNUTLS_E_NO_CERTIFICATE_STATUS;
	in.data=bfr;
	in.size=len;
	if(!gnutls_ocsp_resp_import(rsp,&in))
		if(!gnutls_ocsp_resp_export(rsp,resp))
	{
		gnutls_ocsp_resp_deinit(rsp);
		return GNUTLS_E_SUCCESS;
	}
	gnutls_ocsp_resp_deinit(rsp);
	return GNUTLS_E_NO_CERTIFICATE_STATUS;
#endif
}

static int ext(void *ctx,unsigned id,const unsigned char *data,unsigned len)
{
	HANDSHAKE *h=ctx;
	SERVER *svr;
	int size;
	int type;
	char bfr[256];

	switch(id)
	{
	case 0x0000:
		if(len<2||h->svr)break;

		size=data[0];
		size<<=8;
		size|=data[1];
		data+=2;
		if(len<size+2)break;
		while(size>2)
		{
			type=data[0];
			len=data[1];
			len<<=8;
			len|=data[2];
			if(size<len+3)goto out;
			if(!type&&len<sizeof(bfr))
			{
				memcpy(bfr,data+3,len);
				bfr[len]=0;
				for(svr=h->ctx->list;svr;svr=svr->next)
					if(!strcasecmp(bfr,svr->sniname))
						goto hit;
			}
			size-=len+3;
			data+=len+3;
		}

		break;

hit:		h->svr=svr;
		break;

#ifdef ENABLE_TICKETS
	/* ugly workaround for GnuTLS session ticket security problem */
	case 0x0023:
		if(len<16||h->rxfound)break;
		memcpy(h->rxname,data,16);
		h->rxfound=1;
		break;

	case 0x0029:
		if(len<2||h->rxfound)break;
		size=data[0];
		size<<=8;
		size+=data[1];
		if(len<size+2)break;
		data+=2;
		if(size<2)break;
		len=data[0];
		len<<=8;
		len+=data[1];
		if(size<len+2)break;
		data+=2;
		if(len<16)break;
		memcpy(h->rxname,data,16);
		h->rxfound=1;
		break;
#endif
	}

out:	return GNUTLS_E_SUCCESS;
}

static int hook(gnutls_session_t sess,unsigned int htype,unsigned when,
	unsigned int incoming,const gnutls_datum_t *msg)
{
	HANDSHAKE *h;
	SERVER *mem;
	SERVER *svr;
#ifdef ENABLE_TICKETS
	unsigned char *name=NULL;
	TICKET *tkt;
#endif

	h=gnutls_session_get_ptr(sess);

	switch(htype)
	{
	case GNUTLS_HANDSHAKE_CLIENT_HELLO:
		if(when!=GNUTLS_HOOK_PRE||!incoming)break;
		if(h->gothello)
		{
			mem=h->svr;
			h->svr=NULL;
		}
		if(gnutls_ext_raw_parse(h,ext,msg,
			GNUTLS_EXT_RAW_FLAG_TLS_CLIENT_HELLO))
				return GNUTLS_E_INTERNAL_ERROR;
		if(!h->svr)for(svr=h->ctx->list;svr;svr=svr->next)
			if(!svr->sniname[0])
		{
			h->svr=svr;
			break;
		}
		if(h->gothello)
		{
			if(h->svr!=mem)return GNUTLS_E_UNRECOGNIZED_NAME;
			break;
		}
		if(!h->svr)return GNUTLS_E_UNRECOGNIZED_NAME;
		if(gnutls_credentials_set(sess,GNUTLS_CRD_CERTIFICATE,
			h->svr->cred))return GNUTLS_E_INTERNAL_ERROR;
		if(h->svr->alpn)if(gnutls_alpn_set_protocols(sess,h->svr->alpn,
			h->svr->nalpn,GNUTLS_ALPN_SERVER_PRECEDENCE))
				return GNUTLS_E_INTERNAL_ERROR;
		gnutls_certificate_server_set_request(sess,h->svr->clnca?
			GNUTLS_CERT_REQUIRE:GNUTLS_CERT_IGNORE);
		gnutls_certificate_set_ocsp_status_request_function(
			h->svr->cred,ocsp,h);
		if(!(h->con->sniname=strdup(h->svr->sniname)))
			return GNUTLS_E_INTERNAL_ERROR;
		h->gothello=1;
#ifdef ENABLE_TICKETS
		/* this is broken insofar as this is the only time
		   when session tickets can be enabled due to the
		   GnuTLS philosophy and at this point we don't know
		   the TLS version yet, so it isn't possible to
		   handle session ticket enablement selectively
		   for TLSv1.3 or later. GnuTLS security, Dohhh!!! */
		pthread_mutex_lock(&mtx);
		if(!h->ctx->tktmax||(h->svr->clnca&&!h->svr->clnresok))
		{
			pthread_mutex_unlock(&mtx);
			break;
		}
		if(h->rxfound&&(tkt=lookup(h->ctx,h->rxname)));
		else if(!(tkt=gen(h->ctx)))
		{
			pthread_mutex_unlock(&mtx);
			break;
		}
		h->con->id=tkt->id;
		gnutls_db_set_cache_expiration(sess,h->ctx->tktmax);
		gnutls_session_ticket_enable_server(sess,&tkt->key);
		pthread_mutex_unlock(&mtx);
#endif
		break;

	/* ugly workaround for the fact that gnutls does not allow to
	   separate server CA certificates from client cert CA certificates
	   which may cause the client to present the wrong client
	   certificate - depends on the processing sequence of the
	   tls state machines of gnutls */
	case GNUTLS_HANDSHAKE_ENCRYPTED_EXTENSIONS:
	case GNUTLS_HANDSHAKE_SERVER_KEY_EXCHANGE:
		if(when!=GNUTLS_HOOK_POST||incoming||!h->svr->clnca)break;
		if(gnutls_credentials_set(sess,GNUTLS_CRD_CERTIFICATE,
			h->svr->clncacred))return GNUTLS_E_INTERNAL_ERROR;
		break;

	case GNUTLS_HANDSHAKE_CERTIFICATE_REQUEST:
		if(when!=GNUTLS_HOOK_POST||incoming||!h->svr->clnca)break;
		if(gnutls_credentials_set(sess,GNUTLS_CRD_CERTIFICATE,
			h->svr->cred))return GNUTLS_E_INTERNAL_ERROR;
		break;

#ifdef ENABLE_TICKETS
	/* ugly workaround for GnuTLS session ticket security problem */
	case GNUTLS_HANDSHAKE_NEW_SESSION_TICKET:
		if(when!=GNUTLS_HOOK_PRE||incoming||!h->con->id)break;
		switch(gnutls_protocol_get_version(sess))
		{
		case GNUTLS_TLS1_0:
		case GNUTLS_TLS1_1:
		case GNUTLS_TLS1_2:
			if(msg->size<22)break;
			name=msg->data+6;
			break;
		case GNUTLS_TLS1_3:
			if(msg->size<9)break;
			if(msg->size<27+msg->data[8])break;
			name=msg->data+11+msg->data[8];
		default:break;
		}
		if(!name)break;
		pthread_mutex_lock(&mtx);
		if(h->ctx->tktmax)
		{
			if(!h->svr->clnca)merge(h->ctx,h->con->id,name);
			else if(h->svr->clnresok)merge(h->ctx,h->con->id,name);
		}
		pthread_mutex_unlock(&mtx);
		break;
#endif
	}

	return GNUTLS_E_SUCCESS;
}

static int tls_verify(gnutls_session_t sess)
{
	int r;
	unsigned int cls=0;
	unsigned int status;
	size_t size=0;
	HANDSHAKE *h;
	const gnutls_datum_t *cl;
	gnutls_x509_crt_t cert;

	h=gnutls_session_get_ptr(sess);
	if(gnutls_credentials_set(sess,GNUTLS_CRD_CERTIFICATE,
		h->svr->clnvrycred))return GNUTLS_E_INTERNAL_ERROR;
	r=gnutls_certificate_verify_peers3(sess,NULL,&status);
	if(gnutls_credentials_set(sess,GNUTLS_CRD_CERTIFICATE,
		h->svr->cred))return GNUTLS_E_INTERNAL_ERROR;
	if(r)return GNUTLS_E_CERTIFICATE_ERROR;
	if(status)return GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR;
	if(h->con->cn&&h->con->on&&h->con->ou)return GNUTLS_E_SUCCESS;
	cl=gnutls_certificate_get_peers(sess,&cls);
	if(!cls)return GNUTLS_E_SUCCESS;
	if(gnutls_x509_crt_init(&cert))return GNUTLS_E_SUCCESS;
	if(!gnutls_x509_crt_import(cert,cl,GNUTLS_X509_FMT_DER))
	{
		if(!h->con->cn)if(gnutls_x509_crt_get_dn_by_oid(cert,
			GNUTLS_OID_X520_COMMON_NAME,0,0,NULL,&size)==
				GNUTLS_E_SHORT_MEMORY_BUFFER)
					if((h->con->cn=malloc(size)))
		{
			if(gnutls_x509_crt_get_dn_by_oid(cert,
				GNUTLS_OID_X520_COMMON_NAME,0,0,
				h->con->cn,&size))
			{
				free(h->con->cn);
				h->con->cn=NULL;
			}
		}
		if(!h->con->on)if(gnutls_x509_crt_get_dn_by_oid(cert,
			GNUTLS_OID_X520_ORGANIZATION_NAME,0,0,NULL,&size)==
				GNUTLS_E_SHORT_MEMORY_BUFFER)
					if((h->con->on=malloc(size)))
		{
			if(gnutls_x509_crt_get_dn_by_oid(cert,
				GNUTLS_OID_X520_ORGANIZATION_NAME,0,0,
				h->con->on,&size))
			{
				free(h->con->on);
				h->con->on=NULL;
			}
		}
		if(!h->con->ou)if(gnutls_x509_crt_get_dn_by_oid(cert,
			GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME,0,0,NULL,
				&size)==GNUTLS_E_SHORT_MEMORY_BUFFER)
					if((h->con->ou=malloc(size)))
		{
			if(gnutls_x509_crt_get_dn_by_oid(cert,
				GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME,0,0,
				h->con->ou,&size))
			{
				free(h->con->ou);
				h->con->ou=NULL;
			}
		}
	}
	gnutls_x509_crt_deinit(cert);
	return GNUTLS_E_SUCCESS;
}

static int gnu_server_global_init(void)
{
#ifdef ENABLE_TICKETS
	char *vers;
	char *ptr;
	char *mem;
	int numeric=0;

	if(!(vers=strdup(gnutls_check_version(NULL))))goto err1;
	if(!(ptr=strtok_r(vers,".",&mem)))goto err2;
	numeric=atoi(ptr);
	numeric<<=8;
	if(!(ptr=strtok_r(vers,".",&mem)))goto err2;
	numeric+=atoi(ptr);
	numeric<<=8;
	if(!(ptr=strtok_r(vers,".",&mem)))goto err2;
	numeric+=atoi(ptr);
	if(numeric>0x030603&&numeric<0x03060e)
	{
err2:		free(vers);
err1:		return -1;
	}	
	free(vers);
#endif
	return 0;
}

static void gnu_server_global_fini(void)
{
}

static void *gnu_server_init(int tls_version_min,int tls_version_max,
	int ciphers)
{
	int i;
	SERVERCTX *ctx;
	char bfr[1024];

	if(tls_version_min>tls_version_max)goto err1;
	if(!(ciphers&(TLS_SERVER_CIPHER_STRENGTH_128|
		TLS_SERVER_CIPHER_STRENGTH_256)))goto err1;
	if(!(ciphers&(TLS_SERVER_CIPHER_GROUP_ECDH|TLS_SERVER_CIPHER_GROUP_DH|
		TLS_SERVER_CIPHER_GROUP_RSA)))goto err1;
	if(!(ciphers&(TLS_SERVER_CIPHER_CURVE_X25519|
		TLS_SERVER_CIPHER_CURVE_SECP256R1|
		TLS_SERVER_CIPHER_CURVE_SECP384R1|
		TLS_SERVER_CIPHER_CURVE_SECP521R1)))goto err1;
	if(!(ciphers&(TLS_SERVER_CIPHER_SIG_WITH_SHA1|
		TLS_SERVER_CIPHER_SIG_WITH_SHA256|
		TLS_SERVER_CIPHER_SIG_WITH_SHA384|
		TLS_SERVER_CIPHER_SIG_WITH_SHA512)))goto err1;
	if(!(ciphers&(TLS_SERVER_CIPHER_SIG_RSA|TLS_SERVER_CIPHER_SIG_RSA_PSS|
		TLS_SERVER_CIPHER_SIG_ECDSA)))goto err1;
	if((ciphers&(TLS_SERVER_CIPHER_SIG_WITH_SHA1|
		TLS_SERVER_CIPHER_SIG_WITH_SHA256|
		TLS_SERVER_CIPHER_SIG_WITH_SHA384|
		TLS_SERVER_CIPHER_SIG_WITH_SHA512))==
		TLS_SERVER_CIPHER_SIG_WITH_SHA1&&
		(!(ciphers&TLS_SERVER_CIPHER_SIG_RSA)))goto err1;
	if(!(ctx=malloc(sizeof(SERVERCTX))))goto err1;
	memset(ctx,0,sizeof(SERVERCTX));
#ifdef ENABLE_TICKETS
	ctx->id=1;
#endif
	strcpy(bfr,"-VERS-TLS-ALL");
	for(i=tls_version_min;i<=tls_version_max;i++)switch(i)
	{
	case TLS_SERVER_TLS_1_0:
		strcat(bfr,":+VERS-TLS1.0");
		break;
	case TLS_SERVER_TLS_1_1:
		strcat(bfr,":+VERS-TLS1.1");
		break;
	case TLS_SERVER_TLS_1_2:
		strcat(bfr,":+VERS-TLS1.2");
		break;
	case TLS_SERVER_TLS_1_3:
		strcat(bfr,":+VERS-TLS1.3");
		break;
	default:goto err2;
	}
	strcat(bfr,":%COMPAT:%DISABLE_WILDCARDS");
	strcat(bfr,":-AES-128-CCM:-AES-256-CCM");
	if(!(ciphers&TLS_SERVER_CIPHER_STRENGTH_128))
		strcat(bfr,":-AES-128-GCM:-AES-128-CBC:-CHACHA20-POLY1305");
	if(!(ciphers&TLS_SERVER_CIPHER_STRENGTH_256))
		strcat(bfr,":-AES-256-GCM:-AES-256-CBC");
	if(!(ciphers&TLS_SERVER_CIPHER_GROUP_ECDH))
		strcat(bfr,":-ECDHE-ECDSA:-ECDHE-RSA");
	if(!(ciphers&TLS_SERVER_CIPHER_GROUP_DH))strcat(bfr,":-DHE-RSA");
	if(!(ciphers&TLS_SERVER_CIPHER_GROUP_RSA))strcat(bfr,":-RSA");
	strcat(bfr,":-GROUP-ALL");
	if(ciphers&TLS_SERVER_CIPHER_CURVE_X25519)strcat(bfr,":+GROUP-X25519");
	if(ciphers&TLS_SERVER_CIPHER_CURVE_SECP256R1)
		strcat(bfr,":+GROUP-SECP256R1");
	if(ciphers&TLS_SERVER_CIPHER_CURVE_SECP384R1)
		strcat(bfr,":+GROUP-SECP384R1");
	if(ciphers&TLS_SERVER_CIPHER_CURVE_SECP521R1)
		strcat(bfr,":+GROUP-SECP521R1");
	strcat(bfr,":-SIGN-ALL");
	if(ciphers&TLS_SERVER_CIPHER_SIG_WITH_SHA256)
	{
		if(ciphers&TLS_SERVER_CIPHER_SIG_ECDSA)
			strcat(bfr,":+SIGN-ECDSA-SHA256"
			":+SIGN-ECDSA-SECP256R1-SHA256");
		if(ciphers&TLS_SERVER_CIPHER_SIG_RSA_PSS)
			strcat(bfr,":+SIGN-RSA-PSS-SHA256"
				":+SIGN-RSA-PSS-RSAE-SHA256");
		if(ciphers&TLS_SERVER_CIPHER_SIG_RSA)
			strcat(bfr,":+SIGN-RSA-SHA256");
	}
	if(ciphers&TLS_SERVER_CIPHER_SIG_WITH_SHA384)
	{
		if(ciphers&TLS_SERVER_CIPHER_SIG_ECDSA)
			strcat(bfr,":+SIGN-ECDSA-SHA384"
				":+SIGN-ECDSA-SECP384R1-SHA384");
		if(ciphers&TLS_SERVER_CIPHER_SIG_RSA_PSS)
		    strcat(bfr,":+SIGN-RSA-PSS-SHA384"
				":+SIGN-RSA-PSS-RSAE-SHA384");
		if(ciphers&TLS_SERVER_CIPHER_SIG_RSA)
			strcat(bfr,":+SIGN-RSA-SHA384");
	}
	if(ciphers&TLS_SERVER_CIPHER_SIG_WITH_SHA512)
	{
		if(ciphers&TLS_SERVER_CIPHER_SIG_ECDSA)
			strcat(bfr,":+SIGN-ECDSA-SHA512"
				":+SIGN-ECDSA-SECP521R1-SHA512");
		if(ciphers&TLS_SERVER_CIPHER_SIG_RSA_PSS)
		    strcat(bfr,":+SIGN-RSA-PSS-SHA512"
				":+SIGN-RSA-PSS-RSAE-SHA512");
		if(ciphers&TLS_SERVER_CIPHER_SIG_RSA)
			strcat(bfr,":+SIGN-RSA-SHA512");
	}
	if(ciphers&TLS_SERVER_CIPHER_SIG_WITH_SHA1)
	{
		if(ciphers&TLS_SERVER_CIPHER_SIG_RSA)
			strcat(bfr,":+SIGN-RSA-SHA1");
	}
	strcat(bfr,":%SERVER_PRECEDENCE");
	if(gnutls_dh_params_init(&ctx->dh))goto err2;
	if(gnutls_priority_init2(&ctx->prio,bfr,NULL,
		GNUTLS_PRIORITY_INIT_DEF_APPEND))goto err3;
	return ctx;

err3:	gnutls_dh_params_deinit(ctx->dh);
err2:	free(ctx);
err1:	return NULL;
}

static int gnu_server_add_dhfile(void *context,char *fn)
{
	int len;
	SERVERCTX *ctx=context;
	FILE *fp;
	gnutls_datum_t data;
	unsigned char bfr[8192];

	if(ctx->dhloaded)return -1;
	if(!(fp=fopen(fn,"re")))goto err1;
	if((len=fread(bfr,1,sizeof(bfr),fp))<=0)goto err2;
	fclose(fp);
	data.data=bfr;
	data.size=len;
	if(gnutls_dh_params_import_pkcs3(ctx->dh,&data,GNUTLS_X509_FMT_PEM))
		goto err1;
	ctx->dhloaded=1;
	return 0;

err2:	fclose(fp);
err1:	return -1;
}

static int gnu_server_set_ticket_lifetime(void *context,int lifetime)
{
#ifdef ENABLE_TICKETS
	int i;
	SERVERCTX *ctx=context;
	TICKET *e;
	struct timespec now;
#endif

	if(lifetime)if(lifetime<TLS_SERVER_TICKET_LIFETIME_MIN||
		lifetime>TLS_SERVER_TICKET_LIFETIME_MAX)return -1;

#ifdef ENABLE_TICKETS
	pthread_mutex_lock(&mtx);
	if(!(ctx->tktmax=lifetime))
	{
		while(ctx->first)
		{
			e=ctx->first;
			ctx->first=e->next;
			for(i=0;i<e->namevalid;i++)
				ctx->lookup[i][e->name[i][0]]=NULL;
			gnutls_memset(e->key.data,0,e->key.size);
			gnutls_free(e->key.data);
			free(e);
		}
		ctx->last=NULL;
	}
	else if(!clock_gettime(CLOCK_MONOTONIC,&now))purge(ctx,now.tv_sec);
	pthread_mutex_unlock(&mtx);
#endif
	return 0;
}

static int gnu_server_add_server(void *context,char *sniname,char *cert,
	char *key,char *ocsp)
{
	SERVERCTX *ctx=context;
	SERVER *svr;
	SERVER **e;
	int i;

	if(!sniname)sniname="";
	i=strlen(sniname);
	if(!(svr=malloc(sizeof(SERVER)+i+1)))goto err1;
	memset(svr,0,sizeof(SERVER));
	strcpy(svr->sniname,sniname);

	if(gnutls_certificate_allocate_credentials(&svr->cred)!=
		GNUTLS_E_SUCCESS)goto err2;
	if(gnutls_certificate_allocate_credentials(&svr->clncacred)!=
		GNUTLS_E_SUCCESS)goto err3;
	if(gnutls_certificate_allocate_credentials(&svr->clnvrycred)!=
		GNUTLS_E_SUCCESS)goto err4;
	if(ctx->dhloaded)gnutls_certificate_set_dh_params(svr->cred,ctx->dh);
	else if(gnutls_certificate_set_known_dh_params(svr->cred,
		GNUTLS_SEC_PARAM_MEDIUM))goto err5;
	if(gnutls_certificate_set_x509_key_file(svr->cred,cert,key,
		GNUTLS_X509_FMT_PEM))goto err5;
	if(!ocsp)svr->ocspfn=NULL;
	else if(!(svr->ocspfn=strdup(ocsp)))goto err5;
	for(i=0,e=&ctx->list;*e;e=&(*e)->next,i++)
		if(!strcasecmp((*e)->sniname,svr->sniname))goto err5;
	*e=svr;
	return i;

err5:	gnutls_certificate_free_credentials(svr->clnvrycred);
err4:	gnutls_certificate_free_credentials(svr->clncacred);
err3:	gnutls_certificate_free_credentials(svr->cred);
err2:	free(svr);
err1:	return -1;
}

static int gnu_server_add_verify_cafile(void *context,int id,char *fn)
{
	SERVERCTX *ctx=context;
	SERVER *svr;

	for(svr=ctx->list;id&&svr;svr=svr->next,id--);
	if(!svr)return -1;
	if(gnutls_certificate_set_x509_trust_file(svr->clnvrycred,fn,
		GNUTLS_X509_FMT_PEM)<=0)return -1;
	svr->clnca=1;
	return 0;
}

static int gnu_server_add_verify_crlfile(void *context,int id,char *fn)
{
	SERVERCTX *ctx=context;
	SERVER *svr;

	for(svr=ctx->list;id&&svr;svr=svr->next,id--);
	if(!svr)return -1;
	if(gnutls_certificate_set_x509_crl_file(svr->clnvrycred,fn,
		GNUTLS_X509_FMT_PEM)<=0)return -1;
	svr->clnca=1;
	return 0;
}

static int gnu_server_set_alpn(void *context,int id,int nproto,char **proto)
{
	int len;
	int l;
	int i;
	SERVERCTX *ctx=context;
	SERVER *svr;
	gnutls_datum_t *alpn;
	unsigned char *ptr;

	for(svr=ctx->list;id&&svr;svr=svr->next,id--);
	if(!svr)return -1;
	if(svr->alpn)goto err1;
	for(len=0,i=0;i<nproto;i++)if(!(l=strlen(proto[i]))||len>255)goto err1;
	else len+=l+1+sizeof(gnutls_datum_t);
	if(!len)goto err1;
	if(!(alpn=malloc(len)))goto err1;
	for(ptr=(unsigned char *)&alpn[nproto],i=0;i<nproto;i++,ptr+=l+1)
	{
		alpn[i].size=l=strlen(proto[i]);
		alpn[i].data=ptr;
		memcpy(ptr,proto[i],l+1);
	}
	svr->alpn=alpn;
	svr->nalpn=nproto;
	return 0;

err1:	return -1;
}

static int gnu_server_add_client_cert_ca(void *context,int id,char *fn)
{
	SERVERCTX *ctx=context;
	SERVER *svr;

	for(svr=ctx->list;id&&svr;svr=svr->next,id--);
	if(!svr)return -1;
	if(gnutls_certificate_set_x509_trust_file(svr->clncacred,fn,
		GNUTLS_X509_FMT_PEM)<=0)return -1;
	svr->clnca=1;
	return 0;
}

static int gnu_server_set_client_cert_resume(void *context,int id,int mode)
{
	SERVERCTX *ctx=context;
	SERVER *svr;

	for(svr=ctx->list;id&&svr;svr=svr->next,id--);
	if(!svr)goto err1;
#ifdef ENABLE_TICKETS
	svr->clnresok=mode;
#endif
	return 0;

err1:	return -1;
}

static int gnu_server_resume_only_for_tls13(void *context,int id,int mode)
{
	/* GnuTLS ticket handling is broken, cannot be done */
	if(mode)return -1;
	else return 0;
}

static void gnu_server_fini(void *context)
{
	SERVERCTX *ctx=context;
	SERVER *svr;
#ifdef ENABLE_TICKETS
	TICKET *e;

	pthread_mutex_lock(&mtx);
	while(ctx->first)
	{
		e=ctx->first;
		ctx->first=e->next;
		gnutls_memset(e->key.data,0,e->key.size);
		gnutls_free(e->key.data);
		free(e);
	}
	pthread_mutex_unlock(&mtx);
#endif
	while(ctx->list)
	{
		svr=ctx->list;
		ctx->list=svr->next;
#ifdef OCSP_CACHE
		pthread_mutex_lock(&otx);
		if(svr->ocsp)gnutls_free(svr->ocsp);
		svr->ocsp=NULL;
		pthread_mutex_unlock(&otx);
#endif
		gnutls_certificate_free_credentials(svr->clnvrycred);
		gnutls_certificate_free_credentials(svr->clncacred);
		gnutls_certificate_free_credentials(svr->cred);
		if(svr->ocspfn)free(svr->ocspfn);
		if(svr->alpn)free(svr->alpn);
		free(svr);
	}
	gnutls_priority_deinit(ctx->prio);
	gnutls_dh_params_deinit(ctx->dh);
	free(ctx);
}

static void *gnu_server_accept(void *context,int fd,int timeout)
{
	int r;
	unsigned int cls=0;
	size_t size=0;
	SERVERCTX *cfg=context;
	CONNCTX *ctx;
	const gnutls_datum_t *cl;
	gnutls_x509_crt_t cert;
	HANDSHAKE h;
	gnutls_datum_t alpn;

	if(!(ctx=malloc(sizeof(CONNCTX))))goto err1;
	memset(ctx,0,sizeof(CONNCTX));
	ctx->fd=fd;
	ctx->libid=cfg->libid;
	if(gnutls_init(&ctx->sess,GNUTLS_SERVER))goto err2;
	if(gnutls_priority_set(ctx->sess,cfg->prio))goto err3;
	gnutls_handshake_set_hook_function(ctx->sess,
		GNUTLS_HANDSHAKE_ANY,GNUTLS_HOOK_BOTH,hook);
	h.ctx=cfg;
	h.con=ctx;
	h.svr=NULL;
	h.gothello=0;
#ifdef ENABLE_TICKETS
	h.rxfound=0;
#endif
	gnutls_session_set_ptr(ctx->sess,&h);
	gnutls_handshake_set_timeout(ctx->sess,timeout);
	gnutls_transport_set_int(ctx->sess,fd);
	/* ugly: to set the verify flags use gnutls_session_set_verify_cert
	   and then instantly override the callback with
	   gnutls_session_set_verify_function - the purpose is to use
	   a separate certificate stor for client certificate verify */
	gnutls_session_set_verify_cert(ctx->sess,NULL,
		GNUTLS_VERIFY_DO_NOT_ALLOW_WILDCARDS|
		GNUTLS_VERIFY_DO_NOT_ALLOW_IP_MATCHES|
		GNUTLS_VERIFY_ALLOW_SIGN_WITH_SHA1|
		GNUTLS_VERIFY_IGNORE_UNKNOWN_CRIT_EXTENSIONS|
		GNUTLS_VERIFY_DISABLE_CA_SIGN);
	gnutls_session_set_verify_function(ctx->sess,tls_verify);
	while((r=gnutls_handshake(ctx->sess))<0)
		if(gnutls_error_is_fatal(r))break;
	if(r<0)goto err4;
	if(!gnutls_alpn_get_selected_protocol(ctx->sess,&alpn))if(alpn.size)
	{
		if(!(ctx->alpn=malloc(alpn.size+1)))goto err4;
		memcpy(ctx->alpn,alpn.data,alpn.size);
		ctx->alpn[alpn.size]=0;
	}
	if(!h.svr->clnca||!gnutls_session_is_resumed(ctx->sess)||
		(ctx->cn&&ctx->on&&ctx->ou))goto out;
	cl=gnutls_certificate_get_peers(ctx->sess,&cls);
	if(!cls)goto out;
	if(gnutls_x509_crt_init(&cert))goto out;
	if(!gnutls_x509_crt_import(cert,cl,GNUTLS_X509_FMT_DER))
	{
		if(!ctx->cn)if(gnutls_x509_crt_get_dn_by_oid(cert,
			GNUTLS_OID_X520_COMMON_NAME,0,0,NULL,&size)==
				GNUTLS_E_SHORT_MEMORY_BUFFER)
					if((ctx->cn=malloc(size)))
		{
			if(gnutls_x509_crt_get_dn_by_oid(cert,
				GNUTLS_OID_X520_COMMON_NAME,0,0,
				ctx->cn,&size))
			{
				free(ctx->cn);
				ctx->cn=NULL;
			}
		}
		if(!ctx->on)if(gnutls_x509_crt_get_dn_by_oid(cert,
			GNUTLS_OID_X520_ORGANIZATION_NAME,0,0,NULL,&size)==
				GNUTLS_E_SHORT_MEMORY_BUFFER)
					if((ctx->on=malloc(size)))
		{
			if(gnutls_x509_crt_get_dn_by_oid(cert,
				GNUTLS_OID_X520_ORGANIZATION_NAME,0,0,
				ctx->on,&size))
			{
				free(ctx->on);
				ctx->on=NULL;
			}
		}
		if(!ctx->ou)if(gnutls_x509_crt_get_dn_by_oid(cert,
			GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME,0,0,NULL,
				&size)==GNUTLS_E_SHORT_MEMORY_BUFFER)
					if((ctx->ou=malloc(size)))
		{
			if(gnutls_x509_crt_get_dn_by_oid(cert,
				GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME,0,0,
				ctx->ou,&size))
			{
				free(ctx->ou);
				ctx->ou=NULL;
			}
		}
	}
	gnutls_x509_crt_deinit(cert);
out:	return ctx;

err4:	if(ctx->sniname)free(ctx->sniname);
err3:	gnutls_deinit(ctx->sess);
err2:	free(ctx);
err1:	close(fd);
	return NULL;
}

static void gnu_server_disconnect(void *context)
{
	CONNCTX *ctx=context;

	if(!ctx->err)gnutls_bye(ctx->sess,GNUTLS_SHUT_WR);
	gnutls_deinit(ctx->sess);
	shutdown(ctx->fd,SHUT_RDWR);
	close(ctx->fd);
	if(ctx->sniname)free(ctx->sniname);
	if(ctx->alpn)free(ctx->alpn);
	if(ctx->cn)free(ctx->cn);
	if(ctx->on)free(ctx->on);
	if(ctx->ou)free(ctx->ou);
	free(ctx);
}

static char *gnu_server_get_sni_name(void *context)
{
	CONNCTX *ctx=context;

	return ctx->sniname[0]?ctx->sniname:NULL;
}

static char *gnu_server_get_alpn(void *context)
{
	CONNCTX *ctx=context;

	return ctx->alpn;
}

static char *gnu_server_get_client_cert_cn(void *context)
{
	CONNCTX *ctx=context;

	return ctx->cn;
}

static char *gnu_server_get_client_cert_on(void *context)
{
	CONNCTX *ctx=context;

	return ctx->on;
}

static char *gnu_server_get_client_cert_ou(void *context)
{
	CONNCTX *ctx=context;

	return ctx->ou;
}

static int gnu_server_get_tls_version(void *context)
{
	CONNCTX *ctx=context;

	switch(gnutls_protocol_get_version(ctx->sess))
	{
	case GNUTLS_TLS1_0:
		return TLS_SERVER_TLS_1_0;
	case GNUTLS_TLS1_1:
		return TLS_SERVER_TLS_1_1;
	case GNUTLS_TLS1_2:
		return TLS_SERVER_TLS_1_2;
	case GNUTLS_TLS1_3:
		return TLS_SERVER_TLS_1_3;
	default:return -1;
	}
}

static int gnu_server_get_resumption_state(void *context)
{
	CONNCTX *ctx=context;

	return gnutls_session_is_resumed(ctx->sess)?1:0;
}

static int gnu_server_write(void *context,void *data,int len)
{
	int l;
	CONNCTX *ctx=context;

	if((l=gnutls_record_send(ctx->sess,data,len))<0)switch(l)
	{
	case GNUTLS_E_INTERRUPTED:
	case GNUTLS_E_AGAIN:
		errno=EAGAIN;
		return -1;
	default:errno=EIO;
		return -1;
	}
	else return l;
}

static int gnu_server_read(void *context,void *data,int len)
{
	int l;
	CONNCTX *ctx=context;

	if(!len)return 0;
	if((l=gnutls_record_recv(ctx->sess,data,len))<=0)switch(l)
	{
	case 0: errno=EPIPE;
		return -1;
	case GNUTLS_E_REHANDSHAKE:
		if(gnutls_alert_send(ctx->sess,GNUTLS_AL_WARNING,
			GNUTLS_A_NO_RENEGOTIATION))
		{
			errno=EIO;
			return -1;
		}
	case GNUTLS_E_INTERRUPTED:
	case GNUTLS_E_AGAIN:
		errno=EAGAIN;
		return -1;
	default:errno=EIO;
		return -1;
	}
	else return l;
}

DISPATCH gnutls=
{
	gnu_server_global_init,
	gnu_server_global_fini,
	gnu_server_init,
	gnu_server_add_dhfile,
	gnu_server_set_ticket_lifetime,
	gnu_server_add_server,
	gnu_server_add_client_cert_ca,
	gnu_server_add_verify_cafile,
	gnu_server_add_verify_crlfile,
	gnu_server_set_client_cert_resume,
	gnu_server_resume_only_for_tls13,
	gnu_server_set_alpn,
	gnu_server_fini,
	gnu_server_accept,
	gnu_server_disconnect,
	gnu_server_get_sni_name,
	gnu_server_get_alpn,
	gnu_server_get_client_cert_cn,
	gnu_server_get_client_cert_on,
	gnu_server_get_client_cert_ou,
	gnu_server_get_tls_version,
	gnu_server_get_resumption_state,
	gnu_server_write,
	gnu_server_read,
};
