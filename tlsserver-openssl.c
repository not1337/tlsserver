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
#include <openssl/pem.h>
#include <openssl/safestack.h>
#include <openssl/rand.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "tlsdispatch.h"
#include "tlsserver.h"

#if OPENSSL_VERSION_NUMBER < 0x1010100fL
#error need at least OpenSSL 1.1.1 or later
#endif

#ifdef ENABLE_TICKETS

typedef struct ticket
{
	struct ticket *next;
	struct ticket *prev;
	struct ticket *nxt;
	struct ticket *prv;
	time_t since;
	unsigned char name[16];
	unsigned char aeskey[32];
	unsigned char hmackey[32];
} TICKET;

#endif

typedef struct server
{
	struct server *next;
	SSL_CTX *ctx;
	X509 *cert;
	EVP_PKEY *key;
	STACK_OF(X509) *cachain;
	STACK_OF(X509_NAME) *clnca;
	char *ocspfn;
	unsigned char *alpn;
	int alpnlen;
	int crlenabled;
#ifdef ENABLE_TICKETS
	int onlyv13;
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
	SSL_CTX *ctx;
	DH *dh;
	SERVER *list;
#ifdef ENABLE_TICKETS
	int tktmax;
	TICKET *first;
	TICKET *last;
	TICKET *lookup[256];
#endif
} SERVERCTX;

typedef struct
{
	int libid;
	int err;
	int fd;
	int resumed;
	int gothello;
	SSL *ssl;
	char *sniname;
	char *alpn;
	char *cn;
	char *on;
	char *ou;
} CONNCTX;

static int cfgidx=-1;
static int sslidx=-1;
static int svridx=-1;
static int rngfd=-1;
static RAND_METHOD sys;

#ifdef OCSP_CACHE

static pthread_mutex_t otx=PTHREAD_MUTEX_INITIALIZER;

#endif

#ifdef ENABLE_TICKETS

static pthread_mutex_t mtx=PTHREAD_MUTEX_INITIALIZER;

static void purge(SERVERCTX *cfg,time_t now)
{
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
			if(e->prv)e->prv->nxt=e->nxt;
			else cfg->lookup[e->name[0]]=e->nxt;
			if(e->nxt)e->nxt->prv=e->prv;
			OPENSSL_cleanse(e,sizeof(TICKET));
			free(e);
		}
		break;
	}
}

static TICKET *lookup(SERVERCTX *cfg,unsigned char *name,int *expires)
{
	TICKET *e;
	struct timespec now;

	if(clock_gettime(CLOCK_MONOTONIC,&now))return NULL;
	purge(cfg,now.tv_sec);

	for(e=cfg->lookup[name[0]];e;e=e->nxt)if(!memcmp(name,e->name,16))
	{
		*expires=0;
		if(now.tv_sec-e->since>=cfg->tktmax-(cfg->tktmax>>2))*expires=1;
		return e;
	}
	return NULL;
}

static TICKET *gen(SERVERCTX *cfg,int *expires)
{
	TICKET *e;
	TICKET *m;
	struct timespec now;

	if(clock_gettime(CLOCK_MONOTONIC,&now))return NULL;
	purge(cfg,now.tv_sec);

	if(cfg->first&&now.tv_sec-cfg->first->since<60)
	{
		*expires=0;
		if(now.tv_sec-cfg->first->since>=cfg->tktmax-(cfg->tktmax>>2))
			*expires=1;
		return cfg->first;
	}

	if(!(m=malloc(sizeof(TICKET))))return NULL;

	ERR_clear_error();

	while(1)
	{
		if(RAND_bytes((void *)m,sizeof(TICKET))<=0)
		{
			free(m);
			return NULL;
		}
		for(e=cfg->lookup[m->name[0]];e;e=e->nxt)
			if(!memcmp(m->name,e->name,16))break;
		if(!e)break;
	}
	m->since=now.tv_sec;
	if((m->next=cfg->first))
	{
		m->next->prev=m;
		cfg->first=m;
	}
	else cfg->first=cfg->last=m;
	m->prev=NULL;
	if((m->nxt=cfg->lookup[m->name[0]]))m->nxt->prv=m;
	cfg->lookup[m->name[0]]=m;
	m->prv=NULL;
	*expires=0;
	return m;
}

static int tcb(SSL *s,unsigned char key_name[16],unsigned char *iv,
	EVP_CIPHER_CTX *ctx,HMAC_CTX *hctx,int enc)
{
	int expires=0;
	TICKET *tkt;
	SERVERCTX *cfg;
	SERVER *svr;

	ERR_clear_error();

	if(!(cfg=SSL_get_ex_data(s,cfgidx)))return -1;
	if(!(svr=SSL_get_ex_data(s,svridx)))return -1;

	pthread_mutex_lock(&mtx);

	if(!cfg->tktmax||(svr->clnca&&!svr->clnresok)||
		(svr->onlyv13&&SSL_version(s)!=TLS1_3_VERSION))
	{
		pthread_mutex_unlock(&mtx);
		return 0;
	}

	if(enc)
	{
		if(RAND_bytes(iv,EVP_MAX_IV_LENGTH)<=0)
		{
			pthread_mutex_unlock(&mtx);
			return -1;
		}
		if(!(tkt=gen(cfg,&expires)))
		{
			pthread_mutex_unlock(&mtx);
			return 0;
		}
		memcpy(key_name,tkt->name,16);
		EVP_EncryptInit_ex(ctx,EVP_aes_256_cbc(),NULL,tkt->aeskey,iv);
		HMAC_Init_ex(hctx,tkt->hmackey,32,EVP_sha256(),NULL);
	}
	else
	{
		if(!(tkt=lookup(cfg,key_name,&expires)))
		{
			pthread_mutex_unlock(&mtx);
			return 0;
		}
		HMAC_Init_ex(hctx,tkt->hmackey,32,EVP_sha256(),NULL);
		EVP_DecryptInit_ex(ctx,EVP_aes_256_cbc(),NULL,tkt->aeskey,iv);
	}
	pthread_mutex_unlock(&mtx);
	return expires+1;
}

static int dcb(SSL *s,SSL_SESSION *ss,const unsigned char *keyname,
	size_t keyname_len,SSL_TICKET_STATUS status,void *arg)
{
	SERVER *svr;
	CONNCTX *con;

	ERR_clear_error();

	if(!(svr=SSL_get_ex_data(s,svridx)))return SSL_TICKET_RETURN_ABORT;
	if(!(con=SSL_get_ex_data(s,sslidx)))return SSL_TICKET_RETURN_ABORT;

	if(svr->clnca&&!svr->clnresok)return SSL_TICKET_RETURN_IGNORE;

	switch(status)
	{
	case SSL_TICKET_SUCCESS:
		con->resumed=1;
		SSL_set_verify(s,SSL_VERIFY_NONE,NULL);
		return SSL_TICKET_RETURN_USE;
	case SSL_TICKET_SUCCESS_RENEW:
		con->resumed=1;
		SSL_set_verify(s,SSL_VERIFY_NONE,NULL);
		return SSL_TICKET_RETURN_USE_RENEW;
	default:return SSL_TICKET_RETURN_IGNORE_RENEW;
	}
}

#else

static int tcb(SSL *s,unsigned char key_name[16],unsigned char *iv,
	EVP_CIPHER_CTX *ctx,HMAC_CTX *hctx,int enc)
{
	return 0;
}

static int dcb(SSL *s,SSL_SESSION *ss,const unsigned char *keyname,
	size_t keyname_len,SSL_TICKET_STATUS status,void *arg)
{
	return SSL_TICKET_RETURN_IGNORE;
}

#endif

static int gcb(SSL *s,void *arg)
{
	return 1;
}

static int ecb(SSL *s,void *arg)
{
	return 0;
}

static int scb(SSL *ssl,void *arg)
{
	SERVER *svr;
	OCSP_RESPONSE *resp;
	BIO *bio;
	unsigned char *der;
	unsigned char *mem;
	int len;
#ifdef OCSP_CACHE
	struct timespec now;
	struct stat stb;
#endif

	ERR_clear_error();

	if(!(svr=SSL_get_ex_data(ssl,svridx)))return SSL_TLSEXT_ERR_ALERT_FATAL;
	if(!svr->ocspfn)return SSL_TLSEXT_ERR_NOACK;
#ifdef OCSP_CACHE
	pthread_mutex_lock(&otx);
	if(clock_gettime(CLOCK_MONOTONIC,&now))goto err1;
	if(!svr->stamp||now.tv_sec-svr->stamp>=60)
	{
		svr->stamp=now.tv_sec;
		if(!stat(svr->ocspfn,&stb))
		{
			if(!svr->ocsp||stb.st_mtime!=svr->otime||
				stb.st_size!=svr->osize)
			{
				svr->otime=stb.st_mtime;
				svr->osize=stb.st_size;
				if(svr->ocsp)
				{
					OPENSSL_free(svr->ocsp);
					svr->ocsp=NULL;
				}
				if(!(bio=BIO_new_file(svr->ocspfn,"re")))
					goto err1;
				resp=d2i_OCSP_RESPONSE_bio(bio,NULL);
				BIO_free(bio);
				if(!resp)goto err1;
				if(OCSP_response_status(resp)!=
					OCSP_RESPONSE_STATUS_SUCCESSFUL||
					(len=i2d_OCSP_RESPONSE(resp,NULL))<=0||
					!(mem=der=OPENSSL_malloc(len)))
				{
					OCSP_RESPONSE_free(resp);
err1:					pthread_mutex_unlock(&otx);
					return SSL_TLSEXT_ERR_NOACK;
				}
				i2d_OCSP_RESPONSE(resp,&mem);
				OCSP_RESPONSE_free(resp);
				svr->ocsp=der;
				svr->olen=len;
			}
		}
		else if(svr->ocsp)
		{
			OPENSSL_free(svr->ocsp);
			svr->ocsp=NULL;
		}
	}
	if(!svr->ocsp)der=NULL;
	else if((der=OPENSSL_malloc((len=svr->olen))))memcpy(der,svr->ocsp,len);
	pthread_mutex_unlock(&otx);
	if(!der)return SSL_TLSEXT_ERR_NOACK;
#else
	if(!(bio=BIO_new_file(svr->ocspfn,"re")))return SSL_TLSEXT_ERR_NOACK;
	resp=d2i_OCSP_RESPONSE_bio(bio,NULL);
	BIO_free(bio);
	if(!resp)return SSL_TLSEXT_ERR_NOACK;
	if(OCSP_response_status(resp)!=OCSP_RESPONSE_STATUS_SUCCESSFUL||
		(len=i2d_OCSP_RESPONSE(resp,NULL))<=0||
		!(mem=der=OPENSSL_malloc(len)))
	{
		OCSP_RESPONSE_free(resp);
		return SSL_TLSEXT_ERR_NOACK;
	}
	i2d_OCSP_RESPONSE(resp,&mem);
	OCSP_RESPONSE_free(resp);
#endif
	if(!SSL_set_tlsext_status_ocsp_resp(ssl,der,len))
	{
		OPENSSL_free(der);
		return SSL_TLSEXT_ERR_NOACK;
	}
	return SSL_TLSEXT_ERR_OK;
}

static int acb(SSL *ssl,const unsigned char **out,unsigned char *outlen,
	const unsigned char *in,unsigned int inlen,void *arg)
{
	CONNCTX *con;
	SERVER *svr;

	ERR_clear_error();

	if(!(con=SSL_get_ex_data(ssl,sslidx)))return SSL_TLSEXT_ERR_ALERT_FATAL;
	if(!(svr=SSL_get_ex_data(ssl,svridx)))return SSL_TLSEXT_ERR_ALERT_FATAL;
	if(!svr->alpn)return SSL_TLSEXT_ERR_NOACK;

	if(!con->gothello)if(con->alpn)return SSL_TLSEXT_ERR_ALERT_FATAL;
	if(SSL_select_next_proto((unsigned char **)out,outlen,svr->alpn,
		svr->alpnlen,in,inlen)==OPENSSL_NPN_NO_OVERLAP)
			return SSL_TLSEXT_ERR_ALERT_FATAL;
	if(con->alpn)
	{
		if(!con->alpn)return SSL_TLSEXT_ERR_ALERT_FATAL;
		if(*outlen!=strlen(con->alpn))return SSL_TLSEXT_ERR_ALERT_FATAL;
		if(memcmp(con->alpn,*out,*outlen))
			return SSL_TLSEXT_ERR_ALERT_FATAL;
		return SSL_TLSEXT_ERR_OK;
	}
	if(!(con->alpn=malloc(*outlen+1)))return SSL_TLSEXT_ERR_ALERT_FATAL;
	memcpy(con->alpn,*out,*outlen);
	con->alpn[*outlen]=0;
	return SSL_TLSEXT_ERR_OK;
}

static int hcb(SSL *s,int *al,void *arg)
{
	SERVERCTX *cfg=arg;
	SERVER *svr;
	CONNCTX *con;
	X509_STORE *store;
	STACK_OF(X509_NAME) *clnca;
	unsigned char *data;
	size_t len;
	int size;
	int type;
	char bfr[256];

	ERR_clear_error();

	if(!(con=SSL_get_ex_data(s,sslidx)))goto err;
	if(!cfg->list)goto err;
	if(SSL_client_hello_get0_ext(s,0x0000,(const unsigned char **)(&data),
		&len))if(len>1)
	{
		size=data[0];
		size<<=8;
		size|=data[1];
		data+=2;
		if(len<size+2)goto err;
		while(size>2)
		{
			type=data[0];
			len=data[1];
			len<<=8;
			len|=data[2];
			if(size<len+3)goto err;
			if(!type&&len<sizeof(bfr))
			{
				memcpy(bfr,data+3,len);
				bfr[len]=0;
				for(svr=cfg->list;svr;svr=svr->next)
					if(!strcasecmp(bfr,svr->sniname))
						goto hit;
			}
			size-=len+3;
			data+=len+3;
		}
	}

	for(svr=cfg->list;svr;svr=svr->next)if(!svr->sniname[0])goto hit;

	goto err;

hit:	if(con->gothello)
	{
		if(svr!=SSL_get_ex_data(s,svridx))goto err;
		return SSL_CLIENT_HELLO_SUCCESS;
	}
	if(!SSL_set_ex_data(s,svridx,svr))goto err;
	if(con->sniname)goto err;
	if(!(con->sniname=strdup(svr->sniname)))goto err;
	if(!(store=SSL_CTX_get_cert_store(svr->ctx)))goto err;
	if(!SSL_set1_verify_cert_store(s,store))goto err;
	if(!SSL_use_cert_and_key(s,svr->cert,svr->key,svr->cachain,1))goto err;
	if(svr->clnca)
	{
		if(!(clnca=sk_X509_NAME_deep_copy(svr->clnca,
			(X509_NAME *(*)(const X509_NAME *))X509_NAME_dup,
			X509_NAME_free)))goto err;
		SSL_set_client_CA_list(s,clnca);
		SSL_set_verify_depth(s,4);
		SSL_set_verify(s,
			SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,NULL);
	}
	else SSL_set_verify(s,SSL_VERIFY_NONE,NULL);

#ifdef ENABLE_TICKETS
	pthread_mutex_lock(&mtx);
	if(!cfg->tktmax||(svr->clnca&&!svr->clnresok)||
		(svr->onlyv13&&SSL_version(s)!=TLS1_3_VERSION))
			if(!SSL_set_num_tickets(s,0))
	{
		pthread_mutex_unlock(&mtx);
		goto err;
	}
	pthread_mutex_unlock(&mtx);
#else
	if(!SSL_set_num_tickets(s,0))goto err;
#endif
	con->gothello=1;

	return SSL_CLIENT_HELLO_SUCCESS;

err:	*al=SSL_R_TLSV1_ALERT_ACCESS_DENIED;
	return SSL_CLIENT_HELLO_ERROR;
}

static int pcb(char *buf,int size,int rwflag,void *u)
{
	return -1;
}

static SERVER *load_server(char *sniname,char *cert,char *key)
{
	int len;
	SERVER *svr;
	FILE *fp;
	X509 *x;

	ERR_clear_error();

	len=strlen(sniname);
	if(!(svr=malloc(sizeof(SERVER)+len+1)))goto err1;
	memset(svr,0,sizeof(SERVER));
	strcpy(svr->sniname,sniname);

	if(!(svr->cachain=sk_X509_new_null()))goto err2;

	if(!(fp=fopen(cert,"re")))goto err3;
	if(!PEM_read_X509(fp,&svr->cert,pcb,NULL))
	{
		fclose(fp);
		goto err3;
	}
	while(1)
	{
		x=NULL;
		if(!PEM_read_X509(fp,&x,pcb,NULL))break;
		if(!sk_X509_push(svr->cachain,x))
		{
			fclose(fp);
			goto err4;
		}
	}
	fclose(fp);

	if(!(fp=fopen(key,"re")))goto err4;
	if(!PEM_read_PrivateKey(fp,&svr->key,pcb,NULL))
	{
		fclose(fp);
		goto err4;
	}
	fclose(fp);

	return svr;

err4:	X509_free(svr->cert);
err3:	sk_X509_pop_free(svr->cachain,X509_free);
err2:	free(svr);
err1:	return NULL;
}

static void free_server(SERVER *server)
{
	ERR_clear_error();
	sk_X509_pop_free(server->cachain,X509_free);
	EVP_PKEY_free(server->key);
	X509_free(server->cert);
	SSL_CTX_free(server->ctx);
	if(server->ocspfn)free(server->ocspfn);
	if(server->clnca)sk_X509_NAME_pop_free(server->clnca,X509_NAME_free);
	if(server->alpn)free(server->alpn);
	free(server);
}

static int enable_crl_check(SERVER *svr)
{
	X509_STORE *store;
	X509_VERIFY_PARAM *param;

	ERR_clear_error();

	if(svr->crlenabled)return 0;
	if(!(store=SSL_CTX_get_cert_store(svr->ctx)))goto err1;
	if(!(param=X509_VERIFY_PARAM_new()))goto err1;
	if(!X509_VERIFY_PARAM_set_flags(param,X509_V_FLAG_CRL_CHECK))goto err2;
	if(!X509_STORE_set1_param(store,param))goto err2;
	X509_VERIFY_PARAM_free(param);
	svr->crlenabled=1;
	return 0;

err2:	X509_VERIFY_PARAM_free(param);
err1:	return -1;
}

static int getrandom(unsigned char *buf,int num)
{
	return read(rngfd,buf,num);
}

static int ssl_server_global_init(void)
{
	if(OpenSSL_version_num()<0x1010100fL)goto err1;

	if((rngfd=open("/dev/urandom",O_RDONLY|O_CLOEXEC))==-1)goto err1;

	memset(&sys,0,sizeof(sys));
	sys.bytes=getrandom;
	sys.pseudorand=getrandom;
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	if((cfgidx=SSL_get_ex_new_index(0,NULL,NULL,NULL,NULL))<0)goto err2;
	if((sslidx=SSL_get_ex_new_index(0,NULL,NULL,NULL,NULL))<0)goto err2;
	if((svridx=SSL_get_ex_new_index(0,NULL,NULL,NULL,NULL))<0)goto err2;
	if(!RAND_set_rand_method(&sys))goto err2;
	return 0;

err2:   close(rngfd);
err1:   return -1;
}

static void ssl_server_global_fini(void)
{
	close(rngfd);
}

static void *ssl_server_init(int tls_version_min,int tls_version_max,
	int ciphers)
{
	int i;
	int len;
	SERVERCTX *cfg;
	SSL *ssl;
	const char *ptr;
	int glist[4];
	char bfr[1024];

	ERR_clear_error();

	if(tls_version_min>tls_version_max)goto err1;

	if(!(cfg=malloc(sizeof(SERVERCTX))))goto err1;
	memset(cfg,0,sizeof(SERVERCTX));

	if(!(cfg->ctx=SSL_CTX_new(TLS_server_method())))goto err2;
	if(!SSL_CTX_set_ecdh_auto(cfg->ctx,1))goto err3;

	switch(tls_version_min)
	{
	case TLS_SERVER_TLS_1_0:
		if(!SSL_CTX_set_min_proto_version(cfg->ctx,TLS1_VERSION))
			goto err3;
		break;
	case TLS_SERVER_TLS_1_1:
		if(!SSL_CTX_set_min_proto_version(cfg->ctx,TLS1_1_VERSION))
			goto err3;
		break;
	case TLS_SERVER_TLS_1_2:
		if(!SSL_CTX_set_min_proto_version(cfg->ctx,TLS1_2_VERSION))
			goto err3;
		break;
	case TLS_SERVER_TLS_1_3:
		if(!SSL_CTX_set_min_proto_version(cfg->ctx,TLS1_3_VERSION))
			goto err3;
		break;
	default:goto err3;
	}

	switch(tls_version_max)
	{
	case TLS_SERVER_TLS_1_0:
		if(!SSL_CTX_set_max_proto_version(cfg->ctx,TLS1_VERSION))
			goto err3;
		break;
	case TLS_SERVER_TLS_1_1:
		if(!SSL_CTX_set_max_proto_version(cfg->ctx,TLS1_1_VERSION))
			goto err3;
		break;
	case TLS_SERVER_TLS_1_2:
		if(!SSL_CTX_set_max_proto_version(cfg->ctx,TLS1_2_VERSION))
			goto err3;
		break;
	case TLS_SERVER_TLS_1_3:
		if(!SSL_CTX_set_max_proto_version(cfg->ctx,TLS1_3_VERSION))
			goto err3;
		break;
	default:goto err3;
	}

	if(!SSL_CTX_set_tlsext_status_cb(cfg->ctx,scb))goto err3;
	if(!SSL_CTX_set_session_ticket_cb(cfg->ctx,gcb,dcb,cfg))goto err3;

	SSL_CTX_set_options(cfg->ctx,SSL_OP_ALL);
	SSL_CTX_set_options(cfg->ctx,SSL_OP_NO_COMPRESSION);
	SSL_CTX_set_options(cfg->ctx,SSL_OP_CIPHER_SERVER_PREFERENCE);
	SSL_CTX_set_client_hello_cb(cfg->ctx,hcb,cfg);
	SSL_CTX_set_alpn_select_cb(cfg->ctx,acb,cfg);
	SSL_CTX_set_tlsext_ticket_key_cb(cfg->ctx,tcb);
	SSL_CTX_set_allow_early_data_cb(cfg->ctx,ecb,NULL);
	SSL_CTX_set_session_cache_mode(cfg->ctx,SSL_SESS_CACHE_OFF);

	if(!(ssl=SSL_new(cfg->ctx)))goto err3;
	for(len=0,i=0;(ptr=SSL_get_cipher_list(ssl,i));i++)
	{
		if(!strncmp(ptr,"RSA-PSK-",8))continue;
		if(!strncmp(ptr,"DHE-PSK-",8))continue;
		if(!strncmp(ptr,"ECDHE-PSK-",10))continue;
		if(!strncmp(ptr,"SRP-",4))continue;
		if(!strncmp(ptr,"PSK-",4))continue;
		if(!strncmp(ptr,"ADH-",4))continue;
		if(!strncmp(ptr,"AECDH-",6))continue;
		if(strstr(ptr,"IDEA")||strstr(ptr,"SEED")||
			strstr(ptr,"DES")||strstr(ptr,"CAMELLIA")||
			strstr(ptr,"ARIA")||strstr(ptr,"RC4")||
			strstr(ptr,"NULL")||strstr(ptr,"GOST")||
			strstr(ptr,"DSS")||strstr(ptr,"CCM"))continue;
		if(!strncmp(ptr,"ECDHE-",6))
			if(!(ciphers&TLS_SERVER_CIPHER_GROUP_ECDH))continue;
		if(!strncmp(ptr,"DHE-",4))
			if(!(ciphers&TLS_SERVER_CIPHER_GROUP_DH))continue;
		if(!strncmp(ptr,"AES-",4))
			if(!(ciphers&TLS_SERVER_CIPHER_GROUP_RSA))continue;
		if(!strncmp(ptr,"AES128-",7))
			if(!(ciphers&TLS_SERVER_CIPHER_GROUP_RSA))continue;
		if(!strncmp(ptr,"AES256-",7))
			if(!(ciphers&TLS_SERVER_CIPHER_GROUP_RSA))continue;
		if(strstr(ptr,"AES128")||strstr(ptr,"AES_128")||
			strstr(ptr,"CHACHA20"))
				if(!(ciphers&TLS_SERVER_CIPHER_STRENGTH_128))
					continue;
		if(strstr(ptr,"AES256")||strstr(ptr,"AES_256"))
			if(!(ciphers&TLS_SERVER_CIPHER_STRENGTH_256))continue;
		len+=snprintf(bfr+len,sizeof(bfr)-len,"%s%s",len?":":"",ptr);
	}
	SSL_free(ssl);
	if(!len)goto err3;
	if(!SSL_CTX_set_cipher_list(cfg->ctx,bfr))goto err3;

	len=0;
	if(ciphers&TLS_SERVER_CIPHER_CURVE_X25519)glist[len++]=NID_X25519;
	if(ciphers&TLS_SERVER_CIPHER_CURVE_SECP256R1)
		glist[len++]=NID_X9_62_prime256v1;
	if(ciphers&TLS_SERVER_CIPHER_CURVE_SECP384R1)glist[len++]=NID_secp384r1;
	if(ciphers&TLS_SERVER_CIPHER_CURVE_SECP521R1)glist[len++]=NID_secp521r1;
	if(!len)goto err3;
	if(!SSL_CTX_set1_groups(cfg->ctx,glist,len))goto err3;

	len=0;
	if(ciphers&TLS_SERVER_CIPHER_SIG_WITH_SHA256)
	{
		if(ciphers&TLS_SERVER_CIPHER_SIG_ECDSA)len+=snprintf(bfr+len,
			sizeof(bfr)-len,"%s%s",len?":":"","ECDSA+SHA256");
		if(ciphers&TLS_SERVER_CIPHER_SIG_RSA_PSS)len+=snprintf(bfr+len,
			sizeof(bfr)-len,"%s%s",len?":":"","RSA-PSS+SHA256");
		if(ciphers&TLS_SERVER_CIPHER_SIG_RSA)len+=snprintf(bfr+len,
			sizeof(bfr)-len,"%s%s",len?":":"","RSA+SHA256");
	}
	if(ciphers&TLS_SERVER_CIPHER_SIG_WITH_SHA384)
	{
		if(ciphers&TLS_SERVER_CIPHER_SIG_ECDSA)len+=snprintf(bfr+len,
			sizeof(bfr)-len,"%s%s",len?":":"","ECDSA+SHA384");
		if(ciphers&TLS_SERVER_CIPHER_SIG_RSA_PSS)len+=snprintf(bfr+len,
			sizeof(bfr)-len,"%s%s",len?":":"","RSA-PSS+SHA384");
		if(ciphers&TLS_SERVER_CIPHER_SIG_RSA)len+=snprintf(bfr+len,
			sizeof(bfr)-len,"%s%s",len?":":"","RSA+SHA384");
	}
	if(ciphers&TLS_SERVER_CIPHER_SIG_WITH_SHA512)
	{
		if(ciphers&TLS_SERVER_CIPHER_SIG_ECDSA)len+=snprintf(bfr+len,
			sizeof(bfr)-len,"%s%s",len?":":"","ECDSA+SHA512");
		if(ciphers&TLS_SERVER_CIPHER_SIG_RSA_PSS)len+=snprintf(bfr+len,
			sizeof(bfr)-len,"%s%s",len?":":"","RSA-PSS+SHA512");
		if(ciphers&TLS_SERVER_CIPHER_SIG_RSA)len+=snprintf(bfr+len,
			sizeof(bfr)-len,"%s%s",len?":":"","RSA+SHA512");
	}
	if(ciphers&TLS_SERVER_CIPHER_SIG_WITH_SHA1)
	{
		if(ciphers&TLS_SERVER_CIPHER_SIG_RSA)len+=snprintf(bfr+len,
			sizeof(bfr)-len,"%s%s",len?":":"","RSA+SHA1");
	}
	if(!len)goto err3;
	if(!SSL_CTX_set1_sigalgs_list(cfg->ctx,bfr))goto err3;

	return cfg;

err3:	SSL_CTX_free(cfg->ctx);
err2:	free(cfg);
err1:	return NULL;
}

static int ssl_server_add_dhfile(void *context,char *fn)
{
	SERVERCTX *cfg=context;
	FILE *fp;
	DH *dh;

	ERR_clear_error();

	if(cfg->dh)goto err1;
	if(!(fp=fopen(fn,"re")))goto err1;
	if(!(dh=PEM_read_DHparams(fp,NULL,NULL,NULL)))goto err2;
	fclose(fp);
	if(!SSL_CTX_set_tmp_dh(cfg->ctx,dh))goto err1;
	cfg->dh=dh;
	return 0;

err2:	fclose(fp);
err1:	return -1;
}

static int ssl_server_set_ticket_lifetime(void *context,int lifetime)
{
#ifdef ENABLE_TICKETS
	SERVERCTX *cfg=context;
	TICKET *tkt;
	struct timespec now;
#endif

	ERR_clear_error();

	if(lifetime)if(lifetime<TLS_SERVER_TICKET_LIFETIME_MIN||
		lifetime>TLS_SERVER_TICKET_LIFETIME_MAX)return -1;
#ifdef ENABLE_TICKETS
	pthread_mutex_lock(&mtx);
	if(!(cfg->tktmax=lifetime))
	{
		while(cfg->first)
		{
			tkt=cfg->first;
			cfg->first=tkt->next;
			cfg->lookup[tkt->name[0]]=NULL;
			OPENSSL_cleanse(tkt,sizeof(TICKET));
			free(tkt);
		}
		cfg->last=NULL;
	}
	else
	{
		SSL_CTX_set_timeout(cfg->ctx,cfg->tktmax);
		if(!clock_gettime(CLOCK_MONOTONIC,&now))purge(cfg,now.tv_sec);
	}
	pthread_mutex_unlock(&mtx);
#endif
	return 0;
}

static int ssl_server_add_server(void *context,char *sniname,char *cert,
	char *key,char *ocsp)
{
	SERVERCTX *cfg=context;
	SERVER *svr;
	SERVER **e;
	int i;

	ERR_clear_error();

	if(!(svr=load_server(sniname?sniname:"",cert,key)))goto err1;
	for(i=0,e=&cfg->list;*e;e=&(*e)->next,i++)
		if(!strcasecmp((*e)->sniname,svr->sniname))goto err2;
	if(!(svr->ctx=SSL_CTX_new(TLS_server_method())))goto err2;
	if(!ocsp)svr->ocspfn=NULL;
	else if(!(svr->ocspfn=strdup(ocsp)))goto err3;
	*e=svr;
	return i;

err3:	SSL_CTX_free(svr->ctx);
err2:	free_server(svr);
err1:	return -1;
}

static int ssl_server_add_verify_cafile(void *context,int id,char *fn)
{
	SERVERCTX *cfg=context;
	SERVER *svr;

	ERR_clear_error();

	for(svr=cfg->list;id&&svr;svr=svr->next,id--);
	if(!svr)return -1;
	if(!SSL_CTX_load_verify_locations(svr->ctx,fn,NULL))return -1;
	return 0;
}

static int ssl_server_add_verify_crlfile(void *context,int id,char *fn)
{
	SERVERCTX *cfg=context;
	SERVER *svr;

	ERR_clear_error();

	for(svr=cfg->list;id&&svr;svr=svr->next,id--);
	if(!svr)return -1;
	if(!SSL_CTX_load_verify_locations(svr->ctx,fn,NULL))return -1;
	if(enable_crl_check(svr))return -1;
	return 0;
}

static int ssl_server_set_alpn(void *context,int id,int nproto,char **proto)
{
	SERVERCTX *cfg=context;
	SERVER *svr;
	unsigned char *ptr;
	int len;
	int i;
	int l;

	for(svr=cfg->list;id&&svr;svr=svr->next,id--);
	if(!svr)goto err1;
	for(len=0,i=0;i<nproto;i++)if(!(l=strlen(proto[i]))||l>255)goto err1;
	else len+=l+1;
	if(!len)goto err1;
	if(!(svr->alpn=malloc(len)))goto err1;
	for(ptr=svr->alpn,i=0;i<nproto;i++,ptr+=l)
	{
		*ptr++=(unsigned char)(l=strlen(proto[i]));
		memcpy(ptr,proto[i],l);
	}
	svr->alpnlen=len;
	return 0;

err1:	return -1;
}

static int ssl_server_add_client_cert_ca(void *context,int id,char *fn)
{
	SERVERCTX *cfg=context;
	SERVER *svr;

	ERR_clear_error();

	for(svr=cfg->list;id&&svr;svr=svr->next,id--);
	if(!svr)goto err1;

	if(!svr->clnca)if(!(svr->clnca=sk_X509_NAME_new_null()))goto err1;
	if(!SSL_add_file_cert_subjects_to_stack(svr->clnca,fn))goto err1;
	return 0;

err1:	return -1;
}

static int ssl_server_set_client_cert_resume(void *context,int id,int mode)
{
	SERVERCTX *cfg=context;
	SERVER *svr;

	for(svr=cfg->list;id&&svr;svr=svr->next,id--);
	if(!svr)goto err1;
#ifdef ENABLE_TICKETS
	svr->clnresok=mode;
#endif
	return 0;

err1:	return -1;
}

static int ssl_server_resume_only_for_tls13(void *context,int id,int mode)
{
	SERVERCTX *cfg=context;
	SERVER *svr;

	for(svr=cfg->list;id&&svr;svr=svr->next,id--);
	if(!svr)goto err1;
#ifdef ENABLE_TICKETS
	svr->onlyv13=mode;
#endif
	return 0;

err1:	return -1;
}

static void ssl_server_fini(void *context)
{
	SERVERCTX *cfg=context;
	SERVER *svr;
#ifdef ENABLE_TICKETS
	TICKET *tkt;

	pthread_mutex_lock(&mtx);
	while(cfg->first)
	{
		tkt=cfg->first;
		cfg->first=tkt->next;
		OPENSSL_cleanse(tkt,sizeof(TICKET));
		free(tkt);
	}
	pthread_mutex_unlock(&mtx);
#endif
	while(cfg->list)
	{
		svr=cfg->list;
		cfg->list=svr->next;
#ifdef OCSP_CACHE
		pthread_mutex_lock(&otx);
		if(svr->ocsp)OPENSSL_free(svr->ocsp);
		svr->ocsp=NULL;
		pthread_mutex_unlock(&otx);
#endif
		free_server(svr);
	}
	ERR_clear_error();
	SSL_CTX_free(cfg->ctx);
	if(cfg->dh)DH_free(cfg->dh);
	free(cfg);
}

static void *ssl_server_accept(void *context,int fd,int timeout)
{
	int r;
	SERVERCTX *cfg=context;
	SERVER *svr;
	CONNCTX *ctx;
	X509 *x;
	X509_NAME *n;
	X509_NAME_ENTRY *e;
	ASN1_STRING *a;
	unsigned char *ptr;
	struct pollfd p;

	ERR_clear_error();

	if(!(ctx=malloc(sizeof(CONNCTX))))goto err1;
	memset(ctx,0,sizeof(CONNCTX));
	ctx->fd=p.fd=fd;
	ctx->libid=cfg->libid;

	if(!(ctx->ssl=SSL_new(cfg->ctx)))goto err2;
	if(!SSL_set_fd(ctx->ssl,fd))goto err3;
	if(!SSL_set_ex_data(ctx->ssl,cfgidx,cfg))goto err3;
	if(!SSL_set_ex_data(ctx->ssl,sslidx,ctx))goto err3;
	if(!SSL_set_ex_data(ctx->ssl,svridx,NULL))goto err3;

	while((r=SSL_accept(ctx->ssl))!=1)
	{
		if(r<0)switch(SSL_get_error(ctx->ssl,r))
		{
		case SSL_ERROR_WANT_READ:
			p.events=POLLIN;
			if(poll(&p,1,timeout)<1)goto err3;
			if((p.revents&POLLIN)!=POLLIN)goto err3;
			break;
		case SSL_ERROR_WANT_WRITE:
			p.events=POLLOUT;
			if(poll(&p,1,timeout)<1)goto err3;
			if((p.revents&POLLOUT)!=POLLOUT)goto err3;
			break;
		default:goto err3;
		}
		else goto err3;
	}

	if(!(svr=SSL_get_ex_data(ctx->ssl,svridx)))goto err3;

	if(svr->clnca)
	{
		if(!(x=SSL_get_peer_certificate(ctx->ssl)))goto err3;
		if(!(n=X509_get_subject_name(x)))goto err3;
		if(!ctx->cn)for(r=-1;(r=X509_NAME_get_index_by_NID(n,
			NID_commonName,r))!=-1;)
		{
			if(!(e=X509_NAME_get_entry(n,r)))continue;
			if(!(a=X509_NAME_ENTRY_get_data(e)))continue;
			if(ASN1_STRING_to_UTF8(&ptr,a)<0)continue;
			ctx->cn=strdup((char *)ptr);
			OPENSSL_free(ptr);
		}
		if(!ctx->on)for(r=-1;(r=X509_NAME_get_index_by_NID(n,
			NID_organizationName,r))!=-1;)
		{
			if(!(e=X509_NAME_get_entry(n,r)))continue;
			if(!(a=X509_NAME_ENTRY_get_data(e)))continue;
			if(ASN1_STRING_to_UTF8(&ptr,a)<0)continue;
			ctx->on=strdup((char *)ptr);
			OPENSSL_free(ptr);
		}
		if(!ctx->ou)for(r=-1;(r=X509_NAME_get_index_by_NID(n,
			NID_organizationalUnitName,r))!=-1;)
		{
			if(!(e=X509_NAME_get_entry(n,r)))continue;
			if(!(a=X509_NAME_ENTRY_get_data(e)))continue;
			if(ASN1_STRING_to_UTF8(&ptr,a)<0)continue;
			ctx->ou=strdup((char *)ptr);
			OPENSSL_free(ptr);
		}
	}

	return ctx;

err3:	SSL_free(ctx->ssl);
err2:	free(ctx);
err1:	close(fd);
	return NULL;
}

static void ssl_server_disconnect(void *context)
{
	CONNCTX *ctx=context;

	ERR_clear_error();

	if(!ctx->err)SSL_shutdown(ctx->ssl);
	SSL_free(ctx->ssl);
	shutdown(ctx->fd,SHUT_RDWR);
	close(ctx->fd);
	if(ctx->sniname)free(ctx->sniname);
	if(ctx->alpn)free(ctx->alpn);
	if(ctx->cn)free(ctx->cn);
	if(ctx->on)free(ctx->on);
	if(ctx->ou)free(ctx->ou);
	free(ctx);
}

static char *ssl_server_get_sni_name(void *context)
{
	CONNCTX *ctx=context;

	return ctx->sniname[0]?ctx->sniname:NULL;
}

static char *ssl_server_get_alpn(void *context)
{
	CONNCTX *ctx=context;

	return ctx->alpn;
}

static char *ssl_server_get_client_cert_cn(void *context)
{
	CONNCTX *ctx=context;

	return ctx->cn;
}

static char *ssl_server_get_client_cert_on(void *context)
{
	CONNCTX *ctx=context;

	return ctx->on;
}

static char *ssl_server_get_client_cert_ou(void *context)
{
	CONNCTX *ctx=context;

	return ctx->ou;
}

static int ssl_server_get_tls_version(void *context)
{
	CONNCTX *ctx=context;

	switch(SSL_version(ctx->ssl))
	{
	case TLS1_VERSION:
		return TLS_SERVER_TLS_1_0;
	case TLS1_1_VERSION:
		return TLS_SERVER_TLS_1_1;
	case TLS1_2_VERSION:
		return TLS_SERVER_TLS_1_2;
	case TLS1_3_VERSION:
		return TLS_SERVER_TLS_1_3;
	default:return -1;
	}
}

static int ssl_server_get_resumption_state(void *context)
{
	CONNCTX *ctx=context;

	return ctx->resumed;
}

static int ssl_server_write(void *context,void *data,int len)
{
	int l;
	CONNCTX *ctx=context;

	ERR_clear_error();

	if(!len)return 0;
	if((l=SSL_write(ctx->ssl,data,len))<=0)switch(SSL_get_error(ctx->ssl,l))
	{
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		errno=EAGAIN;
		return -1;
	default:errno=EIO;
		ctx->err=1;
		return -1;
	}
	else return l;
}

static int ssl_server_read(void *context,void *data,int len)
{
	int l;
	CONNCTX *ctx=context;

	ERR_clear_error();

	if(!len)return 0;
	if((l=SSL_read(ctx->ssl,data,len))<=0)switch(SSL_get_error(ctx->ssl,l))
	{
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		errno=EAGAIN;
		return -1;
	case SSL_ERROR_ZERO_RETURN:
		errno=EPIPE;
		ctx->err=1;
		return -1;
	default:errno=EIO;
		ctx->err=1;
		return -1;
	}
	else return l;
}

DISPATCH openssl=
{
	ssl_server_global_init,
	ssl_server_global_fini,
	ssl_server_init,
	ssl_server_add_dhfile,
	ssl_server_set_ticket_lifetime,
	ssl_server_add_server,
	ssl_server_add_client_cert_ca,
	ssl_server_add_verify_cafile,
	ssl_server_add_verify_crlfile,
	ssl_server_set_client_cert_resume,
	ssl_server_resume_only_for_tls13,
	ssl_server_set_alpn,
	ssl_server_fini,
	ssl_server_accept,
	ssl_server_disconnect,
	ssl_server_get_sni_name,
	ssl_server_get_alpn,
	ssl_server_get_client_cert_cn,
	ssl_server_get_client_cert_on,
	ssl_server_get_client_cert_ou,
	ssl_server_get_tls_version,
	ssl_server_get_resumption_state,
	ssl_server_write,
	ssl_server_read,
};
