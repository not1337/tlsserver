/*
 * This file is part of the tlsserver project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#ifdef HTTP2
#include <nghttp2/nghttp2.h>
#endif
#include "tlsserver.h"

typedef struct chain
{
	struct chain *next;
	char data[0];
} CHAIN;

typedef struct
{
	char *name;
	char *cert;
	char *key;
	char *ocsp;
	CHAIN *clnannca;
	CHAIN *clnvryca;
	CHAIN *clnvrycrl;
	int clnresume;
	int v13only;
} SERVER;

#ifdef HTTP2

#define ALPNENTRIES	2

static const char *alpn[2]=
{
	"h2",
	"http/1.1"
};

#else

#define ALPNENTRIES	1

static const char *alpn[1]=
{
	"http/1.1"
};

#endif

static int listensocket(char *host,int port)
{
	int s;
	int x;
	union
	{
		struct sockaddr sa;
		struct sockaddr_in a4;
		struct sockaddr_in6 a6;
	} addr;
	struct linger l;

	memset(&addr,0,sizeof(addr));
	if(inet_pton(AF_INET,host,&addr.a4.sin_addr)==1)
	{
		addr.a4.sin_family=AF_INET;
		addr.a4.sin_port=htons(port);
	}
	else if(inet_pton(AF_INET6,host,&addr.a6.sin6_addr)==1)
	{
		addr.a6.sin6_family=AF_INET6;
		addr.a6.sin6_port=htons(port);
	}
	else goto err1;

	if((s=socket(addr.sa.sa_family,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,
		0))==-1)goto err1;
	x=1;
	if(setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&x,sizeof(x)))goto err2;
	x=0;
	if(setsockopt(s,SOL_SOCKET,SO_OOBINLINE,&x,sizeof(x)))goto err2;
	x=0;
	if(addr.sa.sa_family==AF_INET6)
		if(setsockopt(s,IPPROTO_IPV6,IPV6_V6ONLY,&x,sizeof(x)))
			goto err2;
	if(bind(s,&addr.sa,sizeof(addr)))goto err2;
	l.l_onoff=1;
	l.l_linger=10;
	if(setsockopt(s,SOL_SOCKET,SO_LINGER,&l,sizeof(l)))goto err2;
	x=1;
	if(setsockopt(s,SOL_TCP,TCP_NODELAY,&x,sizeof(x)))goto err2;
	if(listen(s,256))goto err2;
	return s;

err2:   close(s);
err1:   return -1;
}

#ifdef HTTP2

typedef struct
{
	int32_t id;
	int state;
	int page;
	int pos;
	int total;
	char *sniname;
	void *tlsctx;
	nghttp2_session *sess;
	char bfr[1024];
} H2CTX;

static void hdrset(nghttp2_nv *hdr,char *name,char *value)
{
	hdr->name=(void *)name;
	hdr->value=(void *)value;
	hdr->namelen=strlen(name);
	hdr->valuelen=strlen(value);
	hdr->flags=NGHTTP2_NV_FLAG_NONE;
}

static ssize_t send_callback(nghttp2_session *session,const uint8_t *data,
	size_t length,int flags,void *user_data)
{
	int len;
	H2CTX *ctx=user_data;

	if((len=tls_server_write(ctx->tlsctx,(void *)data,length))==-1)
	{
		if(errno==EAGAIN)return NGHTTP2_ERR_WOULDBLOCK;
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}
	return len;
}

static ssize_t data_source_read_callback(nghttp2_session *session,
	int32_t stream_id,uint8_t *buf,size_t length,uint32_t *data_flags,
	nghttp2_data_source *source,void *user_data)
{
	int len;
	H2CTX *ctx=user_data;

	if(stream_id!=ctx->id)return NGHTTP2_ERR_CALLBACK_FAILURE;

	len=(length<ctx->total?length:ctx->total);
	if(!len)return 0;
	memcpy(buf,ctx->bfr+ctx->pos,len);
	ctx->pos+=len;
	ctx->total-=len;
	if(!ctx->total)*data_flags|=NGHTTP2_DATA_FLAG_EOF;
	return len;
}

static int on_frame_recv_callback(nghttp2_session *session,
	const nghttp2_frame *frame,void *user_data)
{
	H2CTX *ctx=user_data;
	nghttp2_nv hdrs[2];
	nghttp2_data_provider prd;

	if(frame->hd.type!=NGHTTP2_HEADERS||
		frame->headers.cat!=NGHTTP2_HCAT_REQUEST||
		frame->hd.stream_id!=ctx->id)return 0;
	if(!(frame->hd.flags&NGHTTP2_FLAG_END_STREAM))return 0;
	if(ctx->state==0xff)
	{
		hdrset(&hdrs[0],":status","200");
		hdrset(&hdrs[1],"Content-type","text/html");

		ctx->total=sprintf(ctx->bfr,"<html><head></head><body>"
			"<h1>Page %d</h1><p>Next page is <a "
			"href=\"/page%d.html\">Page %d</a>.<p>Return "
			"to <a href=\"/\">Home Page</a></body></html>\n",
			ctx->page+1,ctx->page+1,ctx->page+2);
		goto common;
	}
	else if(ctx->state<0x100)
	{
		hdrset(&hdrs[0],":status","404");
		hdrset(&hdrs[1],"Content-type","text/html");

		ctx->total=sprintf(ctx->bfr,"<html><head></head><body>"
			"<h1>Not found</h1></body></html>\n");

common:		ctx->pos=0;
		prd.read_callback=data_source_read_callback;
		if(nghttp2_submit_response(session,ctx->id,hdrs,2,&prd))
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		if(nghttp2_submit_goaway(session,NGHTTP2_FLAG_NONE,ctx->id,
			NGHTTP2_STREAM_CLOSED,NULL,0))
				return NGHTTP2_ERR_CALLBACK_FAILURE;
		if(nghttp2_session_send(session))
			return NGHTTP2_ERR_CALLBACK_FAILURE;
	}
	else return NGHTTP2_ERR_CALLBACK_FAILURE;
	return 0;
}

static int on_stream_close_callback(nghttp2_session *session,int32_t stream_id,
	uint32_t error_code,void *user_data)
{
	H2CTX *ctx=user_data;

	if(stream_id==ctx->id)
	{
		ctx->state|=0x100;
		if(nghttp2_session_terminate_session(session,NGHTTP2_NO_ERROR))
			return NGHTTP2_ERR_CALLBACK_FAILURE;
	}
	return 0;
}

static int on_header_callback(nghttp2_session *session,
	const nghttp2_frame *frame,const uint8_t *name,size_t namelen,
	const uint8_t *value,size_t valuelen,uint8_t flags,void *user_data)
{
	H2CTX *ctx=user_data;
	char *ptr;

	if(frame->hd.type!=NGHTTP2_HEADERS||
		frame->headers.cat!=NGHTTP2_HCAT_REQUEST||
		frame->hd.stream_id!=ctx->id)return 0;
	if(!strcasecmp((char *)name,":method"))
	{
		ctx->state|=0x01;
		if(!strcasecmp((char *)value,"GET"))ctx->state|=0x02;
	}
	else if(!strcasecmp((char *)name,":scheme"))
	{
		ctx->state|=0x04;
		if(!strcasecmp((char *)value,"https"))ctx->state|=0x08;
	}
	else if(!strcasecmp((char *)name,":authority"))
	{
		ctx->state|=0x10;
		if(!ctx->sniname)ctx->state|=0x20;
		else if(!strcasecmp((char *)value,ctx->sniname))
			ctx->state|=0x20;
	}
	else if(!strcasecmp((char *)name,":path"))
	{
		ctx->state|=0x40;
		if(!strcmp((char *)value,"/"))
		{
			ctx->page=0;
			ctx->state|=0x80;
		}
		else if(!strncmp((char *)value,"/page",5))
		{
			for(ptr=(char *)(value+5);*ptr;ptr++)
				if(*ptr<'0'||*ptr>'9')break;
			if(!strcmp(ptr,".html"))
			{
				*ptr=0;
				ctx->page=atoi((char *)(value+5));
				ctx->state|=0x80;
			}
		}
	}
	return 0;
}

static int on_begin_headers_callback(nghttp2_session *session,
	const nghttp2_frame *frame,void *user_data)
{
	H2CTX *ctx=user_data;

	if(frame->hd.type!=NGHTTP2_HEADERS||
		frame->headers.cat!=NGHTTP2_HCAT_REQUEST)return 0;
	if(ctx->id==-1)ctx->id=frame->hd.stream_id;
	return 0;
}

static void http2server(int fd,void *con)
{
	int r;
	int w;
	int len;
	int pos=0;
	int fill=0;
	int n=0;
	nghttp2_session_callbacks *cb;
	struct pollfd p;
	H2CTX h2;
	nghttp2_settings_entry iv[1]=
		{{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,1}};
	unsigned char bfr[16384];

	memset(&h2,0,sizeof(H2CTX));
	h2.id=-1;
	h2.state=0;
	h2.tlsctx=con;
	p.fd=fd;

	if(nghttp2_session_callbacks_new(&cb))goto err1;
	nghttp2_session_callbacks_set_send_callback(cb,send_callback);
	nghttp2_session_callbacks_set_on_frame_recv_callback(cb,
		on_frame_recv_callback);
	nghttp2_session_callbacks_set_on_stream_close_callback(cb,
		on_stream_close_callback);
	nghttp2_session_callbacks_set_on_header_callback(cb,on_header_callback);
	nghttp2_session_callbacks_set_on_begin_headers_callback(cb,
		on_begin_headers_callback);
	if(nghttp2_session_server_new(&h2.sess,cb,&h2))
	{
		nghttp2_session_callbacks_del(cb);
		goto err1;
	}
	nghttp2_session_callbacks_del(cb);
	if(nghttp2_submit_settings(h2.sess,NGHTTP2_FLAG_NONE,iv,1))goto err2;
	if(nghttp2_session_send(h2.sess))goto err2;

	while(1)
	{
repeat:		p.events=0;
		if((r=nghttp2_session_want_read(h2.sess)))p.events|=POLLIN;
		if((w=nghttp2_session_want_write(h2.sess)))p.events|=POLLOUT;
		if(fill)p.events&=~POLLIN;

		if(!r&&!w)break;

		if(poll(&p,1,fill?100:500)<1)
		{
			if(fill)
			{
				len=nghttp2_session_mem_recv(h2.sess,bfr+pos,
					fill);
				if(len<0)goto err2;
				if(len==fill)n=pos=fill=0;
				else
				{
					pos+=len;
					fill-=len;
				}
				if((n+=100)>=500)goto err2;
				goto repeat;
			}
			else goto err2;
		}
		n=0;

		if(p.revents&(POLLERR|POLLHUP))goto err2;

		if(p.revents&POLLIN)
		{
			fill=tls_server_read(h2.tlsctx,bfr,sizeof(bfr));
			switch(fill)
			{
			case -1:if(errno!=EAGAIN)goto err2;
				fill=0;
			case 0: break;
			default:len=nghttp2_session_mem_recv(h2.sess,bfr,fill);
				if(len<0)goto err2;
				if(len==fill)fill=0;
				else
				{
					pos=len;
					fill-=len;
				}
				break;
			}
		}

		if(p.revents&POLLOUT)
			if(w)if(nghttp2_session_send(h2.sess))goto err2;
	}

err2:	nghttp2_session_del(h2.sess);
err1:	tls_server_disconnect(con);
}

#endif

static void http11server(int fd,void *con)
{
	int i;
	int j;
	int l;
	int len;
	char *line;
	char *ptr;
	char *mem;
	struct pollfd p;
	char bfr[8192];

	p.fd=fd;
	p.events=POLLIN;

	for(len=0;len<sizeof(bfr)-1;)
	{
		if(poll(&p,1,500)<1)break;
		if(p.revents!=POLLIN)break;

		if((l=tls_server_read(con,bfr+len,sizeof(bfr)-len-1))==-1)
			switch(errno)
		{
		case EIO:
			goto out;
		case EAGAIN:
			continue;
		case EPIPE:
			goto rxdone;
		}
		len+=l;
		for(i=0,j=0;i<len;i++)if(bfr[i]=='\r')continue;
		else if(bfr[i]!='\n')j=0;
		else if(++j==2)
		{
			bfr[i]=0;
			goto rxdone;
		}
	}

rxdone:	bfr[len]=0;

	if(!(line=strtok_r(bfr,"\r\n",&mem)))goto out;
	if(!(ptr=strtok_r(line," \t",&mem))||strcmp(ptr,"GET"))goto err;
	if(!(ptr=strtok_r(NULL," \t",&mem))||*ptr!='/')goto err;

	if(strcmp(ptr,"/"))
	{
		if(strncmp(ptr,"/page",5))goto err;
		for(line=ptr+6;*line;line++)if(*line<'0'||*line>'9')break;
		if(strcmp(line,".html"))goto err;
		*line=0;
		j=atoi(ptr+5);
	}
	else j=0;

	len=sprintf(bfr,"HTTP/1.1 200 OK\r\nContent-type: text/html\r\n"
		"Connection: close\r\n\r\n<html><head></head><body>"
		"<h1>Page %d</h1><p>Next page is <a href=\"/page%d.html\">"
		"Page %d</a>.<p>Return to <a href=\"/\">Home Page</a>"
		"</body></html>\n",j+1,j+1,j+2);

	if(0)
	{
err:		len=sprintf(bfr,"HTTP/1.1 404 Not Found\r\n"
			"Content-type: text/html\r\n"
			"Connection: close\r\n\r\n"
			"<html><head></head><body><h1>Not found</h1>"
			"</body></html>\n");
	}

	for(p.events=POLLOUT,i=0;i<len;)
	{
		if(poll(&p,1,500)<1)break;
		if(p.revents!=POLLOUT)break;
		if((l=tls_server_write(con,bfr+i,len-i))==-1)goto out;
		i+=l;
	}

out:	tls_server_disconnect(con);
}

static char *connection_protocol(void *con)
{
	switch(tls_server_get_tls_version(con))
	{
	case TLS_SERVER_TLS_1_0:
		return "TLSv1.0";
	case TLS_SERVER_TLS_1_1:
		return "TLSv1.1";
	case TLS_SERVER_TLS_1_2:
		return "TLSv1.2";
	case TLS_SERVER_TLS_1_3:
		return "TLSv1.3";
	default:return "unknown protocol";
	}
}

static void usage(void)
{
	fprintf(stderr,"Usage:\n"
		"tester [General-Options] [TLS-Options] <Per-Server-Options> "
			"[...] <listen-ip>\n\n"
		"General Options:\n"
		"-p <port>     listening port (default 443)\n\n"
		"TLS Options:\n"
		"-0            use TLSv1.0 as minimum accepted version "
			"(default)\n"
		"-2            use TLSv1.2 as minimum accepted version\n"
		"-3            use TLSv1.3 as minimum accepted version\n"
		"-X            use TLSv1.0 as maximum accepted version "
			"(default is TLSv1.3)\n"
		"-x            use TLSv1.2 as maximum accepted version "
			"(default is TLSv1.3) \n"
		"-S            select strong cryptographic configuration\n"
		"-M            select modern cryptographic configuration\n"
		"-N            select normal cryptographic configuration\n"
		"-C            select compatability cryptographic "
			"configuration (default)\n"
		"-G            select specifically GnuTLS backend (default "
			"is any)\n"
		"-O            select specifically OpenSSL backend (default "
			"is any)\n"
		"-l <lifetime> set ticket lifetime in seconds (0 or 90-86400, "
			"default 0=off)\n"
		"-d <dhfile>   set DHE parameter file\n\n"
		"Per SNI Server Options:\n"
		"-s <sni-name> set server SNI name (empty string for "
			"catchall server)\n"
		"-c <certfile> server certificate file (full chain from "
			"server to CA)\n"
		"-k <keyfile>  server key file\n"
		"-o <ocspfile> specify OCSP file for server (optional)\n"
		"-v            allow session resume only if TLSv1.3 is used "
			"(not for GnuTLS backend)\n"
		"-A <certfile> CA file to announce to client (optional, "
			"multiple)\n"
		"-a <certfile> CA file to verify client certificate (optional, "
			"multiple)\n"
		"-r <crlfile>  CRL file to verify client certificate "
			"(optional, multiple)\n"
		"-R            allow session resume for client certificate "
			"authentication\n");
	exit(1);
}

int main(int argc,char *argv[])
{
	int s;
	int c;
	int id;
	int len;
	int minver=-1;
	int maxver=-1;
	unsigned int sec=0;
	int lib=TLSSERVER_USE_ANY;
	int lifetime=-1;
	int port=-1;
	int idx=-1;
	char *dhfile=NULL;
	char *host=NULL;
	char *proto;
	char *cn;
	char *on;
	char *ou;
	CHAIN *ch;
	void *cfg;
	void *con;
	struct pollfd p;
	SERVER svr[8];

	memset(svr,0,sizeof(svr));

	while((c=getopt(argc,argv,"023SMNCOGd:l:s:c:k:o:A:a:r:Rp:xXv"))!=-1)
		switch(c)
	{
	case '0':
		if(minver!=-1)usage();
		minver=TLS_SERVER_TLS_1_0;
		break;
	case '2':
		if(minver!=-1)usage();
		minver=TLS_SERVER_TLS_1_2;
		break;
	case '3':
		if(minver!=-1)usage();
		minver=TLS_SERVER_TLS_1_3;
		break;
	case 'S':
		if(sec)usage();
		sec=TLS_SERVER_SECURITY_STRONG;
		break;
	case 'M':
		if(sec)usage();
		sec=TLS_SERVER_SECURITY_MODERN;
		break;
	case 'N':
		if(sec)usage();
		sec=TLS_SERVER_SECURITY_NORMAL;
		break;
	case 'C':
		if(sec)usage();
		sec=TLS_SERVER_SECURITY_COMPAT;
		break;
	case 'O':
		if(lib!=TLSSERVER_USE_ANY)usage();
		lib=TLSSERVER_USE_OPENSSL;
		break;
	case 'G':
		if(lib!=TLSSERVER_USE_ANY)usage();
		lib=TLSSERVER_USE_GNUTLS;
		break;
	case 'd':
		if(dhfile)usage();
		dhfile=optarg;
		break;
	case 'l':
		if(lifetime!=-1)usage();
		if((lifetime=atoi(optarg))<0||
			lifetime>TLS_SERVER_TICKET_LIFETIME_MAX||
			(lifetime!=TLS_SERVER_NO_TICKETS&&
				lifetime<TLS_SERVER_TICKET_LIFETIME_MIN))
					usage();
		break;
	case 's':
		if(idx==7)usage();
		svr[++idx].name=optarg;
		break;
	case 'c':
		if(idx==-1||svr[idx].cert)usage();
		svr[idx].cert=optarg;
		break;
	case 'k':
		if(idx==-1||svr[idx].key)usage();
		svr[idx].key=optarg;
		break;
	case 'o':
		if(idx==-1||svr[idx].ocsp)usage();
		svr[idx].ocsp=optarg;
		break;
	case 'A':
		if(idx==-1)usage();
		len=strlen(optarg)+1;
		if(svr[idx].clnannca)
		{
			for(ch=svr[idx].clnannca;ch->next;ch=ch->next);
			if(!(ch->next=malloc(sizeof(CHAIN)+len)))
			{
				perror("malloc");
				return 1;
			}
			ch=ch->next;
		}
		else if(!(ch=svr[idx].clnannca=malloc(sizeof(CHAIN)+len)))
		{
			perror("malloc");
			return 1;
		}
		ch->next=NULL;
		strcpy(ch->data,optarg);
		break;
	case 'a':
		if(idx==-1)usage();
		len=strlen(optarg)+1;
		if(svr[idx].clnvryca)
		{
			for(ch=svr[idx].clnvryca;ch->next;ch=ch->next);
			if(!(ch->next=malloc(sizeof(CHAIN)+len)))
			{
				perror("malloc");
				return 1;
			}
			ch=ch->next;
		}
		else if(!(ch=svr[idx].clnvryca=malloc(sizeof(CHAIN)+len)))
		{
			perror("malloc");
			return 1;
		}
		ch->next=NULL;
		strcpy(ch->data,optarg);
		break;
	case 'r':
		if(idx==-1)usage();
		len=strlen(optarg)+1;
		if(svr[idx].clnvrycrl)
		{
			for(ch=svr[idx].clnvrycrl;ch->next;ch=ch->next);
			if(!(ch->next=malloc(sizeof(CHAIN)+len)))
			{
				perror("malloc");
				return 1;
			}
			ch=ch->next;
		}
		else if(!(ch=svr[idx].clnvrycrl=malloc(sizeof(CHAIN)+len)))
		{
			perror("malloc");
			return 1;
		}
		ch->next=NULL;
		strcpy(ch->data,optarg);
		break;
	case 'R':
		if(idx==-1||svr[idx].clnresume)usage();
		svr[idx].clnresume=1;
		break;
	case 'p':
		if(port!=-1)usage();
		if((port=atoi(optarg))<1||port>65535)usage();
		break;
	case 'x':
		if(maxver!=-1)usage();
		maxver=TLS_SERVER_TLS_1_2;
		break;
	case 'X':
		if(maxver!=-1)usage();
		maxver=TLS_SERVER_TLS_1_0;
		break;
	case 'v':
		if(idx==-1||svr[idx].v13only)usage();
		svr[idx].v13only=1;
		break;
	default:usage();
	}

	if(optind+1!=argc||idx==-1)usage();
	host=argv[optind];

	if(minver==-1)minver=TLS_SERVER_TLS_1_0;
	if(maxver==-1)maxver=TLS_SERVER_TLS_1_3;
	if(!sec)sec=TLS_SERVER_SECURITY_COMPAT;
	if(lifetime==-1)lifetime=0;
	if(port==-1)port=443;

	if(maxver<minver)usage();

	signal(SIGPIPE,SIG_IGN);

	if(tls_server_global_init())
	{
		fprintf(stderr,"tls_server_global_init failed\n");
		return 1;
	}

	if(!(cfg=tls_server_init(lib,minver,maxver,sec)))
	{
		fprintf(stderr,"tls_server_init failed\n");
		return 1;
	}

	if(dhfile)if(tls_server_add_dhfile(cfg,dhfile))
	{
		fprintf(stderr,"tls_server_add_dhfile failed\n");
		return 1;
	}

	if(tls_server_set_ticket_lifetime(cfg,lifetime))
	{
		fprintf(stderr,"tls_server_set_ticket_lifetime failed\n");
		return 1;
	}

	for(c=0;c<=idx;c++)
	{
		if((id=tls_server_add_server(cfg,svr[c].name,svr[c].cert,
			svr[c].key,svr[c].ocsp))==-1)
		{
			fprintf(stderr,"tls_server_add_server failed\n");
			return 1;
		}

		for(ch=svr[c].clnannca;ch;ch=ch->next)
			if(tls_server_add_client_cert_ca(cfg,id,ch->data))
		{
			fprintf(stderr,"tls_server_add_client_cert_ca "
				"failed\n");
			return 1;
		}

		for(ch=svr[c].clnvryca;ch;ch=ch->next)
			if(tls_server_add_verify_cafile(cfg,id,ch->data))
		{
			fprintf(stderr,"tls_server_add_verify_cafile "
				"failed\n");
			return 1;
		}

		for(ch=svr[c].clnvrycrl;ch;ch=ch->next)
			if(tls_server_add_verify_crlfile(cfg,id,ch->data))
		{
			fprintf(stderr,"tls_server_add_verify_crlfile "
				"failed\n");
			return 1;
		}

		if(tls_server_set_client_cert_resume(cfg,id,svr[c].clnresume))
		{
			fprintf(stderr,"tls_server_set_client_cert_resume "
				"failed\n");
			return 1;
		}

		if(tls_server_resume_only_for_tls13(cfg,id,svr[c].v13only))
		{
			fprintf(stderr,"tls_server_resume_only_for_tls13 "
				"failed\n");
			return 1;
		}
	}

	if((tls_server_set_alpn(cfg,id,ALPNENTRIES,(char **)alpn)))return 1;
	if((s=listensocket(host,port))==-1)return 1;
	p.fd=s;
	p.events=POLLIN;
	while(1)
	{
		while(poll(&p,1,-1)<1);
		if((c=accept4(s,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC))==-1)
			continue;
		if(!(con=tls_server_accept(cfg,c,500)))continue;
		if(!(host=tls_server_get_sni_name(con)))host="unspecified host";
		if(!(proto=tls_server_get_alpn(con)))proto="unknown";
		if(!(cn=tls_server_get_client_cert_cn(con)))cn="";
		if(!(on=tls_server_get_client_cert_on(con)))on="";
		if(!(ou=tls_server_get_client_cert_ou(con)))ou="";
		printf("%s %s connection for %s using %s protocol.\n",
			tls_server_get_resumption_state(con)?"Resumed":"New",
			connection_protocol(con),host,proto);
		if(*cn||*on||*ou)printf("Client Certificate:\nO=%s\nOU=%s\n"
			"CN=%s\n",on,ou,cn);
#ifdef HTTP2
		if(!strcmp(proto,"h2"))http2server(c,con);
		else http11server(c,con);
#else
		http11server(c,con);
#endif
	}
	tls_server_fini(cfg);
	tls_server_global_fini();
	return 0;
}
