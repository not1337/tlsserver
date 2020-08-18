/*
 * This file is part of the tlsserver project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GNU Lesser General
 * Public License, version 2.1 or, at your choice, any later version of
 * this license.
 */

#ifndef _TLSSERVER_H
#define _TLSSERVER_H

/*
 * backend library to use, any means use first compiled in library
 */

#define TLSSERVER_USE_ANY			0
#define TLSSERVER_USE_OPENSSL			1
#define TLSSERVER_USE_GNUTLS			2

/*
 * tls version definitions, should be self explaining
 */

#define TLS_SERVER_TLS_1_0			0
#define TLS_SERVER_TLS_1_1			1
#define TLS_SERVER_TLS_1_2			2
#define TLS_SERVER_TLS_1_3			3

/*
 * cipher strength, cipher group, curve and signature algorithms
 */

#define TLS_SERVER_CIPHER_STRENGTH_128		0x00000001
#define TLS_SERVER_CIPHER_STRENGTH_256		0x00000002
#define TLS_SERVER_CIPHER_GROUP_ECDH		0x00000100
#define TLS_SERVER_CIPHER_GROUP_DH		0x00000200
#define TLS_SERVER_CIPHER_GROUP_RSA		0x00000400
#define TLS_SERVER_CIPHER_CURVE_X25519		0x00010000
#define TLS_SERVER_CIPHER_CURVE_SECP256R1	0x00020000
#define TLS_SERVER_CIPHER_CURVE_SECP384R1	0x00040000
#define TLS_SERVER_CIPHER_CURVE_SECP521R1	0x00080000
#define TLS_SERVER_CIPHER_SIG_WITH_SHA1		0x01000000
#define TLS_SERVER_CIPHER_SIG_WITH_SHA256	0x02000000
#define TLS_SERVER_CIPHER_SIG_WITH_SHA384	0x04000000
#define TLS_SERVER_CIPHER_SIG_WITH_SHA512	0x08000000
#define TLS_SERVER_CIPHER_SIG_RSA		0x10000000
#define TLS_SERVER_CIPHER_SIG_RSA_PSS		0x20000000
#define TLS_SERVER_CIPHER_SIG_ECDSA		0x40000000

/*
 * strong security, if required or paranoid
 */

#define TLS_SERVER_SECURITY_STRONG \
	(TLS_SERVER_CIPHER_STRENGTH_256|TLS_SERVER_CIPHER_GROUP_ECDH|\
	TLS_SERVER_CIPHER_CURVE_SECP384R1|TLS_SERVER_CIPHER_CURVE_SECP521R1|\
	TLS_SERVER_CIPHER_SIG_WITH_SHA384|TLS_SERVER_CIPHER_SIG_WITH_SHA512|\
	TLS_SERVER_CIPHER_SIG_ECDSA|TLS_SERVER_CIPHER_SIG_RSA_PSS)

/*
 * modern setup, no DHE
 */

#define TLS_SERVER_SECURITY_MODERN \
	(TLS_SERVER_CIPHER_STRENGTH_256|TLS_SERVER_CIPHER_STRENGTH_128|\
	TLS_SERVER_CIPHER_GROUP_ECDH|TLS_SERVER_CIPHER_CURVE_X25519|\
	TLS_SERVER_CIPHER_CURVE_SECP256R1|TLS_SERVER_CIPHER_CURVE_SECP384R1|\
	TLS_SERVER_CIPHER_SIG_WITH_SHA256|TLS_SERVER_CIPHER_SIG_WITH_SHA384|\
	TLS_SERVER_CIPHER_SIG_ECDSA|TLS_SERVER_CIPHER_SIG_RSA_PSS)

/*
 * normal configuration including DHE and standard RSA
 */

#define TLS_SERVER_SECURITY_NORMAL \
	(TLS_SERVER_CIPHER_STRENGTH_256|TLS_SERVER_CIPHER_STRENGTH_128|\
	TLS_SERVER_CIPHER_GROUP_ECDH|TLS_SERVER_CIPHER_GROUP_DH|\
	TLS_SERVER_CIPHER_CURVE_X25519|TLS_SERVER_CIPHER_CURVE_SECP256R1|\
	TLS_SERVER_CIPHER_CURVE_SECP384R1|TLS_SERVER_CIPHER_SIG_WITH_SHA256|\
	TLS_SERVER_CIPHER_SIG_WITH_SHA384|TLS_SERVER_CIPHER_SIG_ECDSA|\
	TLS_SERVER_CIPHER_SIG_RSA_PSS|TLS_SERVER_CIPHER_SIG_RSA)

/*
 * compat mode, allows RSA-SHA1 signature algorithm, emergency use only
 */

#define TLS_SERVER_SECURITY_COMPAT \
	(TLS_SERVER_CIPHER_STRENGTH_256|TLS_SERVER_CIPHER_STRENGTH_128|\
	TLS_SERVER_CIPHER_GROUP_ECDH|TLS_SERVER_CIPHER_GROUP_DH|\
	TLS_SERVER_CIPHER_GROUP_RSA|TLS_SERVER_CIPHER_CURVE_X25519|\
	TLS_SERVER_CIPHER_CURVE_SECP256R1|TLS_SERVER_CIPHER_CURVE_SECP384R1|\
	TLS_SERVER_CIPHER_CURVE_SECP521R1|TLS_SERVER_CIPHER_SIG_WITH_SHA1|\
	TLS_SERVER_CIPHER_SIG_WITH_SHA256|TLS_SERVER_CIPHER_SIG_WITH_SHA384|\
	TLS_SERVER_CIPHER_SIG_WITH_SHA512|TLS_SERVER_CIPHER_SIG_RSA|\
	TLS_SERVER_CIPHER_SIG_RSA_PSS|TLS_SERVER_CIPHER_SIG_ECDSA)

/*
 * session resumption disable and ticket lifetime definitions
 */

#define TLS_SERVER_NO_TICKETS			0
#define TLS_SERVER_TICKET_LIFETIME_MIN		90
#define TLS_SERVER_TICKET_LIFETIME_MAX		86400

/*
 * special resumption handling for client certificate authentication
 */

#define TLS_SERVER_NO_RESUME_WITH_CLIENT_CERT	0
#define TLS_SERVER_DO_RESUME_WITH_CLIENT_CERT	1

/*
 * resumption restriction values depending on the TLS version used
 * (if the selected backend library allows for this feature)
 */

#define TLS_SERVER_RESUME_WITH_ANY_TLS_VERSION	0
#define TLS_SERVER_RESUME_WITH_TLS_1_3_ONLY	1

/*
 * tls_server_global_init
 *
 * call once at application start, returns 0 in case of success and
 * -1 in case of an error
 */

extern int tls_server_global_init(void);

/*
 * tls_server_global_fini
 *
 * call once before application end
 */

extern void tls_server_global_fini(void);

/*
 * tls_server_init
 *
 * initialize common connection parameters, set minimum and maximum
 * supported TLS version as well as acceptable security level, returns
 * a server context or NULL in case of an error
 */

extern void *tls_server_init(int library,int tls_version_min,
	int tls_version_max,int ciphers);

/*
 * tls_server_add_dhfile
 *
 * add DHE parameter file, there can only be one parameter file, returns
 * 0 in case of success and -1 in case of an error - note that such a
 * PEM formatted file can be generated using "openssl dhparam"
 */

extern int tls_server_add_dhfile(void *context,char *fn);

/*
 * tls_server_set_ticket_lifetime
 *
 * set ticket lifetime (see above definitions for limits, use 0 to
 * disable session resumption (default), returns 0 in case of success
 * and -1 in case of an error - note that at runtime you should call
 * this function periodically (once every lifetime seconds) if there is
 * no new client connection to purge expired ticket keys from memory
 * as a security measure
 */

extern int tls_server_set_ticket_lifetime(void *context,int lifetime);

/*
 * tls_server_add_server
 *
 * add a server definition to the common connection parameters,
 * sniname is the SNI host name of the server or an empty string for
 * a catchall server, cert is a file with the full server certificate
 * chain, i.e. starting with the server certificate and ending with the
 * associated CA certificate, key is the file kontaining the key for
 * the server certificate and OCSP is the file name of the file
 * containing the OCSP data for the server certificate or NULL if
 * such a file is not provided - note that the OCSP file specified
 * does not yet need to exist and is reloaded at runtime if modified,
 * this function returns either an id for the server definition or -1
 * in case of an error - note that the cert and key files need to be
 * in PEM format whereas the OCSP file must be DER formatted which is
 * the default when this file is retrieved from an OCSP server.
 */

extern int tls_server_add_server(void *context,char *sniname,char *cert,
	char *key,char *ocsp);

/*
 * tls_server_add_client_cert_ca
 *
 * add a certificate that is presented to the client for client side
 * client certificate selection to a server definition, can be called
 * multiple times, returns 0 in case of success or -1 in case of an error,
 * the CA file must be PEM formatted
 */

extern int tls_server_add_client_cert_ca(void *context,int id,char *fn);

/*
 * tls_server_add_verify_cafile
 *
 * add a certificate that is used to verify a client certificate to a
 * server definition, can be called multiple times, returns 0 in case
 * of success and -1 in case of an error, the CA file must be PEM
 * formatted
 */

extern int tls_server_add_verify_cafile(void *context,int id,char *fn);

/*
 * tls_server_add_verify_crlfile
 *
 * add a certificate CRL file for client certificate verification to a
 * server definition, can be called multiple times, returns 0 in case
 * of success and -1 in case of an error, the CRL file must be PEM
 * formatted
 */

extern int tls_server_add_verify_crlfile(void *context,int id,char *fn);

/*
 * tls_server_set_client_cert_resume
 *
 * enable session resumption for client certificate authentication to a
 * server definition, default is disabled (only enable if you know the
 * implications), returns 0 in case of success and -1 in case of an error
 */

extern int tls_server_set_client_cert_resume(void *context,int id,int mode);

/*
 * tls_server_resume_only_for_tls13
 *
 * enable session resumption only if TLSv1.3 and thus more secure tickets
 * are used for a server definition, returns 0 in case of success and -1
 * in case of an error - note that GnuTLS is so broken with respect to
 * session tickets that this option cannot be implemented and thus for
 * GnuTLS -1 is always returned
 */

extern int tls_server_resume_only_for_tls13(void *context,int id,int mode);

/*
 * tls_server_set_alpn
 *
 * adds ALPN potocol negotiation to a server definition, proto is a pointer
 * to an array of string pointers with the acceptable protocols in
 * descending order of priority, nproto is the amount of protocol strings
 * in the array, returns 0 in case of success and -1 in case of an error
 */

extern int tls_server_set_alpn(void *context,int id,int nproto,char **proto);

/*
 * tls_server_fini
 *
 * release common connection parameters, must always be called
 * after a successful call to tls_server_init if the common
 * connection parameters are no longer required
 */

extern void tls_server_fini(void *context);

/*
 * tls_server_accept
 *
 * accept a client connection and perform the TLS handshake using the
 * common connection parameters and the TCP socket of the connection,
 * timeout is the timeout in milliseconds either for connection
 * completion or poll idle time depending on the library used,
 * returns either a connection context or NULL in case of an error
 */

extern void *tls_server_accept(void *context,int fd,int timeout);

/*
 * tls_server_disconnect
 *
 * disconnect and close the established ths session as well as the
 * used tcp socket, must always be called after a successful call
 * to tls_server_accept when the connection is no longer required
 */

extern void tls_server_disconnect(void *context);

/*
 * tls_server_get_sni_name
 *
 * returns a pointer (do not free) to the desired SNI hostmname or
 * NULL if no SNI host name was selected or matching, meaning that
 * the catchall server definition was selected
 */

extern char *tls_server_get_sni_name(void *context);

/*
 * tls_server_get_alpn
 *
 * returns a pointer (do not free) to the selected ALPN protocol or
 * NULL if no protocol was selected
 */

extern char *tls_server_get_alpn(void *context);

/*
 * tls_server_get_client_cert_cn
 *
 * returns a pointer (do not free) to the common name of the client
 * certificate or NULL if client certificates are not in use or the
 * client certificate does not contain a common name
 */

extern char *tls_server_get_client_cert_cn(void *context);

/*
 * tls_server_get_client_cert_on
 *
 * returns a pointer (do not free) to the organization name of the client
 * certificate or NULL if client certificates are not in use or the
 * client certificate does not contain a organization name
 */

extern char *tls_server_get_client_cert_on(void *context);

/*
 * tls_server_get_client_cert_ou
 *
 * returns a pointer (do not free) to the organizational unit name of
 * the client certificate or NULL if client certificates are not in use
 * or the client certificate does not contain a organizational unit name
 */

extern char *tls_server_get_client_cert_ou(void *context);

/*
 * tls_server_get_tls_version
 *
 * returns either the tls version (see definitions above) or -1 if the
 * version could not be retrieved or if it is unknown
 */

extern int tls_server_get_tls_version(void *context);

/*
 * tls_server_get_resumption_state
 *
 * returns 0 if the connection is new, i.e. not resumed and 1 if the
 * connection is a resumed session
 */

extern int tls_server_get_resumption_state(void *context);

/*
 * tls_server_write
 *
 * send the specified amount of data over the established tls session,
 * in case of an error -1 is returned and errno is set to either
 * EAGAIN (just (e)poll and retry) or EIO (fatal error), in case of
 * success the amount of bytes sent is returned
 */

extern int tls_server_write(void *context,void *data,int len);

/*
 * tls_server_read
 *
 * read up to the amount specified data from the established tls session,
 * in case of an error -1 is returned and errno is set to either
 * EAGAIN (just (e)poll and retry), EPIPE (connection closed by peer)
 * or EIO (fatal error), in case of success the amount of bytes read
 * is returned
 */

extern int tls_server_read(void *context,void *data,int len);

#endif
