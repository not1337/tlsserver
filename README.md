tlsserver - a simple to use TLS server library for Linux

tlsserver is a TLS server library that can use OpenSSL or GnuTLS
as a backend. As a difference to other libraries all mentioned
backends can be enabled at compile time and backend selection
is possibe at runtime.

The libtlsserver.so shared library as well as the required tlsserver.h
header file are licensed LGPLv2.1+, everything else is licensed GPLv2+.

mbedTLS is not included as a backend in the tlsserver library.
While mbedTLS may suit simple use cases as a server it doesn't
support the features required by the tlsserver library, thus its
use as a backend is just not possible.

The tlsserver library should be performant enough to suit low to medium
loaded stand alone servers or clusters without session ticket usage.
High performance servers do in practice require specially tuned code
which then needs a dedicated backend library and clustering with tickets
is successfully prevented by the GnuTLS backend (see rant below).

A tester application in included which serves simple synthetic
HTML pages via HTTP/1.1 or, if compiled with nghttp2, HTTP/2.

The tlsserver API is really very simple. For a very simple setup
(e.g. development) only 9 library calls are necessary, 3 of which
are for cleanup only. In practise you do:

* tls\_server\_global\_init
* tls\_server\_init
* tls\_server\_add\_server
* tls\_server\_accept
* tls\_server\_read and tls\_server\_write
* tls\_server\_disconnect
* tls\_server\_fini
* tls\_server\_global\_fini

If you need to support DHE in addition to ECDHE you need to call:

* tls\_server\_add\_dhfile

Some reasoning why the tlsserver library doesn't enable FFDHE, which is
quite advertised in the GnuTLS API documentation. The specification for this
is RFC7919 and if you would just read chapter 8.3 you will find out
that for the same security level elliptic curves perform much better
than finite field Diffie-Hellman. In general ECDHE should be preferred
over DHE or FFDHE for the forseeable future.

To add ALPN to a per server configuration, i.e. to enable application
protocol negotiation during the TLS handshake, use:

* tls\_server\_set\_alpn

If you require client certificates for authentication you will need to
use the following functions for per server configuration (note that
when you use the tlsserver library and configure client certificate
authentication for a server the authentication is then mandatory):

* tls\_server\_add\_client\_cert\_ca
* tls\_server\_add\_verify\_cafile
* tls\_server\_add\_verify\_crlfile

After a connection between client and server is established, you
can use the following functions to get required information about
the connection:

* tls\_server\_get\_sni\_name
* tls\_server\_get\_alpn
* tls\_server\_get\_tls\_version
* tls\_server\_get\_resumption\_state
* tls\_server\_get\_client\_cert\_cn
* tls\_server\_get\_client\_cert\_on
* tls\_server\_get\_client\_cert\_ou

If you want to enable session resumption the tlsserver library supports
the use of stateless tickets. You will have to set a ticket lifetime
to enable session resumtion in general, can then select to enable
resumption only for the more secure TLSv1.3 tickets per server
configuration if the selected backend offers an API to configure this
and you can, though this is discouraged, enable session tickets for
server configurarions using client certificate authentication.
The relevant functions are:

* tls\_server\_set\_ticket\_lifetime
* tls\_server\_resume\_only\_for\_tls13
* tls\_server\_set\_client\_cert\_resume

In general you should use session resumption with care and think about it
thouroughly. Session resumption is not supposed to ease the load of the
server keeping sessions alive forever. This kind of usage weakens
security and thus endangers communication privacy. A sensible use case for
session resumption is to prevent excessive handshakes in case of an
intermittent connection between client (e.g. a mobile device) and server,
until the necessary communication is complete. As a rule of thumb
keep session ticket validity as short as possible. There's no "just in case"
ruling for unnecessary lengthy ticket validity. If the clients of your
server usually can complete a transaction without reconnect and the
communication protocol you use doesn't demand a rapid series of short
connections between client and server you should keep session resumption
disabled which is the tlsserver library default.

Some words about session resumption and authentication by client certificates.
The tlsserver library by default disables session resumption if client
certificates are used, even when resumption is enabled in general. This is
done for a simple but quite often overseen reason. At session resumption
time no certificates are exchanged or verified. This includes client
certificates. Thus a malicious user could keep access to a server
indefinitely by just disconnecting before a ticket expires and then
reconnecting with this ticket and receiving a new ticket from the
server while the client certificate that should have been verified
has been expired or revoked. This means if you enable session resumption
when client certificates are in use you cannot rely on certificate
expiry or revocation, you must implement an authorization beyond
TLS yourself. Don't say you haven't been warned. And, well, there's
no option within the tlsserver library to make client certificates
optional. If you run such a server you should thoroughly consider
using SNI and splitting your stuff into a public and a restricted
part. This makes security really easier to handle.

And as far as GnuTLS is concerned the tlsserver library has to implement
a workaround over a deficiency of GnuTLS: GnuTLS advertises all loaded
certificates to a client for client side client certificate selection.
Thus if the server CA and the client certificate CA are different but
the client has client certificates of both the server CA (e.g. for
another site) and the client certificiate CA chances are that the
client will present the wrong client certificate to the server and
thus will be prohibited to access the server. The tlsserver library
uses the states of the GnuTLS handshake processing engine in a
hook function to switch certificate stores at the proper time to
assert that the client is only presented the client certificate CA
for client certificate selection. This workaround must be revalidated
if the GnuTLS library receives a major update and unless the GnuTLS
folks fix this deficiency this cannot be helped otherwise.

Some rant about GnuTLS and security. There's a reason why the GnuTLS folks
disable session resume with tickets when PFS is selected in the priority
string. No, its not that they are paranoid. They just know that they're
advertising a big security problem as a feature and thus need to nudge
users into a workaround - if GnuTLS is used on the server side, of course!

Session resumption as such isn't so much a security problem per se. If,
however, the key to the resumption data has to be static there's the
security problem. Now, GnuTLS developers deem users of this library
dumb. They create the session key data from SHA512(timeslice+masterkey).
And "timeslice" is "time()/ticketlifetime" with the default ticket life
time not being something reasonable but instead 6 hours - Dohhh!
As such, they don't allow users to rotate the master key for the
session tickets. If user then does, user will find out that session
resumption will apruptly stop working for all resumption tickets sent
with the previous key. So user will, after some testing, resign
and use a static master ticket key for the lifetime of the server and,
if load balancing is in use, probably even longer than that.

The static master key then simply means, that if a three letter agency
or a blackhat is able to record encrypted traffic for e.g. months and
then gains access to the ticket key e.g. by hacking a less secured backup
server, the same situation as CVE-2020-13777 is in place. So GnuTLS
developers do keep Let's Decrypt 1.0 in action while having
fixed Let's Decrypt 2.0 after a mere 10 releases - even this should
make one think about using GnuTLS on the server side as this problem
could have been detected easily with a simple regression test. And,
by the way, they castrated the encryption HMAC key to 16 bytes
(32 would make the most sense) as 'it fits SHA512', Arrghhhhh!

And, to add insult to injury, the actual ticket life time is three
times as long as the user configured ticket life time. And as
there's a rollback attempt within the library this is then again
multiplied by two resulting in a default ticket lifetime of up to
36 hours, now isn't that what a user does expect as a reasonable
default?!? And if a user configures a ticket lifetime, does the
user need to expect that a ticket is valid up to 6 times longer than
configured?!?

Finally due to the way session ticket handling is implemented by
GnuTLS there is no way, neither via hook or via API, to selectively
enable session tickets based on the TLS version used for a selected
server setup, i.e. when using SNI. So when the more secure
TLSv1.3 tickets shall be enabled the insecure TLSv1.2 tickets can't
be disabled by other means than disabling TLSv1.2 and below completely.
One should thoroughly start to investigate, if GnuTLS has a security design
at all or if it is blackhat or three letter agency sponsored.

And the above neatly matches the fact that when used as a client
GnuTLS deems a session resumable if a zero length session key
is received from a server.

To remedy these problems the tlsserver code has implemented an best
effort workaround which, however, means that input and output data
of GnuTLS needs to be matched which isn't exactly performant and
not guaranteed to work for absolutely every ticket issued - especially
re-issuing tickets after some time when TLSv1.3 is in use simply cannot
be done, the workaround would become to complicated.

Whatever backend library you use when you use the tlsserver library
you can be sure that ticket data cannot be recovered when the ticket
lifetime has expired as long as you follow the rules and assert that
tlsserver ticket purge is invoked regularly especially on a mostly
idle server. Thus PFS after ticket expiry is ensured. This,
however, comes at the expense of not being able to synchronise
a server cluster. It wouldn't be so much of a problem to implement
a cluster ticket key interface if it wouldn't be for the stubborness of
GnuTLS. But as the tlsserver library should have a simple unified
interface such an implementation simply cannot be done until the
GnuTLS folks eventually implement an 'advanced', i.e. usable
interface. And, yes, for exacly the security reasons mentionend
the tlsserver library limits the maximum configurable ticket lifetime
to one day and disables the use of session tickets by default.

For the GnuTLS folks a hint how a secure cluster wide ticket key
management can be implemented: Use per host ticket daemons that
communicate over encrypted and authenticated connections. Use a
quorum to decide the ticket generating master and add a priority
id per daemon in case the quorum fails. A daemon that is isolated
shall not shell out any ticket key. The ticket key shall change
every minute and must consist of irreversible random data. A
ticket daemon should synchronize its key data with the elected
master. No ticket daemon must store ticket keys longer as the
the maximum configured cluster wide ticket lifetime. Any server
running on a host that requires ticket keys shall be able to
retrieve all valid ticket keys from the local ticket
daemon. The server should be notified if the ticket daemon
has one or more new or recovered ticket keys available.
The server must not store the ticket keys longer as their
designated lifetime. It is so simple to do something securely,
isn't it? It just needs the proper interface! This means that
GnuTLS must ask the user at ticket encryption or decryption
time for the proper key with access to the key name at
decryption time and key name takeover at encryption time.
Is this really too difficult to implement?
