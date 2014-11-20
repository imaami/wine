/*
 * Unit test suite for winsock functions
 *
 * Copyright 2002 Martin Wilck
 * Copyright 2005 Thomas Kho
 * Copyright 2008 Jeff Zaroyko
 * Copyright 2017 Dmitry Timoshkov
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <winsock2.h>
#include <windows.h>
#include <winternl.h>
#include <ws2tcpip.h>
#include <wsipx.h>
#include <wsnwlink.h>
#include <mswsock.h>
#include <mstcpip.h>
#include <stdio.h>
#include "wine/test.h"

#define MAX_CLIENTS 4      /* Max number of clients */
#define FIRST_CHAR 'A'     /* First character in transferred pattern */
#define BIND_SLEEP 10      /* seconds to wait between attempts to bind() */
#define BIND_TRIES 6       /* Number of bind() attempts */
#define TEST_TIMEOUT 30    /* seconds to wait before killing child threads
                              after server initialization, if something hangs */

#define NUM_UDP_PEERS 3    /* Number of UDP sockets to create and test > 1 */

#define SERVERIP "127.0.0.1"   /* IP to bind to */
#define SERVERPORT 9374        /* Port number to bind to */

#define wsa_ok(op, cond, msg) \
   do { \
        int tmp, err = 0; \
        tmp = op; \
        if ( !(cond tmp) ) err = WSAGetLastError(); \
        ok ( cond tmp, msg, GetCurrentThreadId(), err); \
   } while (0);

#define make_keepalive(k, enable, time, interval) \
   k.onoff = enable; \
   k.keepalivetime = time; \
   k.keepaliveinterval = interval;

/* Function pointers */
static int   (WINAPI *pWSAPoll)(WSAPOLLFD *,ULONG,INT);

/* Function pointers from ntdll */
static DWORD (WINAPI *pNtClose)(HANDLE);

/**************** Structs and typedefs ***************/

typedef struct thread_info
{
    HANDLE thread;
    DWORD id;
} thread_info;

/* Information in the server about open client connections */
typedef struct sock_info
{
    SOCKET                 s;
    struct sockaddr_in     addr;
    struct sockaddr_in     peer;
    char                  *buf;
    int                    n_recvd;
    int                    n_sent;
} sock_info;

/* Test parameters for both server & client */
typedef struct test_params
{
    int          sock_type;
    int          sock_prot;
    const char  *inet_addr;
    short        inet_port;
    int          chunk_size;
    int          n_chunks;
    int          n_clients;
} test_params;

/* server-specific test parameters */
typedef struct server_params
{
    test_params   *general;
    DWORD          sock_flags;
    int            buflen;
} server_params;

/* client-specific test parameters */
typedef struct client_params
{
    test_params   *general;
    DWORD          sock_flags;
    int            buflen;
} client_params;

/* This type combines all information for setting up a test scenario */
typedef struct test_setup
{
    test_params              general;
    LPVOID                   srv;
    server_params            srv_params;
    LPVOID                   clt;
    client_params            clt_params;
} test_setup;

/* Thread local storage for server */
typedef struct server_memory
{
    SOCKET                  s;
    struct sockaddr_in      addr;
    sock_info               sock[MAX_CLIENTS];
} server_memory;

/* Thread local storage for client */
typedef struct client_memory
{
    SOCKET s;
    struct sockaddr_in      addr;
    char                   *send_buf;
    char                   *recv_buf;
} client_memory;

/* SelectReadThread thread parameters */
typedef struct select_thread_params
{
    SOCKET s;
    BOOL ReadKilled;
} select_thread_params;

/**************** Static variables ***************/

static DWORD      tls;              /* Thread local storage index */
static HANDLE     thread[1+MAX_CLIENTS];
static DWORD      thread_id[1+MAX_CLIENTS];
static HANDLE     server_ready;
static HANDLE     client_ready[MAX_CLIENTS];
static int        client_id;

/**************** General utility functions ***************/

static SOCKET setup_server_socket(struct sockaddr_in *addr, int *len);
static SOCKET setup_connector_socket(struct sockaddr_in *addr, int len, BOOL nonblock);

static void tcp_socketpair_flags(SOCKET *src, SOCKET *dst, DWORD flags)
{
    SOCKET server = INVALID_SOCKET;
    struct sockaddr_in addr;
    int len, ret;

    *src = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, flags);
    ok(*src != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());

    server = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, flags);
    ok(server != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    ret = bind(server, (struct sockaddr *)&addr, sizeof(addr));
    ok(!ret, "failed to bind socket, error %u\n", WSAGetLastError());

    len = sizeof(addr);
    ret = getsockname(server, (struct sockaddr *)&addr, &len);
    ok(!ret, "failed to get address, error %u\n", WSAGetLastError());

    ret = listen(server, 1);
    ok(!ret, "failed to listen, error %u\n", WSAGetLastError());

    ret = connect(*src, (struct sockaddr *)&addr, sizeof(addr));
    ok(!ret, "failed to connect, error %u\n", WSAGetLastError());

    len = sizeof(addr);
    *dst = accept(server, (struct sockaddr *)&addr, &len);
    ok(*dst != INVALID_SOCKET, "failed to accept socket, error %u\n", WSAGetLastError());

    closesocket(server);
}

static void tcp_socketpair(SOCKET *src, SOCKET *dst)
{
    tcp_socketpair_flags(src, dst, WSA_FLAG_OVERLAPPED);
}

static void set_so_opentype ( BOOL overlapped )
{
    int optval = !overlapped, newval, len = sizeof (int);

    ok ( setsockopt ( INVALID_SOCKET, SOL_SOCKET, SO_OPENTYPE,
                      (LPVOID) &optval, sizeof (optval) ) == 0,
         "setting SO_OPENTYPE failed\n" );
    ok ( getsockopt ( INVALID_SOCKET, SOL_SOCKET, SO_OPENTYPE,
                      (LPVOID) &newval, &len ) == 0,
         "getting SO_OPENTYPE failed\n" );
    ok ( optval == newval, "failed to set SO_OPENTYPE\n" );
}

static int set_blocking ( SOCKET s, BOOL blocking )
{
    u_long val = !blocking;
    return ioctlsocket ( s, FIONBIO, &val );
}

static void fill_buffer ( char *buf, int chunk_size, int n_chunks )
{
    char c, *p;
    for ( c = FIRST_CHAR, p = buf; c < FIRST_CHAR + n_chunks; c++, p += chunk_size )
        memset ( p, c, chunk_size );
}

static int test_buffer ( char *buf, int chunk_size, int n_chunks )
{
    char c, *p;
    int i;
    for ( c = FIRST_CHAR, p = buf; c < FIRST_CHAR + n_chunks; c++, p += chunk_size )
    {
        for ( i = 0; i < chunk_size; i++ )
            if ( p[i] != c ) return i;
    }
    return -1;
}

/*
 * This routine is called when a client / server does not expect any more data,
 * but needs to acknowledge the closing of the connection (by reading 0 bytes).
 */
static void read_zero_bytes ( SOCKET s )
{
    char buf[256];
    int tmp, n = 0;
    while ( ( tmp = recv ( s, buf, 256, 0 ) ) > 0 )
        n += tmp;
    ok ( n <= 0, "garbage data received: %d bytes\n", n );
}

static int do_synchronous_send ( SOCKET s, char *buf, int buflen, int flags, int sendlen )
{
    char* last = buf + buflen, *p;
    int n = 1;
    for ( p = buf; n > 0 && p < last; )
    {
        n = send ( s, p, min ( sendlen, last - p ), flags );
        if (n > 0) p += n;
    }
    wsa_ok ( n, 0 <=, "do_synchronous_send (%x): error %d\n" );
    return p - buf;
}

static int do_synchronous_recv ( SOCKET s, char *buf, int buflen, int flags, int recvlen )
{
    char* last = buf + buflen, *p;
    int n = 1;
    for ( p = buf; n > 0 && p < last; )
    {
        n = recv ( s, p, min ( recvlen, last - p ), flags );
        if (n > 0) p += n;
    }
    wsa_ok ( n, 0 <=, "do_synchronous_recv (%x): error %d:\n" );
    return p - buf;
}

static int do_synchronous_recvfrom ( SOCKET s, char *buf, int buflen, int flags, struct sockaddr *from, int *fromlen, int recvlen )
{
    char* last = buf + buflen, *p;
    int n = 1;
    for ( p = buf; n > 0 && p < last; )
    {
        n = recvfrom ( s, p, min ( recvlen, last - p ), flags, from, fromlen );
        if (n > 0) p += n;
    }
    wsa_ok ( n, 0 <=, "do_synchronous_recv (%x): error %d:\n" );
    return p - buf;
}

/*
 *  Call this routine right after thread startup.
 *  SO_OPENTYPE must by 0, regardless what the server did.
 */
static void check_so_opentype (void)
{
    int tmp = 1, len;
    len = sizeof (tmp);
    getsockopt ( INVALID_SOCKET, SOL_SOCKET, SO_OPENTYPE, (LPVOID) &tmp, &len );
    ok ( tmp == 0, "check_so_opentype: wrong startup value of SO_OPENTYPE: %d\n", tmp );
}

/**************** Server utility functions ***************/

/*
 *  Even if we have closed our server socket cleanly,
 *  the OS may mark the address "in use" for some time -
 *  this happens with native Linux apps, too.
 */
static void do_bind ( SOCKET s, struct sockaddr* addr, int addrlen )
{
    int err, wsaerr = 0, n_try = BIND_TRIES;

    while ( ( err = bind ( s, addr, addrlen ) ) != 0 &&
            ( wsaerr = WSAGetLastError () ) == WSAEADDRINUSE &&
            n_try-- >= 0)
    {
        trace ( "address in use, waiting ...\n" );
        Sleep ( 1000 * BIND_SLEEP );
    }
    ok ( err == 0, "failed to bind: %d\n", wsaerr );
}

static void server_start ( server_params *par )
{
    int i;
    test_params *gen = par->general;
    server_memory *mem = LocalAlloc ( LPTR, sizeof ( server_memory ) );

    TlsSetValue ( tls, mem );
    mem->s = WSASocketA ( AF_INET, gen->sock_type, gen->sock_prot,
                          NULL, 0, par->sock_flags );
    ok ( mem->s != INVALID_SOCKET, "Server: WSASocket failed\n" );

    mem->addr.sin_family = AF_INET;
    mem->addr.sin_addr.s_addr = inet_addr ( gen->inet_addr );
    mem->addr.sin_port = htons ( gen->inet_port );

    for (i = 0; i < MAX_CLIENTS; i++)
    {
        mem->sock[i].s = INVALID_SOCKET;
        mem->sock[i].buf = LocalAlloc ( LPTR, gen->n_chunks * gen->chunk_size );
        mem->sock[i].n_recvd = 0;
        mem->sock[i].n_sent = 0;
    }

    if ( gen->sock_type == SOCK_STREAM )
        do_bind ( mem->s, (struct sockaddr*) &mem->addr, sizeof (mem->addr) );
}

static void server_stop (void)
{
    int i;
    server_memory *mem = TlsGetValue ( tls );

    for (i = 0; i < MAX_CLIENTS; i++ )
    {
        LocalFree ( mem->sock[i].buf );
        if ( mem->sock[i].s != INVALID_SOCKET )
            closesocket ( mem->sock[i].s );
    }
    ok ( closesocket ( mem->s ) == 0, "closesocket failed\n" );
    LocalFree ( mem );
    ExitThread ( GetCurrentThreadId () );
}

/**************** Client utilitiy functions ***************/

static void client_start ( client_params *par )
{
    test_params *gen = par->general;
    client_memory *mem = LocalAlloc (LPTR, sizeof (client_memory));

    TlsSetValue ( tls, mem );

    WaitForSingleObject ( server_ready, INFINITE );

    mem->s = WSASocketA ( AF_INET, gen->sock_type, gen->sock_prot,
                          NULL, 0, par->sock_flags );

    mem->addr.sin_family = AF_INET;
    mem->addr.sin_addr.s_addr = inet_addr ( gen->inet_addr );
    mem->addr.sin_port = htons ( gen->inet_port );

    ok ( mem->s != INVALID_SOCKET, "Client: WSASocket failed\n" );

    mem->send_buf = LocalAlloc ( LPTR, 2 * gen->n_chunks * gen->chunk_size );
    mem->recv_buf = mem->send_buf + gen->n_chunks * gen->chunk_size;
    fill_buffer ( mem->send_buf, gen->chunk_size, gen->n_chunks );

    SetEvent ( client_ready[client_id] );
    /* Wait for the other clients to come up */
    WaitForMultipleObjects ( min ( gen->n_clients, MAX_CLIENTS ), client_ready, TRUE, INFINITE );
}

static void client_stop (void)
{
    client_memory *mem = TlsGetValue ( tls );
    wsa_ok ( closesocket ( mem->s ), 0 ==, "closesocket error (%x): %d\n" );
    LocalFree ( mem->send_buf );
    LocalFree ( mem );
    ExitThread(0);
}

/**************** Servers ***************/

/*
 * simple_server: A very basic server doing synchronous IO.
 */
static VOID WINAPI simple_server ( server_params *par )
{
    test_params *gen = par->general;
    server_memory *mem;
    int pos, n_recvd, n_sent, n_expected = gen->n_chunks * gen->chunk_size, tmp, i,
        id = GetCurrentThreadId();

    set_so_opentype ( FALSE ); /* non-overlapped */
    server_start ( par );
    mem = TlsGetValue ( tls );

    wsa_ok ( set_blocking ( mem->s, TRUE ), 0 ==, "simple_server (%x): failed to set blocking mode: %d\n");
    wsa_ok ( listen ( mem->s, SOMAXCONN ), 0 ==, "simple_server (%x): listen failed: %d\n");

    SetEvent ( server_ready ); /* notify clients */

    for ( i = 0; i < min ( gen->n_clients, MAX_CLIENTS ); i++ )
    {
        /* accept a single connection */
        tmp = sizeof ( mem->sock[0].peer );
        mem->sock[0].s = accept ( mem->s, (struct sockaddr*) &mem->sock[0].peer, &tmp );
        wsa_ok ( mem->sock[0].s, INVALID_SOCKET !=, "simple_server (%x): accept failed: %d\n" );

        ok ( mem->sock[0].peer.sin_addr.s_addr == inet_addr ( gen->inet_addr ),
             "simple_server (%x): strange peer address\n", id );

        /* Receive data & check it */
        n_recvd = do_synchronous_recv ( mem->sock[0].s, mem->sock[0].buf, n_expected, 0, par->buflen );
        ok ( n_recvd == n_expected,
             "simple_server (%x): received less data than expected: %d of %d\n", id, n_recvd, n_expected );
        pos = test_buffer ( mem->sock[0].buf, gen->chunk_size, gen->n_chunks );
        ok ( pos == -1, "simple_server (%x): test pattern error: %d\n", id, pos);

        /* Echo data back */
        n_sent = do_synchronous_send ( mem->sock[0].s, mem->sock[0].buf, n_expected, 0, par->buflen );
        ok ( n_sent == n_expected,
             "simple_server (%x): sent less data than expected: %d of %d\n", id, n_sent, n_expected );

        /* cleanup */
        read_zero_bytes ( mem->sock[0].s );
        wsa_ok ( closesocket ( mem->sock[0].s ),  0 ==, "simple_server (%x): closesocket error: %d\n" );
        mem->sock[0].s = INVALID_SOCKET;
    }

    server_stop ();
}

/*
 * oob_server: A very basic server receiving out-of-band data.
 */
static VOID WINAPI oob_server ( server_params *par )
{
    test_params *gen = par->general;
    server_memory *mem;
    u_long atmark = 0;
    int pos, n_sent, n_recvd, n_expected = gen->n_chunks * gen->chunk_size, tmp,
        id = GetCurrentThreadId();

    set_so_opentype ( FALSE ); /* non-overlapped */
    server_start ( par );
    mem = TlsGetValue ( tls );

    wsa_ok ( set_blocking ( mem->s, TRUE ), 0 ==, "oob_server (%x): failed to set blocking mode: %d\n");
    wsa_ok ( listen ( mem->s, SOMAXCONN ), 0 ==, "oob_server (%x): listen failed: %d\n");

    SetEvent ( server_ready ); /* notify clients */

    /* accept a single connection */
    tmp = sizeof ( mem->sock[0].peer );
    mem->sock[0].s = accept ( mem->s, (struct sockaddr*) &mem->sock[0].peer, &tmp );
    wsa_ok ( mem->sock[0].s, INVALID_SOCKET !=, "oob_server (%x): accept failed: %d\n" );

    ok ( mem->sock[0].peer.sin_addr.s_addr == inet_addr ( gen->inet_addr ),
         "oob_server (%x): strange peer address\n", id );

    /* check initial atmark state */
    ioctlsocket ( mem->sock[0].s, SIOCATMARK, &atmark );
    ok ( atmark == 1, "oob_server (%x): unexpectedly at the OOB mark: %i\n", id, atmark );

    /* Receive normal data */
    n_recvd = do_synchronous_recv ( mem->sock[0].s, mem->sock[0].buf, n_expected, 0, par->buflen );
    ok ( n_recvd == n_expected,
         "oob_server (%x): received less data than expected: %d of %d\n", id, n_recvd, n_expected );
    pos = test_buffer ( mem->sock[0].buf, gen->chunk_size, gen->n_chunks );
    ok ( pos == -1, "oob_server (%x): test pattern error: %d\n", id, pos);

    /* check atmark state */
    ioctlsocket ( mem->sock[0].s, SIOCATMARK, &atmark );
    ok ( atmark == 1, "oob_server (%x): unexpectedly at the OOB mark: %i\n", id, atmark );

    /* Echo data back */
    n_sent = do_synchronous_send ( mem->sock[0].s, mem->sock[0].buf, n_expected, 0, par->buflen );
    ok ( n_sent == n_expected,
         "oob_server (%x): sent less data than expected: %d of %d\n", id, n_sent, n_expected );

    /* Receive a part of the out-of-band data and print atmark state */
    n_recvd = do_synchronous_recv ( mem->sock[0].s, mem->sock[0].buf, 8, 0, par->buflen );
    ok ( n_recvd == 8,
         "oob_server (%x): received less data than expected: %d of %d\n", id, n_recvd, 8 );
    n_expected -= 8;

    ioctlsocket ( mem->sock[0].s, SIOCATMARK, &atmark );

    /* Receive the rest of the out-of-band data and check atmark state */
    do_synchronous_recv ( mem->sock[0].s, mem->sock[0].buf, n_expected, 0, par->buflen );

    ioctlsocket ( mem->sock[0].s, SIOCATMARK, &atmark );
    todo_wine ok ( atmark == 0, "oob_server (%x): not at the OOB mark: %i\n", id, atmark );

    /* cleanup */
    wsa_ok ( closesocket ( mem->sock[0].s ),  0 ==, "oob_server (%x): closesocket error: %d\n" );
    mem->sock[0].s = INVALID_SOCKET;

    server_stop ();
}

/*
 * select_server: A non-blocking server.
 */
static VOID WINAPI select_server ( server_params *par )
{
    test_params *gen = par->general;
    server_memory *mem;
    int n_expected = gen->n_chunks * gen->chunk_size, tmp, i,
        id = GetCurrentThreadId(), n_connections = 0, n_sent, n_recvd,
        n_set, delta, n_ready;
    struct timeval timeout = {0,10}; /* wait for 10 milliseconds */
    fd_set fds_recv, fds_send, fds_openrecv, fds_opensend;

    set_so_opentype ( FALSE ); /* non-overlapped */
    server_start ( par );
    mem = TlsGetValue ( tls );

    wsa_ok ( set_blocking ( mem->s, FALSE ), 0 ==, "select_server (%x): failed to set blocking mode: %d\n");
    wsa_ok ( listen ( mem->s, SOMAXCONN ), 0 ==, "select_server (%x): listen failed: %d\n");

    SetEvent ( server_ready ); /* notify clients */

    FD_ZERO ( &fds_openrecv );
    FD_ZERO ( &fds_recv );
    FD_ZERO ( &fds_send );
    FD_ZERO ( &fds_opensend );

    FD_SET ( mem->s, &fds_openrecv );

    while(1)
    {
        fds_recv = fds_openrecv;
        fds_send = fds_opensend;

        n_set = 0;

        wsa_ok ( ( n_ready = select ( 0, &fds_recv, &fds_send, NULL, &timeout ) ), SOCKET_ERROR !=, 
            "select_server (%x): select() failed: %d\n" );

        /* check for incoming requests */
        if ( FD_ISSET ( mem->s, &fds_recv ) ) {
            n_set += 1;

            /* accept a single connection */
            tmp = sizeof ( mem->sock[n_connections].peer );
            mem->sock[n_connections].s = accept ( mem->s, (struct sockaddr*) &mem->sock[n_connections].peer, &tmp );
            wsa_ok ( mem->sock[n_connections].s, INVALID_SOCKET !=, "select_server (%x): accept() failed: %d\n" );

            ok ( mem->sock[n_connections].peer.sin_addr.s_addr == inet_addr ( gen->inet_addr ),
                "select_server (%x): strange peer address\n", id );

            /* add to list of open connections */
            FD_SET ( mem->sock[n_connections].s, &fds_openrecv );
            FD_SET ( mem->sock[n_connections].s, &fds_opensend );

            n_connections++;
        }

        /* handle open requests */

        for ( i = 0; i < n_connections; i++ )
        {
            if ( FD_ISSET( mem->sock[i].s, &fds_recv ) ) {
                n_set += 1;

                if ( mem->sock[i].n_recvd < n_expected ) {
                    /* Receive data & check it */
                    n_recvd = recv ( mem->sock[i].s, mem->sock[i].buf + mem->sock[i].n_recvd, min ( n_expected - mem->sock[i].n_recvd, par->buflen ), 0 );
                    ok ( n_recvd != SOCKET_ERROR, "select_server (%x): error in recv(): %d\n", id, WSAGetLastError() );
                    mem->sock[i].n_recvd += n_recvd;

                    if ( mem->sock[i].n_recvd == n_expected ) {
                        int pos = test_buffer ( mem->sock[i].buf, gen->chunk_size, gen->n_chunks );
                        ok ( pos == -1, "select_server (%x): test pattern error: %d\n", id, pos );
                        FD_CLR ( mem->sock[i].s, &fds_openrecv );
                    }

                    ok ( mem->sock[i].n_recvd <= n_expected, "select_server (%x): received too many bytes: %d\n", id, mem->sock[i].n_recvd );
                }
            }

            /* only echo back what we've received */
            delta = mem->sock[i].n_recvd - mem->sock[i].n_sent;

            if ( FD_ISSET ( mem->sock[i].s, &fds_send ) ) {
                n_set += 1;

                if ( ( delta > 0 ) && ( mem->sock[i].n_sent < n_expected ) ) {
                    /* Echo data back */
                    n_sent = send ( mem->sock[i].s, mem->sock[i].buf + mem->sock[i].n_sent, min ( delta, par->buflen ), 0 );
                    ok ( n_sent != SOCKET_ERROR, "select_server (%x): error in send(): %d\n", id, WSAGetLastError() );
                    mem->sock[i].n_sent += n_sent;

                    if ( mem->sock[i].n_sent == n_expected ) {
                        FD_CLR ( mem->sock[i].s, &fds_opensend );
                    }

                    ok ( mem->sock[i].n_sent <= n_expected, "select_server (%x): sent too many bytes: %d\n", id, mem->sock[i].n_sent );
                }
            }
        }

        /* check that select returned the correct number of ready sockets */
        ok ( ( n_set == n_ready ), "select_server (%x): select() returns wrong number of ready sockets\n", id );

        /* check if all clients are done */
        if ( ( fds_opensend.fd_count == 0 ) 
            && ( fds_openrecv.fd_count == 1 ) /* initial socket that accepts clients */
            && ( n_connections  == min ( gen->n_clients, MAX_CLIENTS ) ) ) {
            break;
        }
    }

    for ( i = 0; i < min ( gen->n_clients, MAX_CLIENTS ); i++ )
    {
        /* cleanup */
        read_zero_bytes ( mem->sock[i].s );
        wsa_ok ( closesocket ( mem->sock[i].s ),  0 ==, "select_server (%x): closesocket error: %d\n" );
        mem->sock[i].s = INVALID_SOCKET;
    }

    server_stop ();
}

/**************** Clients ***************/

/*
 * simple_client: A very basic client doing synchronous IO.
 */
static VOID WINAPI simple_client ( client_params *par )
{
    test_params *gen = par->general;
    client_memory *mem;
    int pos, n_sent, n_recvd, n_expected = gen->n_chunks * gen->chunk_size, id;

    id = GetCurrentThreadId();
    /* wait here because we want to call set_so_opentype before creating a socket */
    WaitForSingleObject ( server_ready, INFINITE );

    check_so_opentype ();
    set_so_opentype ( FALSE ); /* non-overlapped */
    client_start ( par );
    mem = TlsGetValue ( tls );

    /* Connect */
    wsa_ok ( connect ( mem->s, (struct sockaddr*) &mem->addr, sizeof ( mem->addr ) ),
             0 ==, "simple_client (%x): connect error: %d\n" );
    ok ( set_blocking ( mem->s, TRUE ) == 0,
         "simple_client (%x): failed to set blocking mode\n", id );

    /* send data to server */
    n_sent = do_synchronous_send ( mem->s, mem->send_buf, n_expected, 0, par->buflen );
    ok ( n_sent == n_expected,
         "simple_client (%x): sent less data than expected: %d of %d\n", id, n_sent, n_expected );

    /* shutdown send direction */
    wsa_ok ( shutdown ( mem->s, SD_SEND ), 0 ==, "simple_client (%x): shutdown failed: %d\n" );

    /* Receive data echoed back & check it */
    n_recvd = do_synchronous_recv ( mem->s, mem->recv_buf, n_expected, 0, par->buflen );
    ok ( n_recvd == n_expected,
         "simple_client (%x): received less data than expected: %d of %d\n", id, n_recvd, n_expected );

    /* check data */
    pos = test_buffer ( mem->recv_buf, gen->chunk_size, gen->n_chunks );
    ok ( pos == -1, "simple_client (%x): test pattern error: %d\n", id, pos);

    /* cleanup */
    read_zero_bytes ( mem->s );
    client_stop ();
}

/*
 * oob_client: A very basic client sending out-of-band data.
 */
static VOID WINAPI oob_client ( client_params *par )
{
    test_params *gen = par->general;
    client_memory *mem;
    int pos, n_sent, n_recvd, n_expected = gen->n_chunks * gen->chunk_size, id;

    id = GetCurrentThreadId();
    /* wait here because we want to call set_so_opentype before creating a socket */
    WaitForSingleObject ( server_ready, INFINITE );

    check_so_opentype ();
    set_so_opentype ( FALSE ); /* non-overlapped */
    client_start ( par );
    mem = TlsGetValue ( tls );

    /* Connect */
    wsa_ok ( connect ( mem->s, (struct sockaddr*) &mem->addr, sizeof ( mem->addr ) ),
             0 ==, "oob_client (%x): connect error: %d\n" );
    ok ( set_blocking ( mem->s, TRUE ) == 0,
         "oob_client (%x): failed to set blocking mode\n", id );

    /* send data to server */
    n_sent = do_synchronous_send ( mem->s, mem->send_buf, n_expected, 0, par->buflen );
    ok ( n_sent == n_expected,
         "oob_client (%x): sent less data than expected: %d of %d\n", id, n_sent, n_expected );

    /* Receive data echoed back & check it */
    n_recvd = do_synchronous_recv ( mem->s, mem->recv_buf, n_expected, 0, par->buflen );
    ok ( n_recvd == n_expected,
         "simple_client (%x): received less data than expected: %d of %d\n", id, n_recvd, n_expected );
    pos = test_buffer ( mem->recv_buf, gen->chunk_size, gen->n_chunks );
    ok ( pos == -1, "simple_client (%x): test pattern error: %d\n", id, pos);

    /* send out-of-band data to server */
    n_sent = do_synchronous_send ( mem->s, mem->send_buf, n_expected, MSG_OOB, par->buflen );
    ok ( n_sent == n_expected,
         "oob_client (%x): sent less data than expected: %d of %d\n", id, n_sent, n_expected );

    /* shutdown send direction */
    wsa_ok ( shutdown ( mem->s, SD_SEND ), 0 ==, "simple_client (%x): shutdown failed: %d\n" );

    /* cleanup */
    read_zero_bytes ( mem->s );
    client_stop ();
}

/*
 * simple_mixed_client: mixing send and recvfrom
 */
static VOID WINAPI simple_mixed_client ( client_params *par )
{
    test_params *gen = par->general;
    client_memory *mem;
    int pos, n_sent, n_recvd, n_expected = gen->n_chunks * gen->chunk_size, id;
    int fromLen = sizeof(mem->addr);
    struct sockaddr test;

    id = GetCurrentThreadId();
    /* wait here because we want to call set_so_opentype before creating a socket */
    WaitForSingleObject ( server_ready, INFINITE );

    check_so_opentype ();
    set_so_opentype ( FALSE ); /* non-overlapped */
    client_start ( par );
    mem = TlsGetValue ( tls );

    /* Connect */
    wsa_ok ( connect ( mem->s, (struct sockaddr*) &mem->addr, sizeof ( mem->addr ) ),
             0 ==, "simple_client (%x): connect error: %d\n" );
    ok ( set_blocking ( mem->s, TRUE ) == 0,
         "simple_client (%x): failed to set blocking mode\n", id );

    /* send data to server */
    n_sent = do_synchronous_send ( mem->s, mem->send_buf, n_expected, 0, par->buflen );
    ok ( n_sent == n_expected,
         "simple_client (%x): sent less data than expected: %d of %d\n", id, n_sent, n_expected );

    /* shutdown send direction */
    wsa_ok ( shutdown ( mem->s, SD_SEND ), 0 ==, "simple_client (%x): shutdown failed: %d\n" );

    /* this shouldn't change, since lpFrom, is not updated on
       connection oriented sockets - exposed by bug 11640
    */
    ((struct sockaddr_in*)&test)->sin_addr.s_addr = inet_addr("0.0.0.0");

    /* Receive data echoed back & check it */
    n_recvd = do_synchronous_recvfrom ( mem->s,
					mem->recv_buf,
					n_expected,
					0,
					(struct sockaddr *)&test,
					&fromLen,
					par->buflen );
    ok ( n_recvd == n_expected,
         "simple_client (%x): received less data than expected: %d of %d\n", id, n_recvd, n_expected );

    /* check that lpFrom was not updated */
    ok(0 ==
       strcmp(
	      inet_ntoa(((struct sockaddr_in*)&test)->sin_addr),
	      "0.0.0.0"), "lpFrom shouldn't be updated on connection oriented sockets\n");

    /* check data */
    pos = test_buffer ( mem->recv_buf, gen->chunk_size, gen->n_chunks );
    ok ( pos == -1, "simple_client (%x): test pattern error: %d\n", id, pos);

    /* cleanup */
    read_zero_bytes ( mem->s );
    client_stop ();
}

/*
 * event_client: An event-driven client
 */
static void WINAPI event_client ( client_params *par )
{
    test_params *gen = par->general;
    client_memory *mem;
    int id = GetCurrentThreadId(), n_expected = gen->n_chunks * gen->chunk_size,
        tmp, err, n;
    HANDLE event;
    WSANETWORKEVENTS wsa_events;
    char *send_last, *recv_last, *send_p, *recv_p;
    LONG mask = FD_READ | FD_WRITE | FD_CLOSE;

    client_start ( par );

    mem = TlsGetValue ( tls );

    /* Prepare event notification for connect, makes socket nonblocking */
    event = WSACreateEvent ();
    WSAEventSelect ( mem->s, event, FD_CONNECT );
    tmp = connect ( mem->s, (struct sockaddr*) &mem->addr, sizeof ( mem->addr ) );
    if ( tmp != 0 ) {
        err = WSAGetLastError ();
        ok ( err == WSAEWOULDBLOCK, "event_client (%x): connect error: %d\n", id, err );
        tmp = WaitForSingleObject ( event, INFINITE );
        ok ( tmp == WAIT_OBJECT_0, "event_client (%x): wait for connect event failed: %d\n", id, tmp );
        err = WSAEnumNetworkEvents ( mem->s, event, &wsa_events );
        ok ( err == 0, "event_client (%x): WSAEnumNetworkEvents error: %d\n", id, err );
        err = wsa_events.iErrorCode[ FD_CONNECT_BIT ];
        ok ( err == 0, "event_client (%x): connect error: %d\n", id, err );
        if ( err ) goto out;
    }

    WSAEventSelect ( mem->s, event, mask );

    recv_p = mem->recv_buf;
    recv_last = mem->recv_buf + n_expected;
    send_p = mem->send_buf;
    send_last = mem->send_buf + n_expected;

    while ( TRUE )
    {
        err = WaitForSingleObject ( event, INFINITE );
        ok ( err == WAIT_OBJECT_0, "event_client (%x): wait failed\n", id );

        err = WSAEnumNetworkEvents ( mem->s, event, &wsa_events );
        ok( err == 0, "event_client (%x): WSAEnumNetworkEvents error: %d\n", id, err );

        if ( wsa_events.lNetworkEvents & FD_WRITE )
        {
            err = wsa_events.iErrorCode[ FD_WRITE_BIT ];
            ok ( err == 0, "event_client (%x): FD_WRITE error code: %d\n", id, err );

            if ( err== 0 )
                do
                {
                    n = send ( mem->s, send_p, min ( send_last - send_p, par->buflen ), 0 );
                    if ( n < 0 )
                    {
                        err = WSAGetLastError ();
                        ok ( err == WSAEWOULDBLOCK, "event_client (%x): send error: %d\n", id, err );
                    }
                    else
                        send_p += n;
                }
                while ( n >= 0 && send_p < send_last );

            if ( send_p == send_last )
            {
                shutdown ( mem->s, SD_SEND );
                mask &= ~FD_WRITE;
                WSAEventSelect ( mem->s, event, mask );
            }
        }
        if ( wsa_events.lNetworkEvents & FD_READ )
        {
            err = wsa_events.iErrorCode[ FD_READ_BIT ];
            ok ( err == 0, "event_client (%x): FD_READ error code: %d\n", id, err );
            if ( err != 0 ) break;
            
            /* First read must succeed */
            n = recv ( mem->s, recv_p, min ( recv_last - recv_p, par->buflen ), 0 );
            wsa_ok ( n, 0 <=, "event_client (%x): recv error: %d\n" );

            while ( n >= 0 ) {
                recv_p += n;
                if ( recv_p == recv_last )
                {
                    mask &= ~FD_READ;
                    WSAEventSelect ( mem->s, event, mask );
                    break;
                }
                n = recv ( mem->s, recv_p, min ( recv_last - recv_p, par->buflen ), 0 );
                ok(n >= 0 || WSAGetLastError() == WSAEWOULDBLOCK,
                        "event_client (%x): got error %u\n", id, WSAGetLastError());
                
            }
        }   
        if ( wsa_events.lNetworkEvents & FD_CLOSE )
        {
            err = wsa_events.iErrorCode[ FD_CLOSE_BIT ];
            ok ( err == 0, "event_client (%x): FD_CLOSE error code: %d\n", id, err );
            break;
        }
    }

    n = send_p - mem->send_buf;
    ok ( send_p == send_last,
         "simple_client (%x): sent less data than expected: %d of %d\n", id, n, n_expected );
    n = recv_p - mem->recv_buf;
    ok ( recv_p == recv_last,
         "simple_client (%x): received less data than expected: %d of %d\n", id, n, n_expected );
    n = test_buffer ( mem->recv_buf, gen->chunk_size, gen->n_chunks );
    ok ( n == -1, "event_client (%x): test pattern error: %d\n", id, n);

out:
    WSACloseEvent ( event );
    client_stop ();
}

/* Tests for WSAStartup */
static void test_WithoutWSAStartup(void)
{
    DWORD err;

    WSASetLastError(0xdeadbeef);
    ok(WSASocketA(0, 0, 0, NULL, 0, 0) == INVALID_SOCKET, "WSASocketA should have failed\n");
    err = WSAGetLastError();
    ok(err == WSANOTINITIALISED, "Expected 10093, received %d\n", err);

    WSASetLastError(0xdeadbeef);
    ok(gethostbyname("localhost") == NULL, "gethostbyname() succeeded unexpectedly\n");
    err = WSAGetLastError();
    ok(err == WSANOTINITIALISED, "Expected 10093, received %d\n", err);
}

static void test_WithWSAStartup(void)
{
    WSADATA data;
    WORD version = MAKEWORD( 2, 2 );
    INT res, socks, i, j;
    SOCKET sock;
    LPVOID ptr;
    struct
    {
        SOCKET src, dst, dup_src, dup_dst;
    } pairs[32];
    DWORD error;

    res = WSAStartup( version, &data );
    ok(res == 0, "WSAStartup() failed unexpectedly: %d\n", res);

    ptr = gethostbyname("localhost");
    ok(ptr != NULL, "gethostbyname() failed unexpectedly: %d\n", WSAGetLastError());

    /* Alloc some sockets to check if they are destroyed on WSACleanup */
    for (socks = 0; socks < ARRAY_SIZE(pairs); socks++)
    {
        WSAPROTOCOL_INFOA info;
        tcp_socketpair(&pairs[socks].src, &pairs[socks].dst);

        memset(&info, 0, sizeof(info));
        ok(!WSADuplicateSocketA(pairs[socks].src, GetCurrentProcessId(), &info),
           "WSADuplicateSocketA should have worked\n");
        pairs[socks].dup_src = WSASocketA(0, 0, 0, &info, 0, 0);
        ok(pairs[socks].dup_src != SOCKET_ERROR, "expected != -1\n");

        memset(&info, 0, sizeof(info));
        ok(!WSADuplicateSocketA(pairs[socks].dst, GetCurrentProcessId(), &info),
           "WSADuplicateSocketA should have worked\n");
        pairs[socks].dup_dst = WSASocketA(0, 0, 0, &info, 0, 0);
        ok(pairs[socks].dup_dst != SOCKET_ERROR, "expected != -1\n");
    }

    res = send(pairs[0].src, "TEST", 4, 0);
    ok(res == 4, "send failed with error %d\n", WSAGetLastError());

    WSACleanup();

    res = WSAStartup( version, &data );
    ok(res == 0, "WSAStartup() failed unexpectedly: %d\n", res);

    /* show that sockets are destroyed automatically after WSACleanup */
    SetLastError(0xdeadbeef);
    res = send(pairs[0].src, "TEST", 4, 0);
    error = WSAGetLastError();
    ok(res == SOCKET_ERROR, "send should have failed\n");
    ok(error == WSAENOTSOCK, "expected 10038, got %d\n", error);

    SetLastError(0xdeadbeef);
    res = send(pairs[0].dst, "TEST", 4, 0);
    error = WSAGetLastError();
    ok(res == SOCKET_ERROR, "send should have failed\n");
    ok(error == WSAENOTSOCK, "expected 10038, got %d\n", error);

    /* Check that all sockets were destroyed */
    for (i = 0; i < socks; i++)
    {
        for (j = 0; j < 4; j++)
        {
            struct sockaddr_in saddr;
            int size = sizeof(saddr);
            switch(j)
            {
                case 0: sock = pairs[i].src; break;
                case 1: sock = pairs[i].dup_src; break;
                case 2: sock = pairs[i].dst; break;
                case 3: sock = pairs[i].dup_dst; break;
            }

            SetLastError(0xdeadbeef);
            res = getsockname(sock, (struct sockaddr *)&saddr, &size);
            error = WSAGetLastError();
            ok(res == SOCKET_ERROR, "Test[%d]: getsockname should have failed\n", i);
            if (res == SOCKET_ERROR)
                ok(error == WSAENOTSOCK, "Test[%d]: expected 10038, got %d\n", i, error);
        }
    }

    /* While wine is not fixed, close all sockets manually */
    for (i = 0; i < socks; i++)
    {
        closesocket(pairs[i].src);
        closesocket(pairs[i].dst);
        closesocket(pairs[i].dup_src);
        closesocket(pairs[i].dup_dst);
    }

    res = WSACleanup();
    ok(res == 0, "expected 0, got %d\n", res);
    WSASetLastError(0xdeadbeef);
    res = WSACleanup();
    error = WSAGetLastError();
    ok ( res == SOCKET_ERROR && error ==  WSANOTINITIALISED,
            "WSACleanup returned %d WSAGetLastError is %d\n", res, error);
}

/**************** Main program utility functions ***************/

static void Init (void)
{
    WORD ver = MAKEWORD (2, 2);
    WSADATA data;
    HMODULE hws2_32 = GetModuleHandleA("ws2_32.dll"), ntdll;

    pWSAPoll = (void *)GetProcAddress(hws2_32, "WSAPoll");

    ntdll = LoadLibraryA("ntdll.dll");
    if (ntdll)
        pNtClose = (void *)GetProcAddress(ntdll, "NtClose");

    ok ( WSAStartup ( ver, &data ) == 0, "WSAStartup failed\n" );
    tls = TlsAlloc();
}

static void Exit (void)
{
    INT ret, err;
    TlsFree ( tls );
    ret = WSACleanup();
    err = WSAGetLastError();
    ok ( ret == 0, "WSACleanup failed ret = %d GetLastError is %d\n", ret, err);
}

static void StartServer (LPTHREAD_START_ROUTINE routine,
                         test_params *general, server_params *par)
{
    par->general = general;
    thread[0] = CreateThread ( NULL, 0, routine, par, 0, &thread_id[0] );
    ok ( thread[0] != NULL, "Failed to create server thread\n" );
}

static void StartClients (LPTHREAD_START_ROUTINE routine,
                          test_params *general, client_params *par)
{
    int i;
    par->general = general;
    for ( i = 1; i <= min ( general->n_clients, MAX_CLIENTS ); i++ )
    {
        client_id = i - 1;
        thread[i] = CreateThread ( NULL, 0, routine, par, 0, &thread_id[i] );
        ok ( thread[i] != NULL, "Failed to create client thread\n" );
        /* Make sure the client is up and running */
        WaitForSingleObject ( client_ready[client_id], INFINITE );
    };
}

static void do_test( test_setup *test )
{
    DWORD i, n = min (test->general.n_clients, MAX_CLIENTS);
    DWORD wait;

    server_ready = CreateEventA ( NULL, TRUE, FALSE, NULL );
    for (i = 0; i <= n; i++)
        client_ready[i] = CreateEventA ( NULL, TRUE, FALSE, NULL );

    StartServer ( test->srv, &test->general, &test->srv_params );
    StartClients ( test->clt, &test->general, &test->clt_params );
    WaitForSingleObject ( server_ready, INFINITE );

    wait = WaitForMultipleObjects ( 1 + n, thread, TRUE, 1000 * TEST_TIMEOUT );
    ok(!wait, "wait failed, error %u\n", wait);

    CloseHandle ( server_ready );
    for (i = 0; i <= n; i++)
        CloseHandle ( client_ready[i] );
}

/********* some tests for getsockopt(setsockopt(X)) == X ***********/
/* optname = SO_LINGER */
static const LINGER linger_testvals[] = {
    {0,0},
    {0,73}, 
    {1,0},
    {5,189}
};

/* optname = SO_RCVTIMEO, SOSNDTIMEO */
#define SOCKTIMEOUT1 63000 /* 63 seconds. Do not test fractional part because of a
                        bug in the linux kernel (fixed in 2.6.8) */ 
#define SOCKTIMEOUT2 997000 /* 997 seconds */

static void test_set_getsockopt(void)
{
    SOCKET s, s2;
    int i, err, lasterr;
    int timeout;
    LINGER lingval;
    int size;
    WSAPROTOCOL_INFOA infoA;
    WSAPROTOCOL_INFOW infoW;
    char providername[WSAPROTOCOL_LEN + 1];
    DWORD value;
    struct _prottest
    {
        int family, type, proto;
    } prottest[] = {
        {AF_INET, SOCK_STREAM, IPPROTO_TCP},
        {AF_INET, SOCK_DGRAM, IPPROTO_UDP},
        {AF_INET6, SOCK_STREAM, IPPROTO_TCP},
        {AF_INET6, SOCK_DGRAM, IPPROTO_UDP}
    };
    union _csspace
    {
        CSADDR_INFO cs;
        char space[128];
    } csinfoA, csinfoB;

    s = socket(AF_INET, SOCK_STREAM, 0);
    ok(s!=INVALID_SOCKET, "socket() failed error: %d\n", WSAGetLastError());
    if( s == INVALID_SOCKET) return;
    /* SO_RCVTIMEO */
    timeout = SOCKTIMEOUT1;
    size = sizeof(timeout);
    err = setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, size); 
    if( !err)
        err = getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, &size); 
    ok( !err, "get/setsockopt(SO_RCVTIMEO) failed error: %d\n", WSAGetLastError());
    ok( timeout == SOCKTIMEOUT1, "getsockopt(SO_RCVTIMEO) returned wrong value %d\n", timeout);

    timeout = 0;
    size = sizeof(timeout);
    err = setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, size);
    if( !err)
        err = getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, &size);
    ok( !err, "get/setsockopt(SO_RCVTIMEO) failed error: %d\n", WSAGetLastError());
    ok( timeout == 0, "getsockopt(SO_RCVTIMEO) returned wrong value %d\n", timeout);

    /* SO_SNDTIMEO */
    timeout = SOCKTIMEOUT2; /* 997 seconds. See remark above */
    size = sizeof(timeout);
    err = setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, size); 
    if( !err)
        err = getsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, &size); 
    ok( !err, "get/setsockopt(SO_SNDTIMEO) failed error: %d\n", WSAGetLastError());
    ok( timeout == SOCKTIMEOUT2, "getsockopt(SO_SNDTIMEO) returned wrong value %d\n", timeout);

    /* SO_SNDBUF */
    value = 4096;
    size = sizeof(value);
    err = setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char *)&value, size);
    ok( !err, "setsockopt(SO_SNDBUF) failed error: %u\n", WSAGetLastError() );
    value = 0xdeadbeef;
    err = getsockopt(s, SOL_SOCKET, SO_SNDBUF, (char *)&value, &size);
    ok( !err, "getsockopt(SO_SNDBUF) failed error: %u\n", WSAGetLastError() );
    todo_wine ok( value == 4096, "expected 4096, got %u\n", value );

    /* SO_RCVBUF */
    value = 4096;
    size = sizeof(value);
    err = setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&value, size);
    ok( !err, "setsockopt(SO_RCVBUF) failed error: %u\n", WSAGetLastError() );
    value = 0xdeadbeef;
    err = getsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&value, &size);
    ok( !err, "getsockopt(SO_RCVBUF) failed error: %u\n", WSAGetLastError() );
    todo_wine ok( value == 4096, "expected 4096, got %u\n", value );

    /* SO_LINGER */
    for( i = 0; i < ARRAY_SIZE(linger_testvals);i++) {
        size =  sizeof(lingval);
        lingval = linger_testvals[i];
        err = setsockopt(s, SOL_SOCKET, SO_LINGER, (char *)&lingval, size);
        ok(!err, "Test %u: failed to set SO_LINGER, error %u\n", i, WSAGetLastError());
        err = getsockopt(s, SOL_SOCKET, SO_LINGER, (char *)&lingval, &size);
        ok(!err, "Test %u: failed to get SO_LINGER, error %u\n", i, WSAGetLastError());
        ok(!lingval.l_onoff == !linger_testvals[i].l_onoff, "Test %u: expected %d, got %d\n",
                i, linger_testvals[i].l_onoff, lingval.l_onoff);
        if (lingval.l_onoff)
            ok(lingval.l_linger == linger_testvals[i].l_linger, "Test %u: expected %d, got %d\n",
                    i, linger_testvals[i].l_linger, lingval.l_linger);
    }

    size =  sizeof(lingval);
    err = setsockopt(s, SOL_SOCKET, SO_LINGER, NULL, size);
    ok(err == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT,
       "got %d with %d (expected SOCKET_ERROR with WSAEFAULT)\n", err, WSAGetLastError());
    err = setsockopt(s, SOL_SOCKET, SO_LINGER, NULL, 0);
    ok(err == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT,
       "got %d with %d (expected SOCKET_ERROR with WSAEFAULT)\n", err, WSAGetLastError());

    size =  sizeof(BOOL);
    err = setsockopt(s, SOL_SOCKET, SO_DONTLINGER, NULL, size);
    ok(err == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT,
       "got %d with %d (expected SOCKET_ERROR with WSAEFAULT)\n", err, WSAGetLastError());
    err = setsockopt(s, SOL_SOCKET, SO_DONTLINGER, NULL, 0);
    ok(err == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT,
       "got %d with %d (expected SOCKET_ERROR with WSAEFAULT)\n", err, WSAGetLastError());

    /* Test for erroneously passing a value instead of a pointer as optval */
    size = sizeof(char);
    err = setsockopt(s, SOL_SOCKET, SO_DONTROUTE, (char *)1, size);
    ok(err == SOCKET_ERROR, "setsockopt with optval being a value passed "
                            "instead of failing.\n");
    lasterr = WSAGetLastError();
    ok(lasterr == WSAEFAULT, "setsockopt with optval being a value "
                             "returned 0x%08x, not WSAEFAULT(0x%08x)\n",
                             lasterr, WSAEFAULT);

    /* SO_RCVTIMEO with invalid values for level */
    size = sizeof(timeout);
    timeout = SOCKTIMEOUT1;
    SetLastError(0xdeadbeef);
    err = setsockopt(s, 0xffffffff, SO_RCVTIMEO, (char *) &timeout, size);
    ok( (err == SOCKET_ERROR) && (WSAGetLastError() == WSAEINVAL),
        "got %d with %d (expected SOCKET_ERROR with WSAEINVAL)\n",
        err, WSAGetLastError());

    timeout = SOCKTIMEOUT1;
    SetLastError(0xdeadbeef);
    err = setsockopt(s, 0x00008000, SO_RCVTIMEO, (char *) &timeout, size);
    ok( (err == SOCKET_ERROR) && (WSAGetLastError() == WSAEINVAL),
        "got %d with %d (expected SOCKET_ERROR with WSAEINVAL)\n",
        err, WSAGetLastError());

    /* Test SO_ERROR set/get */
    SetLastError(0xdeadbeef);
    i = 1234;
    err = setsockopt(s, SOL_SOCKET, SO_ERROR, (char *) &i, size);
todo_wine
    ok( !err && !WSAGetLastError(),
        "got %d with %d (expected 0 with 0)\n",
        err, WSAGetLastError());

    SetLastError(0xdeadbeef);
    i = 4321;
    err = getsockopt(s, SOL_SOCKET, SO_ERROR, (char *) &i, &size);
todo_wine
    ok( !err && !WSAGetLastError(),
        "got %d with %d (expected 0 with 0)\n",
        err, WSAGetLastError());
todo_wine
    ok (i == 1234, "got %d (expected 1234)\n", i);

    /* Test invalid optlen */
    SetLastError(0xdeadbeef);
    size = 1;
    err = getsockopt(s, SOL_SOCKET, SO_ERROR, (char *) &i, &size);
todo_wine
    ok( (err == SOCKET_ERROR) && (WSAGetLastError() == WSAEFAULT),
        "got %d with %d (expected SOCKET_ERROR with WSAEFAULT)\n",
        err, WSAGetLastError());

    closesocket(s);
    /* Test with the closed socket */
    SetLastError(0xdeadbeef);
    size = sizeof(i);
    i = 1234;
    err = getsockopt(s, SOL_SOCKET, SO_ERROR, (char *) &i, &size);
    ok( (err == SOCKET_ERROR) && (WSAGetLastError() == WSAENOTSOCK),
        "got %d with %d (expected SOCKET_ERROR with WSAENOTSOCK)\n",
        err, WSAGetLastError());
    ok (i == 1234, "expected 1234, got %d\n", i);

    /* Test WS_IP_MULTICAST_TTL with 8, 16, 24 and 32 bits values */
    s = socket(AF_INET, SOCK_DGRAM, 0);
    ok(s != INVALID_SOCKET, "Failed to create socket\n");
    size = sizeof(i);
    i = 0x0000000a;
    err = setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (char *) &i, size);
    if (!err)
    {
        for (i = 0; i < 4; i++)
        {
            int k, j;
            const int tests[] = {0xffffff0a, 0xffff000b, 0xff00000c, 0x0000000d};
            err = setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (char *) &tests[i], i + 1);
            ok(!err, "Test [%d] Expected 0, got %d\n", i, err);
            err = getsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (char *) &k, &size);
            ok(!err, "Test [%d] Expected 0, got %d\n", i, err);
            j = i != 3 ? tests[i] & ((1 << (i + 1) * 8) - 1) : tests[i];
            ok(k == j, "Test [%d] Expected 0x%x, got 0x%x\n", i, j, k);
        }
    }
    else
        win_skip("IP_MULTICAST_TTL is unsupported\n");
    closesocket(s);

    /* test SO_PROTOCOL_INFOA invalid parameters */
    ok(getsockopt(INVALID_SOCKET, SOL_SOCKET, SO_PROTOCOL_INFOA, NULL, NULL),
       "getsockopt should have failed\n");
    err = WSAGetLastError();
    ok(err == WSAENOTSOCK, "expected 10038, got %d instead\n", err);
    size = sizeof(WSAPROTOCOL_INFOA);
    ok(getsockopt(INVALID_SOCKET, SOL_SOCKET, SO_PROTOCOL_INFOA, (char *) &infoA, &size),
       "getsockopt should have failed\n");
    ok(size == sizeof(WSAPROTOCOL_INFOA), "got size %d\n", size);
    err = WSAGetLastError();
    ok(err == WSAENOTSOCK, "expected 10038, got %d instead\n", err);
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFOA, NULL, NULL),
       "getsockopt should have failed\n");
    err = WSAGetLastError();
    ok(err == WSAEFAULT, "expected 10014, got %d instead\n", err);
    ok(getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFOA, (char *) &infoA, NULL),
       "getsockopt should have failed\n");
    err = WSAGetLastError();
    ok(err == WSAEFAULT, "expected 10014, got %d instead\n", err);
    ok(getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFOA, NULL, &size),
       "getsockopt should have failed\n");
    err = WSAGetLastError();
    ok(err == WSAEFAULT, "expected 10014, got %d instead\n", err);
    size = sizeof(WSAPROTOCOL_INFOA) / 2;
    ok(getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFOA, (char *) &infoA, &size),
       "getsockopt should have failed\n");
    err = WSAGetLastError();
    ok(err == WSAEFAULT, "expected 10014, got %d instead\n", err);
    ok(size == sizeof(WSAPROTOCOL_INFOA), "got size %d\n", size);
    size = sizeof(WSAPROTOCOL_INFOA) * 2;
    err = getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFOA, (char *) &infoA, &size);
    ok(!err,"getsockopt failed with %d\n", WSAGetLastError());
    ok(size == sizeof(WSAPROTOCOL_INFOA) * 2, "got size %d\n", size);

    closesocket(s);

    /* test SO_PROTOCOL_INFO structure returned for different protocols */
    for (i = 0; i < ARRAY_SIZE(prottest); i++)
    {
        int k;

        s = socket(prottest[i].family, prottest[i].type, prottest[i].proto);
        if (s == INVALID_SOCKET && prottest[i].family == AF_INET6) continue;

        ok(s != INVALID_SOCKET, "Failed to create socket: %d\n",
          WSAGetLastError());

        /* compare both A and W version */
        infoA.szProtocol[0] = 0;
        size = sizeof(WSAPROTOCOL_INFOA);
        err = getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFOA, (char *) &infoA, &size);
        ok(!err,"getsockopt failed with %d\n", WSAGetLastError());
        ok(size == sizeof(WSAPROTOCOL_INFOA), "got size %d\n", size);

        infoW.szProtocol[0] = 0;
        size = sizeof(WSAPROTOCOL_INFOW);
        err = getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFOW, (char *) &infoW, &size);
        ok(!err,"getsockopt failed with %d\n", WSAGetLastError());
        ok(size == sizeof(WSAPROTOCOL_INFOW), "got size %d\n", size);

        ok(infoA.szProtocol[0], "WSAPROTOCOL_INFOA was not filled\n");
        ok(infoW.szProtocol[0], "WSAPROTOCOL_INFOW was not filled\n");

        WideCharToMultiByte(CP_ACP, 0, infoW.szProtocol, -1,
                            providername, sizeof(providername), NULL, NULL);
        ok(!strcmp(infoA.szProtocol,providername),
           "different provider names '%s' != '%s'\n", infoA.szProtocol, providername);

        ok(!memcmp(&infoA, &infoW, FIELD_OFFSET(WSAPROTOCOL_INFOA, szProtocol)),
           "SO_PROTOCOL_INFO[A/W] comparison failed\n");

        /* Remove IF when WSAEnumProtocols support IPV6 data */
        ok(infoA.iAddressFamily == prottest[i].family, "socket family invalid, expected %d received %d\n",
           prottest[i].family, infoA.iAddressFamily);
        ok(infoA.iSocketType == prottest[i].type, "socket type invalid, expected %d received %d\n",
           prottest[i].type, infoA.iSocketType);
        ok(infoA.iProtocol == prottest[i].proto, "socket protocol invalid, expected %d received %d\n",
           prottest[i].proto, infoA.iProtocol);

        /* IP_HDRINCL is supported only on SOCK_RAW but passed to SOCK_DGRAM by Impossible Creatures */
        size = sizeof(i);
        k = 1;
        SetLastError(0xdeadbeef);
        err = setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char *) &k, size);
        if (err == -1) /* >= Vista */
        {
            todo_wine {
            ok(GetLastError() == WSAEINVAL, "Expected 10022, got %d\n", GetLastError());
            k = 99;
            SetLastError(0xdeadbeef);
            err = getsockopt(s, IPPROTO_IP, IP_HDRINCL, (char *) &k, &size);
            ok(err == -1, "Expected -1, got %d\n", err);
            ok(GetLastError() == WSAEINVAL, "Expected 10022, got %d\n", GetLastError());
            ok(k == 99, "Expected 99, got %d\n", k);

            size = sizeof(k);
            k = 0;
            SetLastError(0xdeadbeef);
            err = setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char *) &k, size);
            }
            ok(err == -1, "Expected -1, got %d\n", err);
            todo_wine {
            ok(GetLastError() == WSAEINVAL, "Expected 10022, got %d\n", GetLastError());
            k = 99;
            SetLastError(0xdeadbeef);
            err = getsockopt(s, IPPROTO_IP, IP_HDRINCL, (char *) &k, &size);
            ok(err == -1, "Expected -1, got %d\n", err);
            ok(GetLastError() == WSAEINVAL, "Expected 10022, got %d\n", GetLastError());
            ok(k == 99, "Expected 99, got %d\n", k);
            }
        }
        else /* <= 2003 the tests differ between TCP and UDP, UDP silently accepts */
        {
            SetLastError(0xdeadbeef);
            k = 99;
            err = getsockopt(s, IPPROTO_IP, IP_HDRINCL, (char *) &k, &size);
            if (prottest[i].type == SOCK_DGRAM)
            {
                ok(err == 0, "Expected 0, got %d\n", err);
                ok(k == 1, "Expected 1, got %d\n", k);
            }
            else
            {
                /* contratry to what we could expect the function returns error but k is changed */
                ok(err == -1, "Expected -1, got %d\n", err);
                ok(GetLastError() == WSAENOPROTOOPT, "Expected 10042, got %d\n", GetLastError());
                ok(k == 0, "Expected 0, got %d\n", k);
            }

            k = 0;
            err = setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char *) &k, size);
            ok(err == 0, "Expected 0, got %d\n", err);

            k = 99;
            err = getsockopt(s, IPPROTO_IP, IP_HDRINCL, (char *) &k, &size);
            if (prottest[i].type == SOCK_DGRAM)
            {
                ok(err == 0, "Expected 0, got %d\n", err);
                ok(k == 0, "Expected 0, got %d\n", k);
            }
            else
            {
                /* contratry to what we could expect the function returns error but k is changed */
                ok(err == -1, "Expected -1, got %d\n", err);
                ok(GetLastError() == WSAENOPROTOOPT, "Expected 10042, got %d\n", GetLastError());
                ok(k == 0, "Expected 0, got %d\n", k);
            }
        }

        closesocket(s);
    }

    /* Test SO_BSP_STATE - Present only in >= Win 2008 */
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(s != INVALID_SOCKET, "Failed to create socket\n");
    s2 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(s2 != INVALID_SOCKET, "Failed to create socket\n");

    SetLastError(0xdeadbeef);
    size = sizeof(csinfoA);
    err = getsockopt(s, SOL_SOCKET, SO_BSP_STATE, (char *) &csinfoA, &size);
    if (!err)
    {
        struct sockaddr_in saddr;
        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = inet_addr("127.0.0.1");

        /* Socket is not bound, no information provided */
        ok(!csinfoA.cs.LocalAddr.iSockaddrLength, "Expected 0, got %d\n", csinfoA.cs.LocalAddr.iSockaddrLength);
        ok(csinfoA.cs.LocalAddr.lpSockaddr == NULL, "Expected NULL, got %p\n", csinfoA.cs.LocalAddr.lpSockaddr);
        /* Socket is not connected, no information provided */
        ok(!csinfoA.cs.RemoteAddr.iSockaddrLength, "Expected 0, got %d\n", csinfoA.cs.RemoteAddr.iSockaddrLength);
        ok(csinfoA.cs.RemoteAddr.lpSockaddr == NULL, "Expected NULL, got %p\n", csinfoA.cs.RemoteAddr.lpSockaddr);

        err = bind(s, (struct sockaddr*)&saddr, sizeof(saddr));
        ok(!err, "Expected 0, got %d\n", err);
        size = sizeof(csinfoA);
        err = getsockopt(s, SOL_SOCKET, SO_BSP_STATE, (char *) &csinfoA, &size);
        ok(!err, "Expected 0, got %d\n", err);

        /* Socket is bound */
        ok(csinfoA.cs.LocalAddr.iSockaddrLength, "Expected non-zero\n");
        ok(csinfoA.cs.LocalAddr.lpSockaddr != NULL, "Expected non-null\n");
        /* Socket is not connected, no information provided */
        ok(!csinfoA.cs.RemoteAddr.iSockaddrLength, "Expected 0, got %d\n", csinfoA.cs.RemoteAddr.iSockaddrLength);
        ok(csinfoA.cs.RemoteAddr.lpSockaddr == NULL, "Expected NULL, got %p\n", csinfoA.cs.RemoteAddr.lpSockaddr);

        err = bind(s2, (struct sockaddr*)&saddr, sizeof(saddr));
        ok(!err, "Expected 0, got %d\n", err);
        err = getsockname(s2, (struct sockaddr *)&saddr, &size);
        ok(!err, "Expected 0, got %d\n", err);
        err = listen(s2, 1);
        ok(!err, "Expected 0, got %d\n", err);
        err = connect(s, (struct sockaddr*)&saddr, sizeof(saddr));
        ok(!err, "Expected 0, got %d\n", err);
        size = sizeof(saddr);
        err = accept(s2, (struct sockaddr*)&saddr, &size);
        ok(err != INVALID_SOCKET, "Failed to accept socket\n");
        closesocket(s2);
        s2 = err;

        size = sizeof(csinfoA);
        err = getsockopt(s, SOL_SOCKET, SO_BSP_STATE, (char *) &csinfoA, &size);
        ok(!err, "Expected 0, got %d\n", err);
        err = getsockopt(s2, SOL_SOCKET, SO_BSP_STATE, (char *) &csinfoB, &size);
        ok(!err, "Expected 0, got %d\n", err);
        ok(size == sizeof(csinfoA), "Got %d\n", size);
        size = sizeof(saddr);
        ok(size == csinfoA.cs.LocalAddr.iSockaddrLength, "Expected %d, got %d\n", size,
           csinfoA.cs.LocalAddr.iSockaddrLength);
        ok(size == csinfoA.cs.RemoteAddr.iSockaddrLength, "Expected %d, got %d\n", size,
           csinfoA.cs.RemoteAddr.iSockaddrLength);
        ok(!memcmp(csinfoA.cs.LocalAddr.lpSockaddr, csinfoB.cs.RemoteAddr.lpSockaddr, size),
           "Expected matching addresses\n");
        ok(!memcmp(csinfoB.cs.LocalAddr.lpSockaddr, csinfoA.cs.RemoteAddr.lpSockaddr, size),
           "Expected matching addresses\n");
        ok(csinfoA.cs.iSocketType == SOCK_STREAM, "Wrong socket type\n");
        ok(csinfoB.cs.iSocketType == SOCK_STREAM, "Wrong socket type\n");
        ok(csinfoA.cs.iProtocol == IPPROTO_TCP, "Wrong socket protocol\n");
        ok(csinfoB.cs.iProtocol == IPPROTO_TCP, "Wrong socket protocol\n");

        err = getpeername(s, (struct sockaddr *)&saddr, &size);
        ok(!err, "Expected 0, got %d\n", err);
        ok(!memcmp(&saddr, csinfoA.cs.RemoteAddr.lpSockaddr, size), "Expected matching addresses\n");
        ok(!memcmp(&saddr, csinfoB.cs.LocalAddr.lpSockaddr, size), "Expected matching addresses\n");
        err = getpeername(s2, (struct sockaddr *)&saddr, &size);
        ok(!err, "Expected 0, got %d\n", err);
        ok(!memcmp(&saddr, csinfoB.cs.RemoteAddr.lpSockaddr, size), "Expected matching addresses\n");
        ok(!memcmp(&saddr, csinfoA.cs.LocalAddr.lpSockaddr, size), "Expected matching addresses\n");
        err = getsockname(s, (struct sockaddr *)&saddr, &size);
        ok(!err, "Expected 0, got %d\n", err);
        ok(!memcmp(&saddr, csinfoA.cs.LocalAddr.lpSockaddr, size), "Expected matching addresses\n");
        ok(!memcmp(&saddr, csinfoB.cs.RemoteAddr.lpSockaddr, size), "Expected matching addresses\n");
        err = getsockname(s2, (struct sockaddr *)&saddr, &size);
        ok(!err, "Expected 0, got %d\n", err);
        ok(!memcmp(&saddr, csinfoB.cs.LocalAddr.lpSockaddr, size), "Expected matching addresses\n");
        ok(!memcmp(&saddr, csinfoA.cs.RemoteAddr.lpSockaddr, size), "Expected matching addresses\n");

        SetLastError(0xdeadbeef);
        size = sizeof(CSADDR_INFO);
        err = getsockopt(s, SOL_SOCKET, SO_BSP_STATE, (char *) &csinfoA, &size);
        ok(err, "Expected non-zero\n");
        ok(size == sizeof(CSADDR_INFO), "Got %d\n", size);
        ok(GetLastError() == WSAEFAULT, "Expected 10014, got %d\n", GetLastError());

        /* At least for IPv4 the size is exactly 56 bytes */
        size = sizeof(*csinfoA.cs.LocalAddr.lpSockaddr) * 2 + sizeof(csinfoA.cs);
        err = getsockopt(s, SOL_SOCKET, SO_BSP_STATE, (char *) &csinfoA, &size);
        ok(!err, "Expected 0, got %d\n", err);
        size--;
        SetLastError(0xdeadbeef);
        err = getsockopt(s, SOL_SOCKET, SO_BSP_STATE, (char *) &csinfoA, &size);
        ok(err, "Expected non-zero\n");
        ok(GetLastError() == WSAEFAULT, "Expected 10014, got %d\n", GetLastError());
    }
    else
        ok(GetLastError() == WSAENOPROTOOPT, "Expected 10042, got %d\n", GetLastError());

    closesocket(s);
    closesocket(s2);

    for (i = 0; i < 2; i++)
    {
        int family, level;

        if (i)
        {
            family = AF_INET6;
            level = IPPROTO_IPV6;
        }
        else
        {
            family = AF_INET;
            level = IPPROTO_IP;
        }

        s = socket(family, SOCK_DGRAM, 0);
        if (s == INVALID_SOCKET && i)
        {
            skip("IPv6 is not supported\n");
            break;
        }
        ok(s != INVALID_SOCKET, "socket failed with error %d\n", GetLastError());

        size = sizeof(value);
        value = 0xdead;
        err = getsockopt(s, level, IP_DONTFRAGMENT, (char *) &value, &size);
        ok(!err, "Expected 0, got %d with error %d\n", err, GetLastError());
        ok(value == 0, "Expected 0, got %d\n", value);

        size = sizeof(value);
        value = 1;
        err = setsockopt(s, level, IP_DONTFRAGMENT, (char *) &value, size);
        ok(!err, "Expected 0, got %d with error %d\n", err, GetLastError());

        value = 0xdead;
        err = getsockopt(s, level, IP_DONTFRAGMENT, (char *) &value, &size);
        ok(!err, "Expected 0, got %d with error %d\n", err, GetLastError());
        ok(value == 1, "Expected 1, got %d\n", value);

        size = sizeof(value);
        value = 0xdead;
        err = setsockopt(s, level, IP_DONTFRAGMENT, (char *) &value, size);
        ok(!err, "Expected 0, got %d with error %d\n", err, GetLastError());

        err = getsockopt(s, level, IP_DONTFRAGMENT, (char *) &value, &size);
        ok(!err, "Expected 0, got %d with error %d\n", err, GetLastError());
        ok(value == 1, "Expected 1, got %d\n", value);

        closesocket(s);

        s = socket(family, SOCK_STREAM, 0);
        ok(s != INVALID_SOCKET, "socket failed with error %d\n", GetLastError());

        size = sizeof(value);
        value = 0xdead;
        err = getsockopt(s, level, IP_DONTFRAGMENT, (char *) &value, &size);
        ok(!err, "Expected 0, got %d with error %d\n", err, GetLastError());
        ok(value == 1 || broken(value == 0) /* < vista */, "Expected 1, got %d\n", value);

        size = sizeof(value);
        value = 0;
        err = setsockopt(s, level, IP_DONTFRAGMENT, (char *) &value, size);
        ok(!err, "Expected 0, got %d with error %d\n", err, GetLastError());

        value = 0xdead;
        err = getsockopt(s, level, IP_DONTFRAGMENT, (char *) &value, &size);
        ok(!err, "Expected 0, got %d with error %d\n", err, GetLastError());
        ok(value == 0, "Expected 0, got %d\n", value);

        closesocket(s);

        s = socket(family, SOCK_RAW, 0);
        if (s == INVALID_SOCKET)
        {
            if (WSAGetLastError() == WSAEACCES) skip("SOCK_RAW is not available\n");
            else if (i) skip("IPv6 is not supported\n");
            break;
        }
        ok(s != INVALID_SOCKET, "socket failed with error %d\n", GetLastError());

        size = sizeof(value);
        value = 0xdead;
        err = getsockopt(s, level, IP_DONTFRAGMENT, (char *) &value, &size);
        ok(!err, "Expected 0, got %d with error %d\n", err, GetLastError());
        ok(value == 0, "Expected 0, got %d\n", value);

        size = sizeof(value);
        value = 1;
        err = setsockopt(s, level, IP_DONTFRAGMENT, (char *) &value, size);
        ok(!err, "Expected 0, got %d with error %d\n", err, GetLastError());

        value = 0xdead;
        err = getsockopt(s, level, IP_DONTFRAGMENT, (char *) &value, &size);
        ok(!err, "Expected 0, got %d with error %d\n", err, GetLastError());
        ok(value == 1, "Expected 1, got %d\n", value);

        closesocket(s);
    }
}

static void test_so_reuseaddr(void)
{
    struct sockaddr_in saddr;
    SOCKET s1,s2;
    unsigned int rc,reuse;
    int size;
    DWORD err;

    saddr.sin_family      = AF_INET;
    saddr.sin_port        = htons(SERVERPORT+1);
    saddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    s1=socket(AF_INET, SOCK_STREAM, 0);
    ok(s1!=INVALID_SOCKET, "socket() failed error: %d\n", WSAGetLastError());
    rc = bind(s1, (struct sockaddr*)&saddr, sizeof(saddr));
    ok(rc!=SOCKET_ERROR, "bind(s1) failed error: %d\n", WSAGetLastError());

    s2=socket(AF_INET, SOCK_STREAM, 0);
    ok(s2!=INVALID_SOCKET, "socket() failed error: %d\n", WSAGetLastError());

    reuse=0x1234;
    size=sizeof(reuse);
    rc=getsockopt(s2, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, &size );
    ok(rc==0 && reuse==0,"wrong result in getsockopt(SO_REUSEADDR): rc=%d reuse=%d\n",rc,reuse);

    rc = bind(s2, (struct sockaddr*)&saddr, sizeof(saddr));
    ok(rc==SOCKET_ERROR, "bind() succeeded\n");

    reuse = 1;
    rc = setsockopt(s2, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));
    ok(rc==0, "setsockopt() failed error: %d\n", WSAGetLastError());

    /* On Win2k3 and above, all SO_REUSEADDR seems to do is to allow binding to
     * a port immediately after closing another socket on that port, so
     * basically following the BSD socket semantics here. */
    rc = bind(s2, (struct sockaddr*)&saddr, sizeof(saddr));
    if(rc==0)
    {
        int s3=socket(AF_INET, SOCK_STREAM, 0), s4;

        /* If we could bind again in the same port this is Windows version <= XP.
         * Lets test if we can really connect to one of them. */
        set_blocking(s1, FALSE);
        set_blocking(s2, FALSE);
        rc = listen(s1, 1);
        ok(!rc, "listen() failed with error: %d\n", WSAGetLastError());
        rc = listen(s2, 1);
        ok(!rc, "listen() failed with error: %d\n", WSAGetLastError());
        rc = connect(s3, (struct sockaddr*)&saddr, sizeof(saddr));
        ok(!rc, "connecting to accepting socket failed %d\n", WSAGetLastError());

        /* the delivery of the connection is random so we need to try on both sockets */
        size = sizeof(saddr);
        s4 = accept(s1, (struct sockaddr*)&saddr, &size);
        if(s4 == INVALID_SOCKET)
            s4 = accept(s2, (struct sockaddr*)&saddr, &size);
        ok(s4 != INVALID_SOCKET, "none of the listening sockets could get the connection\n");

        closesocket(s1);
        closesocket(s3);
        closesocket(s4);
    }
    else
    {
        err = WSAGetLastError();
        ok(err==WSAEACCES, "expected 10013, got %d\n", err);

        closesocket(s1);
        rc = bind(s2, (struct sockaddr*)&saddr, sizeof(saddr));
        ok(rc==0, "bind() failed error: %d\n", WSAGetLastError());
    }

    closesocket(s2);
}

#define IP_PKTINFO_LEN (sizeof(WSACMSGHDR) + WSA_CMSG_ALIGN(sizeof(struct in_pktinfo)))

static void test_ip_pktinfo(void)
{
    ULONG addresses[2] = {inet_addr("127.0.0.1"), htonl(INADDR_ANY)};
    char recvbuf[10], pktbuf[512], msg[] = "HELLO";
    struct sockaddr_in s1addr, s2addr, s3addr;
    GUID WSARecvMsg_GUID = WSAID_WSARECVMSG;
    LPFN_WSARECVMSG pWSARecvMsg = NULL;
    unsigned int rc, yes = 1;
    BOOL foundhdr;
    DWORD dwBytes, dwSize, dwFlags;
    socklen_t addrlen;
    WSACMSGHDR *cmsg;
    WSAOVERLAPPED ov;
    WSABUF iovec[1];
    SOCKET s1, s2;
    WSAMSG hdr;
    int i, err;

    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);

    memset(&hdr, 0x00, sizeof(hdr));
    s1addr.sin_family = AF_INET;
    s1addr.sin_port   = htons(0);
    /* Note: s1addr.sin_addr is set below */
    iovec[0].buf      = recvbuf;
    iovec[0].len      = sizeof(recvbuf);
    hdr.name          = (struct sockaddr*)&s3addr;
    hdr.namelen       = sizeof(s3addr);
    hdr.lpBuffers     = &iovec[0];
    hdr.dwBufferCount = 1;
    hdr.Control.buf   = pktbuf;
    /* Note: hdr.Control.len is set below */
    hdr.dwFlags       = 0;

    for (i=0;i<ARRAY_SIZE(addresses);i++)
    {
        s1addr.sin_addr.s_addr = addresses[i];

        /* Build "server" side socket */
        s1=socket(AF_INET, SOCK_DGRAM, 0);
        ok(s1 != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());

        /* Obtain the WSARecvMsg function */
        rc = WSAIoctl(s1, SIO_GET_EXTENSION_FUNCTION_POINTER, &WSARecvMsg_GUID, sizeof(WSARecvMsg_GUID),
                 &pWSARecvMsg, sizeof(pWSARecvMsg), &dwBytes, NULL, NULL);
        ok(!rc, "failed to get WSARecvMsg, error %u\n", WSAGetLastError());

        /* Setup the server side socket */
        rc=bind(s1, (struct sockaddr*)&s1addr, sizeof(s1addr));
        ok(rc != SOCKET_ERROR, "bind() failed error: %d\n", WSAGetLastError());

        /* Build "client" side socket */
        addrlen = sizeof(s2addr);
        rc = getsockname(s1, (struct sockaddr *) &s2addr, &addrlen);
        ok(!rc, "failed to get address, error %u\n", WSAGetLastError());
        s2addr.sin_addr.s_addr = addresses[0]; /* Always target the local adapter address */
        s2=socket(AF_INET, SOCK_DGRAM, 0);
        ok(s2 != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());

        /* Test an empty message header */
        rc=pWSARecvMsg(s1, NULL, NULL, NULL, NULL);
        err=WSAGetLastError();
        ok(rc == SOCKET_ERROR && err == WSAEFAULT, "WSARecvMsg() failed error: %d (ret = %d)\n", err, rc);

        /* Test that when no control data arrives, a 0-length NULL-valued control buffer should succeed */
        SetLastError(0xdeadbeef);
        rc=sendto(s2, msg, sizeof(msg), 0, (struct sockaddr*)&s2addr, sizeof(s2addr));
        ok(rc == sizeof(msg), "sendto() failed error: %d\n", WSAGetLastError());
        ok(GetLastError() == ERROR_SUCCESS, "Expected 0, got %d\n", GetLastError());
        hdr.Control.buf = NULL;
        hdr.Control.len = 0;
        rc=pWSARecvMsg(s1, &hdr, &dwSize, NULL, NULL);
        ok(rc == 0, "WSARecvMsg() failed error: %d\n", WSAGetLastError());
        hdr.Control.buf = pktbuf;

        /* Now start IP_PKTINFO for future tests */
        rc=setsockopt(s1, IPPROTO_IP, IP_PKTINFO, (const char*)&yes, sizeof(yes));
        ok(rc == 0, "failed to set IPPROTO_IP flag IP_PKTINFO!\n");

        /*
         * Send a packet from the client to the server and test for specifying
         * a short control header.
         */
        SetLastError(0xdeadbeef);
        rc=sendto(s2, msg, sizeof(msg), 0, (struct sockaddr*)&s2addr, sizeof(s2addr));
        ok(rc == sizeof(msg), "sendto() failed error: %d\n", WSAGetLastError());
        ok(GetLastError() == ERROR_SUCCESS, "Expected 0, got %d\n", GetLastError());
        hdr.Control.len = 1;
        rc=pWSARecvMsg(s1, &hdr, &dwSize, NULL, NULL);
        err=WSAGetLastError();
        ok(rc == SOCKET_ERROR && err == WSAEMSGSIZE && (hdr.dwFlags & MSG_CTRUNC),
           "WSARecvMsg() failed error: %d (ret: %d, flags: %d)\n", err, rc, hdr.dwFlags);
        hdr.dwFlags = 0; /* Reset flags */

        /* Perform another short control header test, this time with an overlapped receive */
        hdr.Control.len = 1;
        rc=pWSARecvMsg(s1, &hdr, NULL, &ov, NULL);
        err=WSAGetLastError();
        ok(rc != 0 && err == WSA_IO_PENDING, "WSARecvMsg() failed error: %d\n", err);
        SetLastError(0xdeadbeef);
        rc=sendto(s2, msg, sizeof(msg), 0, (struct sockaddr*)&s2addr, sizeof(s2addr));
        ok(rc == sizeof(msg), "sendto() failed error: %d\n", WSAGetLastError());
        ok(GetLastError() == ERROR_SUCCESS, "Expected 0, got %d\n", GetLastError());
        ok(!WaitForSingleObject(ov.hEvent, 100), "wait failed\n");
        dwFlags = 0;
        WSAGetOverlappedResult(s1, &ov, NULL, FALSE, &dwFlags);
        ok(dwFlags == 0,
           "WSAGetOverlappedResult() returned unexpected flags %d!\n", dwFlags);
        ok(hdr.dwFlags == MSG_CTRUNC,
           "WSARecvMsg() overlapped operation set unexpected flags %d.\n", hdr.dwFlags);
        hdr.dwFlags = 0; /* Reset flags */

        /*
         * Setup an overlapped receive, send a packet, then wait for the packet to be retrieved
         * on the server end and check that the returned packet matches what was sent.
         */
        hdr.Control.len = sizeof(pktbuf);
        rc=pWSARecvMsg(s1, &hdr, NULL, &ov, NULL);
        err=WSAGetLastError();
        ok(rc != 0 && err == WSA_IO_PENDING, "WSARecvMsg() failed error: %d\n", err);
        ok(hdr.Control.len == sizeof(pktbuf),
           "WSARecvMsg() control length mismatch (%d != sizeof pktbuf).\n", hdr.Control.len);
        rc=sendto(s2, msg, sizeof(msg), 0, (struct sockaddr*)&s2addr, sizeof(s2addr));
        ok(rc == sizeof(msg), "sendto() failed error: %d\n", WSAGetLastError());
        ok(!WaitForSingleObject(ov.hEvent, 100), "wait failed\n");
        dwSize = 0;
        WSAGetOverlappedResult(s1, &ov, &dwSize, FALSE, NULL);
        ok(dwSize == sizeof(msg),
           "WSARecvMsg() buffer length does not match transmitted data!\n");
        ok(strncmp(iovec[0].buf, msg, sizeof(msg)) == 0,
           "WSARecvMsg() buffer does not match transmitted data!\n");
        ok(hdr.Control.len == IP_PKTINFO_LEN,
           "WSARecvMsg() control length mismatch (%d).\n", hdr.Control.len);

        /* Test for the expected IP_PKTINFO return information. */
        foundhdr = FALSE;
        for (cmsg = WSA_CMSG_FIRSTHDR(&hdr); cmsg != NULL; cmsg = WSA_CMSG_NXTHDR(&hdr, cmsg))
        {
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO)
            {
                struct in_pktinfo *pi = (struct in_pktinfo *)WSA_CMSG_DATA(cmsg);

                ok(pi->ipi_addr.s_addr == s2addr.sin_addr.s_addr, "destination ip mismatch!\n");
                foundhdr = TRUE;
            }
        }
        ok(foundhdr, "IP_PKTINFO header information was not returned!\n");

        closesocket(s2);
        closesocket(s1);
    }

    CloseHandle(ov.hEvent);
}

/************* Array containing the tests to run **********/

#define STD_STREAM_SOCKET \
            SOCK_STREAM, \
            0, \
            SERVERIP, \
            SERVERPORT

static test_setup tests [] =
{
    /* Test 0: synchronous client and server */
    {
        {
            STD_STREAM_SOCKET,
            2048,
            16,
            2
        },
        simple_server,
        {
            NULL,
            0,
            64
        },
        simple_client,
        {
            NULL,
            0,
            128
        }
    },
    /* Test 1: event-driven client, synchronous server */
    {
        {
            STD_STREAM_SOCKET,
            2048,
            16,
            2
        },
        simple_server,
        {
            NULL,
            0,
            64
        },
        event_client,
        {
            NULL,
            WSA_FLAG_OVERLAPPED,
            128
        }
    },
    /* Test 2: synchronous client, non-blocking server via select() */
    {
        {
            STD_STREAM_SOCKET,
            2048,
            16,
            2
        },
        select_server,
        {
            NULL,
            0,
            64
        },
        simple_client,
        {
            NULL,
            0,
            128
        }
    },
    /* Test 3: OOB client, OOB server */
    {
        {
            STD_STREAM_SOCKET,
            128,
            16,
            1
        },
        oob_server,
        {
            NULL,
            0,
            128
        },
        oob_client,
        {
            NULL,
            0,
            128
        }
    },
    /* Test 4: synchronous mixed client and server */
    {
        {
            STD_STREAM_SOCKET,
            2048,
            16,
            2
        },
        simple_server,
        {
            NULL,
            0,
            64
        },
        simple_mixed_client,
        {
            NULL,
            0,
            128
        }
    }
};

static void test_UDP(void)
{
    /* This function tests UDP sendto() and recvfrom(). UDP is unreliable, so it is
       possible that this test fails due to dropped packets. */

    /* peer 0 receives data from all other peers */
    struct sock_info peer[NUM_UDP_PEERS];
    char buf[16];
    int ss, i, n_recv, n_sent;

    memset (buf,0,sizeof(buf));
    for ( i = NUM_UDP_PEERS - 1; i >= 0; i-- ) {
        ok ( ( peer[i].s = socket ( AF_INET, SOCK_DGRAM, 0 ) ) != INVALID_SOCKET, "UDP: socket failed\n" );

        peer[i].addr.sin_family         = AF_INET;
        peer[i].addr.sin_addr.s_addr    = inet_addr ( SERVERIP );

        if ( i == 0 ) {
            peer[i].addr.sin_port       = htons ( SERVERPORT );
        } else {
            peer[i].addr.sin_port       = htons ( 0 );
        }

        do_bind ( peer[i].s, (struct sockaddr *) &peer[i].addr, sizeof( peer[i].addr ) );

        /* test getsockname() to get peer's port */
        ss = sizeof ( peer[i].addr );
        ok ( getsockname ( peer[i].s, (struct sockaddr *) &peer[i].addr, &ss ) != SOCKET_ERROR, "UDP: could not getsockname()\n" );
        ok ( peer[i].addr.sin_port != htons ( 0 ), "UDP: bind() did not associate port\n" );
    }

    /* test getsockname() */
    ok ( peer[0].addr.sin_port == htons ( SERVERPORT ), "UDP: getsockname returned incorrect peer port\n" );

    for ( i = 1; i < NUM_UDP_PEERS; i++ ) {
        /* send client's ip */
        memcpy( buf, &peer[i].addr.sin_port, sizeof(peer[i].addr.sin_port) );
        n_sent = sendto ( peer[i].s, buf, sizeof(buf), 0, (struct sockaddr*) &peer[0].addr, sizeof(peer[0].addr) );
        ok ( n_sent == sizeof(buf), "UDP: sendto() sent wrong amount of data or socket error: %d\n", n_sent );
    }

    for ( i = 1; i < NUM_UDP_PEERS; i++ ) {
        n_recv = recvfrom ( peer[0].s, buf, sizeof(buf), 0,(struct sockaddr *) &peer[0].peer, &ss );
        ok ( n_recv == sizeof(buf), "UDP: recvfrom() received wrong amount of data or socket error: %d\n", n_recv );
        ok ( memcmp ( &peer[0].peer.sin_port, buf, sizeof(peer[0].addr.sin_port) ) == 0, "UDP: port numbers do not match\n" );
    }
}

static void test_WSASocket(void)
{
    SOCKET sock = INVALID_SOCKET;
    WSAPROTOCOL_INFOA *pi;
    int wsaproviders[] = {IPPROTO_TCP, IPPROTO_IP};
    int autoprotocols[] = {IPPROTO_TCP, IPPROTO_UDP};
    int items, err, size, socktype, i, j;
    UINT pi_size;

    static const struct
    {
        int family, type, protocol;
        DWORD error;
        int ret_family, ret_type, ret_protocol;
    }
    tests[] =
    {
        /* 0 */
        {0xdead,    SOCK_STREAM, IPPROTO_TCP, WSAEAFNOSUPPORT},
        {-1,        SOCK_STREAM, IPPROTO_TCP, WSAEAFNOSUPPORT},
        {AF_INET,   0xdead,      IPPROTO_TCP, WSAESOCKTNOSUPPORT},
        {AF_INET,   -1,          IPPROTO_TCP, WSAESOCKTNOSUPPORT},
        {AF_INET,   SOCK_STREAM, 0xdead,      WSAEPROTONOSUPPORT},
        {AF_INET,   SOCK_STREAM, -1,          WSAEPROTONOSUPPORT},
        {0xdead,    0xdead,      IPPROTO_TCP, WSAESOCKTNOSUPPORT},
        {0xdead,    SOCK_STREAM, 0xdead,      WSAEAFNOSUPPORT},
        {AF_INET,   0xdead,      0xdead,      WSAESOCKTNOSUPPORT},
        {0xdead,    SOCK_STREAM, IPPROTO_UDP, WSAEAFNOSUPPORT},

        /* 10 */
        {AF_INET,   SOCK_STREAM, 0,           0, AF_INET, SOCK_STREAM, IPPROTO_TCP},
        {AF_INET,   SOCK_DGRAM,  0,           0, AF_INET, SOCK_DGRAM,  IPPROTO_UDP},
        {AF_INET,   0xdead,      0,           WSAESOCKTNOSUPPORT},
        {AF_INET,   0,           IPPROTO_TCP, 0, AF_INET, SOCK_STREAM, IPPROTO_TCP},
        {AF_INET,   0,           IPPROTO_UDP, 0, AF_INET, SOCK_DGRAM,  IPPROTO_UDP},
        {AF_INET,   0,           0xdead,      WSAEPROTONOSUPPORT},
        {AF_INET,   0,           0,           0, AF_INET, SOCK_STREAM, IPPROTO_TCP},
        {AF_INET,   SOCK_STREAM, IPPROTO_UDP, WSAEPROTONOSUPPORT},
        {AF_INET,   SOCK_DGRAM,  IPPROTO_TCP, WSAEPROTONOSUPPORT},

        /* 19 */
        {AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, 0, AF_INET, SOCK_STREAM, IPPROTO_TCP},
        {AF_UNSPEC, SOCK_STREAM, 0xdead,      WSAEPROTONOSUPPORT},
        {AF_UNSPEC, 0xdead,      IPPROTO_UDP, WSAESOCKTNOSUPPORT},
        {AF_UNSPEC, SOCK_STREAM, 0,           WSAEINVAL},
        {AF_UNSPEC, SOCK_DGRAM,  0,           WSAEINVAL},
        {AF_UNSPEC, 0xdead,      0,           WSAEINVAL},
        {AF_UNSPEC, 0,           IPPROTO_TCP, 0, AF_INET, SOCK_STREAM, IPPROTO_TCP},
        {AF_UNSPEC, 0,           IPPROTO_UDP, 0, AF_INET, SOCK_DGRAM,  IPPROTO_UDP},
        {AF_UNSPEC, 0,           0xdead,      WSAEPROTONOSUPPORT},
        {AF_UNSPEC, 0,           0,           WSAEINVAL},
    };

    for (i = 0; i < ARRAY_SIZE(tests); ++i)
    {
        SetLastError( 0xdeadbeef );
        sock = WSASocketA( tests[i].family, tests[i].type, tests[i].protocol, NULL, 0, 0 );
        todo_wine_if (!tests[i].error || i == 7)
            ok(WSAGetLastError() == tests[i].error, "Test %u: got wrong error %u\n", i, WSAGetLastError());
        if (tests[i].error)
        {
            ok(sock == INVALID_SOCKET, "Test %u: expected failure\n", i);
        }
        else
        {
            WSAPROTOCOL_INFOA info;

            ok(sock != INVALID_SOCKET, "Text %u: expected success\n", i);

            size = sizeof(info);
            err = getsockopt( sock, SOL_SOCKET, SO_PROTOCOL_INFOA, (char *)&info, &size );
            ok(!err, "Test %u: getsockopt failed, error %u\n", i, WSAGetLastError());
            ok(info.iAddressFamily == tests[i].ret_family, "Test %u: got wrong family %d\n", i, info.iAddressFamily);
            ok(info.iSocketType == tests[i].ret_type, "Test %u: got wrong type %d\n", i, info.iSocketType);
            ok(info.iProtocol == tests[i].ret_protocol, "Test %u: got wrong protocol %d\n", i, info.iProtocol);

            closesocket( sock );
        }
    }

    /* Set pi_size explicitly to a value below 2*sizeof(WSAPROTOCOL_INFOA)
     * to avoid a crash on win98.
     */
    pi_size = 0;
    items = WSAEnumProtocolsA(wsaproviders, NULL, &pi_size);
    ok(items == SOCKET_ERROR, "WSAEnumProtocolsA({6,0}, NULL, 0) returned %d\n",
            items);
    err = WSAGetLastError();
    ok(err == WSAENOBUFS, "WSAEnumProtocolsA error is %d, not WSAENOBUFS(%d)\n",
            err, WSAENOBUFS);

    pi = HeapAlloc(GetProcessHeap(), 0, pi_size);
    ok(pi != NULL, "Failed to allocate memory\n");

    items = WSAEnumProtocolsA(wsaproviders, pi, &pi_size);
    ok(items != SOCKET_ERROR, "WSAEnumProtocolsA failed, last error is %d\n",
            WSAGetLastError());

    if (items == 0) {
        skip("No protocols enumerated.\n");
        HeapFree(GetProcessHeap(), 0, pi);
        return;
    }

    sock = WSASocketA(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO,
                      FROM_PROTOCOL_INFO, &pi[0], 0, 0);
    ok(sock != INVALID_SOCKET, "Failed to create socket: %d\n",
            WSAGetLastError());
    closesocket(sock);

    /* find what parameters are used first: plain parameters or protocol info struct */
    pi[0].iProtocol = -1;
    pi[0].iSocketType = -1;
    pi[0].iAddressFamily = -1;
    ok(WSASocketA(0, 0, IPPROTO_UDP, &pi[0], 0, 0) == INVALID_SOCKET,
       "WSASocketA should have failed\n");
    err = WSAGetLastError();
    ok(err == WSAEAFNOSUPPORT, "Expected 10047, received %d\n", err);

    pi[0].iProtocol = 0;
    pi[0].iSocketType = 0;
    pi[0].iAddressFamily = 0;
    sock = WSASocketA(0, 0, IPPROTO_UDP, &pi[0], 0, 0);
    if(sock != INVALID_SOCKET)
    {
      win_skip("must work only in OS <= 2003\n");
      closesocket(sock);
    }
    else
    {
      err = WSAGetLastError();
      ok(err == WSAEAFNOSUPPORT, "Expected 10047, received %d\n", err);
    }

    pi[0].iProtocol = IPPROTO_UDP;
    pi[0].iSocketType = SOCK_DGRAM;
    pi[0].iAddressFamily = AF_INET;
    sock = WSASocketA(0, 0, 0, &pi[0], 0, 0);
    ok(sock != INVALID_SOCKET, "Failed to create socket: %d\n",
            WSAGetLastError());
    size = sizeof(socktype);
    socktype = 0xdead;
    err = getsockopt(sock, SOL_SOCKET, SO_TYPE, (char *) &socktype, &size);
    ok(!err,"getsockopt failed with %d\n", WSAGetLastError());
    ok(socktype == SOCK_DGRAM, "Wrong socket type, expected %d received %d\n",
       SOCK_DGRAM, socktype);
    closesocket(sock);

    sock = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, &pi[0], 0, 0);
    ok(sock != INVALID_SOCKET, "Failed to create socket: %d\n",
            WSAGetLastError());
    size = sizeof(socktype);
    socktype = 0xdead;
    err = getsockopt(sock, SOL_SOCKET, SO_TYPE, (char *) &socktype, &size);
    ok(!err,"getsockopt failed with %d\n", WSAGetLastError());
    ok(socktype == SOCK_STREAM, "Wrong socket type, expected %d received %d\n",
       SOCK_STREAM, socktype);
    closesocket(sock);

    HeapFree(GetProcessHeap(), 0, pi);

    pi_size = 0;
    items = WSAEnumProtocolsA(NULL, NULL, &pi_size);
    ok(items == SOCKET_ERROR, "WSAEnumProtocolsA(NULL, NULL, 0) returned %d\n",
            items);
    err = WSAGetLastError();
    ok(err == WSAENOBUFS, "WSAEnumProtocolsA error is %d, not WSAENOBUFS(%d)\n",
            err, WSAENOBUFS);

    pi = HeapAlloc(GetProcessHeap(), 0, pi_size);
    ok(pi != NULL, "Failed to allocate memory\n");

    items = WSAEnumProtocolsA(NULL, pi, &pi_size);
    ok(items != SOCKET_ERROR, "WSAEnumProtocolsA failed, last error is %d\n",
            WSAGetLastError());

    /* when no protocol and socket type are specified the first entry
     * from WSAEnumProtocols that has the flag PFL_MATCHES_PROTOCOL_ZERO
     * is returned */
    sock = WSASocketA(AF_INET, 0, 0, NULL, 0, 0);
    ok(sock != INVALID_SOCKET, "Failed to create socket: %d\n",
            WSAGetLastError());

    size = sizeof(socktype);
    socktype = 0xdead;
    err = getsockopt(sock, SOL_SOCKET, SO_TYPE, (char *) &socktype, &size);
    ok(!err, "getsockopt failed with %d\n", WSAGetLastError());
    for(i = 0; i < items; i++)
    {
        if(pi[i].dwProviderFlags & PFL_MATCHES_PROTOCOL_ZERO)
        {
            ok(socktype == pi[i].iSocketType, "Wrong socket type, expected %d received %d\n",
               pi[i].iSocketType, socktype);
             break;
        }
    }
    ok(i != items, "Creating a socket without protocol and socket type didn't work\n");
    closesocket(sock);

    /* when no socket type is specified the first entry from WSAEnumProtocols
     * that matches the protocol is returned */
    for (i = 0; i < ARRAY_SIZE(autoprotocols); i++)
    {
        sock = WSASocketA(0, 0, autoprotocols[i], NULL, 0, 0);
        ok(sock != INVALID_SOCKET, "Failed to create socket for protocol %d, received %d\n",
                autoprotocols[i], WSAGetLastError());

        size = sizeof(socktype);
        socktype = 0xdead;
        err = getsockopt(sock, SOL_SOCKET, SO_TYPE, (char *) &socktype, &size);
        ok(!err, "getsockopt failed with %d\n", WSAGetLastError());

        for (err = 1, j = 0; j < items; j++)
        {
            if (pi[j].iProtocol == autoprotocols[i])
            {
                ok(pi[j].iSocketType == socktype, "expected %d, got %d\n", socktype, pi[j].iSocketType);
                err = 0;
                break;
            }
        }
        ok(!err, "Protocol %d not found in WSAEnumProtocols\n", autoprotocols[i]);

        closesocket(sock);
    }

    HeapFree(GetProcessHeap(), 0, pi);

    SetLastError(0xdeadbeef);
    /* starting on vista the socket function returns error during the socket
       creation and no longer in the socket operations (sendto, readfrom) */
    sock = WSASocketA(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, 0);
    if (sock == INVALID_SOCKET)
    {
        err = WSAGetLastError();
        ok(err == WSAEACCES, "Expected 10013, received %d\n", err);
        skip("SOCK_RAW is not supported\n");
    }
    else
    {
        size = sizeof(socktype);
        socktype = 0xdead;
        err = getsockopt(sock, SOL_SOCKET, SO_TYPE, (char *) &socktype, &size);
        ok(!err, "getsockopt failed with %d\n", WSAGetLastError());
        ok(socktype == SOCK_RAW, "Wrong socket type, expected %d received %d\n",
           SOCK_RAW, socktype);
        closesocket(sock);

        sock = WSASocketA(0, 0, IPPROTO_RAW, NULL, 0, 0);
        if (sock != INVALID_SOCKET)
        {
            todo_wine {
            size = sizeof(socktype);
            socktype = 0xdead;
            err = getsockopt(sock, SOL_SOCKET, SO_TYPE, (char *) &socktype, &size);
            ok(!err, "getsockopt failed with %d\n", WSAGetLastError());
            ok(socktype == SOCK_RAW, "Wrong socket type, expected %d received %d\n",
               SOCK_RAW, socktype);
            closesocket(sock);
            }

            sock = WSASocketA(AF_INET, SOCK_RAW, IPPROTO_TCP, NULL, 0, 0);
            ok(sock != INVALID_SOCKET, "Failed to create socket: %d\n",
               WSAGetLastError());
            size = sizeof(socktype);
            socktype = 0xdead;
            err = getsockopt(sock, SOL_SOCKET, SO_TYPE, (char *) &socktype, &size);
            ok(!err, "getsockopt failed with %d\n", WSAGetLastError());
            ok(socktype == SOCK_RAW, "Wrong socket type, expected %d received %d\n",
               SOCK_RAW, socktype);
            closesocket(sock);
        }
        else if (WSAGetLastError() == WSAEACCES)
            skip("SOCK_RAW is not available\n");
        else
            ok(0, "Failed to create socket: %d\n", WSAGetLastError());

    }

    /* IPX socket tests */

    SetLastError(0xdeadbeef);
    sock = WSASocketA(AF_IPX, SOCK_DGRAM, NSPROTO_IPX, NULL, 0, 0);
    if (sock == INVALID_SOCKET)
    {
        ok(WSAGetLastError() == WSAEAFNOSUPPORT, "got error %u\n", WSAGetLastError());
        skip("IPX is not supported\n");
    }
    else
    {
        WSAPROTOCOL_INFOA info;
        closesocket(sock);

        sock = WSASocketA(0, 0, NSPROTO_IPX, NULL, 0, 0);
        ok(sock != INVALID_SOCKET, "Failed to create socket: %d\n",
                WSAGetLastError());

        size = sizeof(socktype);
        socktype = 0xdead;
        err = getsockopt(sock, SOL_SOCKET, SO_TYPE, (char *) &socktype, &size);
        ok(!err,"getsockopt failed with %d\n", WSAGetLastError());
        ok(socktype == SOCK_DGRAM, "Wrong socket type, expected %d received %d\n",
           SOCK_DGRAM, socktype);

        /* check socket family, type and protocol */
        size = sizeof(WSAPROTOCOL_INFOA);
        err = getsockopt(sock, SOL_SOCKET, SO_PROTOCOL_INFOA, (char *) &info, &size);
        ok(!err,"getsockopt failed with %d\n", WSAGetLastError());
        ok(info.iProtocol == NSPROTO_IPX, "expected protocol %d, received %d\n",
           NSPROTO_IPX, info.iProtocol);
        ok(info.iAddressFamily == AF_IPX, "expected family %d, received %d\n",
           AF_IPX, info.iProtocol);
        ok(info.iSocketType == SOCK_DGRAM, "expected type %d, received %d\n",
           SOCK_DGRAM, info.iSocketType);
        closesocket(sock);

        /* SOCK_STREAM does not support NSPROTO_IPX */
        SetLastError(0xdeadbeef);
        ok(WSASocketA(AF_IPX, SOCK_STREAM, NSPROTO_IPX, NULL, 0, 0) == INVALID_SOCKET,
           "WSASocketA should have failed\n");
        err = WSAGetLastError();
        ok(err == WSAEPROTONOSUPPORT, "Expected 10043, received %d\n", err);

        /* test extended IPX support - that is adding any number between 0 and 255
         * to the IPX protocol value will make it be used as IPX packet type */
        for(i = 0;i <= 255;i += 17)
        {
          SetLastError(0xdeadbeef);
          sock = WSASocketA(0, 0, NSPROTO_IPX + i, NULL, 0, 0);
          ok(sock != INVALID_SOCKET, "Failed to create socket: %d\n",
                  WSAGetLastError());

          size = sizeof(int);
          socktype = -1;
          err = getsockopt(sock, NSPROTO_IPX, IPX_PTYPE, (char *) &socktype, &size);
          ok(!err, "getsockopt failed with %d\n", WSAGetLastError());
          ok(socktype == i, "Wrong IPX packet type, expected %d received %d\n",
             i, socktype);

          closesocket(sock);
        }
    }
}

static void test_WSADuplicateSocket(void)
{
    SOCKET source, dupsock;
    WSAPROTOCOL_INFOA info;
    DWORD err;
    struct sockaddr_in addr;
    int socktype, size, addrsize, ret;
    char teststr[] = "TEST", buffer[16];

    source = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    ok(source != INVALID_SOCKET, "WSASocketA should have succeeded\n");

    /* test invalid parameters */
    SetLastError(0xdeadbeef);
    ok(WSADuplicateSocketA(0, 0, NULL), "WSADuplicateSocketA should have failed\n");
    err = WSAGetLastError();
    ok(err == WSAENOTSOCK, "expected 10038, received %d\n", err);

    SetLastError(0xdeadbeef);
    ok(WSADuplicateSocketA(source, 0, NULL),
       "WSADuplicateSocketA should have failed\n");
    err = WSAGetLastError();
    ok(err == WSAEINVAL, "expected 10022, received %d\n", err);

    SetLastError(0xdeadbeef);
    ok(WSADuplicateSocketA(source, ~0, &info),
       "WSADuplicateSocketA should have failed\n");
    err = WSAGetLastError();
    ok(err == WSAEINVAL, "expected 10022, received %d\n", err);

    SetLastError(0xdeadbeef);
    ok(WSADuplicateSocketA(0, GetCurrentProcessId(), &info),
       "WSADuplicateSocketA should have failed\n");
    err = WSAGetLastError();
    ok(err == WSAENOTSOCK, "expected 10038, received %d\n", err);

    SetLastError(0xdeadbeef);
    ok(WSADuplicateSocketA(source, GetCurrentProcessId(), NULL),
       "WSADuplicateSocketA should have failed\n");
    err = WSAGetLastError();
    ok(err == WSAEFAULT, "expected 10014, received %d\n", err);

    /* test returned structure */
    memset(&info, 0, sizeof(info));
    ok(!WSADuplicateSocketA(source, GetCurrentProcessId(), &info),
       "WSADuplicateSocketA should have worked\n");

    ok(info.iProtocol == IPPROTO_TCP, "expected protocol %d, received %d\n",
       IPPROTO_TCP, info.iProtocol);
    ok(info.iAddressFamily == AF_INET, "expected family %d, received %d\n",
       AF_INET, info.iProtocol);
    ok(info.iSocketType == SOCK_STREAM, "expected type %d, received %d\n",
       SOCK_STREAM, info.iSocketType);

    dupsock = WSASocketA(0, 0, 0, &info, 0, 0);
    ok(dupsock != INVALID_SOCKET, "WSASocketA should have succeeded\n");

    closesocket(dupsock);
    closesocket(source);

    /* create a socket, bind it, duplicate it then send data on source and
     * receive in the duplicated socket */
    source = WSASocketA(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, 0);
    ok(source != INVALID_SOCKET, "WSASocketA should have succeeded\n");

    memset(&info, 0, sizeof(info));
    ok(!WSADuplicateSocketA(source, GetCurrentProcessId(), &info),
       "WSADuplicateSocketA should have worked\n");

    ok(info.iProtocol == IPPROTO_UDP, "expected protocol %d, received %d\n",
       IPPROTO_UDP, info.iProtocol);
    ok(info.iAddressFamily == AF_INET, "expected family %d, received %d\n",
       AF_INET, info.iProtocol);
    ok(info.iSocketType == SOCK_DGRAM, "expected type %d, received %d\n",
       SOCK_DGRAM, info.iSocketType);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    ok(!bind(source, (struct sockaddr*)&addr, sizeof(addr)),
       "bind should have worked\n");

    /* read address to find out the port number to be used in sendto */
    memset(&addr, 0, sizeof(addr));
    addrsize = sizeof(addr);
    ok(!getsockname(source, (struct sockaddr *) &addr, &addrsize),
       "getsockname should have worked\n");
    ok(addr.sin_port, "socket port should be != 0\n");

    dupsock = WSASocketA(0, 0, 0, &info, 0, 0);
    ok(dupsock != INVALID_SOCKET, "WSASocketA should have succeeded\n");

    size = sizeof(int);
    ret = getsockopt(dupsock, SOL_SOCKET, SO_TYPE, (char *) &socktype, &size);
    ok(!ret, "getsockopt failed with %d\n", WSAGetLastError());
    ok(socktype == SOCK_DGRAM, "Wrong socket type, expected %d received %d\n",
       SOCK_DGRAM, socktype);

    set_blocking(source, TRUE);

    /* send data on source socket */
    addrsize = sizeof(addr);
    size = sendto(source, teststr, sizeof(teststr), 0, (struct sockaddr *) &addr, addrsize);
    ok(size == sizeof(teststr), "got %d (err %d)\n", size, WSAGetLastError());

    /* receive on duplicated socket */
    addrsize = sizeof(addr);
    memset(buffer, 0, sizeof(buffer));
    size = recvfrom(dupsock, buffer, sizeof(teststr), 0, (struct sockaddr *) &addr, &addrsize);
    ok(size == sizeof(teststr), "got %d (err %d)\n", size, WSAGetLastError());
    buffer[sizeof(teststr) - 1] = 0;
    ok(!strcmp(buffer, teststr), "expected '%s', received '%s'\n", teststr, buffer);

    closesocket(dupsock);
    closesocket(source);

    /* show that the source socket need to be bound before the duplicated
     * socket is created */
    source = WSASocketA(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, 0);
    ok(source != INVALID_SOCKET, "WSASocketA should have succeeded\n");

    memset(&info, 0, sizeof(info));
    ok(!WSADuplicateSocketA(source, GetCurrentProcessId(), &info),
       "WSADuplicateSocketA should have worked\n");

    dupsock = WSASocketA(0, 0, 0, &info, 0, 0);
    ok(dupsock != INVALID_SOCKET, "WSASocketA should have succeeded\n");

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    ok(!bind(source, (struct sockaddr*)&addr, sizeof(addr)),
       "bind should have worked\n");

    /* read address to find out the port number to be used in sendto */
    memset(&addr, 0, sizeof(addr));
    addrsize = sizeof(addr);
    ok(!getsockname(source, (struct sockaddr *) &addr, &addrsize),
       "getsockname should have worked\n");
    ok(addr.sin_port, "socket port should be != 0\n");

    set_blocking(source, TRUE);

    addrsize = sizeof(addr);
    size = sendto(source, teststr, sizeof(teststr), 0, (struct sockaddr *) &addr, addrsize);
    ok(size == sizeof(teststr), "got %d (err %d)\n", size, WSAGetLastError());

    SetLastError(0xdeadbeef);
    addrsize = sizeof(addr);
    memset(buffer, 0, sizeof(buffer));
    todo_wine {
    ok(recvfrom(dupsock, buffer, sizeof(teststr), 0, (struct sockaddr *) &addr, &addrsize) == -1,
       "recvfrom should have failed\n");
    err = WSAGetLastError();
    ok(err == WSAEINVAL, "expected 10022, received %d\n", err);
    }

    closesocket(dupsock);
    closesocket(source);
}

static void test_WSAEnumNetworkEvents(void)
{
    SOCKET s, s2;
    int sock_type[] = {SOCK_STREAM, SOCK_DGRAM, SOCK_STREAM}, i, j, k, l;
    struct sockaddr_in address;
    HANDLE event;
    WSANETWORKEVENTS net_events;

    memset(&address, 0, sizeof(address));
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_family = AF_INET;

    /* This test follows the steps from bugs 10204 and 24946 */
    for (l = 0; l < 2; l++)
    {
        for (i = 0; i < ARRAY_SIZE(sock_type); i++)
        {
            if (i == 2)
                tcp_socketpair(&s, &s2);
            else
            {
                s = socket(AF_INET, sock_type[i], 0);
                ok (s != SOCKET_ERROR, "Test[%d]: failed to create socket\n", i);
                ok (!bind(s, (struct sockaddr*) &address, sizeof(address)), "Test[%d]: bind failed\n", i);
            }
            event = WSACreateEvent();
            ok (event != NULL, "Test[%d]: failed to create event\n", i);
            for (j = 0; j < 5; j++) /* Repeat sometimes and the result must be the same */
            {
                /* When the TCP socket is not connected NO events will be returned.
                 * When connected and no data pending it will get the write event.
                 * UDP sockets don't have connections so as soon as they are bound
                 * they can read/write data. Since nobody is sendind us data only
                 * the write event will be returned and ONLY once.
                 */
                ok (!WSAEventSelect(s, event, FD_READ | FD_WRITE), "Test[%d]: WSAEventSelect failed\n", i);
                memset(&net_events, 0xAB, sizeof(net_events));
                ok (!WSAEnumNetworkEvents(s, l == 0 ? event : NULL, &net_events),
                    "Test[%d]: WSAEnumNetworkEvents failed\n", i);
                if (i >= 1 && j == 0) /* FD_WRITE is SET on first try for UDP and connected TCP */
                {
                    ok (net_events.lNetworkEvents == FD_WRITE, "Test[%d]: expected 2, got %d\n",
                        i, net_events.lNetworkEvents);
                }
                else
                {
                    todo_wine_if (i != 0) /* Remove when fixed */
                        ok (net_events.lNetworkEvents == 0, "Test[%d]: expected 0, got %d\n",
                            i, net_events.lNetworkEvents);
                }
                for (k = 0; k < FD_MAX_EVENTS; k++)
                {
                    if (net_events.lNetworkEvents & (1 << k))
                    {
                        ok (net_events.iErrorCode[k] == 0x0, "Test[%d][%d]: expected 0x0, got 0x%x\n",
                            i, k, net_events.iErrorCode[k]);
                    }
                    else
                    {
                        /* Bits that are not set in lNetworkEvents MUST not be changed */
                        ok (net_events.iErrorCode[k] == 0xABABABAB, "Test[%d][%d]: expected 0xABABABAB, got 0x%x\n",
                            i, k, net_events.iErrorCode[k]);
                    }
                }
            }
            closesocket(s);
            WSACloseEvent(event);
            if (i == 2) closesocket(s2);
        }
    }
}

static DWORD WINAPI SelectReadThread(void *param)
{
    select_thread_params *par = param;
    fd_set readfds;
    int ret;
    struct sockaddr_in addr;
    struct timeval select_timeout;

    FD_ZERO(&readfds);
    FD_SET(par->s, &readfds);
    select_timeout.tv_sec=5;
    select_timeout.tv_usec=0;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(SERVERIP);
    addr.sin_port = htons(SERVERPORT);

    do_bind(par->s, (struct sockaddr *)&addr, sizeof(addr));
    wsa_ok(listen(par->s, SOMAXCONN ), 0 ==, "SelectReadThread (%x): listen failed: %d\n");

    SetEvent(server_ready);
    ret = select(par->s+1, &readfds, NULL, NULL, &select_timeout);
    par->ReadKilled = (ret == 1);

    return 0;
}

static DWORD WINAPI SelectCloseThread(void *param)
{
    SOCKET s = *(SOCKET*)param;
    Sleep(500);
    closesocket(s);
    return 0;
}

static void test_errors(void)
{
    SOCKET sock;
    SOCKADDR_IN  SockAddr;
    int ret, err;

    WSASetLastError(NO_ERROR);
    sock = socket(PF_INET, SOCK_STREAM, 0);
    ok( (sock != INVALID_SOCKET), "socket failed unexpectedly: %d\n", WSAGetLastError() );
    memset(&SockAddr, 0, sizeof(SockAddr));
    SockAddr.sin_family = AF_INET;
    SockAddr.sin_port = htons(6924);
    SockAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    ret = connect(sock, (PSOCKADDR)&SockAddr, sizeof(SockAddr));
    ok( (ret == SOCKET_ERROR), "expected SOCKET_ERROR, got: %d\n", ret );
    if (ret == SOCKET_ERROR)
    {
        err = WSAGetLastError();
        ok( (err == WSAECONNREFUSED), "expected WSAECONNREFUSED, got: %d\n", err );
    }

    {
        TIMEVAL timeval;
        fd_set set = {1, {sock}};

        timeval.tv_sec = 0;
        timeval.tv_usec = 50000;

        ret = select(1, NULL, &set, NULL, &timeval);
        ok( (ret == 0), "expected 0 (timeout), got: %d\n", ret );
    }

    ret = closesocket(sock);
    ok ( (ret == 0), "closesocket failed unexpectedly: %d\n", WSAGetLastError());
}

static void test_listen(void)
{
    SOCKET fdA, fdB;
    int ret, acceptc, olen = sizeof(acceptc);
    struct sockaddr_in address;

    memset(&address, 0, sizeof(address));
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    address.sin_family = AF_INET;
    address.sin_port = htons(SERVERPORT);

    /* invalid socket tests */
    SetLastError(0xdeadbeef);
    ok ((listen(0, 0) == SOCKET_ERROR), "listen did not fail\n");
    ret = WSAGetLastError();
    ok (ret == WSAENOTSOCK, "expected 10038, received %d\n", ret);

    SetLastError(0xdeadbeef);
    ok ((listen(0xdeadbeef, 0) == SOCKET_ERROR), "listen did not fail\n");
    ret = WSAGetLastError();
    ok (ret == WSAENOTSOCK, "expected 10038, received %d\n", ret);

    /* tcp tests */
    fdA = socket(AF_INET, SOCK_STREAM, 0);
    ok ((fdA != INVALID_SOCKET), "socket failed unexpectedly: %d\n", WSAGetLastError() );

    fdB = socket(AF_INET, SOCK_STREAM, 0);
    ok ((fdB != INVALID_SOCKET), "socket failed unexpectedly: %d\n", WSAGetLastError() );

    SetLastError(0xdeadbeef);
    ok ((listen(fdA, -2) == SOCKET_ERROR), "listen did not fail\n");
    ret = WSAGetLastError();
    ok (ret == WSAEINVAL, "expected 10022, received %d\n", ret);

    SetLastError(0xdeadbeef);
    ok ((listen(fdA, 1) == SOCKET_ERROR), "listen did not fail\n");
    ret = WSAGetLastError();
    ok (ret == WSAEINVAL, "expected 10022, received %d\n", ret);

    SetLastError(0xdeadbeef);
    ok ((listen(fdA, SOMAXCONN) == SOCKET_ERROR), "listen did not fail\n");
    ret = WSAGetLastError();
    ok (ret == WSAEINVAL, "expected 10022, received %d\n", ret);

    ok (!bind(fdA, (struct sockaddr*) &address, sizeof(address)), "bind failed\n");

    SetLastError(0xdeadbeef);
    ok (bind(fdB, (struct sockaddr*) &address, sizeof(address)), "bind should have failed\n");
    ok (ret == WSAEINVAL, "expected 10022, received %d\n", ret);

    acceptc = 0xdead;
    ret = getsockopt(fdA, SOL_SOCKET, SO_ACCEPTCONN, (char*)&acceptc, &olen);
    ok (!ret, "getsockopt failed\n");
    ok (acceptc == 0, "SO_ACCEPTCONN should be 0, received %d\n", acceptc);

    ok (!listen(fdA, 0), "listen failed\n");
    ok (!listen(fdA, SOMAXCONN), "double listen failed\n");

    acceptc = 0xdead;
    ret = getsockopt(fdA, SOL_SOCKET, SO_ACCEPTCONN, (char*)&acceptc, &olen);
    ok (!ret, "getsockopt failed\n");
    ok (acceptc == 1, "SO_ACCEPTCONN should be 1, received %d\n", acceptc);

    SetLastError(0xdeadbeef);
    ok ((listen(fdB, SOMAXCONN) == SOCKET_ERROR), "listen did not fail\n");
    ret = WSAGetLastError();
    ok (ret == WSAEINVAL, "expected 10022, received %d\n", ret);

    ret = closesocket(fdB);
    ok (ret == 0, "closesocket failed unexpectedly: %d\n", ret);

    fdB = socket(AF_INET, SOCK_STREAM, 0);
    ok ((fdB != INVALID_SOCKET), "socket failed unexpectedly: %d\n", WSAGetLastError() );

    SetLastError(0xdeadbeef);
    ok (bind(fdB, (struct sockaddr*) &address, sizeof(address)), "bind should have failed\n");
    ret = WSAGetLastError();
    ok (ret == WSAEADDRINUSE, "expected 10048, received %d\n", ret);

    ret = closesocket(fdA);
    ok (ret == 0, "closesocket failed unexpectedly: %d\n", ret);
    ret = closesocket(fdB);
    ok (ret == 0, "closesocket failed unexpectedly: %d\n", ret);
}

#define FD_ZERO_ALL() { FD_ZERO(&readfds); FD_ZERO(&writefds); FD_ZERO(&exceptfds); }
#define FD_SET_ALL(s) { FD_SET(s, &readfds); FD_SET(s, &writefds); FD_SET(s, &exceptfds); }
static void test_select(void)
{
    static char tmp_buf[1024];

    SOCKET fdListen, fdRead, fdWrite;
    fd_set readfds, writefds, exceptfds;
    unsigned int maxfd;
    int ret, len;
    char buffer;
    struct timeval select_timeout;
    struct sockaddr_in address;
    select_thread_params thread_params;
    HANDLE thread_handle;
    DWORD ticks, id;

    fdRead = socket(AF_INET, SOCK_STREAM, 0);
    ok( (fdRead != INVALID_SOCKET), "socket failed unexpectedly: %d\n", WSAGetLastError() );
    fdWrite = socket(AF_INET, SOCK_STREAM, 0);
    ok( (fdWrite != INVALID_SOCKET), "socket failed unexpectedly: %d\n", WSAGetLastError() );

    maxfd = fdRead;
    if (fdWrite > maxfd)
        maxfd = fdWrite;

    FD_ZERO_ALL();
    FD_SET_ALL(fdRead);
    FD_SET_ALL(fdWrite);
    select_timeout.tv_sec=0;
    select_timeout.tv_usec=0;

    ticks = GetTickCount();
    ret = select(maxfd+1, &readfds, &writefds, &exceptfds, &select_timeout);
    ticks = GetTickCount() - ticks;
    ok(ret == 0, "select should not return any socket handles\n");
    ok(ticks < 10, "select was blocking for %u ms, expected < 10 ms\n", ticks);
    ok(!FD_ISSET(fdRead, &readfds), "FD should not be set\n");
    ok(!FD_ISSET(fdWrite, &writefds), "FD should not be set\n");
    ok(!FD_ISSET(fdRead, &exceptfds), "FD should not be set\n");
    ok(!FD_ISSET(fdWrite, &exceptfds), "FD should not be set\n");
 
    FD_ZERO_ALL();
    FD_SET_ALL(fdRead);
    FD_SET_ALL(fdWrite);
    select_timeout.tv_sec=0;
    select_timeout.tv_usec=500;

    ret = select(maxfd+1, &readfds, &writefds, &exceptfds, &select_timeout);
    ok(ret == 0, "select should not return any socket handles\n");
    ok(!FD_ISSET(fdRead, &readfds), "FD should not be set\n");
    ok(!FD_ISSET(fdWrite, &writefds), "FD should not be set\n");
    ok(!FD_ISSET(fdRead, &exceptfds), "FD should not be set\n");
    ok(!FD_ISSET(fdWrite, &exceptfds), "FD should not be set\n");

    ok ((listen(fdWrite, SOMAXCONN) == SOCKET_ERROR), "listen did not fail\n");
    ret = closesocket(fdWrite);
    ok ( (ret == 0), "closesocket failed unexpectedly: %d\n", ret);

    thread_params.s = fdRead;
    thread_params.ReadKilled = FALSE;
    server_ready = CreateEventA(NULL, TRUE, FALSE, NULL);
    thread_handle = CreateThread (NULL, 0, SelectReadThread, &thread_params, 0, &id );
    ok ( (thread_handle != NULL), "CreateThread failed unexpectedly: %d\n", GetLastError());

    WaitForSingleObject (server_ready, INFINITE);
    Sleep(200);
    ret = closesocket(fdRead);
    ok ( (ret == 0), "closesocket failed unexpectedly: %d\n", ret);

    WaitForSingleObject (thread_handle, 1000);
    ok ( thread_params.ReadKilled, "closesocket did not wake up select\n");
    ret = recv(fdRead, &buffer, 1, MSG_PEEK);
    ok( (ret == -1), "peek at closed socket expected -1 got %d\n", ret);

    /* Test selecting invalid handles */
    FD_ZERO_ALL();

    SetLastError(0);
    ret = select(maxfd+1, 0, 0, 0, &select_timeout);
    ok ( (ret == SOCKET_ERROR), "expected SOCKET_ERROR, got %i\n", ret);
    ok ( WSAGetLastError() == WSAEINVAL, "expected WSAEINVAL, got %i\n", WSAGetLastError());

    SetLastError(0);
    ret = select(maxfd+1, &readfds, &writefds, &exceptfds, &select_timeout);
    ok ( (ret == SOCKET_ERROR), "expected SOCKET_ERROR, got %i\n", ret);
    ok ( WSAGetLastError() == WSAEINVAL, "expected WSAEINVAL, got %i\n", WSAGetLastError());

    FD_SET(INVALID_SOCKET, &readfds);
    SetLastError(0);
    ret = select(maxfd+1, &readfds, &writefds, &exceptfds, &select_timeout);
    ok ( (ret == SOCKET_ERROR), "expected SOCKET_ERROR, got %i\n", ret);
    ok ( WSAGetLastError() == WSAENOTSOCK, "expected WSAENOTSOCK, got %i\n", WSAGetLastError());
    ok ( !FD_ISSET(fdRead, &readfds), "FD should not be set\n");

    FD_ZERO(&readfds);
    FD_SET(INVALID_SOCKET, &writefds);
    SetLastError(0);
    ret = select(maxfd+1, &readfds, &writefds, &exceptfds, &select_timeout);
    ok ( (ret == SOCKET_ERROR), "expected SOCKET_ERROR, got %i\n", ret);
    ok ( WSAGetLastError() == WSAENOTSOCK, "expected WSAENOTSOCK, got %i\n", WSAGetLastError());
    ok ( !FD_ISSET(fdRead, &writefds), "FD should not be set\n");

    FD_ZERO(&writefds);
    FD_SET(INVALID_SOCKET, &exceptfds);
    SetLastError(0);
    ret = select(maxfd+1, &readfds, &writefds, &exceptfds, &select_timeout);
    ok ( (ret == SOCKET_ERROR), "expected SOCKET_ERROR, got %i\n", ret);
    ok ( WSAGetLastError() == WSAENOTSOCK, "expected WSAENOTSOCK, got %i\n", WSAGetLastError());
    ok ( !FD_ISSET(fdRead, &exceptfds), "FD should not be set\n");

    tcp_socketpair(&fdRead, &fdWrite);
    maxfd = fdRead;
    if(fdWrite > maxfd) maxfd = fdWrite;

    FD_ZERO(&readfds);
    FD_SET(fdRead, &readfds);
    ret = select(fdRead+1, &readfds, NULL, NULL, &select_timeout);
    ok(!ret, "select returned %d\n", ret);

    FD_ZERO(&writefds);
    FD_SET(fdWrite, &writefds);
    ret = select(fdWrite+1, NULL, &writefds, NULL, &select_timeout);
    ok(ret == 1, "select returned %d\n", ret);
    ok(FD_ISSET(fdWrite, &writefds), "fdWrite socket is not in the set\n");

    /* tests for overlapping fd_set pointers */
    FD_ZERO(&readfds);
    FD_SET(fdWrite, &readfds);
    ret = select(fdWrite+1, &readfds, &readfds, NULL, &select_timeout);
    ok(ret == 1, "select returned %d\n", ret);
    ok(FD_ISSET(fdWrite, &readfds), "fdWrite socket is not in the set\n");

    FD_ZERO(&readfds);
    FD_SET(fdWrite, &readfds);
    FD_SET(fdRead, &readfds);
    ret = select(maxfd+1, &readfds, &readfds, NULL, &select_timeout);
    ok(ret == 2, "select returned %d\n", ret);
    ok(FD_ISSET(fdWrite, &readfds), "fdWrite socket is not in the set\n");
    ok(FD_ISSET(fdRead, &readfds), "fdRead socket is not in the set\n");

    ok(send(fdWrite, "test", 4, 0) == 4, "failed to send data\n");
    FD_ZERO(&readfds);
    FD_SET(fdRead, &readfds);
    ret = select(fdRead+1, &readfds, NULL, NULL, &select_timeout);
    ok(ret == 1, "select returned %d\n", ret);
    ok(FD_ISSET(fdRead, &readfds), "fdRead socket is not in the set\n");

    FD_ZERO(&readfds);
    FD_SET(fdWrite, &readfds);
    FD_SET(fdRead, &readfds);
    ret = select(maxfd+1, &readfds, &readfds, NULL, &select_timeout);
    ok(ret == 2, "select returned %d\n", ret);
    ok(FD_ISSET(fdWrite, &readfds), "fdWrite socket is not in the set\n");
    ok(FD_ISSET(fdRead, &readfds), "fdRead socket is not in the set\n");

    while(1) {
        FD_ZERO(&writefds);
        FD_SET(fdWrite, &writefds);
        ret = select(fdWrite+1, NULL, &writefds, NULL, &select_timeout);
        if(!ret) break;
        ok(send(fdWrite, tmp_buf, sizeof(tmp_buf), 0) > 0, "failed to send data\n");
    }
    FD_ZERO(&readfds);
    FD_SET(fdWrite, &readfds);
    FD_SET(fdRead, &readfds);
    ret = select(maxfd+1, &readfds, &readfds, NULL, &select_timeout);
    ok(ret == 1, "select returned %d\n", ret);
    ok(!FD_ISSET(fdWrite, &readfds), "fdWrite socket is in the set\n");
    ok(FD_ISSET(fdRead, &readfds), "fdRead socket is not in the set\n");

    ok(send(fdRead, "test", 4, 0) == 4, "failed to send data\n");
    Sleep(100);
    FD_ZERO(&readfds);
    FD_SET(fdWrite, &readfds);
    FD_SET(fdRead, &readfds);
    ret = select(maxfd+1, &readfds, &readfds, NULL, &select_timeout);
    ok(ret == 2, "select returned %d\n", ret);
    ok(FD_ISSET(fdWrite, &readfds), "fdWrite socket is not in the set\n");
    ok(FD_ISSET(fdRead, &readfds), "fdRead socket is not in the set\n");

    closesocket(fdRead);
    closesocket(fdWrite);

    /* select() works in 3 distinct states:
     * - to check if a connection attempt ended with success or error;
     * - to check if a pending connection is waiting for acceptance;
     * - to check for data to read, availability for write and OOB data
     *
     * The tests below ensure that all conditions are tested.
     */
    memset(&address, 0, sizeof(address));
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    address.sin_family = AF_INET;
    len = sizeof(address);
    fdListen = setup_server_socket(&address, &len);
    select_timeout.tv_sec = 1;
    select_timeout.tv_usec = 250000;

    /* When no events are pending select returns 0 with no error */
    FD_ZERO_ALL();
    FD_SET_ALL(fdListen);
    ret = select(0, &readfds, &writefds, &exceptfds, &select_timeout);
    ok(ret == 0, "expected 0, got %d\n", ret);

    /* When a socket is attempting to connect the listening socket receives the read descriptor */
    fdWrite = setup_connector_socket(&address, len, TRUE);
    FD_ZERO_ALL();
    FD_SET_ALL(fdListen);
    ret = select(0, &readfds, &writefds, &exceptfds, &select_timeout);
    ok(ret == 1, "expected 1, got %d\n", ret);
    ok(FD_ISSET(fdListen, &readfds), "fdListen socket is not in the set\n");
    len = sizeof(address);
    fdRead = accept(fdListen, (struct sockaddr*) &address, &len);
    ok(fdRead != INVALID_SOCKET, "expected a valid socket\n");

    /* The connector is signaled through the write descriptor */
    FD_ZERO_ALL();
    FD_SET_ALL(fdListen);
    FD_SET_ALL(fdRead);
    FD_SET_ALL(fdWrite);
    ret = select(0, &readfds, &writefds, &exceptfds, &select_timeout);
    ok(ret == 2, "expected 2, got %d\n", ret);
    ok(FD_ISSET(fdWrite, &writefds), "fdWrite socket is not in the set\n");
    ok(FD_ISSET(fdRead, &writefds), "fdRead socket is not in the set\n");
    len = sizeof(id);
    id = 0xdeadbeef;
    ret = getsockopt(fdWrite, SOL_SOCKET, SO_ERROR, (char*)&id, &len);
    ok(!ret, "getsockopt failed with %d\n", WSAGetLastError());
    ok(id == 0, "expected 0, got %d\n", id);

    /* When data is received the receiver gets the read descriptor */
    ret = send(fdWrite, "1234", 4, 0);
    ok(ret == 4, "expected 4, got %d\n", ret);
    FD_ZERO_ALL();
    FD_SET_ALL(fdListen);
    FD_SET(fdRead, &readfds);
    FD_SET(fdRead, &exceptfds);
    ret = select(0, &readfds, &writefds, &exceptfds, &select_timeout);
    ok(ret == 1, "expected 1, got %d\n", ret);
    ok(FD_ISSET(fdRead, &readfds), "fdRead socket is not in the set\n");
    ret = recv(fdRead, tmp_buf, sizeof(tmp_buf), 0);
    ok(ret == 4, "expected 4, got %d\n", ret);
    ok(!strcmp(tmp_buf, "1234"), "data received differs from sent\n");

    /* When OOB data is received the socket is set in the except descriptor */
    ret = send(fdWrite, "A", 1, MSG_OOB);
    ok(ret == 1, "expected 1, got %d\n", ret);
    FD_ZERO_ALL();
    FD_SET_ALL(fdListen);
    FD_SET(fdRead, &readfds);
    FD_SET(fdRead, &exceptfds);
    ret = select(0, &readfds, &writefds, &exceptfds, &select_timeout);
    ok(ret == 1, "expected 1, got %d\n", ret);
    ok(FD_ISSET(fdRead, &exceptfds), "fdRead socket is not in the set\n");
    tmp_buf[0] = 0xAF;
    ret = recv(fdRead, tmp_buf, sizeof(tmp_buf), MSG_OOB);
    ok(ret == 1, "expected 1, got %d\n", ret);
    ok(tmp_buf[0] == 'A', "expected 'A', got 0x%02X\n", tmp_buf[0]);

    /* If the socket is OOBINLINED it will not receive the OOB in except fds */
    ret = 1;
    ret = setsockopt(fdRead, SOL_SOCKET, SO_OOBINLINE, (char*) &ret, sizeof(ret));
    ok(ret == 0, "expected 0, got %d\n", ret);
    ret = send(fdWrite, "A", 1, MSG_OOB);
    ok(ret == 1, "expected 1, got %d\n", ret);
    FD_ZERO_ALL();
    FD_SET_ALL(fdListen);
    FD_SET(fdRead, &readfds);
    FD_SET(fdRead, &exceptfds);
    ret = select(0, &readfds, &writefds, &exceptfds, &select_timeout);
    ok(ret == 1, "expected 1, got %d\n", ret);
    ok(FD_ISSET(fdRead, &readfds), "fdRead socket is not in the set\n");
    tmp_buf[0] = 0xAF;
    SetLastError(0xdeadbeef);
    ret = recv(fdRead, tmp_buf, sizeof(tmp_buf), MSG_OOB);
    ok(ret == SOCKET_ERROR, "expected SOCKET_ERROR, got %d\n", ret);
    ok(GetLastError() == WSAEINVAL, "expected 10022, got %d\n", GetLastError());
    ret = recv(fdRead, tmp_buf, sizeof(tmp_buf), 0);
    ok(ret == 1, "expected 1, got %d\n", ret);
    ok(tmp_buf[0] == 'A', "expected 'A', got 0x%02X\n", tmp_buf[0]);

    /* When the connection is closed the socket is set in the read descriptor */
    ret = closesocket(fdRead);
    ok(ret == 0, "expected 0, got %d\n", ret);
    FD_ZERO_ALL();
    FD_SET_ALL(fdListen);
    FD_SET(fdWrite, &readfds);
    ret = select(0, &readfds, &writefds, &exceptfds, &select_timeout);
    ok(ret == 1, "expected 1, got %d\n", ret);
    ok(FD_ISSET(fdWrite, &readfds), "fdWrite socket is not in the set\n");
    ret = recv(fdWrite, tmp_buf, sizeof(tmp_buf), 0);
    ok(ret == 0, "expected 0, got %d\n", ret);
    ret = closesocket(fdWrite);
    ok(ret == 0, "expected 0, got %d\n", ret);
    ret = closesocket(fdListen);
    ok(ret == 0, "expected 0, got %d\n", ret);

    /* w10pro64 sometimes takes over 2 seconds for an error to be reported. */
    if (winetest_interactive)
    {
        len = sizeof(address);
        fdWrite = setup_connector_socket(&address, len, TRUE);
        FD_ZERO_ALL();
        FD_SET(fdWrite, &writefds);
        FD_SET(fdWrite, &exceptfds);
        select_timeout.tv_sec = 10;
        ret = select(0, &readfds, &writefds, &exceptfds, &select_timeout);
        ok(ret == 1, "expected 1, got %d\n", ret);
        len = sizeof(id);
        id = 0xdeadbeef;
        ret = getsockopt(fdWrite, SOL_SOCKET, SO_ERROR, (char*)&id, &len);
        ok(!ret, "getsockopt failed with %d\n", WSAGetLastError());
        ok(id == WSAECONNREFUSED, "expected 10061, got %d\n", id);
        ok(FD_ISSET(fdWrite, &exceptfds), "fdWrite socket is not in the set\n");
        ok(select_timeout.tv_usec == 250000, "select timeout should not have changed\n");
        closesocket(fdWrite);
    }

    /* Try select() on a closed socket after connection */
    tcp_socketpair(&fdRead, &fdWrite);
    closesocket(fdRead);
    FD_ZERO_ALL();
    FD_SET_ALL(fdWrite);
    FD_SET_ALL(fdRead);
    SetLastError(0xdeadbeef);
    ret = select(0, &readfds, NULL, &exceptfds, &select_timeout);
    ok(ret == SOCKET_ERROR, "expected -1, got %d\n", ret);
    ok(GetLastError() == WSAENOTSOCK, "got %d\n", GetLastError());
    /* descriptor sets are unchanged */
    ok(readfds.fd_count == 2, "expected 2, got %d\n", readfds.fd_count);
    ok(exceptfds.fd_count == 2, "expected 2, got %d\n", exceptfds.fd_count);
    closesocket(fdWrite);

    /* Close the socket currently being selected in a thread - bug 38399 */
    tcp_socketpair(&fdRead, &fdWrite);
    thread_handle = CreateThread(NULL, 0, SelectCloseThread, &fdWrite, 0, &id);
    ok(thread_handle != NULL, "CreateThread failed unexpectedly: %d\n", GetLastError());
    FD_ZERO_ALL();
    FD_SET_ALL(fdWrite);
    ret = select(0, &readfds, NULL, &exceptfds, &select_timeout);
    ok(ret == 1, "expected 1, got %d\n", ret);
    ok(FD_ISSET(fdWrite, &readfds), "fdWrite socket is not in the set\n");
    WaitForSingleObject (thread_handle, 1000);
    closesocket(fdRead);
    /* test again with only the except descriptor */
    tcp_socketpair(&fdRead, &fdWrite);
    thread_handle = CreateThread(NULL, 0, SelectCloseThread, &fdWrite, 0, &id);
    ok(thread_handle != NULL, "CreateThread failed unexpectedly: %d\n", GetLastError());
    FD_ZERO_ALL();
    FD_SET(fdWrite, &exceptfds);
    SetLastError(0xdeadbeef);
    ret = select(0, NULL, NULL, &exceptfds, &select_timeout);
todo_wine
    ok(ret == SOCKET_ERROR, "expected -1, got %d\n", ret);
    ok(GetLastError() == WSAENOTSOCK, "got %d\n", GetLastError());
    WaitForSingleObject (thread_handle, 1000);
    closesocket(fdRead);

    /* test UDP behavior of unbound sockets */
    select_timeout.tv_sec = 0;
    select_timeout.tv_usec = 250000;
    fdWrite = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ok(fdWrite != INVALID_SOCKET, "socket call failed\n");
    FD_ZERO_ALL();
    FD_SET_ALL(fdWrite);
    ret = select(0, &readfds, &writefds, &exceptfds, &select_timeout);
    ok(ret == 1, "expected 1, got %d\n", ret);
    ok(FD_ISSET(fdWrite, &writefds), "fdWrite socket is not in the set\n");
    closesocket(fdWrite);
}
#undef FD_SET_ALL
#undef FD_ZERO_ALL

static DWORD WINAPI AcceptKillThread(void *param)
{
    select_thread_params *par = param;
    struct sockaddr_in address;
    int len = sizeof(address);
    SOCKET client_socket;

    SetEvent(server_ready);
    client_socket = accept(par->s, (struct sockaddr*) &address, &len);
    if (client_socket != INVALID_SOCKET)
        closesocket(client_socket);
    par->ReadKilled = (client_socket == INVALID_SOCKET);
    return 0;
}


static int CALLBACK AlwaysDeferConditionFunc(LPWSABUF lpCallerId, LPWSABUF lpCallerData, LPQOS pQos,
                                             LPQOS lpGQOS, LPWSABUF lpCalleeId, LPWSABUF lpCalleeData,
                                             GROUP *g, DWORD_PTR dwCallbackData)
{
    return CF_DEFER;
}

static SOCKET setup_server_socket(struct sockaddr_in *addr, int *len)
{
    int ret, val;
    SOCKET server_socket;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    ok(server_socket != INVALID_SOCKET, "failed to bind socket, error %u\n", WSAGetLastError());

    val = 1;
    ret = setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&val, sizeof(val));
    ok(!ret, "failed to set SO_REUSEADDR, error %u\n", WSAGetLastError());

    ret = bind(server_socket, (struct sockaddr *)addr, *len);
    ok(!ret, "failed to bind socket, error %u\n", WSAGetLastError());

    ret = getsockname(server_socket, (struct sockaddr *)addr, len);
    ok(!ret, "failed to get address, error %u\n", WSAGetLastError());

    ret = listen(server_socket, 5);
    ok(!ret, "failed to listen, error %u\n", WSAGetLastError());

    return server_socket;
}

static SOCKET setup_connector_socket(struct sockaddr_in *addr, int len, BOOL nonblock)
{
    int ret;
    SOCKET connector;

    connector = socket(AF_INET, SOCK_STREAM, 0);
    ok(connector != INVALID_SOCKET, "failed to create connector socket %d\n", WSAGetLastError());

    if (nonblock)
        set_blocking(connector, !nonblock);

    ret = connect(connector, (struct sockaddr *)addr, len);
    if (!nonblock)
        ok(!ret, "connecting to accepting socket failed %d\n", WSAGetLastError());
    else if (ret == SOCKET_ERROR)
        ok(WSAGetLastError() == WSAEWOULDBLOCK, "got error %u\n", WSAGetLastError());

    return connector;
}

static void test_accept(void)
{
    int ret;
    SOCKET server_socket, accepted = INVALID_SOCKET, connector;
    struct sockaddr_in address;
    SOCKADDR_STORAGE ss, ss_empty;
    int socklen;
    select_thread_params thread_params;
    HANDLE thread_handle = NULL;
    DWORD id;

    memset(&address, 0, sizeof(address));
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    address.sin_family = AF_INET;

    socklen = sizeof(address);
    server_socket = setup_server_socket(&address, &socklen);

    connector = setup_connector_socket(&address, socklen, FALSE);
    if (connector == INVALID_SOCKET) goto done;

    accepted = WSAAccept(server_socket, NULL, NULL, AlwaysDeferConditionFunc, 0);
    ok(accepted == INVALID_SOCKET && WSAGetLastError() == WSATRY_AGAIN, "Failed to defer connection, %d\n", WSAGetLastError());

    accepted = accept(server_socket, NULL, 0);
    ok(accepted != INVALID_SOCKET, "Failed to accept deferred connection, error %d\n", WSAGetLastError());

    server_ready = CreateEventA(NULL, TRUE, FALSE, NULL);

    thread_params.s = server_socket;
    thread_params.ReadKilled = FALSE;
    thread_handle = CreateThread(NULL, 0, AcceptKillThread, &thread_params, 0, &id);

    WaitForSingleObject(server_ready, INFINITE);
    Sleep(200);
    ret = closesocket(server_socket);
    ok(!ret, "failed to close socket, error %u\n", WSAGetLastError());

    WaitForSingleObject(thread_handle, 1000);
    ok(thread_params.ReadKilled, "closesocket did not wake up accept\n");

    closesocket(accepted);
    closesocket(connector);
    accepted = connector = INVALID_SOCKET;

    socklen = sizeof(address);
    server_socket = setup_server_socket(&address, &socklen);

    connector = setup_connector_socket(&address, socklen, FALSE);
    if (connector == INVALID_SOCKET) goto done;

    socklen = 0;
    accepted = WSAAccept(server_socket, (struct sockaddr *)&ss, &socklen, NULL, 0);
    ok(accepted == INVALID_SOCKET && WSAGetLastError() == WSAEFAULT, "got %d\n", WSAGetLastError());
    ok(!socklen, "got %d\n", socklen);
    closesocket(connector);
    connector = INVALID_SOCKET;

    socklen = sizeof(address);
    connector = setup_connector_socket(&address, socklen, FALSE);
    if (connector == INVALID_SOCKET) goto done;

    accepted = WSAAccept(server_socket, NULL, NULL, NULL, 0);
    ok(accepted != INVALID_SOCKET, "Failed to accept connection, %d\n", WSAGetLastError());
    closesocket(accepted);
    closesocket(connector);
    accepted = connector = INVALID_SOCKET;

    socklen = sizeof(address);
    connector = setup_connector_socket(&address, socklen, FALSE);
    if (connector == INVALID_SOCKET) goto done;

    socklen = sizeof(ss);
    memset(&ss, 0, sizeof(ss));
    accepted = WSAAccept(server_socket, (struct sockaddr *)&ss, &socklen, NULL, 0);
    ok(accepted != INVALID_SOCKET, "Failed to accept connection, %d\n", WSAGetLastError());
    ok(socklen != sizeof(ss), "unexpected length\n");
    ok(ss.ss_family, "family not set\n");
    closesocket(accepted);
    closesocket(connector);
    accepted = connector = INVALID_SOCKET;

    socklen = sizeof(address);
    connector = setup_connector_socket(&address, socklen, FALSE);
    if (connector == INVALID_SOCKET) goto done;

    socklen = 0;
    accepted = accept(server_socket, (struct sockaddr *)&ss, &socklen);
    ok(accepted == INVALID_SOCKET && WSAGetLastError() == WSAEFAULT, "got %d\n", WSAGetLastError());
    ok(!socklen, "got %d\n", socklen);
    closesocket(connector);
    accepted = connector = INVALID_SOCKET;

    socklen = sizeof(address);
    connector = setup_connector_socket(&address, socklen, FALSE);
    if (connector == INVALID_SOCKET) goto done;

    accepted = accept(server_socket, NULL, NULL);
    ok(accepted != INVALID_SOCKET, "Failed to accept connection, %d\n", WSAGetLastError());
    closesocket(accepted);
    closesocket(connector);
    accepted = connector = INVALID_SOCKET;

    socklen = sizeof(address);
    connector = setup_connector_socket(&address, socklen, FALSE);
    if (connector == INVALID_SOCKET) goto done;

    socklen = sizeof(ss);
    memset(&ss, 0, sizeof(ss));
    accepted = accept(server_socket, (struct sockaddr *)&ss, &socklen);
    ok(accepted != INVALID_SOCKET, "Failed to accept connection, %d\n", WSAGetLastError());
    ok(socklen != sizeof(ss), "unexpected length\n");
    ok(ss.ss_family, "family not set\n");
    closesocket(accepted);
    closesocket(connector);
    accepted = connector = INVALID_SOCKET;

    socklen = sizeof(address);
    connector = setup_connector_socket(&address, socklen, FALSE);
    if (connector == INVALID_SOCKET) goto done;

    memset(&ss, 0, sizeof(ss));
    memset(&ss_empty, 0, sizeof(ss_empty));
    accepted = accept(server_socket, (struct sockaddr *)&ss, NULL);
    ok(accepted != INVALID_SOCKET, "Failed to accept connection, %d\n", WSAGetLastError());
    ok(!memcmp(&ss, &ss_empty, sizeof(ss)), "structure is different\n");

done:
    if (accepted != INVALID_SOCKET)
        closesocket(accepted);
    if (connector != INVALID_SOCKET)
        closesocket(connector);
    if (thread_handle != NULL)
        CloseHandle(thread_handle);
    if (server_ready != INVALID_HANDLE_VALUE)
        CloseHandle(server_ready);
    if (server_socket != INVALID_SOCKET)
        closesocket(server_socket);
}

static void test_extendedSocketOptions(void)
{
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in sa;
    int sa_len = sizeof(struct sockaddr_in);
    int optval, optlen = sizeof(int), ret;
    BOOL bool_opt_val;
    LINGER linger_val;

    ret = WSAStartup(MAKEWORD(2,0), &wsa);
    ok(!ret, "failed to startup, error %u\n", WSAGetLastError());

    memset(&sa, 0, sa_len);

    sa.sin_family = AF_INET;
    sa.sin_port = htons(0);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);

    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    ok(sock != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());

    ret = bind(sock, (struct sockaddr *) &sa, sa_len);
    ok(!ret, "failed to bind socket, error %u\n", WSAGetLastError());

    ret = getsockopt(sock, SOL_SOCKET, SO_MAX_MSG_SIZE, (char *)&optval, &optlen);

    ok(ret == 0, "getsockopt failed to query SO_MAX_MSG_SIZE, return value is 0x%08x\n", ret);
    ok((optval == 65507) || (optval == 65527),
            "SO_MAX_MSG_SIZE reported %d, expected 65507 or 65527\n", optval);

    /* IE 3 use 0xffffffff instead of SOL_SOCKET (0xffff) */
    SetLastError(0xdeadbeef);
    optval = 0xdeadbeef;
    optlen = sizeof(int);
    ret = getsockopt(sock, 0xffffffff, SO_MAX_MSG_SIZE, (char *)&optval, &optlen);
    ok( (ret == SOCKET_ERROR) && (WSAGetLastError() == WSAEINVAL),
        "got %d with %d and optval: 0x%x/%d (expected SOCKET_ERROR with WSAEINVAL)\n",
        ret, WSAGetLastError(), optval, optval);

    /* more invalid values for level */
    SetLastError(0xdeadbeef);
    optval = 0xdeadbeef;
    optlen = sizeof(int);
    ret = getsockopt(sock, 0x1234ffff, SO_MAX_MSG_SIZE, (char *)&optval, &optlen);
    ok( (ret == SOCKET_ERROR) && (WSAGetLastError() == WSAEINVAL),
        "got %d with %d and optval: 0x%x/%d (expected SOCKET_ERROR with WSAEINVAL)\n",
        ret, WSAGetLastError(), optval, optval);

    SetLastError(0xdeadbeef);
    optval = 0xdeadbeef;
    optlen = sizeof(int);
    ret = getsockopt(sock, 0x8000ffff, SO_MAX_MSG_SIZE, (char *)&optval, &optlen);
    ok( (ret == SOCKET_ERROR) && (WSAGetLastError() == WSAEINVAL),
        "got %d with %d and optval: 0x%x/%d (expected SOCKET_ERROR with WSAEINVAL)\n",
        ret, WSAGetLastError(), optval, optval);

    SetLastError(0xdeadbeef);
    optval = 0xdeadbeef;
    optlen = sizeof(int);
    ret = getsockopt(sock, 0x00008000, SO_MAX_MSG_SIZE, (char *)&optval, &optlen);
    ok( (ret == SOCKET_ERROR) && (WSAGetLastError() == WSAEINVAL),
        "got %d with %d and optval: 0x%x/%d (expected SOCKET_ERROR with WSAEINVAL)\n",
        ret, WSAGetLastError(), optval, optval);

    SetLastError(0xdeadbeef);
    optval = 0xdeadbeef;
    optlen = sizeof(int);
    ret = getsockopt(sock, 0x00000800, SO_MAX_MSG_SIZE, (char *)&optval, &optlen);
    ok( (ret == SOCKET_ERROR) && (WSAGetLastError() == WSAEINVAL),
        "got %d with %d and optval: 0x%x/%d (expected SOCKET_ERROR with WSAEINVAL)\n",
        ret, WSAGetLastError(), optval, optval);

    SetLastError(0xdeadbeef);
    optlen = sizeof(LINGER);
    ret = getsockopt(sock, SOL_SOCKET, SO_LINGER, (char *)&linger_val, &optlen);
    ok( (ret == SOCKET_ERROR) && (WSAGetLastError() == WSAENOPROTOOPT), 
        "getsockopt should fail for UDP sockets setting last error to WSAENOPROTOOPT, got %d with %d\n", 
        ret, WSAGetLastError());
    closesocket(sock);

    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
    ok(sock != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());

    ret = bind(sock, (struct sockaddr *) &sa, sa_len);
    ok(!ret, "failed to bind socket, error %u\n", WSAGetLastError());

    ret = getsockopt(sock, SOL_SOCKET, SO_LINGER, (char *)&linger_val, &optlen);
    ok(ret == 0, "getsockopt failed to query SO_LINGER, return value is 0x%08x\n", ret);

    optlen = sizeof(BOOL);
    ret = getsockopt(sock, SOL_SOCKET, SO_DONTLINGER, (char *)&bool_opt_val, &optlen);
    ok(ret == 0, "getsockopt failed to query SO_DONTLINGER, return value is 0x%08x\n", ret);
    ok((linger_val.l_onoff && !bool_opt_val) || (!linger_val.l_onoff && bool_opt_val),
            "Return value of SO_DONTLINGER is %d, but SO_LINGER returned l_onoff == %d.\n",
            bool_opt_val, linger_val.l_onoff);

    closesocket(sock);
    WSACleanup();
}

static void test_getsockname(void)
{
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in sa_set, sa_get;
    int sa_set_len = sizeof(struct sockaddr_in);
    int sa_get_len = sa_set_len;
    static const unsigned char null_padding[] = {0,0,0,0,0,0,0,0};
    int ret;
    struct hostent *h;

    ret = WSAStartup(MAKEWORD(2,0), &wsa);
    ok(!ret, "failed to startup, error %u\n", WSAGetLastError());

    memset(&sa_set, 0, sa_set_len);

    sa_set.sin_family = AF_INET;
    sa_set.sin_port = htons(0);
    sa_set.sin_addr.s_addr = htonl(INADDR_ANY);

    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
    ok(sock != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());

    sa_get = sa_set;
    ret = getsockname(sock, (struct sockaddr *)&sa_get, &sa_get_len);
    ok(ret == SOCKET_ERROR, "expected failure\n");
    ok(WSAGetLastError() == WSAEINVAL, "got error %u\n", WSAGetLastError());
    ok(!memcmp(&sa_get, &sa_set, sizeof(sa_get)), "address should not be changed\n");

    ret = bind(sock, (struct sockaddr *) &sa_set, sa_set_len);
    ok(!ret, "failed to bind, error %u\n", WSAGetLastError());

    ret = getsockname(sock, (struct sockaddr *) &sa_get, &sa_get_len);
    ok(!ret, "failed to get address, error %u\n", WSAGetLastError());

    ret = memcmp(sa_get.sin_zero, null_padding, 8);
    ok(ret == 0, "getsockname did not zero the sockaddr_in structure\n");

    closesocket(sock);

    h = gethostbyname("");
    if (h && h->h_length == 4) /* this test is only meaningful in IPv4 */
    {
        int i;
        for (i = 0; h->h_addr_list[i]; i++)
        {
            char ipstr[32];
            struct in_addr ip;
            ip.s_addr = *(ULONG *) h->h_addr_list[i];

            sock = socket(AF_INET, SOCK_DGRAM, 0);
            ok(sock != INVALID_SOCKET, "socket failed with %d\n", GetLastError());

            memset(&sa_set, 0, sizeof(sa_set));
            sa_set.sin_family = AF_INET;
            sa_set.sin_addr.s_addr = ip.s_addr;
            /* The same address we bind must be the same address we get */
            ret = bind(sock, (struct sockaddr*)&sa_set, sizeof(sa_set));
            ok(ret == 0, "bind failed with %d\n", GetLastError());
            sa_get_len = sizeof(sa_get);
            ret = getsockname(sock, (struct sockaddr*)&sa_get, &sa_get_len);
            ok(ret == 0, "getsockname failed with %d\n", GetLastError());
            strcpy(ipstr, inet_ntoa(sa_get.sin_addr));
            ok(sa_get.sin_addr.s_addr == sa_set.sin_addr.s_addr,
               "address does not match: %s != %s\n", ipstr, inet_ntoa(sa_set.sin_addr));

            closesocket(sock);
        }
    }

    WSACleanup();
}

static void test_ioctlsocket(void)
{
    SOCKET sock, src, dst;
    struct tcp_keepalive kalive;
    struct sockaddr_in address;
    int ret, optval;
    static const LONG cmds[] = {FIONBIO, FIONREAD, SIOCATMARK};
    UINT i, bytes_rec;
    char data;
    WSABUF bufs;
    u_long arg = 0;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(sock != INVALID_SOCKET, "Creating the socket failed: %d\n", WSAGetLastError());

    for(i = 0; i < ARRAY_SIZE(cmds); i++)
    {
        /* broken apps like defcon pass the argp value directly instead of a pointer to it */
        ret = ioctlsocket(sock, cmds[i], (u_long *)1);
        ok(ret == SOCKET_ERROR, "ioctlsocket succeeded unexpectedly\n");
        ret = WSAGetLastError();
        ok(ret == WSAEFAULT, "expected WSAEFAULT, got %d instead\n", ret);
    }

    /* A fresh and not connected socket has no urgent data, this test shows
     * that normal(not urgent) data returns a non-zero value for SIOCATMARK. */

    ret = ioctlsocket(sock, SIOCATMARK, &arg);
    ok(ret != SOCKET_ERROR, "ioctlsocket failed unexpectedly\n");
    ok(arg, "SIOCATMARK expected a non-zero value\n");

    /* when SO_OOBINLINE is set SIOCATMARK must always return TRUE */
    optval = 1;
    ret = setsockopt(sock, SOL_SOCKET, SO_OOBINLINE, (void *)&optval, sizeof(optval));
    ok(ret != SOCKET_ERROR, "setsockopt failed unexpectedly\n");
    arg = 0;
    ret = ioctlsocket(sock, SIOCATMARK, &arg);
    ok(ret != SOCKET_ERROR, "ioctlsocket failed unexpectedly\n");
    ok(arg, "SIOCATMARK expected a non-zero value\n");

    /* disable SO_OOBINLINE and get the same old behavior */
    optval = 0;
    ret = setsockopt(sock, SOL_SOCKET, SO_OOBINLINE, (void *)&optval, sizeof(optval));
    ok(ret != SOCKET_ERROR, "setsockopt failed unexpectedly\n");
    arg = 0;
    ret = ioctlsocket(sock, SIOCATMARK, &arg);
    ok(ret != SOCKET_ERROR, "ioctlsocket failed unexpectedly\n");
    ok(arg, "SIOCATMARK expected a non-zero value\n");

    ret = WSAIoctl(sock, SIO_KEEPALIVE_VALS, &arg, 0, NULL, 0, &arg, NULL, NULL);
    ok(ret == SOCKET_ERROR, "WSAIoctl succeeded unexpectedly\n");
    ok(WSAGetLastError() == WSAEFAULT, "got error %u\n", WSAGetLastError());

    ret = WSAIoctl(sock, SIO_KEEPALIVE_VALS, NULL, sizeof(struct tcp_keepalive), NULL, 0, &arg, NULL, NULL);
    ok(ret == SOCKET_ERROR, "WSAIoctl succeeded unexpectedly\n");
    ok(WSAGetLastError() == WSAEFAULT, "got error %u\n", WSAGetLastError());

    make_keepalive(kalive, 0, 0, 0);
    ret = WSAIoctl(sock, SIO_KEEPALIVE_VALS, &kalive, sizeof(struct tcp_keepalive), NULL, 0, &arg, NULL, NULL);
    ok(ret == 0, "WSAIoctl failed unexpectedly\n");

    make_keepalive(kalive, 1, 0, 0);
    ret = WSAIoctl(sock, SIO_KEEPALIVE_VALS, &kalive, sizeof(struct tcp_keepalive), NULL, 0, &arg, NULL, NULL);
    ok(ret == 0, "WSAIoctl failed unexpectedly\n");

    make_keepalive(kalive, 1, 1000, 1000);
    ret = WSAIoctl(sock, SIO_KEEPALIVE_VALS, &kalive, sizeof(struct tcp_keepalive), NULL, 0, &arg, NULL, NULL);
    ok(ret == 0, "WSAIoctl failed unexpectedly\n");

    make_keepalive(kalive, 1, 10000, 10000);
    ret = WSAIoctl(sock, SIO_KEEPALIVE_VALS, &kalive, sizeof(struct tcp_keepalive), NULL, 0, &arg, NULL, NULL);
    ok(ret == 0, "WSAIoctl failed unexpectedly\n");

    make_keepalive(kalive, 1, 100, 100);
    ret = WSAIoctl(sock, SIO_KEEPALIVE_VALS, &kalive, sizeof(struct tcp_keepalive), NULL, 0, &arg, NULL, NULL);
    ok(ret == 0, "WSAIoctl failed unexpectedly\n");

    make_keepalive(kalive, 0, 100, 100);
    ret = WSAIoctl(sock, SIO_KEEPALIVE_VALS, &kalive, sizeof(struct tcp_keepalive), NULL, 0, &arg, NULL, NULL);
    ok(ret == 0, "WSAIoctl failed unexpectedly\n");

    closesocket(sock);

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(sock != INVALID_SOCKET, "Creating the socket failed: %d\n", WSAGetLastError());

    /* test FIONREAD with a fresh and non-connected socket */
    arg = 0xdeadbeef;
    ret = ioctlsocket(sock, FIONREAD, &arg);
    ok(ret == 0, "ioctlsocket failed unexpectedly with error %d\n", WSAGetLastError());
    ok(arg == 0, "expected 0, got %u\n", arg);

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr( SERVERIP );
    address.sin_port = htons( SERVERPORT );
    ret = bind(sock, (struct sockaddr *)&address, sizeof(address));
    ok(ret == 0, "bind failed unexpectedly with error %d\n", WSAGetLastError());

    ret = listen(sock, SOMAXCONN);
    ok(ret == 0, "listen failed unexpectedly with error %d\n", WSAGetLastError());

    /* test FIONREAD with listening socket */
    arg = 0xdeadbeef;
    ret = ioctlsocket(sock, FIONREAD, &arg);
    ok(ret == 0, "ioctlsocket failed unexpectedly with error %d\n", WSAGetLastError());
    ok(arg == 0, "expected 0, got %u\n", arg);

    closesocket(sock);

    tcp_socketpair(&src, &dst);

    /* test FIONREAD on TCP sockets */
    optval = 0xdeadbeef;
    ret = WSAIoctl(dst, FIONREAD, NULL, 0, &optval, sizeof(optval), &arg, NULL, NULL);
    ok(ret == 0, "WSAIoctl failed unexpectedly with error %d\n", WSAGetLastError());
    ok(optval == 0, "FIONREAD should have returned 0 bytes, got %d instead\n", optval);

    optval = 0xdeadbeef;
    ok(send(src, "TEST", 4, 0) == 4, "failed to send test data\n");
    Sleep(100);
    ret = WSAIoctl(dst, FIONREAD, NULL, 0, &optval, sizeof(optval), &arg, NULL, NULL);
    ok(ret == 0, "WSAIoctl failed unexpectedly with error %d\n", WSAGetLastError());
    ok(optval == 4, "FIONREAD should have returned 4 bytes, got %d instead\n", optval);

    /* trying to read from an OOB inlined socket with MSG_OOB results in WSAEINVAL */
    set_blocking(dst, FALSE);
    i = MSG_OOB;
    SetLastError(0xdeadbeef);
    ret = recv(dst, &data, 1, i);
    ok(ret == SOCKET_ERROR, "expected -1, got %d\n", ret);
    ret = GetLastError();
    ok(ret == WSAEWOULDBLOCK, "expected 10035, got %d\n", ret);
    bufs.len = sizeof(char);
    bufs.buf = &data;
    ret = WSARecv(dst, &bufs, 1, &bytes_rec, &i, NULL, NULL);
    ok(ret == SOCKET_ERROR, "expected -1, got %d\n", ret);
    ret = GetLastError();
    ok(ret == WSAEWOULDBLOCK, "expected 10035, got %d\n", ret);
    optval = 1;
    ret = setsockopt(dst, SOL_SOCKET, SO_OOBINLINE, (void *)&optval, sizeof(optval));
    ok(ret != SOCKET_ERROR, "setsockopt failed unexpectedly\n");
    i = MSG_OOB;
    SetLastError(0xdeadbeef);
    ret = recv(dst, &data, 1, i);
    ok(ret == SOCKET_ERROR, "expected SOCKET_ERROR, got %d\n", ret);
    ret = GetLastError();
    ok(ret == WSAEINVAL, "expected 10022, got %d\n", ret);
    bufs.len = sizeof(char);
    bufs.buf = &data;
    ret = WSARecv(dst, &bufs, 1, &bytes_rec, &i, NULL, NULL);
    ok(ret == SOCKET_ERROR, "expected -1, got %d\n", ret);
    ret = GetLastError();
    ok(ret == WSAEINVAL, "expected 10022, got %d\n", ret);

    closesocket(dst);
    optval = 0xdeadbeef;
    ret = WSAIoctl(dst, FIONREAD, NULL, 0, &optval, sizeof(optval), &arg, NULL, NULL);
    ok(ret == SOCKET_ERROR, "WSAIoctl succeeded unexpectedly\n");
    ok(optval == 0xdeadbeef, "FIONREAD should not have changed last error, got %d instead\n", optval);
    closesocket(src);
}

static BOOL drain_pause = FALSE;
static DWORD WINAPI drain_socket_thread(LPVOID arg)
{
    char buffer[1024];
    SOCKET sock = *(SOCKET*)arg;
    int ret;

    while ((ret = recv(sock, buffer, sizeof(buffer), 0)) != 0)
    {
        if (ret < 0)
        {
            if (WSAGetLastError() == WSAEWOULDBLOCK)
            {
                fd_set readset;
                FD_ZERO(&readset);
                FD_SET(sock, &readset);
                select(sock+1, &readset, NULL, NULL, NULL);
                while (drain_pause)
                    Sleep(100);
            }
            else
                break;
        }
    }
    return 0;
}

static void test_send(void)
{
    SOCKET src = INVALID_SOCKET;
    SOCKET dst = INVALID_SOCKET;
    HANDLE hThread = NULL;
    const int buflen = 1024*1024;
    char *buffer = NULL;
    int ret, i, zero = 0;
    WSABUF buf;
    OVERLAPPED ov;
    BOOL bret;
    DWORD id, bytes_sent, dwRet;
    DWORD expected_time, connect_time;
    socklen_t optlen;

    memset(&ov, 0, sizeof(ov));

    tcp_socketpair(&src, &dst);

    expected_time = GetTickCount();

    set_blocking(dst, FALSE);
    /* force disable buffering so we can get a pending overlapped request */
    ret = setsockopt(dst, SOL_SOCKET, SO_SNDBUF, (char *) &zero, sizeof(zero));
    ok(!ret, "setsockopt SO_SNDBUF failed: %d - %d\n", ret, GetLastError());

    hThread = CreateThread(NULL, 0, drain_socket_thread, &dst, 0, &id);

    buffer = HeapAlloc(GetProcessHeap(), 0, buflen);

    /* fill the buffer with some nonsense */
    for (i = 0; i < buflen; ++i)
    {
        buffer[i] = (char) i;
    }

    ret = send(src, buffer, buflen, 0);
    ok(ret == buflen, "send should have sent %d bytes, but it only sent %d\n", buflen, ret);

    buf.buf = buffer;
    buf.len = buflen;

    ov.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    ok(ov.hEvent != NULL, "could not create event object, errno = %d\n", GetLastError());
    if (!ov.hEvent)
        goto end;

    bytes_sent = 0;
    WSASetLastError(12345);
    ret = WSASend(dst, &buf, 1, &bytes_sent, 0, &ov, NULL);
    ok(ret == SOCKET_ERROR, "expected failure\n");
    ok(WSAGetLastError() == ERROR_IO_PENDING, "wrong error %u\n", WSAGetLastError());

    /* don't check for completion yet, we may need to drain the buffer while still sending */
    set_blocking(src, FALSE);
    for (i = 0; i < buflen; ++i)
    {
        int j = 0;

        ret = recv(src, buffer, 1, 0);
        while (ret == SOCKET_ERROR && GetLastError() == WSAEWOULDBLOCK && j < 100)
        {
            j++;
            Sleep(50);
            ret = recv(src, buffer, 1, 0);
        }

        ok(ret == 1, "Failed to receive data %d - %d (got %d/%d)\n", ret, GetLastError(), i, buflen);
        if (ret != 1)
            break;

        ok(buffer[0] == (char) i, "Received bad data at position %d\n", i);
    }

    dwRet = WaitForSingleObject(ov.hEvent, 1000);
    ok(dwRet == WAIT_OBJECT_0, "Failed to wait for recv message: %d - %d\n", dwRet, GetLastError());
    if (dwRet == WAIT_OBJECT_0)
    {
        bret = GetOverlappedResult((HANDLE)dst, &ov, &bytes_sent, FALSE);
        ok(bret && bytes_sent == buflen,
           "Got %d instead of %d (%d - %d)\n", bytes_sent, buflen, bret, GetLastError());
    }

    WSASetLastError(12345);
    ret = WSASend(INVALID_SOCKET, &buf, 1, NULL, 0, &ov, NULL);
    ok(ret == SOCKET_ERROR && WSAGetLastError() == WSAENOTSOCK,
       "WSASend failed %d - %d\n", ret, WSAGetLastError());

    WSASetLastError(12345);
    ret = WSASend(dst, &buf, 1, NULL, 0, &ov, NULL);
    ok(ret == SOCKET_ERROR && WSAGetLastError() == ERROR_IO_PENDING,
       "Failed to start overlapped send %d - %d\n", ret, WSAGetLastError());

    expected_time = (GetTickCount() - expected_time) / 1000;

    connect_time = 0xdeadbeef;
    optlen = sizeof(connect_time);
    ret = getsockopt(dst, SOL_SOCKET, SO_CONNECT_TIME, (char *)&connect_time, &optlen);
    ok(!ret, "getsockopt failed %d\n", WSAGetLastError());
    ok(connect_time >= expected_time && connect_time <= expected_time + 1,
       "unexpected connect time %u, expected %u\n", connect_time, expected_time);

    connect_time = 0xdeadbeef;
    optlen = sizeof(connect_time);
    ret = getsockopt(src, SOL_SOCKET, SO_CONNECT_TIME, (char *)&connect_time, &optlen);
    ok(!ret, "getsockopt failed %d\n", WSAGetLastError());
    ok(connect_time >= expected_time && connect_time <= expected_time + 1,
       "unexpected connect time %u, expected %u\n", connect_time, expected_time);

end:
    if (src != INVALID_SOCKET)
        closesocket(src);
    if (dst != INVALID_SOCKET)
        closesocket(dst);
    if (hThread != NULL)
    {
        dwRet = WaitForSingleObject(hThread, 500);
        ok(dwRet == WAIT_OBJECT_0, "failed to wait for thread termination: %d\n", GetLastError());
        CloseHandle(hThread);
    }
    if (ov.hEvent)
        CloseHandle(ov.hEvent);
    HeapFree(GetProcessHeap(), 0, buffer);
}

#define WM_SOCKET (WM_USER+100)

struct event_test_ctx
{
    int is_message;
    SOCKET socket;
    HANDLE event;
    HWND window;
};

static void select_events(struct event_test_ctx *ctx, SOCKET socket, LONG events)
{
    int ret;

    if (ctx->is_message)
        ret = WSAAsyncSelect(socket, ctx->window, WM_USER, events);
    else
        ret = WSAEventSelect(socket, ctx->event, events);
    ok(!ret, "failed to select, error %u\n", WSAGetLastError());
    ctx->socket = socket;
}

#define check_events(a, b, c, d) check_events_(__LINE__, a, b, c, d, FALSE, FALSE)
#define check_events_todo(a, b, c, d) check_events_(__LINE__, a, b, c, d, TRUE, TRUE)
#define check_events_todo_event(a, b, c, d) check_events_(__LINE__, a, b, c, d, TRUE, FALSE)
#define check_events_todo_msg(a, b, c, d) check_events_(__LINE__, a, b, c, d, FALSE, TRUE)
static void check_events_(int line, struct event_test_ctx *ctx,
        LONG flag1, LONG flag2, DWORD timeout, BOOL todo_event, BOOL todo_msg)
{
    int ret;

    if (ctx->is_message)
    {
        BOOL any_fail = FALSE;
        MSG msg;

        if (flag1)
        {
            ret = PeekMessageA(&msg, ctx->window, WM_USER, WM_USER, PM_REMOVE);
            while (!ret && !MsgWaitForMultipleObjects(0, NULL, FALSE, timeout, QS_POSTMESSAGE))
                ret = PeekMessageA(&msg, ctx->window, WM_USER, WM_USER, PM_REMOVE);
            todo_wine_if (todo_msg && !ret) ok_(__FILE__, line)(ret, "expected a message\n");
            if (ret)
            {
                ok_(__FILE__, line)(msg.wParam == ctx->socket,
                        "expected wparam %#Ix, got %#Ix\n", ctx->socket, msg.wParam);
                todo_wine_if (todo_msg && msg.lParam != flag1)
                    ok_(__FILE__, line)(msg.lParam == flag1, "got first event %#Ix\n", msg.lParam);
                if (msg.lParam != flag1) any_fail = TRUE;
            }
            else
                any_fail = TRUE;
        }
        if (flag2)
        {
            ret = PeekMessageA(&msg, ctx->window, WM_USER, WM_USER, PM_REMOVE);
            while (!ret && !MsgWaitForMultipleObjects(0, NULL, FALSE, timeout, QS_POSTMESSAGE))
                ret = PeekMessageA(&msg, ctx->window, WM_USER, WM_USER, PM_REMOVE);
            ok_(__FILE__, line)(ret, "expected a message\n");
            ok_(__FILE__, line)(msg.wParam == ctx->socket, "got wparam %#Ix\n", msg.wParam);
            todo_wine_if (todo_msg) ok_(__FILE__, line)(msg.lParam == flag2, "got second event %#Ix\n", msg.lParam);
        }
        ret = PeekMessageA(&msg, ctx->window, WM_USER, WM_USER, PM_REMOVE);
        todo_wine_if (todo_msg && ret) ok_(__FILE__, line)(!ret, "got unexpected event %#Ix\n", msg.lParam);
        if (ret) any_fail = TRUE;

        /* catch tests which succeed */
        todo_wine_if (todo_msg) ok_(__FILE__, line)(!any_fail, "event series matches\n");
    }
    else
    {
        WSANETWORKEVENTS events;

        ret = WaitForSingleObject(ctx->event, timeout);
        if (flag1 | flag2)
            todo_wine_if (todo_event && ret) ok_(__FILE__, line)(!ret, "event wait timed out\n");
        else
            todo_wine_if (todo_event) ok_(__FILE__, line)(ret == WAIT_TIMEOUT, "expected timeout\n");
        ret = WSAEnumNetworkEvents(ctx->socket, ctx->event, &events);
        ok_(__FILE__, line)(!ret, "failed to get events, error %u\n", WSAGetLastError());
        todo_wine_if (todo_event)
            ok_(__FILE__, line)(events.lNetworkEvents == (flag1 | flag2), "got events %#x\n", events.lNetworkEvents);
    }
}

static void test_accept_events(struct event_test_ctx *ctx)
{
    const struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    SOCKET listener, server, client, client2;
    struct sockaddr_in destaddr;
    int len, ret;

    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(listener != -1, "failed to create socket, error %u\n", WSAGetLastError());

    select_events(ctx, listener, FD_CONNECT | FD_READ | FD_OOB | FD_ACCEPT);

    ret = bind(listener, (const struct sockaddr *)&addr, sizeof(addr));
    ok(!ret, "failed to bind, error %u\n", WSAGetLastError());
    len = sizeof(destaddr);
    ret = getsockname(listener, (struct sockaddr *)&destaddr, &len);
    ok(!ret, "failed to get address, error %u\n", WSAGetLastError());
    ret = listen(listener, 2);
    ok(!ret, "failed to listen, error %u\n", WSAGetLastError());

    check_events(ctx, 0, 0, 0);

    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(client != -1, "failed to create socket, error %u\n", WSAGetLastError());
    ret = connect(client, (struct sockaddr *)&destaddr, sizeof(destaddr));
    ok(!ret, "failed to connect, error %u\n", WSAGetLastError());

    check_events(ctx, FD_ACCEPT, 0, 200);
    check_events(ctx, 0, 0, 0);
    select_events(ctx, listener, FD_CONNECT | FD_READ | FD_OOB | FD_ACCEPT);
    if (ctx->is_message)
        check_events(ctx, FD_ACCEPT, 0, 200);
    check_events_todo_event(ctx, 0, 0, 0);
    select_events(ctx, listener, 0);
    select_events(ctx, listener, FD_CONNECT | FD_READ | FD_OOB | FD_ACCEPT);
    if (ctx->is_message)
        check_events(ctx, FD_ACCEPT, 0, 200);
    check_events_todo_event(ctx, 0, 0, 0);

    client2 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(client2 != -1, "failed to create socket, error %u\n", WSAGetLastError());
    ret = connect(client2, (struct sockaddr *)&destaddr, sizeof(destaddr));
    ok(!ret, "failed to connect, error %u\n", WSAGetLastError());

    if (!ctx->is_message)
        check_events_todo(ctx, FD_ACCEPT, 0, 200);
    check_events(ctx, 0, 0, 0);

    server = accept(listener, NULL, NULL);
    ok(server != -1, "failed to accept, error %u\n", WSAGetLastError());
    closesocket(server);

    check_events(ctx, FD_ACCEPT, 0, 200);
    check_events(ctx, 0, 0, 0);

    server = accept(listener, NULL, NULL);
    ok(server != -1, "failed to accept, error %u\n", WSAGetLastError());
    closesocket(server);

    check_events(ctx, 0, 0, 0);

    closesocket(client2);
    closesocket(client);

    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(client != -1, "failed to create socket, error %u\n", WSAGetLastError());
    ret = connect(client, (struct sockaddr *)&destaddr, sizeof(destaddr));
    ok(!ret, "failed to connect, error %u\n", WSAGetLastError());

    check_events(ctx, FD_ACCEPT, 0, 200);

    server = accept(listener, NULL, NULL);
    ok(server != -1, "failed to accept, error %u\n", WSAGetLastError());
    closesocket(server);
    closesocket(client);

    check_events(ctx, 0, 0, 200);

    closesocket(listener);

    /* Connect and then select. */

    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(listener != -1, "failed to create socket, error %u\n", WSAGetLastError());
    ret = bind(listener, (const struct sockaddr *)&addr, sizeof(addr));
    ok(!ret, "failed to bind, error %u\n", WSAGetLastError());
    len = sizeof(destaddr);
    ret = getsockname(listener, (struct sockaddr *)&destaddr, &len);
    ok(!ret, "failed to get address, error %u\n", WSAGetLastError());
    ret = listen(listener, 2);
    ok(!ret, "failed to listen, error %u\n", WSAGetLastError());

    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(client != -1, "failed to create socket, error %u\n", WSAGetLastError());
    ret = connect(client, (struct sockaddr *)&destaddr, sizeof(destaddr));
    ok(!ret, "failed to connect, error %u\n", WSAGetLastError());

    select_events(ctx, listener, FD_CONNECT | FD_READ | FD_OOB | FD_ACCEPT);

    check_events(ctx, FD_ACCEPT, 0, 200);

    server = accept(listener, NULL, NULL);
    ok(server != -1, "failed to accept, error %u\n", WSAGetLastError());
    closesocket(server);
    closesocket(client);

    /* As above, but select on a subset not containing FD_ACCEPT first. */

    select_events(ctx, listener, FD_CONNECT | FD_READ | FD_OOB);

    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(client != -1, "failed to create socket, error %u\n", WSAGetLastError());
    ret = connect(client, (struct sockaddr *)&destaddr, sizeof(destaddr));
    ok(!ret, "failed to connect, error %u\n", WSAGetLastError());

    select_events(ctx, listener, FD_CONNECT | FD_READ | FD_OOB | FD_ACCEPT);
    check_events(ctx, FD_ACCEPT, 0, 200);

    server = accept(listener, NULL, NULL);
    ok(server != -1, "failed to accept, error %u\n", WSAGetLastError());
    closesocket(server);
    closesocket(client);

    /* As above, but call accept() before selecting. */

    select_events(ctx, listener, FD_CONNECT | FD_READ | FD_OOB);

    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(client != -1, "failed to create socket, error %u\n", WSAGetLastError());
    ret = connect(client, (struct sockaddr *)&destaddr, sizeof(destaddr));
    ok(!ret, "failed to connect, error %u\n", WSAGetLastError());
    Sleep(200);
    server = accept(listener, NULL, NULL);
    ok(server != -1, "failed to accept, error %u\n", WSAGetLastError());

    select_events(ctx, listener, FD_CONNECT | FD_READ | FD_OOB | FD_ACCEPT);
    check_events(ctx, 0, 0, 200);

    closesocket(server);
    closesocket(client);

    closesocket(listener);
}

static void test_connect_events(struct event_test_ctx *ctx)
{
    const struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    SOCKET listener, server, client;
    struct sockaddr_in destaddr;
    int len, ret;

    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(listener != -1, "failed to create socket, error %u\n", WSAGetLastError());
    ret = bind(listener, (const struct sockaddr *)&addr, sizeof(addr));
    ok(!ret, "failed to bind, error %u\n", WSAGetLastError());
    len = sizeof(destaddr);
    ret = getsockname(listener, (struct sockaddr *)&destaddr, &len);
    ok(!ret, "failed to get address, error %u\n", WSAGetLastError());
    ret = listen(listener, 2);
    ok(!ret, "failed to listen, error %u\n", WSAGetLastError());

    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(client != -1, "failed to create socket, error %u\n", WSAGetLastError());

    select_events(ctx, client, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE);
    check_events(ctx, 0, 0, 0);

    ret = connect(client, (struct sockaddr *)&destaddr, sizeof(destaddr));
    ok(!ret || WSAGetLastError() == WSAEWOULDBLOCK, "failed to connect, error %u\n", WSAGetLastError());

    check_events(ctx, FD_CONNECT, FD_WRITE, 200);
    check_events(ctx, 0, 0, 0);
    select_events(ctx, client, 0);
    select_events(ctx, client, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE);
    if (ctx->is_message)
        check_events(ctx, FD_WRITE, 0, 200);
    check_events_todo_event(ctx, 0, 0, 0);

    server = accept(listener, NULL, NULL);
    ok(server != -1, "failed to accept, error %u\n", WSAGetLastError());

    closesocket(client);
    closesocket(server);

    /* Connect and then select. */

    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(client != -1, "failed to create socket, error %u\n", WSAGetLastError());

    ret = connect(client, (struct sockaddr *)&destaddr, sizeof(destaddr));
    ok(!ret, "failed to connect, error %u\n", WSAGetLastError());

    server = accept(listener, NULL, NULL);
    ok(server != -1, "failed to accept, error %u\n", WSAGetLastError());

    ret = send(client, "data", 5, 0);
    ok(ret == 5, "got %d\n", ret);

    select_events(ctx, client, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE);
    if (ctx->is_message)
        check_events(ctx, FD_WRITE, 0, 200);
    else
        check_events_todo(ctx, FD_CONNECT, FD_WRITE, 200);

    closesocket(client);
    closesocket(server);

    /* As above, but select on a subset not containing FD_CONNECT first. */

    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(client != -1, "failed to create socket, error %u\n", WSAGetLastError());

    select_events(ctx, client, FD_ACCEPT | FD_CLOSE | FD_OOB | FD_READ | FD_WRITE);

    ret = connect(client, (struct sockaddr *)&destaddr, sizeof(destaddr));
    ok(!ret || WSAGetLastError() == WSAEWOULDBLOCK, "failed to connect, error %u\n", WSAGetLastError());

    server = accept(listener, NULL, NULL);
    ok(server != -1, "failed to accept, error %u\n", WSAGetLastError());

    check_events_todo_msg(ctx, FD_WRITE, 0, 200);

    select_events(ctx, client, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE);

    if (ctx->is_message)
        check_events(ctx, FD_WRITE, 0, 200);
    else
        check_events_todo(ctx, FD_CONNECT, 0, 200);

    closesocket(client);
    closesocket(server);

    closesocket(listener);
}

/* perform a blocking recv() even on a nonblocking socket */
static int sync_recv(SOCKET s, void *buffer, int len, DWORD flags)
{
    OVERLAPPED overlapped = {0};
    WSABUF wsabuf;
    DWORD ret_len;
    int ret;

    overlapped.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    wsabuf.buf = buffer;
    wsabuf.len = len;
    ret = WSARecv(s, &wsabuf, 1, &ret_len, &flags, &overlapped, NULL);
    if (ret == -1 && WSAGetLastError() == ERROR_IO_PENDING)
    {
        ret = WaitForSingleObject(overlapped.hEvent, 1000);
        ok(!ret, "wait timed out\n");
        ret = WSAGetOverlappedResult(s, &overlapped, &ret_len, FALSE, &flags);
        ret = (ret ? 0 : -1);
    }
    CloseHandle(overlapped.hEvent);
    if (!ret) return ret_len;
    return -1;
}

static void test_write_events(struct event_test_ctx *ctx)
{
    static const int buffer_size = 1024 * 1024;
    SOCKET server, client;
    char *buffer;
    int ret;

    buffer = malloc(buffer_size);

    tcp_socketpair(&client, &server);
    set_blocking(client, FALSE);

    select_events(ctx, server, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE);
    check_events(ctx, FD_WRITE, 0, 200);
    check_events(ctx, 0, 0, 0);
    select_events(ctx, server, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE);
    if (ctx->is_message)
        check_events(ctx, FD_WRITE, 0, 200);
    check_events_todo_event(ctx, 0, 0, 0);
    select_events(ctx, server, 0);
    select_events(ctx, server, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE);
    if (ctx->is_message)
        check_events(ctx, FD_WRITE, 0, 200);
    check_events_todo_event(ctx, 0, 0, 0);

    ret = send(server, "data", 5, 0);
    ok(ret == 5, "got %d\n", ret);

    check_events(ctx, 0, 0, 0);

    ret = sync_recv(client, buffer, buffer_size, 0);
    ok(ret == 5, "got %d\n", ret);

    check_events(ctx, 0, 0, 0);

    if (!broken(1))
    {
        while (send(server, buffer, buffer_size, 0) == buffer_size);
        todo_wine ok(WSAGetLastError() == WSAEWOULDBLOCK, "got error %u\n", WSAGetLastError());

        while (recv(client, buffer, buffer_size, 0) > 0);
        ok(WSAGetLastError() == WSAEWOULDBLOCK, "got error %u\n", WSAGetLastError());

        /* Broken on Windows versions older than win10v1607 (though sometimes
         * works regardless, for unclear reasons. */
        check_events(ctx, FD_WRITE, 0, 200);
        check_events(ctx, 0, 0, 0);
        select_events(ctx, server, 0);
        select_events(ctx, server, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE);
        if (ctx->is_message)
            check_events(ctx, FD_WRITE, 0, 200);
        check_events_todo_event(ctx, 0, 0, 0);
    }

    closesocket(server);
    closesocket(client);

    /* Despite the documentation, and unlike FD_ACCEPT and FD_RECV, calling
     * send() doesn't clear the FD_WRITE bit. */

    tcp_socketpair(&client, &server);

    select_events(ctx, server, FD_ACCEPT | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE);

    ret = send(server, "data", 5, 0);
    ok(ret == 5, "got %d\n", ret);

    check_events(ctx, FD_WRITE, 0, 200);

    closesocket(server);
    closesocket(client);

    free(buffer);
}

static void test_read_events(struct event_test_ctx *ctx)
{
    SOCKET server, client;
    unsigned int i;
    char buffer[8];
    int ret;

    tcp_socketpair(&client, &server);
    set_blocking(client, FALSE);

    select_events(ctx, server, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    check_events(ctx, 0, 0, 0);

    ret = send(client, "data", 5, 0);
    ok(ret == 5, "got %d\n", ret);

    check_events(ctx, FD_READ, 0, 200);
    check_events(ctx, 0, 0, 0);
    select_events(ctx, server, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    if (ctx->is_message)
        check_events(ctx, FD_READ, 0, 200);
    check_events_todo_event(ctx, 0, 0, 0);
    select_events(ctx, server, 0);
    select_events(ctx, server, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    if (ctx->is_message)
        check_events(ctx, FD_READ, 0, 200);
    check_events_todo_event(ctx, 0, 0, 0);

    ret = send(client, "data", 5, 0);
    ok(ret == 5, "got %d\n", ret);

    if (!ctx->is_message)
        check_events_todo(ctx, FD_READ, 0, 200);
    check_events(ctx, 0, 0, 0);

    ret = recv(server, buffer, 2, 0);
    ok(ret == 2, "got %d\n", ret);

    check_events(ctx, FD_READ, 0, 200);
    check_events(ctx, 0, 0, 0);

    ret = recv(server, buffer, -1, 0);
    ok(ret == -1, "got %d\n", ret);
    ok(WSAGetLastError() == WSAEFAULT || WSAGetLastError() == WSAENOBUFS /* < Windows 7 */,
             "got error %u\n", WSAGetLastError());

    if (ctx->is_message)
        check_events_todo_msg(ctx, FD_READ, 0, 200);
    check_events(ctx, 0, 0, 0);

    for (i = 0; i < 8; ++i)
    {
        ret = sync_recv(server, buffer, 1, 0);
        ok(ret == 1, "got %d\n", ret);

        if (i < 7)
            check_events(ctx, FD_READ, 0, 200);
        check_events(ctx, 0, 0, 0);
    }

    /* Send data while we're not selecting. */

    select_events(ctx, server, 0);
    ret = send(client, "data", 5, 0);
    ok(ret == 5, "got %d\n", ret);
    select_events(ctx, server, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);

    check_events(ctx, FD_READ, 0, 200);

    ret = recv(server, buffer, 5, 0);
    ok(ret == 5, "got %d\n", ret);

    select_events(ctx, server, 0);
    ret = send(client, "data", 5, 0);
    ok(ret == 5, "got %d\n", ret);
    ret = sync_recv(server, buffer, 5, 0);
    ok(ret == 5, "got %d\n", ret);
    select_events(ctx, server, FD_ACCEPT | FD_CONNECT | FD_OOB | FD_READ);

    check_events(ctx, 0, 0, 200);

    closesocket(server);
    closesocket(client);
}

static void test_oob_events(struct event_test_ctx *ctx)
{
    SOCKET server, client;
    char buffer[1];
    int ret;

    tcp_socketpair(&client, &server);
    set_blocking(client, FALSE);

    select_events(ctx, server, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    check_events(ctx, 0, 0, 0);

    ret = send(client, "a", 1, MSG_OOB);
    ok(ret == 1, "got %d\n", ret);

    check_events_todo_msg(ctx, FD_OOB, 0, 200);
    check_events_todo(ctx, 0, 0, 0);
    select_events(ctx, server, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    if (ctx->is_message)
        check_events_todo_msg(ctx, FD_OOB, 0, 200);
    check_events_todo(ctx, 0, 0, 0);
    select_events(ctx, server, 0);
    select_events(ctx, server, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    if (ctx->is_message)
        check_events_todo_msg(ctx, FD_OOB, 0, 200);
    check_events_todo(ctx, 0, 0, 0);

    ret = send(client, "b", 1, MSG_OOB);
    ok(ret == 1, "got %d\n", ret);

    if (!ctx->is_message)
        check_events(ctx, FD_OOB, 0, 200);
    check_events_todo(ctx, 0, 0, 0);

    ret = recv(server, buffer, 1, MSG_OOB);
    ok(ret == 1, "got %d\n", ret);

    check_events_todo_msg(ctx, FD_OOB, 0, 200);
    check_events_todo_msg(ctx, 0, 0, 0);

    ret = recv(server, buffer, 1, MSG_OOB);
    todo_wine ok(ret == 1, "got %d\n", ret);

    check_events_todo_msg(ctx, 0, 0, 0);

    /* Send data while we're not selecting. */

    select_events(ctx, server, 0);
    ret = send(client, "a", 1, MSG_OOB);
    ok(ret == 1, "got %d\n", ret);
    select_events(ctx, server, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);

    check_events_todo_msg(ctx, FD_OOB, 0, 200);

    ret = recv(server, buffer, 1, MSG_OOB);
    ok(ret == 1, "got %d\n", ret);

    closesocket(server);
    closesocket(client);
}

static void test_close_events(struct event_test_ctx *ctx)
{
    SOCKET server, client;
    char buffer[5];
    int ret;

    /* Test closesocket(). */

    tcp_socketpair(&client, &server);

    select_events(ctx, server, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);

    closesocket(client);

    check_events(ctx, FD_CLOSE, 0, 200);
    check_events(ctx, 0, 0, 0);
    select_events(ctx, server, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    if (ctx->is_message)
        check_events_todo_msg(ctx, FD_CLOSE, 0, 200);
    check_events(ctx, 0, 0, 0);
    select_events(ctx, server, 0);
    select_events(ctx, server, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    if (ctx->is_message)
        check_events_todo_msg(ctx, FD_CLOSE, 0, 200);
    check_events(ctx, 0, 0, 0);

    closesocket(server);

    /* Test shutdown(remote end, SD_SEND). */

    tcp_socketpair(&client, &server);

    select_events(ctx, server, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);

    shutdown(client, SD_SEND);

    check_events(ctx, FD_CLOSE, 0, 200);
    check_events(ctx, 0, 0, 0);

    closesocket(client);

    check_events(ctx, 0, 0, 0);

    closesocket(server);

    /* No other shutdown() call generates an event. */

    tcp_socketpair(&client, &server);

    select_events(ctx, server, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);

    shutdown(client, SD_RECEIVE);
    shutdown(server, SD_BOTH);

    check_events(ctx, 0, 0, 200);

    shutdown(client, SD_SEND);

    check_events_todo(ctx, FD_CLOSE, 0, 200);
    check_events(ctx, 0, 0, 0);

    closesocket(server);
    closesocket(client);

    /* Test sending data before calling closesocket(). */

    tcp_socketpair(&client, &server);

    select_events(ctx, server, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);

    ret = send(client, "data", 5, 0);
    ok(ret == 5, "got %d\n", ret);

    check_events(ctx, FD_READ, 0, 200);

    closesocket(client);

    check_events_todo(ctx, FD_CLOSE, 0, 200);

    ret = recv(server, buffer, 3, 0);
    ok(ret == 3, "got %d\n", ret);

    check_events(ctx, FD_READ, 0, 200);

    ret = recv(server, buffer, 5, 0);
    ok(ret == 2, "got %d\n", ret);

    check_events_todo(ctx, 0, 0, 0);

    closesocket(server);

    /* Close and then select. */

    tcp_socketpair(&client, &server);
    closesocket(client);

    select_events(ctx, server, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    check_events(ctx, FD_CLOSE, 0, 200);

    closesocket(server);

    /* As above, but select on a subset not containing FD_CLOSE first. */

    tcp_socketpair(&client, &server);

    select_events(ctx, server, FD_ACCEPT | FD_CONNECT | FD_OOB | FD_READ);

    closesocket(client);

    check_events(ctx, 0, 0, 200);
    select_events(ctx, server, FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ);
    check_events_todo_event(ctx, FD_CLOSE, 0, 200);

    closesocket(server);
}

static void test_events(void)
{
    struct event_test_ctx ctx;

    ctx.is_message = FALSE;
    ctx.event = CreateEventW(NULL, TRUE, FALSE, NULL);

    test_accept_events(&ctx);
    test_connect_events(&ctx);
    test_write_events(&ctx);
    test_read_events(&ctx);
    test_close_events(&ctx);
    test_oob_events(&ctx);

    CloseHandle(ctx.event);

    ctx.is_message = TRUE;
    ctx.window = CreateWindowA("Message", NULL, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, NULL);

    test_accept_events(&ctx);
    test_connect_events(&ctx);
    test_write_events(&ctx);
    test_read_events(&ctx);
    test_close_events(&ctx);
    test_oob_events(&ctx);

    DestroyWindow(ctx.window);
}

static void test_ipv6only(void)
{
    SOCKET v4 = INVALID_SOCKET, v6;
    struct sockaddr_in sin4;
    struct sockaddr_in6 sin6;
    int ret, enabled, len = sizeof(enabled);

    memset(&sin4, 0, sizeof(sin4));
    sin4.sin_family = AF_INET;
    sin4.sin_port = htons(SERVERPORT);

    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(SERVERPORT);

    v6 = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (v6 == INVALID_SOCKET)
    {
        skip("Could not create IPv6 socket (LastError: %d)\n", WSAGetLastError());
        goto end;
    }

    enabled = 2;
    ret = getsockopt(v6, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&enabled, &len);
    ok(!ret, "getsockopt(IPV6_ONLY) failed (LastError: %d)\n", WSAGetLastError());
    ok(enabled == 1, "expected 1, got %d\n", enabled);

    ret = bind(v6, (struct sockaddr*)&sin6, sizeof(sin6));
    ok(!ret, "failed to bind, error %u\n", WSAGetLastError());

    v4 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(v4 != INVALID_SOCKET, "Could not create IPv4 socket (LastError: %d)\n", WSAGetLastError());

todo_wine {
    enabled = 2;
    ret = getsockopt(v4, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&enabled, &len);
    ok(!ret, "getsockopt(IPV6_ONLY) failed (LastError: %d)\n", WSAGetLastError());
    ok(enabled == 1, "expected 1, got %d\n", enabled);
}

    enabled = 0;
    len = sizeof(enabled);
    ret = setsockopt(v4, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&enabled, len);
    ok(!ret, "setsockopt(IPV6_ONLY) failed (LastError: %d)\n", WSAGetLastError());

todo_wine {
    enabled = 2;
    ret = getsockopt(v4, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&enabled, &len);
    ok(!ret, "getsockopt(IPV6_ONLY) failed (LastError: %d)\n", WSAGetLastError());
    ok(!enabled, "expected 0, got %d\n", enabled);
}

    enabled = 1;
    len = sizeof(enabled);
    ret = setsockopt(v4, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&enabled, len);
    ok(!ret, "setsockopt(IPV6_ONLY) failed (LastError: %d)\n", WSAGetLastError());

    /* bind on IPv4 socket should succeed - IPV6_V6ONLY is enabled by default */
    ret = bind(v4, (struct sockaddr*)&sin4, sizeof(sin4));
    ok(!ret, "Could not bind IPv4 address (LastError: %d)\n", WSAGetLastError());

todo_wine {
    enabled = 2;
    ret = getsockopt(v4, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&enabled, &len);
    ok(!ret, "getsockopt(IPV6_ONLY) failed (LastError: %d)\n", WSAGetLastError());
    ok(enabled == 1, "expected 1, got %d\n", enabled);
}

    enabled = 0;
    len = sizeof(enabled);
    ret = setsockopt(v4, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&enabled, len);
    ok(ret, "setsockopt(IPV6_ONLY) succeeded (LastError: %d)\n", WSAGetLastError());

todo_wine {
    enabled = 0;
    ret = getsockopt(v4, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&enabled, &len);
    ok(!ret, "getsockopt(IPV6_ONLY) failed (LastError: %d)\n", WSAGetLastError());
    ok(enabled == 1, "expected 1, got %d\n", enabled);
}

    enabled = 1;
    len = sizeof(enabled);
    ret = setsockopt(v4, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&enabled, len);
    ok(ret, "setsockopt(IPV6_ONLY) succeeded (LastError: %d)\n", WSAGetLastError());

    closesocket(v4);
    closesocket(v6);

    /* Test again, this time disabling IPV6_V6ONLY. */
    sin4.sin_port = htons(SERVERPORT+2);
    sin6.sin6_port = htons(SERVERPORT+2);

    v6 = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    ok(v6 != INVALID_SOCKET, "Could not create IPv6 socket (LastError: %d; %d expected if IPv6 not available).\n",
        WSAGetLastError(), WSAEAFNOSUPPORT);

    enabled = 0;
    ret = setsockopt(v6, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&enabled, len);
    ok(!ret, "Could not disable IPV6_V6ONLY (LastError: %d).\n", WSAGetLastError());

    enabled = 2;
    ret = getsockopt(v6, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&enabled, &len);
    ok(!ret, "getsockopt(IPV6_ONLY) failed (LastError: %d)\n", WSAGetLastError());
    ok(!enabled, "expected 0, got %d\n", enabled);

    /*
        Observaition:
        On Windows, bind on both IPv4 and IPv6 with IPV6_V6ONLY disabled succeeds by default.
        Application must set SO_EXCLUSIVEADDRUSE on first socket to disallow another successful bind.
        In general, a standard application should not use SO_REUSEADDR.
        Setting both SO_EXCLUSIVEADDRUSE and SO_REUSEADDR on the same socket is not possible in
        either order, the later setsockopt call always fails.
    */
    enabled = 1;
    ret = setsockopt(v6, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char*)&enabled, len);
    ok(!ret, "Could not set SO_EXCLUSIVEADDRUSE on IPv6 socket (LastError: %d)\n", WSAGetLastError());

    ret = bind(v6, (struct sockaddr*)&sin6, sizeof(sin6));
    ok(!ret, "Could not bind IPv6 address (LastError: %d)\n", WSAGetLastError());

    enabled = 2;
    len = sizeof(enabled);
    getsockopt(v6, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&enabled, &len);
    ok(!ret, "getsockopt(IPV6_ONLY) failed (LastError: %d)\n", WSAGetLastError());
    ok(!enabled, "IPV6_V6ONLY is enabled after bind\n");

    v4 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(v4 != INVALID_SOCKET, "Could not create IPv4 socket (LastError: %d)\n", WSAGetLastError());

    enabled = 1;
    ret = setsockopt(v4, SOL_SOCKET, SO_REUSEADDR, (char*)&enabled, len);
    ok(!ret, "Could not set SO_REUSEADDR on IPv4 socket (LastError: %d)\n", WSAGetLastError());

    WSASetLastError(0xdeadbeef);
    ret = bind(v4, (struct sockaddr*)&sin4, sizeof(sin4));
    ok(ret, "bind succeeded unexpectedly for the IPv4 socket\n");
    ok(WSAGetLastError() == WSAEACCES, "Expected 10013, got %d\n", WSAGetLastError());

end:
    if (v4 != INVALID_SOCKET)
        closesocket(v4);
    if (v6 != INVALID_SOCKET)
        closesocket(v6);
}

static void test_WSASendMsg(void)
{
    SOCKET sock, dst;
    struct sockaddr_in sendaddr, sockaddr;
    GUID WSASendMsg_GUID = WSAID_WSASENDMSG;
    LPFN_WSASENDMSG pWSASendMsg = NULL;
    char teststr[12] = "hello world", buffer[32];
    WSABUF iovec[2];
    WSAMSG msg;
    DWORD bytesSent, err;
    int ret, addrlen;

    /* FIXME: Missing OVERLAPPED and OVERLAPPED COMPLETION ROUTINE tests */

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    ok(sock != INVALID_SOCKET, "socket() failed\n");

    /* Obtain the WSASendMsg function */
    WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER, &WSASendMsg_GUID, sizeof(WSASendMsg_GUID),
             &pWSASendMsg, sizeof(pWSASendMsg), &err, NULL, NULL);
    if (!pWSASendMsg)
    {
        closesocket(sock);
        win_skip("WSASendMsg is unsupported, some tests will be skipped.\n");
        return;
    }

    /* fake address for now */
    sendaddr.sin_family = AF_INET;
    sendaddr.sin_port = htons(139);
    sendaddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    memset(&msg, 0, sizeof(msg));
    iovec[0].buf      = teststr;
    iovec[0].len      = sizeof(teststr);
    iovec[1].buf      = teststr;
    iovec[1].len      = sizeof(teststr) / 2;
    msg.name          = (struct sockaddr *) &sendaddr;
    msg.namelen       = sizeof(sendaddr);
    msg.lpBuffers     = iovec;
    msg.dwBufferCount = 1; /* send only one buffer for now */

    WSASetLastError(0xdeadbeef);
    ret = pWSASendMsg(INVALID_SOCKET, &msg, 0, NULL, NULL, NULL);
    ok(ret == SOCKET_ERROR, "WSASendMsg should have failed\n");
    err = WSAGetLastError();
    ok(err == WSAENOTSOCK, "expected 10038, got %d instead\n", err);

    WSASetLastError(0xdeadbeef);
    ret = pWSASendMsg(sock, NULL, 0, NULL, NULL, NULL);
    ok(ret == SOCKET_ERROR, "WSASendMsg should have failed\n");
    err = WSAGetLastError();
    ok(err == WSAEFAULT, "expected 10014, got %d instead\n", err);

    WSASetLastError(0xdeadbeef);
    ret = pWSASendMsg(sock, NULL, 0, &bytesSent, NULL, NULL);
    ok(ret == SOCKET_ERROR, "WSASendMsg should have failed\n");
    err = WSAGetLastError();
    ok(err == WSAEFAULT, "expected 10014, got %d instead\n", err);

    WSASetLastError(0xdeadbeef);
    ret = pWSASendMsg(sock, &msg, 0, NULL, NULL, NULL);
    ok(ret == SOCKET_ERROR, "WSASendMsg should have failed\n");
    err = WSAGetLastError();
    ok(err == WSAEFAULT, "expected 10014, got %d instead\n", err);

    closesocket(sock);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    ok(sock != INVALID_SOCKET, "socket() failed\n");

    dst = socket(AF_INET, SOCK_DGRAM, 0);
    ok(dst != INVALID_SOCKET, "socket() failed\n");

    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    ok(!bind(dst, (struct sockaddr*)&sockaddr, sizeof(sockaddr)),
       "bind should have worked\n");

    /* read address to find out the port number to be used in send */
    memset(&sendaddr, 0, sizeof(sendaddr));
    addrlen = sizeof(sendaddr);
    ok(!getsockname(dst, (struct sockaddr *) &sendaddr, &addrlen),
       "getsockname should have worked\n");
    ok(sendaddr.sin_port, "socket port should be != 0\n");

    /* ensure the sending socket is not bound */
    WSASetLastError(0xdeadbeef);
    addrlen = sizeof(sockaddr);
    ret = getsockname(sock, (struct sockaddr*)&sockaddr, &addrlen);
    ok(ret == SOCKET_ERROR, "getsockname should have failed\n");
    err = WSAGetLastError();
    ok(err == WSAEINVAL, "expected 10022, got %d instead\n", err);

    set_blocking(sock, TRUE);

    bytesSent = 0;
    SetLastError(0xdeadbeef);
    ret = pWSASendMsg(sock, &msg, 0, &bytesSent, NULL, NULL);
    ok(!ret, "WSASendMsg should have worked\n");
    ok(GetLastError() == 0 || broken(GetLastError() == 0xdeadbeef) /* Win <= 2008 */,
       "Expected 0, got %d\n", GetLastError());
    ok(bytesSent == iovec[0].len, "incorrect bytes sent, expected %d, sent %d\n",
       iovec[0].len, bytesSent);

    /* receive data */
    addrlen = sizeof(sockaddr);
    memset(buffer, 0, sizeof(buffer));
    SetLastError(0xdeadbeef);
    ret = recvfrom(dst, buffer, sizeof(buffer), 0, (struct sockaddr *) &sockaddr, &addrlen);
    ok(ret == bytesSent, "got %d, expected %d\n",
       ret, bytesSent);
    ok(GetLastError() == ERROR_SUCCESS, "Expected 0, got %d\n", GetLastError());

    /* A successful call to WSASendMsg must have bound the socket */
    addrlen = sizeof(sockaddr);
    sockaddr.sin_port = 0;
    sockaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    ret = getsockname(sock, (struct sockaddr*)&sockaddr, &addrlen);
    ok(!ret, "getsockname should have worked\n");
    ok(sockaddr.sin_addr.s_addr == htonl(INADDR_ANY), "expected 0.0.0.0, got %s\n",
       inet_ntoa(sockaddr.sin_addr));
    ok(sockaddr.sin_port, "sin_port should be != 0\n");

    msg.dwBufferCount = 2; /* send both buffers */

    bytesSent = 0;
    SetLastError(0xdeadbeef);
    ret = pWSASendMsg(sock, &msg, 0, &bytesSent, NULL, NULL);
    ok(!ret, "WSASendMsg should have worked\n");
    ok(bytesSent == iovec[0].len + iovec[1].len, "incorrect bytes sent, expected %d, sent %d\n",
       iovec[0].len + iovec[1].len, bytesSent);
    ok(GetLastError() == 0 || broken(GetLastError() == 0xdeadbeef) /* Win <= 2008 */,
       "Expected 0, got %d\n", GetLastError());

    /* receive data */
    addrlen = sizeof(sockaddr);
    memset(buffer, 0, sizeof(buffer));
    SetLastError(0xdeadbeef);
    ret = recvfrom(dst, buffer, sizeof(buffer), 0, (struct sockaddr *) &sockaddr, &addrlen);
    ok(ret == bytesSent, "got %d, expected %d\n",
       ret, bytesSent);
    ok(GetLastError() == ERROR_SUCCESS, "Expected 0, got %d\n", GetLastError());

    closesocket(sock);
    closesocket(dst);

    /* a bad call to WSASendMsg will also bind the socket */
    addrlen = sizeof(sockaddr);
    sockaddr.sin_port = 0;
    sockaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    ok(sock != INVALID_SOCKET, "socket() failed\n");
    ok(pWSASendMsg(sock, &msg, 0, NULL, NULL, NULL) == SOCKET_ERROR, "WSASendMsg should have failed\n");
todo_wine {
    ok(!getsockname(sock, (struct sockaddr*)&sockaddr, &addrlen), "getsockname should have worked\n");
    ok(sockaddr.sin_addr.s_addr == htonl(INADDR_ANY), "expected 0.0.0.0, got %s\n",
       inet_ntoa(sockaddr.sin_addr));
    ok(sockaddr.sin_port, "sin_port should be > 0\n");
}
    closesocket(sock);

    /* a bad call without msg parameter will not trigger the auto-bind */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    ok(sock != INVALID_SOCKET, "socket() failed\n");
    ok(pWSASendMsg(sock, NULL, 0, NULL, NULL, NULL) == SOCKET_ERROR, "WSASendMsg should have failed\n");
    ok(getsockname(sock, (struct sockaddr*)&sockaddr, &addrlen), "getsockname should have failed\n");
    err = WSAGetLastError();
    ok(err == WSAEINVAL, "expected 10022, got %d instead\n", err);
    closesocket(sock);

    /* SOCK_STREAM sockets are not supported */
    bytesSent = 0;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    ok(sock != INVALID_SOCKET, "socket() failed\n");
    SetLastError(0xdeadbeef);
    ret = pWSASendMsg(sock, &msg, 0, &bytesSent, NULL, NULL);
    ok(ret == SOCKET_ERROR, "WSASendMsg should have failed\n");
    err = WSAGetLastError();
todo_wine
    ok(err == WSAEINVAL, "expected 10014, got %d instead\n", err);
    closesocket(sock);
}

static void test_WSASendTo(void)
{
    SOCKET s;
    struct sockaddr_in addr;
    char buf[12] = "hello world";
    WSABUF data_buf;
    DWORD bytesSent;
    int ret;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(139);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    data_buf.len = sizeof(buf);
    data_buf.buf = buf;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    ok(s != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());

    WSASetLastError(12345);
    ret = WSASendTo(INVALID_SOCKET, &data_buf, 1, NULL, 0, (struct sockaddr*)&addr, sizeof(addr), NULL, NULL);
    ok(ret == SOCKET_ERROR && WSAGetLastError() == WSAENOTSOCK,
       "WSASendTo() failed: %d/%d\n", ret, WSAGetLastError());

    WSASetLastError(12345);
    ret = WSASendTo(s, &data_buf, 1, NULL, 0, (struct sockaddr*)&addr, sizeof(addr), NULL, NULL);
    ok(ret == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT,
       "WSASendTo() failed: %d/%d\n", ret, WSAGetLastError());

    WSASetLastError(12345);
    ret = WSASendTo(s, &data_buf, 1, &bytesSent, 0, (struct sockaddr *)&addr, sizeof(addr), NULL, NULL);
    ok(!ret, "expected success\n");
    ok(!WSAGetLastError(), "got error %u\n", WSAGetLastError());
}

static DWORD WINAPI recv_thread(LPVOID arg)
{
    SOCKET sock = *(SOCKET *)arg;
    char buffer[32];
    WSABUF wsa;
    WSAOVERLAPPED ov;
    DWORD flags = 0;

    wsa.buf = buffer;
    wsa.len = sizeof(buffer);
    ov.hEvent = WSACreateEvent();
    WSARecv(sock, &wsa, 1, NULL, &flags, &ov, NULL);

    WaitForSingleObject(ov.hEvent, 1000);
    WSACloseEvent(ov.hEvent);
    return 0;
}

static int completion_called;

static void WINAPI io_completion(DWORD error, DWORD transferred, WSAOVERLAPPED *overlapped, DWORD flags)
{
    completion_called++;
}

static void test_WSARecv(void)
{
    SOCKET src, dest, server = INVALID_SOCKET;
    char buf[20];
    WSABUF bufs[2];
    WSAOVERLAPPED ov;
    DWORD bytesReturned, flags, id;
    struct linger ling;
    struct sockaddr_in addr;
    int iret, len;
    DWORD dwret;
    BOOL bret;
    HANDLE thread, event = NULL, io_port;

    tcp_socketpair(&src, &dest);

    memset(&ov, 0, sizeof(ov));
    flags = 0;
    bufs[0].len = 2;
    bufs[0].buf = buf;

    /* Send 4 bytes and receive in two calls of 2 */
    SetLastError(0xdeadbeef);
    iret = send(src, "test", 4, 0);
    ok(iret == 4, "Expected 4, got %d\n", iret);
    ok(GetLastError() == ERROR_SUCCESS, "Expected 0, got %d\n", GetLastError());
    SetLastError(0xdeadbeef);
    bytesReturned = 0xdeadbeef;
    iret = WSARecv(dest, bufs, 1, &bytesReturned, &flags, NULL, NULL);
    ok(!iret, "Expected 0, got %d\n", iret);
    ok(bytesReturned == 2, "Expected 2, got %d\n", bytesReturned);
    ok(GetLastError() == ERROR_SUCCESS, "Expected 0, got %d\n", GetLastError());
    SetLastError(0xdeadbeef);
    bytesReturned = 0xdeadbeef;
    iret = WSARecv(dest, bufs, 1, &bytesReturned, &flags, NULL, NULL);
    ok(!iret, "Expected 0, got %d\n", iret);
    ok(bytesReturned == 2, "Expected 2, got %d\n", bytesReturned);
    ok(GetLastError() == ERROR_SUCCESS, "Expected 0, got %d\n", GetLastError());

    bufs[0].len = 4;
    SetLastError(0xdeadbeef);
    iret = send(src, "test", 4, 0);
    ok(iret == 4, "Expected 4, got %d\n", iret);
    ok(GetLastError() == ERROR_SUCCESS, "Expected 0, got %d\n", GetLastError());
    SetLastError(0xdeadbeef);
    bytesReturned = 0xdeadbeef;
    iret = WSARecv(dest, bufs, 1, &bytesReturned, &flags, NULL, NULL);
    ok(!iret, "Expected 0, got %d\n", iret);
    ok(bytesReturned == 4, "Expected 4, got %d\n", bytesReturned);
    ok(GetLastError() == ERROR_SUCCESS, "Expected 0, got %d\n", GetLastError());

    /* Test 2 buffers */
    bufs[0].len = 4;
    bufs[1].len = 5;
    bufs[1].buf = buf + 10;
    SetLastError(0xdeadbeef);
    iret = send(src, "deadbeefs", 9, 0);
    ok(iret == 9, "Expected 9, got %d\n", iret);
    ok(GetLastError() == ERROR_SUCCESS, "Expected 0, got %d\n", GetLastError());
    SetLastError(0xdeadbeef);
    bytesReturned = 0xdeadbeef;
    iret = WSARecv(dest, bufs, 2, &bytesReturned, &flags, NULL, NULL);
    ok(!iret, "Expected 0, got %d\n", iret);
    ok(bytesReturned == 9, "Expected 9, got %d\n", bytesReturned);
    bufs[0].buf[4] = '\0';
    bufs[1].buf[5] = '\0';
    ok(!strcmp(bufs[0].buf, "dead"), "buf[0] doesn't match: %s != dead\n", bufs[0].buf);
    ok(!strcmp(bufs[1].buf, "beefs"), "buf[1] doesn't match: %s != beefs\n", bufs[1].buf);
    ok(GetLastError() == ERROR_SUCCESS, "Expected 0, got %d\n", GetLastError());

    bufs[0].len = sizeof(buf);
    ov.hEvent = event = CreateEventA(NULL, FALSE, FALSE, NULL);
    ok(ov.hEvent != NULL, "could not create event object, errno = %d\n", GetLastError());
    if (!event)
        goto end;

    ling.l_onoff = 1;
    ling.l_linger = 0;
    iret = setsockopt (src, SOL_SOCKET, SO_LINGER, (char *) &ling, sizeof(ling));
    ok(!iret, "Failed to set linger %d\n", GetLastError());

    iret = WSARecv(dest, bufs, 1, NULL, &flags, &ov, NULL);
    ok(iret == SOCKET_ERROR && GetLastError() == ERROR_IO_PENDING, "WSARecv failed - %d error %d\n", iret, GetLastError());

    iret = WSARecv(dest, bufs, 1, &bytesReturned, &flags, &ov, NULL);
    ok(iret == SOCKET_ERROR && GetLastError() == ERROR_IO_PENDING, "WSARecv failed - %d error %d\n", iret, GetLastError());

    closesocket(src);
    src = INVALID_SOCKET;

    dwret = WaitForSingleObject(ov.hEvent, 1000);
    ok(dwret == WAIT_OBJECT_0, "Waiting for disconnect event failed with %d + errno %d\n", dwret, GetLastError());

    bret = GetOverlappedResult((HANDLE)dest, &ov, &bytesReturned, FALSE);
    todo_wine ok(!bret, "expected failure\n");
    todo_wine ok(GetLastError() == ERROR_NETNAME_DELETED, "got error %u\n", GetLastError());
    ok(bytesReturned == 0, "Bytes received is %d\n", bytesReturned);
    closesocket(dest);
    dest = INVALID_SOCKET;

    src = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    ok(src != INVALID_SOCKET, "failed to create socket %d\n", WSAGetLastError());
    if (src == INVALID_SOCKET) goto end;

    server = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    ok(server != INVALID_SOCKET, "failed to create socket %d\n", WSAGetLastError());
    if (server == INVALID_SOCKET) goto end;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    iret = bind(server, (struct sockaddr *)&addr, sizeof(addr));
    ok(!iret, "failed to bind, error %u\n", WSAGetLastError());

    len = sizeof(addr);
    iret = getsockname(server, (struct sockaddr *)&addr, &len);
    ok(!iret, "failed to get address, error %u\n", WSAGetLastError());

    iret = listen(server, 1);
    ok(!iret, "failed to listen, error %u\n", WSAGetLastError());

    iret = connect(src, (struct sockaddr *)&addr, sizeof(addr));
    ok(!iret, "failed to connect, error %u\n", WSAGetLastError());

    len = sizeof(addr);
    dest = accept(server, (struct sockaddr *)&addr, &len);
    ok(dest != INVALID_SOCKET, "failed to create socket %d\n", WSAGetLastError());
    if (dest == INVALID_SOCKET) goto end;

    send(src, "test message", sizeof("test message"), 0);
    thread = CreateThread(NULL, 0, recv_thread, &dest, 0, &id);
    WaitForSingleObject(thread, 3000);
    CloseHandle(thread);

    memset(&ov, 0, sizeof(ov));
    ov.hEvent = event;
    ResetEvent(event);
    iret = WSARecv(dest, bufs, 1, NULL, &flags, &ov, io_completion);
    ok(iret == SOCKET_ERROR && GetLastError() == ERROR_IO_PENDING, "WSARecv failed - %d error %d\n", iret, GetLastError());
    send(src, "test message", sizeof("test message"), 0);

    completion_called = 0;
    dwret = SleepEx(1000, TRUE);
    ok(dwret == WAIT_IO_COMPLETION, "got %u\n", dwret);
    ok(completion_called == 1, "completion not called\n");

    dwret = WaitForSingleObject(event, 1);
    ok(dwret == WAIT_TIMEOUT, "got %u\n", dwret);

    io_port = CreateIoCompletionPort( (HANDLE)dest, NULL, 0, 0 );
    ok(io_port != NULL, "failed to create completion port %u\n", GetLastError());

    /* Using completion function on socket associated with completion port is not allowed. */
    memset(&ov, 0, sizeof(ov));
    completion_called = 0;
    iret = WSARecv(dest, bufs, 1, NULL, &flags, &ov, io_completion);
    ok(iret == SOCKET_ERROR && GetLastError() == WSAEINVAL, "WSARecv failed - %d error %d\n", iret, GetLastError());
    ok(!completion_called, "completion called\n");

    CloseHandle(io_port);

end:
    if (server != INVALID_SOCKET)
        closesocket(server);
    if (dest != INVALID_SOCKET)
        closesocket(dest);
    if (src != INVALID_SOCKET)
        closesocket(src);
    if (event)
        WSACloseEvent(event);
}

struct write_watch_thread_args
{
    int func;
    SOCKET dest;
    void *base;
    DWORD size;
    const char *expect;
};

static DWORD CALLBACK write_watch_thread( void *arg )
{
    struct write_watch_thread_args *args = arg;
    struct sockaddr addr;
    int addr_len = sizeof(addr), ret;
    DWORD bytes, flags = 0;
    WSABUF buf[1];

    switch (args->func)
    {
    case 0:
        ret = recv( args->dest, args->base, args->size, 0 );
        ok( ret == strlen(args->expect) + 1, "wrong len %d\n", ret );
        ok( !strcmp( args->base, args->expect ), "wrong data\n" );
        break;
    case 1:
        ret = recvfrom( args->dest, args->base, args->size, 0, &addr, &addr_len );
        ok( ret == strlen(args->expect) + 1, "wrong len %d\n", ret );
        ok( !strcmp( args->base, args->expect ), "wrong data\n" );
        break;
    case 2:
        buf[0].len = args->size;
        buf[0].buf = args->base;
        ret = WSARecv( args->dest, buf, 1, &bytes, &flags, NULL, NULL );
        ok( !ret, "WSARecv failed %u\n", GetLastError() );
        ok( bytes == strlen(args->expect) + 1, "wrong len %d\n", bytes );
        ok( !strcmp( args->base, args->expect ), "wrong data\n" );
        break;
    case 3:
        buf[0].len = args->size;
        buf[0].buf = args->base;
        ret = WSARecvFrom( args->dest, buf, 1, &bytes, &flags, &addr, &addr_len, NULL, NULL );
        ok( !ret, "WSARecvFrom failed %u\n", GetLastError() );
        ok( bytes == strlen(args->expect) + 1, "wrong len %d\n", bytes );
        ok( !strcmp( args->base, args->expect ), "wrong data\n" );
        break;
    }
    return 0;
}

static void test_write_watch(void)
{
    SOCKET src, dest;
    WSABUF bufs[2];
    WSAOVERLAPPED ov;
    struct write_watch_thread_args args;
    DWORD bytesReturned, flags, size;
    struct sockaddr addr;
    int addr_len, ret;
    HANDLE thread, event;
    char *base;
    void *results[64];
    ULONG_PTR count;
    ULONG pagesize;
    UINT (WINAPI *pGetWriteWatch)(DWORD,LPVOID,SIZE_T,LPVOID*,ULONG_PTR*,ULONG*);

    pGetWriteWatch = (void *)GetProcAddress( GetModuleHandleA("kernel32.dll"), "GetWriteWatch" );
    if (!pGetWriteWatch)
    {
        win_skip( "write watched not supported\n" );
        return;
    }

    tcp_socketpair(&src, &dest);

    memset(&ov, 0, sizeof(ov));
    ov.hEvent = event = CreateEventA(NULL, FALSE, FALSE, NULL);
    ok(ov.hEvent != NULL, "could not create event object, errno = %d\n", GetLastError());

    flags = 0;

    size = 0x10000;
    base = VirtualAlloc( 0, size, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE );
    ok( base != NULL, "VirtualAlloc failed %u\n", GetLastError() );

    memset( base, 0, size );
    count = 64;
    ret = pGetWriteWatch( WRITE_WATCH_FLAG_RESET, base, size, results, &count, &pagesize );
    ok( !ret, "GetWriteWatch failed %u\n", GetLastError() );
    ok( count == 16, "wrong count %lu\n", count );

    bufs[0].len = 5;
    bufs[0].buf = base;
    bufs[1].len = 0x8000;
    bufs[1].buf = base + 0x4000;

    ret = WSARecv( dest, bufs, 2, NULL, &flags, &ov, NULL);
    ok(ret == SOCKET_ERROR && GetLastError() == ERROR_IO_PENDING,
       "WSARecv failed - %d error %d\n", ret, GetLastError());

    count = 64;
    ret = pGetWriteWatch( WRITE_WATCH_FLAG_RESET, base, size, results, &count, &pagesize );
    ok( !ret, "GetWriteWatch failed %u\n", GetLastError() );
    ok( count == 9, "wrong count %lu\n", count );
    ok( !base[0], "data set\n" );

    send(src, "test message", sizeof("test message"), 0);

    ret = GetOverlappedResult( (HANDLE)dest, &ov, &bytesReturned, TRUE );
    ok( ret, "GetOverlappedResult failed %u\n", GetLastError() );
    ok( bytesReturned == sizeof("test message"), "wrong size %u\n", bytesReturned );
    ok( !memcmp( base, "test ", 5 ), "wrong data %s\n", base );
    ok( !memcmp( base + 0x4000, "message", 8 ), "wrong data %s\n", base + 0x4000 );

    count = 64;
    ret = pGetWriteWatch( WRITE_WATCH_FLAG_RESET, base, size, results, &count, &pagesize );
    ok( !ret, "GetWriteWatch failed %u\n", GetLastError() );
    ok( count == 0, "wrong count %lu\n", count );

    memset( base, 0, size );
    count = 64;
    ret = pGetWriteWatch( WRITE_WATCH_FLAG_RESET, base, size, results, &count, &pagesize );
    ok( !ret, "GetWriteWatch failed %u\n", GetLastError() );
    ok( count == 16, "wrong count %lu\n", count );

    bufs[1].len = 0x4000;
    bufs[1].buf = base + 0x2000;
    ret = WSARecvFrom( dest, bufs, 2, NULL, &flags, &addr, &addr_len, &ov, NULL);
    ok(ret == SOCKET_ERROR && GetLastError() == ERROR_IO_PENDING,
       "WSARecv failed - %d error %d\n", ret, GetLastError());

    count = 64;
    ret = pGetWriteWatch( WRITE_WATCH_FLAG_RESET, base, size, results, &count, &pagesize );
    ok( !ret, "GetWriteWatch failed %u\n", GetLastError() );
    ok( count == 5, "wrong count %lu\n", count );
    ok( !base[0], "data set\n" );

    send(src, "test message", sizeof("test message"), 0);

    ret = GetOverlappedResult( (HANDLE)dest, &ov, &bytesReturned, TRUE );
    ok( ret, "GetOverlappedResult failed %u\n", GetLastError() );
    ok( bytesReturned == sizeof("test message"), "wrong size %u\n", bytesReturned );
    ok( !memcmp( base, "test ", 5 ), "wrong data %s\n", base );
    ok( !memcmp( base + 0x2000, "message", 8 ), "wrong data %s\n", base + 0x2000 );

    count = 64;
    ret = pGetWriteWatch( WRITE_WATCH_FLAG_RESET, base, size, results, &count, &pagesize );
    ok( !ret, "GetWriteWatch failed %u\n", GetLastError() );
    ok( count == 0, "wrong count %lu\n", count );

    memset( base, 0, size );
    count = 64;
    ret = pGetWriteWatch( WRITE_WATCH_FLAG_RESET, base, size, results, &count, &pagesize );
    ok( !ret, "GetWriteWatch failed %u\n", GetLastError() );
    ok( count == 16, "wrong count %lu\n", count );

    args.dest = dest;
    args.base = base;
    args.size = 0x7002;
    args.expect = "test message";
    for (args.func = 0; args.func < 4; args.func++)
    {
        thread = CreateThread( NULL, 0, write_watch_thread, &args, 0, NULL );
        Sleep( 200 );

        count = 64;
        ret = pGetWriteWatch( WRITE_WATCH_FLAG_RESET, base, size, results, &count, &pagesize );
        ok( !ret, "GetWriteWatch failed %u\n", GetLastError() );
        ok( count == 8, "wrong count %lu\n", count );

        send(src, "test message", sizeof("test message"), 0);
        WaitForSingleObject( thread, 10000 );
        CloseHandle( thread );

        count = 64;
        ret = pGetWriteWatch( WRITE_WATCH_FLAG_RESET, base, size, results, &count, &pagesize );
        ok( !ret, "GetWriteWatch failed %u\n", GetLastError() );
        ok( count == 0, "wrong count %lu\n", count );
    }
    WSACloseEvent( event );
    closesocket( dest );
    closesocket( src );
    VirtualFree( base, 0, MEM_FREE );
}

#define POLL_CLEAR() ix = 0
#define POLL_SET(s, ev) {fds[ix].fd = s; fds[ix++].events = ev;}
#define POLL_ISSET(s, rev) poll_isset(fds, ix, s, rev)
static BOOL poll_isset(WSAPOLLFD *fds, int max, SOCKET s, int rev)
{
    int k;
    for (k = 0; k < max; k++)
        if (fds[k].fd == s && (fds[k].revents == rev)) return TRUE;
    return FALSE;
}

static void test_WSAPoll(void)
{
    int ix, ret, err;
    SOCKET fdListen, fdRead, fdWrite;
    struct sockaddr_in address;
    socklen_t len;
    static char tmp_buf[1024];
    WSAPOLLFD fds[16];
    HANDLE thread_handle;
    DWORD id;

    if (!pWSAPoll) /* >= Vista */
    {
        win_skip("WSAPoll is unsupported, some tests will be skipped.\n");
        return;
    }

    /* Invalid parameters test */
    SetLastError(0xdeadbeef);
    ret = pWSAPoll(NULL, 0, 0);
    err = GetLastError();
    ok(ret == SOCKET_ERROR, "expected -1, got %d\n", ret);
    ok(err == WSAEINVAL, "expected 10022, got %d\n", err);
    SetLastError(0xdeadbeef);
    ret = pWSAPoll(NULL, 1, 0);
    err = GetLastError();
    ok(ret == SOCKET_ERROR, "expected -1, got %d\n", ret);
    ok(err == WSAEFAULT, "expected 10014, got %d\n", err);
    SetLastError(0xdeadbeef);
    ret = pWSAPoll(NULL, 0, 1);
    err = GetLastError();
    ok(ret == SOCKET_ERROR, "expected -1, got %d\n", ret);
    ok(err == WSAEINVAL, "expected 10022, got %d\n", err);
    SetLastError(0xdeadbeef);
    ret = pWSAPoll(NULL, 1, 1);
    err = GetLastError();
    ok(ret == SOCKET_ERROR, "expected -1, got %d\n", ret);
    ok(err == WSAEFAULT, "expected 10014, got %d\n", err);

    /* WSAPoll() tries to mime the unix poll() call. The following tests do:
     * - check if a connection attempt ended with success or error;
     * - check if a pending connection is waiting for acceptance;
     * - check for data to read, availability for write and OOB data
     */
    memset(&address, 0, sizeof(address));
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    address.sin_family = AF_INET;
    len = sizeof(address);
    fdListen = setup_server_socket(&address, &len);

    /* When no events are pending poll returns 0 with no error */
    POLL_CLEAR();
    POLL_SET(fdListen, POLLIN);
    ret = pWSAPoll(fds, ix, 100);
    ok(ret == 0, "expected 0, got %d\n", ret);

    /* Test listening socket connection attempt notifications */
    fdWrite = setup_connector_socket(&address, len, TRUE);
    POLL_CLEAR();
    POLL_SET(fdListen, POLLIN | POLLOUT);
    ret = pWSAPoll(fds, ix, 100);
    ok(ret == 1, "expected 1, got %d\n", ret);
    ok(POLL_ISSET(fdListen, POLLRDNORM), "fdListen socket events incorrect\n");
    len = sizeof(address);
    fdRead = accept(fdListen, (struct sockaddr*) &address, &len);
    ok(fdRead != INVALID_SOCKET, "expected a valid socket\n");

    /* Test client side connection attempt notifications */
    POLL_CLEAR();
    POLL_SET(fdListen, POLLIN | POLLOUT);
    POLL_SET(fdRead, POLLIN | POLLOUT);
    POLL_SET(fdWrite, POLLIN | POLLOUT);
    ret = pWSAPoll(fds, ix, 100);
    ok(ret == 2, "expected 2, got %d\n", ret);
    ok(POLL_ISSET(fdWrite, POLLWRNORM), "fdWrite socket events incorrect\n");
    ok(POLL_ISSET(fdRead, POLLWRNORM), "fdRead socket events incorrect\n");
    len = sizeof(id);
    id = 0xdeadbeef;
    err = getsockopt(fdWrite, SOL_SOCKET, SO_ERROR, (char*)&id, &len);
    ok(!err, "getsockopt failed with %d\n", WSAGetLastError());
    ok(id == 0, "expected 0, got %d\n", id);

    /* Test data receiving notifications */
    ret = send(fdWrite, "1234", 4, 0);
    ok(ret == 4, "expected 4, got %d\n", ret);
    POLL_CLEAR();
    POLL_SET(fdListen, POLLIN | POLLOUT);
    POLL_SET(fdRead, POLLIN);
    ret = pWSAPoll(fds, ix, 100);
    ok(ret == 1, "expected 1, got %d\n", ret);
    ok(POLL_ISSET(fdRead, POLLRDNORM), "fdRead socket events incorrect\n");
    ret = recv(fdRead, tmp_buf, sizeof(tmp_buf), 0);
    ok(ret == 4, "expected 4, got %d\n", ret);
    ok(!strcmp(tmp_buf, "1234"), "data received differs from sent\n");

    /* Test OOB data notifications */
    ret = send(fdWrite, "A", 1, MSG_OOB);
    ok(ret == 1, "expected 1, got %d\n", ret);
    POLL_CLEAR();
    POLL_SET(fdListen, POLLIN | POLLOUT);
    POLL_SET(fdRead, POLLIN);
    ret = pWSAPoll(fds, ix, 100);
    ok(ret == 1, "expected 1, got %d\n", ret);
    ok(POLL_ISSET(fdRead, POLLRDBAND), "fdRead socket events incorrect\n");
    tmp_buf[0] = 0xAF;
    ret = recv(fdRead, tmp_buf, sizeof(tmp_buf), MSG_OOB);
    ok(ret == 1, "expected 1, got %d\n", ret);
    ok(tmp_buf[0] == 'A', "expected 'A', got 0x%02X\n", tmp_buf[0]);

    /* If the socket is OOBINLINED the notification is like normal data */
    ret = 1;
    ret = setsockopt(fdRead, SOL_SOCKET, SO_OOBINLINE, (char*) &ret, sizeof(ret));
    ok(ret == 0, "expected 0, got %d\n", ret);
    ret = send(fdWrite, "A", 1, MSG_OOB);
    ok(ret == 1, "expected 1, got %d\n", ret);
    POLL_CLEAR();
    POLL_SET(fdListen, POLLIN | POLLOUT);
    POLL_SET(fdRead, POLLIN | POLLOUT);
    ret = pWSAPoll(fds, ix, 100);
    ok(ret == 1, "expected 1, got %d\n", ret);
    tmp_buf[0] = 0xAF;
    SetLastError(0xdeadbeef);
    ret = recv(fdRead, tmp_buf, sizeof(tmp_buf), MSG_OOB);
    ok(ret == SOCKET_ERROR, "expected -1, got %d\n", ret);
    ok(GetLastError() == WSAEINVAL, "expected 10022, got %d\n", GetLastError());
    ret = recv(fdRead, tmp_buf, sizeof(tmp_buf), 0);
    ok(ret == 1, "expected 1, got %d\n", ret);
    ok(tmp_buf[0] == 'A', "expected 'A', got 0x%02X\n", tmp_buf[0]);

    /* Test connection closed notifications */
    ret = closesocket(fdRead);
    ok(ret == 0, "expected 0, got %d\n", ret);
    POLL_CLEAR();
    POLL_SET(fdListen, POLLIN | POLLOUT);
    POLL_SET(fdWrite, POLLIN);
    ret = pWSAPoll(fds, ix, 100);
    ok(ret == 1, "expected 1, got %d\n", ret);
    ok(POLL_ISSET(fdWrite, POLLHUP), "fdWrite socket events incorrect\n");
    ret = recv(fdWrite, tmp_buf, sizeof(tmp_buf), 0);
    ok(ret == 0, "expected 0, got %d\n", ret);
    ret = closesocket(fdWrite);
    ok(ret == 0, "expected 0, got %d\n", ret);
    ret = closesocket(fdListen);
    ok(ret == 0, "expected 0, got %d\n", ret);

    /* The following WSAPoll() call times out on versions older than w10pro64,
     * but even on w10pro64 it takes over 2 seconds for an error to be reported,
     * so make the test interactive-only. */
    if (winetest_interactive)
    {
        len = sizeof(address);
        fdWrite = setup_connector_socket(&address, len, TRUE);
        POLL_CLEAR();
        POLL_SET(fdWrite, POLLIN | POLLOUT);
        ret = pWSAPoll(fds, ix, 10000);
        ok(ret == 1, "expected 0, got %d\n", ret);
        len = sizeof(id);
        id = 0xdeadbeef;
        err = getsockopt(fdWrite, SOL_SOCKET, SO_ERROR, (char*)&id, &len);
        ok(!err, "getsockopt failed with %d\n", WSAGetLastError());
        ok(id == WSAECONNREFUSED, "expected 10061, got %d\n", id);
        closesocket(fdWrite);
    }

    /* Try poll() on a closed socket after connection */
    tcp_socketpair(&fdRead, &fdWrite);
    closesocket(fdRead);
    POLL_CLEAR();
    POLL_SET(fdWrite, POLLIN | POLLOUT);
    POLL_SET(fdRead, POLLIN | POLLOUT);
    ret = pWSAPoll(fds, ix, 2000);
    ok(ret == 1, "expected 1, got %d\n", ret);
    ok(POLL_ISSET(fdRead, POLLNVAL), "fdRead socket events incorrect\n");
    POLL_CLEAR();
    POLL_SET(fdWrite, POLLIN | POLLOUT);
    ret = pWSAPoll(fds, ix, 2000);
    ok(ret == 1, "expected 1, got %d\n", ret);
todo_wine
    ok(POLL_ISSET(fdWrite, POLLWRNORM | POLLHUP) || broken(POLL_ISSET(fdWrite, POLLWRNORM)) /* <= 2008 */,
       "fdWrite socket events incorrect\n");
    closesocket(fdWrite);

    /* Close the socket currently being polled in a thread */
    tcp_socketpair(&fdRead, &fdWrite);
    thread_handle = CreateThread(NULL, 0, SelectCloseThread, &fdWrite, 0, &id);
    ok(thread_handle != NULL, "CreateThread failed unexpectedly: %d\n", GetLastError());
    POLL_CLEAR();
    POLL_SET(fdWrite, POLLIN | POLLOUT);
    ret = pWSAPoll(fds, ix, 2000);
    ok(ret == 1, "expected 1, got %d\n", ret);
    ok(POLL_ISSET(fdWrite, POLLWRNORM), "fdWrite socket events incorrect\n");
    WaitForSingleObject (thread_handle, 1000);
    closesocket(fdRead);
    /* test again with less flags - behavior changes */
    tcp_socketpair(&fdRead, &fdWrite);
    thread_handle = CreateThread(NULL, 0, SelectCloseThread, &fdWrite, 0, &id);
    ok(thread_handle != NULL, "CreateThread failed unexpectedly: %d\n", GetLastError());
    POLL_CLEAR();
    POLL_SET(fdWrite, POLLIN);
    ret = pWSAPoll(fds, ix, 2000);
    ok(ret == 1, "expected 1, got %d\n", ret);
    ok(POLL_ISSET(fdWrite, POLLNVAL), "fdWrite socket events incorrect\n");
    WaitForSingleObject (thread_handle, 1000);
    closesocket(fdRead);
}
#undef POLL_SET
#undef POLL_ISSET
#undef POLL_CLEAR

static void test_ConnectEx(void)
{
    SOCKET listener = INVALID_SOCKET;
    SOCKET acceptor = INVALID_SOCKET;
    SOCKET connector = INVALID_SOCKET;
    struct sockaddr_in address, conaddress;
    int addrlen;
    OVERLAPPED overlapped, *olp;
    LPFN_CONNECTEX pConnectEx;
    GUID connectExGuid = WSAID_CONNECTEX;
    HANDLE previous_port, io_port;
    DWORD bytesReturned;
    char buffer[1024];
    ULONG_PTR key;
    BOOL bret;
    DWORD dwret;
    int iret;

    memset(&overlapped, 0, sizeof(overlapped));

    listener = socket(AF_INET, SOCK_STREAM, 0);
    ok(listener != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());

    connector = socket(AF_INET, SOCK_STREAM, 0);
    ok(connector != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    iret = bind(listener, (struct sockaddr*)&address, sizeof(address));
    ok(!iret, "failed to bind, error %u\n", WSAGetLastError());

    addrlen = sizeof(address);
    iret = getsockname(listener, (struct sockaddr*)&address, &addrlen);
    ok(!iret, "failed to get address, error %u\n", WSAGetLastError());

    iret = set_blocking(listener, TRUE);
    ok(!iret, "failed to set nonblocking, error %u\n", WSAGetLastError());

    bytesReturned = 0xdeadbeef;
    iret = WSAIoctl(connector, SIO_GET_EXTENSION_FUNCTION_POINTER, &connectExGuid, sizeof(connectExGuid),
        &pConnectEx, sizeof(pConnectEx), &bytesReturned, NULL, NULL);
    ok(!iret, "failed to get ConnectEx, error %u\n", WSAGetLastError());

    ok(bytesReturned == sizeof(pConnectEx), "expected sizeof(pConnectEx), got %u\n", bytesReturned);

    bret = pConnectEx(INVALID_SOCKET, (struct sockaddr*)&address, addrlen, NULL, 0, &bytesReturned, &overlapped);
    ok(bret == FALSE && WSAGetLastError() == WSAENOTSOCK, "ConnectEx on invalid socket "
        "returned %d + errno %d\n", bret, WSAGetLastError());

    bret = pConnectEx(connector, (struct sockaddr*)&address, addrlen, NULL, 0, &bytesReturned, &overlapped);
    ok(bret == FALSE && WSAGetLastError() == WSAEINVAL, "ConnectEx on a unbound socket "
        "returned %d + errno %d\n", bret, WSAGetLastError());

    /* ConnectEx needs a bound socket */
    memset(&conaddress, 0, sizeof(conaddress));
    conaddress.sin_family = AF_INET;
    conaddress.sin_addr.s_addr = inet_addr("127.0.0.1");
    iret = bind(connector, (struct sockaddr*)&conaddress, sizeof(conaddress));
    ok(!iret, "failed to bind, error %u\n", WSAGetLastError());

    bret = pConnectEx(connector, (struct sockaddr*)&address, addrlen, NULL, 0, &bytesReturned, NULL);
    ok(bret == FALSE && WSAGetLastError() == ERROR_INVALID_PARAMETER, "ConnectEx on a NULL overlapped "
        "returned %d + errno %d\n", bret, WSAGetLastError());

    overlapped.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);

    iret = listen(listener, 1);
    ok(!iret, "failed to listen, error %u\n", WSAGetLastError());

    bret = pConnectEx(connector, (struct sockaddr*)&address, addrlen, NULL, 0, &bytesReturned, &overlapped);
    ok(bret == FALSE && WSAGetLastError() == ERROR_IO_PENDING, "ConnectEx failed: "
        "returned %d + errno %d\n", bret, WSAGetLastError());
    dwret = WaitForSingleObject(overlapped.hEvent, 15000);
    ok(dwret == WAIT_OBJECT_0, "Waiting for connect event failed with %d + errno %d\n", dwret, GetLastError());

    bret = GetOverlappedResult((HANDLE)connector, &overlapped, &bytesReturned, FALSE);
    ok(bret, "Connecting failed, error %d\n", GetLastError());
    ok(bytesReturned == 0, "Bytes sent is %d\n", bytesReturned);

    closesocket(connector);
    connector = socket(AF_INET, SOCK_STREAM, 0);
    ok(connector != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());
    /* ConnectEx needs a bound socket */
    memset(&conaddress, 0, sizeof(conaddress));
    conaddress.sin_family = AF_INET;
    conaddress.sin_addr.s_addr = inet_addr("127.0.0.1");
    iret = bind(connector, (struct sockaddr*)&conaddress, sizeof(conaddress));
    ok(!iret, "failed to bind, error %u\n", WSAGetLastError());

    acceptor = accept(listener, NULL, NULL);
    ok(acceptor != INVALID_SOCKET, "failed to accept socket, error %u\n", WSAGetLastError());

    buffer[0] = '1';
    buffer[1] = '2';
    buffer[2] = '3';
    bret = pConnectEx(connector, (struct sockaddr*)&address, addrlen, buffer, 3, &bytesReturned, &overlapped);
    memset(buffer, 0, 3);
    ok(bret == FALSE && WSAGetLastError() == ERROR_IO_PENDING, "ConnectEx failed: "
        "returned %d + errno %d\n", bret, WSAGetLastError());
    dwret = WaitForSingleObject(overlapped.hEvent, 15000);
    ok(dwret == WAIT_OBJECT_0, "Waiting for connect event failed with %d + errno %d\n", dwret, GetLastError());

    bret = GetOverlappedResult((HANDLE)connector, &overlapped, &bytesReturned, FALSE);
    ok(bret, "Connecting failed, error %d\n", GetLastError());
    ok(bytesReturned == 3, "Bytes sent is %d\n", bytesReturned);

    acceptor = accept(listener, NULL, NULL);
    ok(acceptor != INVALID_SOCKET, "could not accept socket error %d\n", WSAGetLastError());

    bytesReturned = recv(acceptor, buffer, 3, 0);
    buffer[4] = 0;
    ok(bytesReturned == 3, "Didn't get all sent data, got only %d\n", bytesReturned);
    ok(buffer[0] == '1' && buffer[1] == '2' && buffer[2] == '3',
       "Failed to get the right data, expected '123', got '%s'\n", buffer);

    closesocket(connector);
    connector = socket(AF_INET, SOCK_STREAM, 0);
    ok(connector != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());
    /* ConnectEx needs a bound socket */
    memset(&conaddress, 0, sizeof(conaddress));
    conaddress.sin_family = AF_INET;
    conaddress.sin_addr.s_addr = inet_addr("127.0.0.1");
    iret = bind(connector, (struct sockaddr*)&conaddress, sizeof(conaddress));
    ok(!iret, "failed to bind, error %u\n", WSAGetLastError());

    closesocket(acceptor);
    closesocket(listener);

    /* Connect with error */

    address.sin_port = htons(1);

    previous_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    ok( previous_port != NULL, "Failed to create completion port %u\n", GetLastError());

    io_port = CreateIoCompletionPort((HANDLE)connector, previous_port, 125, 0);
    ok(io_port != NULL, "failed to create completion port %u\n", GetLastError());

    bret = SetFileCompletionNotificationModes((HANDLE)connector, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS);
    ok(bret, "Got unexpected bret %#x, GetLastError() %u.\n", bret, GetLastError());

    bret = pConnectEx(connector, (struct sockaddr*)&address, addrlen, NULL, 0, &bytesReturned, &overlapped);
    ok(bret == FALSE && GetLastError() == ERROR_IO_PENDING, "ConnectEx to bad destination failed: "
        "returned %d + errno %d\n", bret, GetLastError());
    dwret = WaitForSingleObject(overlapped.hEvent, 15000);
    ok(dwret == WAIT_OBJECT_0, "Waiting for connect event failed with %d + errno %d\n", dwret, GetLastError());

    bytesReturned = 0xdeadbeef;
    bret = GetQueuedCompletionStatus( io_port, &bytesReturned, &key, &olp, 200 );
    ok(!bret && GetLastError() == ERROR_CONNECTION_REFUSED, "Got unexpected bret %#x, GetLastError() %u.\n",
            bret, GetLastError());
    ok(key == 125, "Key is %lu\n", key);
    ok(!bytesReturned, "Number of bytes transferred is %u\n", bytesReturned);
    ok(olp == &overlapped, "Overlapped structure is at %p\n", olp);

    bret = GetOverlappedResult((HANDLE)connector, &overlapped, &bytesReturned, FALSE);
    ok(bret == FALSE && GetLastError() == ERROR_CONNECTION_REFUSED,
       "Connecting to a disconnected host returned error %d - %d\n", bret, WSAGetLastError());

    CloseHandle(io_port);

    WSACloseEvent(overlapped.hEvent);
    closesocket(connector);

    CloseHandle(previous_port);
}

static void test_AcceptEx(void)
{
    SOCKET listener, acceptor, acceptor2, connector, connector2;
    struct sockaddr_in bindAddress, peerAddress, *readBindAddress, *readRemoteAddress;
    int socklen, optlen;
    GUID acceptExGuid = WSAID_ACCEPTEX, getAcceptExGuid = WSAID_GETACCEPTEXSOCKADDRS;
    LPFN_ACCEPTEX pAcceptEx = NULL;
    LPFN_GETACCEPTEXSOCKADDRS pGetAcceptExSockaddrs = NULL;
    fd_set fds_accept, fds_send;
    static const struct timeval timeout = {1, 0};
    DWORD bytesReturned, connect_time;
    char buffer[1024], ipbuffer[32];
    OVERLAPPED overlapped;
    int iret, localSize = sizeof(struct sockaddr_in), remoteSize = localSize;
    BOOL bret;
    DWORD dwret;

    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);

    listener = socket(AF_INET, SOCK_STREAM, 0);
    ok(listener != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());

    acceptor = socket(AF_INET, SOCK_STREAM, 0);
    ok(acceptor != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());

    memset(&bindAddress, 0, sizeof(bindAddress));
    bindAddress.sin_family = AF_INET;
    bindAddress.sin_addr.s_addr = inet_addr("127.0.0.1");
    iret = bind(listener, (struct sockaddr*)&bindAddress, sizeof(bindAddress));
    ok(!iret, "failed to bind, error %u\n", WSAGetLastError());

    socklen = sizeof(bindAddress);
    iret = getsockname(listener, (struct sockaddr*)&bindAddress, &socklen);
    ok(!iret, "failed to get address, error %u\n", WSAGetLastError());

    iret = set_blocking(listener, FALSE);
    ok(!iret, "Failed to set nonblocking, error %u\n", WSAGetLastError());

    iret = WSAIoctl(listener, SIO_GET_EXTENSION_FUNCTION_POINTER, &acceptExGuid, sizeof(acceptExGuid),
        &pAcceptEx, sizeof(pAcceptEx), &bytesReturned, NULL, NULL);
    ok(!iret, "Failed to get AcceptEx, error %u\n", WSAGetLastError());

    iret = WSAIoctl(listener, SIO_GET_EXTENSION_FUNCTION_POINTER, &getAcceptExGuid, sizeof(getAcceptExGuid),
        &pGetAcceptExSockaddrs, sizeof(pGetAcceptExSockaddrs), &bytesReturned, NULL, NULL);
    ok(!iret, "Failed to get GetAcceptExSockaddrs, error %u\n", WSAGetLastError());

    overlapped.Internal = 0xdeadbeef;
    bret = pAcceptEx(INVALID_SOCKET, acceptor, buffer, sizeof(buffer) - 2*(sizeof(struct sockaddr_in) + 16),
        sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
        &bytesReturned, &overlapped);
    ok(bret == FALSE && WSAGetLastError() == WSAENOTSOCK, "AcceptEx on invalid listening socket "
        "returned %d + errno %d\n", bret, WSAGetLastError());
    ok(overlapped.Internal == STATUS_PENDING, "got %08x\n", (ULONG)overlapped.Internal);

    overlapped.Internal = 0xdeadbeef;
    bret = pAcceptEx(listener, acceptor, buffer, sizeof(buffer) - 2*(sizeof(struct sockaddr_in) + 16),
        sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
        &bytesReturned, &overlapped);
todo_wine
    ok(bret == FALSE && WSAGetLastError() == WSAEINVAL, "AcceptEx on a non-listening socket "
        "returned %d + errno %d\n", bret, WSAGetLastError());
    ok(overlapped.Internal == STATUS_PENDING, "got %08x\n", (ULONG)overlapped.Internal);
    if (!bret && WSAGetLastError() == ERROR_IO_PENDING)
        CancelIo((HANDLE)listener);

    iret = listen(listener, 5);
    ok(!iret, "failed to listen, error %u\n", GetLastError());

    overlapped.Internal = 0xdeadbeef;
    bret = pAcceptEx(listener, INVALID_SOCKET, buffer, sizeof(buffer) - 2*(sizeof(struct sockaddr_in) + 16),
        sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
        &bytesReturned, &overlapped);
    ok(bret == FALSE && WSAGetLastError() == WSAENOTSOCK, "AcceptEx on invalid accepting socket "
        "returned %d + errno %d\n", bret, WSAGetLastError());
    ok(overlapped.Internal == STATUS_PENDING, "got %08x\n", (ULONG)overlapped.Internal);

    overlapped.Internal = 0xdeadbeef;
    bret = pAcceptEx(listener, acceptor, NULL, sizeof(buffer) - 2*(sizeof(struct sockaddr_in) + 16),
        sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
        &bytesReturned, &overlapped);
    todo_wine ok(bret == FALSE && WSAGetLastError() == WSAEFAULT,
        "AcceptEx on NULL buffer returned %d + errno %d\n", bret, WSAGetLastError());
    ok(overlapped.Internal == STATUS_PENDING, "got %08x\n", (ULONG)overlapped.Internal);

    overlapped.Internal = 0xdeadbeef;
    bret = pAcceptEx(listener, acceptor, buffer, 0, 0, sizeof(struct sockaddr_in) + 16,
        &bytesReturned, &overlapped);
    ok(bret == FALSE && WSAGetLastError() == ERROR_IO_PENDING,
        "AcceptEx on too small local address size returned %d + errno %d\n",
        bret, WSAGetLastError());
    ok(overlapped.Internal == STATUS_PENDING, "got %08x\n", (ULONG)overlapped.Internal);

    connector = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(connector != -1, "failed to create socket, error %u\n", WSAGetLastError());
    iret = connect(connector, (struct sockaddr *)&bindAddress, sizeof(bindAddress));
    ok(!iret, "failed to connect, error %u\n", WSAGetLastError());
    iret = getsockname(connector, (struct sockaddr *)&peerAddress, &remoteSize);
    ok(!iret, "getsockname failed, error %u\n", WSAGetLastError());

    dwret = WaitForSingleObject(overlapped.hEvent, 1000);
    ok(!dwret, "wait failed\n");
    bret = GetOverlappedResult((HANDLE)listener, &overlapped, &bytesReturned, FALSE);
    ok(bret, "got error %u\n", GetLastError());
    ok(!(NTSTATUS)overlapped.Internal, "got %#lx\n", overlapped.Internal);
    ok(!bytesReturned, "got size %u\n", bytesReturned);

    readBindAddress = readRemoteAddress = (struct sockaddr_in *)0xdeadbeef;
    localSize = remoteSize = 0xdeadbeef;
    pGetAcceptExSockaddrs(buffer, 0, 0, sizeof(struct sockaddr_in) + 16,
            (struct sockaddr **)&readBindAddress, &localSize, (struct sockaddr **)&readRemoteAddress, &remoteSize);
    todo_wine ok(readBindAddress == (struct sockaddr_in *)0xdeadbeef, "got local addr %p\n", readBindAddress);
    ok(!memcmp(readRemoteAddress, &peerAddress, sizeof(peerAddress)), "remote addr didn't match\n");
    todo_wine ok(localSize == 0xdeadbeef, "got local size %u\n", localSize);
    ok(remoteSize == sizeof(struct sockaddr_in), "got remote size %u\n", remoteSize);

    closesocket(connector);
    closesocket(acceptor);

    acceptor = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(acceptor != -1, "failed to create socket, error %u\n", WSAGetLastError());

    overlapped.Internal = 0xdeadbeef;
    bret = pAcceptEx(listener, acceptor, buffer, 0, 3,
            sizeof(struct sockaddr_in) + 16, &bytesReturned, &overlapped);
    ok(!bret && WSAGetLastError() == ERROR_IO_PENDING, "got %d, error %u\n", bret, WSAGetLastError());
    ok((NTSTATUS)overlapped.Internal == STATUS_PENDING, "got %#lx\n", overlapped.Internal);

    connector = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(connector != -1, "failed to create socket, error %u\n", WSAGetLastError());
    iret = connect(connector, (struct sockaddr *)&bindAddress, sizeof(bindAddress));
    ok(!iret, "failed to connect, error %u\n", WSAGetLastError());

    dwret = WaitForSingleObject(overlapped.hEvent, 1000);
    ok(!dwret, "wait failed\n");
    bytesReturned = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    bret = GetOverlappedResult((HANDLE)listener, &overlapped, &bytesReturned, FALSE);
    ok(!bret, "expected failure\n");
    ok(GetLastError() == ERROR_INSUFFICIENT_BUFFER, "got error %u\n", GetLastError());
    ok((NTSTATUS)overlapped.Internal == STATUS_BUFFER_TOO_SMALL, "got %#lx\n", overlapped.Internal);
    ok(!bytesReturned, "got size %u\n", bytesReturned);

    closesocket(acceptor);

    /* The above connection request is not accepted. */
    acceptor = accept(listener, NULL, NULL);
    todo_wine ok(acceptor != INVALID_SOCKET, "failed to accept, error %u\n", WSAGetLastError());
    closesocket(acceptor);

    closesocket(connector);

    acceptor = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(acceptor != -1, "failed to create socket, error %u\n", WSAGetLastError());

    overlapped.Internal = 0xdeadbeef;
    bret = pAcceptEx(listener, acceptor, buffer, 0, sizeof(struct sockaddr_in) + 4,
            sizeof(struct sockaddr_in) + 16, &bytesReturned, &overlapped);
    ok(!bret && WSAGetLastError() == ERROR_IO_PENDING, "got %d, error %u\n", bret, WSAGetLastError());
    ok((NTSTATUS)overlapped.Internal == STATUS_PENDING, "got %#lx\n", overlapped.Internal);

    connector = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(connector != -1, "failed to create socket, error %u\n", WSAGetLastError());
    iret = connect(connector, (struct sockaddr *)&bindAddress, sizeof(bindAddress));
    ok(!iret, "failed to connect, error %u\n", WSAGetLastError());

    dwret = WaitForSingleObject(overlapped.hEvent, 1000);
    ok(!dwret, "wait failed\n");
    bytesReturned = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    bret = GetOverlappedResult((HANDLE)listener, &overlapped, &bytesReturned, FALSE);
    todo_wine ok(!bret, "expected failure\n");
    todo_wine ok(GetLastError() == ERROR_INSUFFICIENT_BUFFER, "got error %u\n", GetLastError());
    todo_wine ok((NTSTATUS)overlapped.Internal == STATUS_BUFFER_TOO_SMALL, "got %#lx\n", overlapped.Internal);
    ok(!bytesReturned, "got size %u\n", bytesReturned);

    closesocket(acceptor);

    /* The above connection request is not accepted. */
    acceptor = accept(listener, NULL, NULL);
    todo_wine ok(acceptor != INVALID_SOCKET, "failed to accept, error %u\n", WSAGetLastError());
    closesocket(acceptor);

    closesocket(connector);

    acceptor = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(acceptor != -1, "failed to create socket, error %u\n", WSAGetLastError());

    overlapped.Internal = 0xdeadbeef;
    bret = pAcceptEx(listener, acceptor, buffer, 0, sizeof(struct sockaddr_in) + 15,
        sizeof(struct sockaddr_in) + 16, &bytesReturned, &overlapped);
    ok(bret == FALSE && WSAGetLastError() == ERROR_IO_PENDING, "AcceptEx on too small local address "
        "size returned %d + errno %d\n",
        bret, WSAGetLastError());
    ok(overlapped.Internal == STATUS_PENDING, "got %08x\n", (ULONG)overlapped.Internal);
    bret = CancelIo((HANDLE) listener);
    ok(bret, "Failed to cancel pending accept socket\n");

    overlapped.Internal = 0xdeadbeef;
    bret = pAcceptEx(listener, acceptor, buffer, 0, sizeof(struct sockaddr_in) + 16, 0,
        &bytesReturned, &overlapped);
    ok(bret == FALSE && WSAGetLastError() == WSAEFAULT,
        "AcceptEx on too small remote address size returned %d + errno %d\n", bret, WSAGetLastError());
    ok(overlapped.Internal == STATUS_PENDING, "got %08x\n", (ULONG)overlapped.Internal);

    overlapped.Internal = 0xdeadbeef;
    bret = pAcceptEx(listener, acceptor, buffer, 0, sizeof(struct sockaddr_in) + 16,
        sizeof(struct sockaddr_in) + 15, &bytesReturned, &overlapped);
    ok(bret == FALSE && WSAGetLastError() == ERROR_IO_PENDING,
        "AcceptEx on too small remote address size returned %d + errno %d\n", bret, WSAGetLastError());
    ok(overlapped.Internal == STATUS_PENDING, "got %08x\n", (ULONG)overlapped.Internal);
    bret = CancelIo((HANDLE) listener);
    ok(bret, "Failed to cancel pending accept socket\n");

    bret = pAcceptEx(listener, acceptor, buffer, 0,
        sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
        &bytesReturned, NULL);
    ok(bret == FALSE && WSAGetLastError() == ERROR_INVALID_PARAMETER, "AcceptEx on a NULL overlapped "
        "returned %d + errno %d\n", bret, WSAGetLastError());

    bret = pAcceptEx(listener, acceptor, buffer, 0, 0, 0, &bytesReturned, NULL);
    ok(bret == FALSE && WSAGetLastError() == ERROR_INVALID_PARAMETER, "AcceptEx on a NULL overlapped "
        "returned %d + errno %d\n", bret, WSAGetLastError());

    overlapped.Internal = 0xdeadbeef;
    bret = pAcceptEx(listener, acceptor, buffer, 0,
        sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
        &bytesReturned, &overlapped);
    ok(bret == FALSE && WSAGetLastError() == ERROR_IO_PENDING, "AcceptEx returned %d + errno %d\n", bret, WSAGetLastError());
    ok(overlapped.Internal == STATUS_PENDING, "got %08x\n", (ULONG)overlapped.Internal);

    overlapped.Internal = 0xdeadbeef;
    bret = pAcceptEx(listener, acceptor, buffer, 0,
        sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
        &bytesReturned, &overlapped);
    ok(bret == FALSE && WSAGetLastError() == WSAEINVAL,
       "AcceptEx on already pending socket returned %d + errno %d\n", bret, WSAGetLastError());
    ok(overlapped.Internal == STATUS_PENDING, "got %08x\n", (ULONG)overlapped.Internal);

    iret = connect(acceptor,  (struct sockaddr*)&bindAddress, sizeof(bindAddress));
    todo_wine ok(iret == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL,
       "connecting to acceptex acceptor succeeded? return %d + errno %d\n", iret, WSAGetLastError());
    if (!iret || (iret == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK)) {
        /* We need to cancel this call, otherwise things fail */
        closesocket(acceptor);
        acceptor = socket(AF_INET, SOCK_STREAM, 0);
        ok(acceptor != INVALID_SOCKET, "failed to create socket, error %u\n", GetLastError());

        bret = CancelIo((HANDLE) listener);
        ok(bret, "Failed to cancel failed test. Bailing...\n");
        if (!bret) return;

        overlapped.Internal = 0xdeadbeef;
        bret = pAcceptEx(listener, acceptor, buffer, 0,
            sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
            &bytesReturned, &overlapped);
        ok(bret == FALSE && WSAGetLastError() == ERROR_IO_PENDING, "AcceptEx returned %d + errno %d\n", bret, WSAGetLastError());
        ok(overlapped.Internal == STATUS_PENDING, "got %08x\n", (ULONG)overlapped.Internal);
    }

    connector = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(connector != -1, "failed to create socket, error %u\n", WSAGetLastError());
    overlapped.Internal = 0xdeadbeef;
    iret = connect(connector, (struct sockaddr*)&bindAddress, sizeof(bindAddress));
    ok(iret == 0, "connecting to accepting socket failed, error %d\n", WSAGetLastError());

    dwret = WaitForSingleObject(overlapped.hEvent, INFINITE);
    ok(dwret == WAIT_OBJECT_0, "Waiting for accept event failed with %d + errno %d\n", dwret, GetLastError());
    ok(overlapped.Internal == STATUS_SUCCESS, "got %08x\n", (ULONG)overlapped.Internal);

    bret = GetOverlappedResult((HANDLE)listener, &overlapped, &bytesReturned, FALSE);
    ok(bret, "GetOverlappedResult failed, error %d\n", GetLastError());
    ok(bytesReturned == 0, "bytesReturned isn't supposed to be %d\n", bytesReturned);

    closesocket(connector);
    connector = INVALID_SOCKET;
    closesocket(acceptor);

    /* Test short reads */

    acceptor = socket(AF_INET, SOCK_STREAM, 0);
    ok(acceptor != INVALID_SOCKET, "failed to create socket, error %u\n", GetLastError());
    connector = socket(AF_INET, SOCK_STREAM, 0);
    ok(connector != INVALID_SOCKET, "failed to create socket, error %u\n", GetLastError());
    overlapped.Internal = 0xdeadbeef;
    bret = pAcceptEx(listener, acceptor, buffer, 2,
        sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
        &bytesReturned, &overlapped);
    ok(bret == FALSE && WSAGetLastError() == ERROR_IO_PENDING, "AcceptEx returned %d + errno %d\n", bret, WSAGetLastError());
    ok(overlapped.Internal == STATUS_PENDING, "got %08x\n", (ULONG)overlapped.Internal);

    connect_time = 0xdeadbeef;
    optlen = sizeof(connect_time);
    iret = getsockopt(connector, SOL_SOCKET, SO_CONNECT_TIME, (char *)&connect_time, &optlen);
    ok(!iret, "getsockopt failed %d\n", WSAGetLastError());
    ok(connect_time == ~0u, "unexpected connect time %u\n", connect_time);

    /* AcceptEx() still won't complete until we send data */
    iret = connect(connector, (struct sockaddr*)&bindAddress, sizeof(bindAddress));
    ok(iret == 0, "connecting to accepting socket failed, error %d\n", WSAGetLastError());

    connect_time = 0xdeadbeef;
    optlen = sizeof(connect_time);
    iret = getsockopt(connector, SOL_SOCKET, SO_CONNECT_TIME, (char *)&connect_time, &optlen);
    ok(!iret, "getsockopt failed %d\n", WSAGetLastError());
    ok(connect_time < 0xdeadbeef, "unexpected connect time %u\n", connect_time);

    dwret = WaitForSingleObject(overlapped.hEvent, 0);
    ok(dwret == WAIT_TIMEOUT, "Waiting for accept event timeout failed with %d + errno %d\n", dwret, GetLastError());
    ok(overlapped.Internal == STATUS_PENDING, "got %08x\n", (ULONG)overlapped.Internal);

    iret = getsockname( connector, (struct sockaddr *)&peerAddress, &remoteSize);
    ok( !iret, "getsockname failed.\n");

    /* AcceptEx() could complete any time now */
    iret = send(connector, buffer, 1, 0);
    ok(iret == 1, "could not send 1 byte: send %d errno %d\n", iret, WSAGetLastError());

    dwret = WaitForSingleObject(overlapped.hEvent, 1000);
    ok(dwret == WAIT_OBJECT_0, "Waiting for accept event failed with %d + errno %d\n", dwret, GetLastError());
    ok(overlapped.Internal == STATUS_SUCCESS, "got %08x\n", (ULONG)overlapped.Internal);

    /* Check if the buffer from AcceptEx is decoded correctly */
    pGetAcceptExSockaddrs(buffer, 2, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
                          (struct sockaddr **)&readBindAddress, &localSize,
                          (struct sockaddr **)&readRemoteAddress, &remoteSize);
    strcpy( ipbuffer, inet_ntoa(readBindAddress->sin_addr));
    ok( readBindAddress->sin_addr.s_addr == bindAddress.sin_addr.s_addr,
            "Local socket address is different %s != %s\n",
            ipbuffer, inet_ntoa(bindAddress.sin_addr));
    ok( readBindAddress->sin_port == bindAddress.sin_port,
            "Local socket port is different: %d != %d\n",
            readBindAddress->sin_port, bindAddress.sin_port);
    strcpy( ipbuffer, inet_ntoa(readRemoteAddress->sin_addr));
    ok( readRemoteAddress->sin_addr.s_addr == peerAddress.sin_addr.s_addr,
            "Remote socket address is different %s != %s\n",
            ipbuffer, inet_ntoa(peerAddress.sin_addr));
    ok( readRemoteAddress->sin_port == peerAddress.sin_port,
            "Remote socket port is different: %d != %d\n",
            readRemoteAddress->sin_port, peerAddress.sin_port);

    bret = GetOverlappedResult((HANDLE)listener, &overlapped, &bytesReturned, FALSE);
    ok(bret, "GetOverlappedResult failed, error %d\n", GetLastError());
    ok(bytesReturned == 1, "bytesReturned isn't supposed to be %d\n", bytesReturned);

    closesocket(connector);
    connector = INVALID_SOCKET;
    closesocket(acceptor);

    /* Test CF_DEFER & AcceptEx interaction */

    acceptor = socket(AF_INET, SOCK_STREAM, 0);
    ok(acceptor != INVALID_SOCKET, "failed to create socket, error %u\n", GetLastError());
    connector = socket(AF_INET, SOCK_STREAM, 0);
    ok(connector != INVALID_SOCKET, "failed to create socket, error %u\n", GetLastError());
    connector2 = socket(AF_INET, SOCK_STREAM, 0);
    ok(connector2 != INVALID_SOCKET, "failed to create socket, error %u\n", GetLastError());

    iret = set_blocking(connector, FALSE);
    ok(!iret, "failed to set nonblocking, error %u\n", GetLastError());
    iret = set_blocking(connector2, FALSE);
    ok(!iret, "failed to set nonblocking, error %u\n", GetLastError());

    /* Connect socket #1 */
    iret = connect(connector, (struct sockaddr*)&bindAddress, sizeof(bindAddress));
    ok(iret == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK, "connecting to accepting socket failed, error %d\n", WSAGetLastError());

    buffer[0] = '0';

    FD_ZERO(&fds_accept);
    FD_SET(listener, &fds_accept);
    iret = select(0, &fds_accept, NULL, NULL, &timeout);
    ok(iret == 1, "wait timed out\n");

    acceptor2 = WSAAccept(listener, NULL, NULL, AlwaysDeferConditionFunc, 0);
    ok(acceptor2 == INVALID_SOCKET, "expected failure\n");
    ok(WSAGetLastError() == WSATRY_AGAIN, "got error %u\n", WSAGetLastError());
    bret = pAcceptEx(listener, acceptor, buffer, 0, sizeof(struct sockaddr_in) + 16,
            sizeof(struct sockaddr_in) + 16, &bytesReturned, &overlapped);
    ok(!bret, "expected failure\n");
    ok(WSAGetLastError() == ERROR_IO_PENDING, "got error %u\n", WSAGetLastError());

    FD_ZERO(&fds_send);
    FD_SET(connector, &fds_send);
    iret = select(0, NULL, &fds_send, NULL, &timeout);
    ok(iret == 1, "wait timed out\n");

    iret = send(connector, "1", 1, 0);
    ok(iret == 1, "got ret %d, error %u\n", iret, WSAGetLastError());

    iret = connect(connector2, (struct sockaddr *)&bindAddress, sizeof(bindAddress));
    ok(iret == SOCKET_ERROR, "expected failure\n");
    ok(WSAGetLastError() == WSAEWOULDBLOCK, "got error %u\n", WSAGetLastError());

    iret = select(0, &fds_accept, NULL, NULL, &timeout);
    ok(iret == 1, "wait timed out\n");

    acceptor2 = accept(listener, NULL, NULL);
    ok(acceptor2 != INVALID_SOCKET, "failed to accept, error %u\n", WSAGetLastError());
    closesocket(acceptor2);

    FD_ZERO(&fds_send);
    FD_SET(connector2, &fds_send);
    iret = select(0, NULL, &fds_send, NULL, &timeout);
    ok(iret == 1, "wait timed out\n");

    iret = send(connector2, "2", 1, 0);
    ok(iret == 1, "got ret %d, error %u\n", iret, WSAGetLastError());

    dwret = WaitForSingleObject(overlapped.hEvent, 0);
    ok(dwret == WAIT_OBJECT_0, "Waiting for accept event failed with %d + errno %d\n", dwret, GetLastError());

    bret = GetOverlappedResult((HANDLE)listener, &overlapped, &bytesReturned, FALSE);
    ok(bret, "GetOverlappedResult failed, error %d\n", GetLastError());
    ok(bytesReturned == 0, "bytesReturned isn't supposed to be %d\n", bytesReturned);

    set_blocking(acceptor, TRUE);
    iret = recv( acceptor, buffer, 2, 0);
    ok(iret == 1, "Failed to get data, %d, errno: %d\n", iret, WSAGetLastError());
    ok(buffer[0] == '1', "The wrong first client was accepted by acceptex: %c != 1\n", buffer[0]);

    closesocket(connector);
    closesocket(connector2);
    closesocket(acceptor);

    /* clean up in case of failures */
    while ((acceptor = accept(listener, NULL, NULL)) != INVALID_SOCKET)
        closesocket(acceptor);

    /* Disconnect during receive? */

    acceptor = socket(AF_INET, SOCK_STREAM, 0);
    ok(acceptor != INVALID_SOCKET, "failed to create socket, error %u\n", GetLastError());
    connector = socket(AF_INET, SOCK_STREAM, 0);
    ok(connector != INVALID_SOCKET, "failed to create socket, error %u\n", GetLastError());
    bret = pAcceptEx(listener, acceptor, buffer, sizeof(buffer) - 2*(sizeof(struct sockaddr_in) + 16),
        sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
        &bytesReturned, &overlapped);
    ok(bret == FALSE && WSAGetLastError() == ERROR_IO_PENDING, "AcceptEx returned %d + errno %d\n", bret, WSAGetLastError());

    iret = connect(connector, (struct sockaddr*)&bindAddress, sizeof(bindAddress));
    ok(iret == 0, "connecting to accepting socket failed, error %d\n", WSAGetLastError());

    closesocket(connector);
    connector = INVALID_SOCKET;

    dwret = WaitForSingleObject(overlapped.hEvent, 1000);
    ok(dwret == WAIT_OBJECT_0, "Waiting for accept event failed with %d + errno %d\n", dwret, GetLastError());

    bytesReturned = 123456;
    bret = GetOverlappedResult((HANDLE)listener, &overlapped, &bytesReturned, FALSE);
    ok(bret, "GetOverlappedResult failed, error %d\n", GetLastError());
    ok(bytesReturned == 0, "bytesReturned isn't supposed to be %d\n", bytesReturned);

    closesocket(acceptor);

    /* Test closing with pending requests */

    acceptor = socket(AF_INET, SOCK_STREAM, 0);
    ok(acceptor != INVALID_SOCKET, "failed to create socket, error %u\n", GetLastError());
    bret = pAcceptEx(listener, acceptor, buffer, sizeof(buffer) - 2*(sizeof(struct sockaddr_in) + 16),
        sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
        &bytesReturned, &overlapped);
    ok(bret == FALSE && WSAGetLastError() == ERROR_IO_PENDING, "AcceptEx returned %d + errno %d\n", bret, WSAGetLastError());

    closesocket(acceptor);

    dwret = WaitForSingleObject(overlapped.hEvent, 1000);
    ok(dwret == WAIT_OBJECT_0,
       "Waiting for accept event failed with %d + errno %d\n", dwret, GetLastError());
    bret = GetOverlappedResult((HANDLE)listener, &overlapped, &bytesReturned, FALSE);
    ok(!bret && GetLastError() == ERROR_OPERATION_ABORTED, "GetOverlappedResult failed, error %d\n", GetLastError());

    acceptor = socket(AF_INET, SOCK_STREAM, 0);
    ok(acceptor != INVALID_SOCKET, "failed to create socket, error %u\n", GetLastError());
    bret = pAcceptEx(listener, acceptor, buffer, sizeof(buffer) - 2*(sizeof(struct sockaddr_in) + 16),
        sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
        &bytesReturned, &overlapped);
    ok(bret == FALSE && WSAGetLastError() == ERROR_IO_PENDING, "AcceptEx returned %d + errno %d\n", bret, WSAGetLastError());

    CancelIo((HANDLE) acceptor);

    dwret = WaitForSingleObject(overlapped.hEvent, 1000);
    ok(dwret == WAIT_TIMEOUT, "Waiting for timeout failed with %d + errno %d\n", dwret, GetLastError());

    closesocket(acceptor);

    acceptor = socket(AF_INET, SOCK_STREAM, 0);
    ok(acceptor != INVALID_SOCKET, "failed to create socket, error %u\n", GetLastError());
    bret = pAcceptEx(listener, acceptor, buffer, sizeof(buffer) - 2*(sizeof(struct sockaddr_in) + 16),
        sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
        &bytesReturned, &overlapped);
    ok(bret == FALSE && WSAGetLastError() == ERROR_IO_PENDING, "AcceptEx returned %d + errno %d\n", bret, WSAGetLastError());

    closesocket(listener);

    dwret = WaitForSingleObject(overlapped.hEvent, 1000);
    ok(dwret == WAIT_OBJECT_0, "Waiting for accept event failed with %d + errno %d\n", dwret, GetLastError());

    bret = GetOverlappedResult((HANDLE)listener, &overlapped, &bytesReturned, FALSE);
    ok(!bret && GetLastError() == ERROR_OPERATION_ABORTED, "GetOverlappedResult failed, error %d\n", GetLastError());

    WSACloseEvent(overlapped.hEvent);
    closesocket(acceptor);
    closesocket(connector2);
}

static void test_DisconnectEx(void)
{
    SOCKET listener, acceptor, connector;
    LPFN_DISCONNECTEX pDisconnectEx;
    GUID disconnectExGuid = WSAID_DISCONNECTEX;
    struct sockaddr_in address;
    DWORD num_bytes, flags;
    OVERLAPPED overlapped;
    int addrlen, iret;
    BOOL bret;

    connector = socket(AF_INET, SOCK_STREAM, 0);
    ok(connector != INVALID_SOCKET, "failed to create connector socket, error %d\n", WSAGetLastError());

    iret = WSAIoctl(connector, SIO_GET_EXTENSION_FUNCTION_POINTER, &disconnectExGuid, sizeof(disconnectExGuid),
                    &pDisconnectEx, sizeof(pDisconnectEx), &num_bytes, NULL, NULL);
    if (iret)
    {
        win_skip("WSAIoctl failed to get DisconnectEx, error %d\n", WSAGetLastError());
        closesocket(connector);
        return;
    }

    listener = socket(AF_INET, SOCK_STREAM, 0);
    ok(listener != INVALID_SOCKET, "failed to create listener socket, error %d\n", WSAGetLastError());

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    iret = bind(listener, (struct sockaddr *)&address, sizeof(address));
    ok(iret == 0, "failed to bind, error %d\n", WSAGetLastError());

    addrlen = sizeof(address);
    iret = getsockname(listener, (struct sockaddr *)&address, &addrlen);
    ok(iret == 0, "failed to lookup bind address, error %d\n", WSAGetLastError());

    iret = listen(listener, 1);
    ok(iret == 0, "failed to listen, error %d\n", WSAGetLastError());

    set_blocking(listener, TRUE);

    memset(&overlapped, 0, sizeof(overlapped));
    bret = pDisconnectEx(INVALID_SOCKET, &overlapped, 0, 0);
    ok(bret == FALSE, "DisconnectEx unexpectedly succeeded\n");
    ok(WSAGetLastError() == WSAENOTSOCK, "expected WSAENOTSOCK, got %d\n", WSAGetLastError());

    memset(&overlapped, 0, sizeof(overlapped));
    bret = pDisconnectEx(connector, &overlapped, 0, 0);
    ok(bret == FALSE, "DisconnectEx unexpectedly succeeded\n");
    todo_wine ok(WSAGetLastError() == WSAENOTCONN, "expected WSAENOTCONN, got %d\n", WSAGetLastError());

    iret = connect(connector, (struct sockaddr *)&address, addrlen);
    ok(iret == 0, "failed to connect, error %d\n", WSAGetLastError());

    acceptor = accept(listener, NULL, NULL);
    ok(acceptor != INVALID_SOCKET, "could not accept socket, error %d\n", WSAGetLastError());

    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.hEvent = WSACreateEvent();
    ok(overlapped.hEvent != WSA_INVALID_EVENT, "WSACreateEvent failed, error %d\n", WSAGetLastError());
    bret = pDisconnectEx(connector, &overlapped, 0, 0);
    if (bret)
        ok(overlapped.Internal == STATUS_PENDING, "expected STATUS_PENDING, got %08lx\n", overlapped.Internal);
    else if (WSAGetLastError() == ERROR_IO_PENDING)
        bret = WSAGetOverlappedResult(connector, &overlapped, &num_bytes, TRUE, &flags);
    ok(bret, "DisconnectEx failed, error %d\n", WSAGetLastError());
    WSACloseEvent(overlapped.hEvent);

    iret = connect(connector, (struct sockaddr *)&address, sizeof(address));
    ok(iret != 0, "connect unexpectedly succeeded\n");
    ok(WSAGetLastError() == WSAEISCONN, "expected WSAEISCONN, got %d\n", WSAGetLastError());

    closesocket(acceptor);
    closesocket(connector);

    connector = socket(AF_INET, SOCK_STREAM, 0);
    ok(connector != INVALID_SOCKET, "failed to create connector socket, error %d\n", WSAGetLastError());

    iret = connect(connector, (struct sockaddr *)&address, addrlen);
    ok(iret == 0, "failed to connect, error %d\n", WSAGetLastError());

    acceptor = accept(listener, NULL, NULL);
    ok(acceptor != INVALID_SOCKET, "could not accept socket, error %d\n", WSAGetLastError());

    bret = pDisconnectEx(connector, NULL, 0, 0);
    ok(bret, "DisconnectEx failed, error %d\n", WSAGetLastError());

    iret = connect(connector, (struct sockaddr *)&address, sizeof(address));
    ok(iret != 0, "connect unexpectedly succeeded\n");
    ok(WSAGetLastError() == WSAEISCONN, "expected WSAEISCONN, got %d\n", WSAGetLastError());

    closesocket(acceptor);
    closesocket(connector);
    closesocket(listener);
}

#define compare_file(h,s,o) compare_file2(h,s,o,__FILE__,__LINE__)

static void compare_file2(HANDLE handle, SOCKET sock, int offset, const char *file, int line)
{
    char buf1[256], buf2[256];
    BOOL success;
    int i = 0;

    SetFilePointer(handle, offset, NULL, FILE_BEGIN);
    while (1)
    {
        DWORD n1 = 0, n2 = 0;

        success = ReadFile(handle, buf1, sizeof(buf1), &n1, NULL);
        ok_(file,line)(success, "Failed to read from file.\n");
        if (success && n1 == 0)
            break;
        else if(!success)
            return;
        n2 = recv(sock, buf2, n1, 0);
        ok_(file,line)(n1 == n2, "Block %d size mismatch (%d != %d)\n", i, n1, n2);
        ok_(file,line)(memcmp(buf1, buf2, n2) == 0, "Block %d failed\n", i);
        i++;
    }
}

static void test_TransmitFile(void)
{
    DWORD num_bytes, err, file_size, total_sent;
    GUID transmitFileGuid = WSAID_TRANSMITFILE;
    LPFN_TRANSMITFILE pTransmitFile = NULL;
    HANDLE file = INVALID_HANDLE_VALUE;
    char header_msg[] = "hello world";
    char footer_msg[] = "goodbye!!!";
    char system_ini_path[MAX_PATH];
    struct sockaddr_in bindAddress;
    TRANSMIT_FILE_BUFFERS buffers;
    SOCKET client, server, dest;
    WSAOVERLAPPED ov;
    char buf[256];
    int iret, len;
    BOOL bret;

    memset( &ov, 0, sizeof(ov) );

    /* Setup sockets for testing TransmitFile */
    client = socket(AF_INET, SOCK_STREAM, 0);
    ok(client != INVALID_SOCKET, "failed to create socket, error %u\n", GetLastError());
    server = socket(AF_INET, SOCK_STREAM, 0);
    ok(server != INVALID_SOCKET, "failed to create socket, error %u\n", GetLastError());
    iret = WSAIoctl(client, SIO_GET_EXTENSION_FUNCTION_POINTER, &transmitFileGuid, sizeof(transmitFileGuid),
                    &pTransmitFile, sizeof(pTransmitFile), &num_bytes, NULL, NULL);
    ok(!iret, "failed to get TransmitFile, error %u\n", GetLastError());
    GetSystemWindowsDirectoryA(system_ini_path, MAX_PATH );
    strcat(system_ini_path, "\\system.ini");
    file = CreateFileA(system_ini_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0x0, NULL);
    ok(file != INVALID_HANDLE_VALUE, "failed to open file, error %u\n", GetLastError());
    file_size = GetFileSize(file, NULL);

    /* Test TransmitFile with an invalid socket */
    bret = pTransmitFile(INVALID_SOCKET, file, 0, 0, NULL, NULL, 0);
    err = WSAGetLastError();
    ok(!bret, "TransmitFile succeeded unexpectedly.\n");
    ok(err == WSAENOTSOCK, "TransmitFile triggered unexpected errno (%d != %d)\n", err, WSAENOTSOCK);

    /* Test a bogus TransmitFile without a connected socket */
    bret = pTransmitFile(client, NULL, 0, 0, NULL, NULL, TF_REUSE_SOCKET);
    err = WSAGetLastError();
    ok(!bret, "TransmitFile succeeded unexpectedly.\n");
    ok(err == WSAENOTCONN, "TransmitFile triggered unexpected errno (%d != %d)\n", err, WSAENOTCONN);

    /* Setup a properly connected socket for transfers */
    memset(&bindAddress, 0, sizeof(bindAddress));
    bindAddress.sin_family = AF_INET;
    bindAddress.sin_port = htons(SERVERPORT+1);
    bindAddress.sin_addr.s_addr = inet_addr("127.0.0.1");
    iret = bind(server, (struct sockaddr*)&bindAddress, sizeof(bindAddress));
    ok(!iret, "failed to bind socket, error %u\n", GetLastError());
    iret = listen(server, 1);
    ok(!iret, "failed to listen, error %u\n", GetLastError());
    iret = connect(client, (struct sockaddr*)&bindAddress, sizeof(bindAddress));
    ok(!iret, "failed to connect, error %u\n", GetLastError());
    len = sizeof(bindAddress);
    dest = accept(server, (struct sockaddr*)&bindAddress, &len);
    ok(dest != INVALID_SOCKET, "failed to accept, error %u\n", GetLastError());
    iret = set_blocking(dest, FALSE);
    ok(!iret, "failed to set nonblocking, error %u\n", GetLastError());

    /* Test TransmitFile with no possible buffer */
    bret = pTransmitFile(client, NULL, 0, 0, NULL, NULL, 0);
    ok(bret, "TransmitFile failed unexpectedly.\n");
    iret = recv(dest, buf, sizeof(buf), 0);
    ok(iret == -1, "Returned an unexpected buffer from TransmitFile (%d != -1).\n", iret);

    /* Test TransmitFile with only buffer data */
    buffers.Head = &header_msg[0];
    buffers.HeadLength = sizeof(header_msg);
    buffers.Tail = &footer_msg[0];
    buffers.TailLength = sizeof(footer_msg);
    bret = pTransmitFile(client, NULL, 0, 0, NULL, &buffers, 0);
    ok(bret, "TransmitFile failed unexpectedly.\n");
    iret = recv(dest, buf, sizeof(buf), 0);
    ok(iret == sizeof(header_msg)+sizeof(footer_msg),
       "Returned an unexpected buffer from TransmitFile: %d\n", iret );
    ok(memcmp(&buf[0], &header_msg[0], sizeof(header_msg)) == 0,
       "TransmitFile header buffer did not match!\n");
    ok(memcmp(&buf[sizeof(header_msg)], &footer_msg[0], sizeof(footer_msg)) == 0,
       "TransmitFile footer buffer did not match!\n");

    /* Test TransmitFile with only file data */
    bret = pTransmitFile(client, file, 0, 0, NULL, NULL, 0);
    ok(bret, "TransmitFile failed unexpectedly.\n");
    compare_file(file, dest, 0);

    /* Test TransmitFile with both file and buffer data */
    buffers.Head = &header_msg[0];
    buffers.HeadLength = sizeof(header_msg);
    buffers.Tail = &footer_msg[0];
    buffers.TailLength = sizeof(footer_msg);
    SetFilePointer(file, 0, NULL, FILE_BEGIN);
    bret = pTransmitFile(client, file, 0, 0, NULL, &buffers, 0);
    ok(bret, "TransmitFile failed unexpectedly.\n");
    iret = recv(dest, buf, sizeof(header_msg), 0);
    ok(memcmp(buf, &header_msg[0], sizeof(header_msg)) == 0,
       "TransmitFile header buffer did not match!\n");
    compare_file(file, dest, 0);
    iret = recv(dest, buf, sizeof(footer_msg), 0);
    ok(memcmp(buf, &footer_msg[0], sizeof(footer_msg)) == 0,
       "TransmitFile footer buffer did not match!\n");

    /* Test overlapped TransmitFile */
    ov.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    SetFilePointer(file, 0, NULL, FILE_BEGIN);
    bret = pTransmitFile(client, file, 0, 0, &ov, NULL, 0);
    err = WSAGetLastError();
    ok(!bret, "TransmitFile succeeded unexpectedly.\n");
    ok(err == ERROR_IO_PENDING, "TransmitFile triggered unexpected errno (%d != %d)\n",
       err, ERROR_IO_PENDING);
    iret = WaitForSingleObject(ov.hEvent, 2000);
    ok(iret == WAIT_OBJECT_0, "Overlapped TransmitFile failed.\n");
    WSAGetOverlappedResult(client, &ov, &total_sent, FALSE, NULL);
    ok(total_sent == file_size,
       "Overlapped TransmitFile sent an unexpected number of bytes (%d != %d).\n",
       total_sent, file_size);
    compare_file(file, dest, 0);

    /* Test overlapped TransmitFile w/ start offset */
    ov.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    SetFilePointer(file, 0, NULL, FILE_BEGIN);
    ov.Offset = 10;
    bret = pTransmitFile(client, file, 0, 0, &ov, NULL, 0);
    err = WSAGetLastError();
    ok(!bret, "TransmitFile succeeded unexpectedly.\n");
    ok(err == ERROR_IO_PENDING, "TransmitFile triggered unexpected errno (%d != %d)\n", err, ERROR_IO_PENDING);
    iret = WaitForSingleObject(ov.hEvent, 2000);
    ok(iret == WAIT_OBJECT_0, "Overlapped TransmitFile failed.\n");
    WSAGetOverlappedResult(client, &ov, &total_sent, FALSE, NULL);
    ok(total_sent == (file_size - ov.Offset),
       "Overlapped TransmitFile sent an unexpected number of bytes (%d != %d).\n",
       total_sent, file_size - ov.Offset);
    compare_file(file, dest, ov.Offset);

    /* Test overlapped TransmitFile w/ file and buffer data */
    ov.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    buffers.Head = &header_msg[0];
    buffers.HeadLength = sizeof(header_msg);
    buffers.Tail = &footer_msg[0];
    buffers.TailLength = sizeof(footer_msg);
    SetFilePointer(file, 0, NULL, FILE_BEGIN);
    ov.Offset = 0;
    bret = pTransmitFile(client, file, 0, 0, &ov, &buffers, 0);
    err = WSAGetLastError();
    ok(!bret, "TransmitFile succeeded unexpectedly.\n");
    ok(err == ERROR_IO_PENDING, "TransmitFile triggered unexpected errno (%d != %d)\n", err, ERROR_IO_PENDING);
    iret = WaitForSingleObject(ov.hEvent, 2000);
    ok(iret == WAIT_OBJECT_0, "Overlapped TransmitFile failed.\n");
    WSAGetOverlappedResult(client, &ov, &total_sent, FALSE, NULL);
    ok(total_sent == (file_size + buffers.HeadLength + buffers.TailLength),
       "Overlapped TransmitFile sent an unexpected number of bytes (%d != %d).\n",
       total_sent, file_size  + buffers.HeadLength + buffers.TailLength);
    iret = recv(dest, buf, sizeof(header_msg), 0);
    ok(memcmp(buf, &header_msg[0], sizeof(header_msg)) == 0,
       "TransmitFile header buffer did not match!\n");
    compare_file(file, dest, 0);
    iret = recv(dest, buf, sizeof(footer_msg), 0);
    ok(memcmp(buf, &footer_msg[0], sizeof(footer_msg)) == 0,
       "TransmitFile footer buffer did not match!\n");

    /* Test TransmitFile with a UDP datagram socket */
    closesocket(client);
    client = socket(AF_INET, SOCK_DGRAM, 0);
    bret = pTransmitFile(client, NULL, 0, 0, NULL, NULL, 0);
    err = WSAGetLastError();
    ok(!bret, "TransmitFile succeeded unexpectedly.\n");
    ok(err == WSAENOTCONN, "TransmitFile triggered unexpected errno (%d != %d)\n", err, WSAENOTCONN);

    CloseHandle(file);
    CloseHandle(ov.hEvent);
    closesocket(client);
    closesocket(server);
}

static void test_getpeername(void)
{
    SOCKET sock;
    struct sockaddr_in sa, sa_out;
    SOCKADDR_STORAGE ss;
    int sa_len;
    const char buf[] = "hello world";
    int ret;

    /* Test the parameter validation order. */
    ret = getpeername(INVALID_SOCKET, NULL, NULL);
    ok(ret == SOCKET_ERROR, "Expected getpeername to return SOCKET_ERROR, got %d\n", ret);
    ok(WSAGetLastError() == WSAENOTSOCK,
       "Expected WSAGetLastError() to return WSAENOTSOCK, got %d\n", WSAGetLastError());

    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    ok(sock != INVALID_SOCKET, "Expected socket to return a valid socket\n");

    ret = getpeername(sock, NULL, NULL);
    ok(ret == SOCKET_ERROR, "Expected getpeername to return SOCKET_ERROR, got %d\n", ret);
    ok(WSAGetLastError() == WSAENOTCONN,
       "Expected WSAGetLastError() to return WSAENOTCONN, got %d\n", WSAGetLastError());

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(139);
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");

    /* sendto does not change a socket's connection state. */
    ret = sendto(sock, buf, sizeof(buf), 0, (struct sockaddr*)&sa, sizeof(sa));
    ok(ret != SOCKET_ERROR,
       "Expected sendto to succeed, WSAGetLastError() = %d\n", WSAGetLastError());

    ret = getpeername(sock, NULL, NULL);
    ok(ret == SOCKET_ERROR, "Expected getpeername to return SOCKET_ERROR, got %d\n", ret);
    ok(WSAGetLastError() == WSAENOTCONN,
       "Expected WSAGetLastError() to return WSAENOTCONN, got %d\n", WSAGetLastError());

    ret = connect(sock, (struct sockaddr*)&sa, sizeof(sa));
    ok(ret == 0,
       "Expected connect to succeed, WSAGetLastError() = %d\n", WSAGetLastError());

    ret = getpeername(sock, NULL, NULL);
    ok(ret == SOCKET_ERROR, "Expected getpeername to return SOCKET_ERROR, got %d\n", ret);
    ok(WSAGetLastError() == WSAEFAULT,
       "Expected WSAGetLastError() to return WSAEFAULT, got %d\n", WSAGetLastError());

    /* Test crashes on Wine. */
    if (0)
    {
        ret = getpeername(sock, (void*)0xdeadbeef, (void*)0xcafebabe);
        ok(ret == SOCKET_ERROR, "Expected getpeername to return SOCKET_ERROR, got %d\n", ret);
        ok(WSAGetLastError() == WSAEFAULT,
           "Expected WSAGetLastError() to return WSAEFAULT, got %d\n", WSAGetLastError());
    }

    ret = getpeername(sock, (struct sockaddr*)&sa_out, NULL);
    ok(ret == SOCKET_ERROR, "Expected getpeername to return 0, got %d\n", ret);
    ok(WSAGetLastError() == WSAEFAULT,
       "Expected WSAGetLastError() to return WSAEFAULT, got %d\n", WSAGetLastError());

    sa_len = 0;
    ret = getpeername(sock, NULL, &sa_len);
    ok(ret == SOCKET_ERROR, "Expected getpeername to return 0, got %d\n", ret);
    ok(WSAGetLastError() == WSAEFAULT,
       "Expected WSAGetLastError() to return WSAEFAULT, got %d\n", WSAGetLastError());
    ok(!sa_len, "got %d\n", sa_len);

    sa_len = 0;
    ret = getpeername(sock, (struct sockaddr *)&ss, &sa_len);
    ok(ret == SOCKET_ERROR, "Expected getpeername to return 0, got %d\n", ret);
    ok(WSAGetLastError() == WSAEFAULT,
       "Expected WSAGetLastError() to return WSAEFAULT, got %d\n", WSAGetLastError());
    ok(!sa_len, "got %d\n", sa_len);

    sa_len = sizeof(ss);
    ret = getpeername(sock, (struct sockaddr *)&ss, &sa_len);
    ok(ret == 0, "Expected getpeername to return 0, got %d\n", ret);
    ok(!memcmp(&sa, &ss, sizeof(sa)),
       "Expected the returned structure to be identical to the connect structure\n");
    ok(sa_len == sizeof(sa), "got %d\n", sa_len);

    closesocket(sock);
}

static void test_sioRoutingInterfaceQuery(void)
{
    int ret;
    SOCKET sock;
    SOCKADDR_IN sin = { 0 }, sout = { 0 };
    DWORD bytesReturned;

    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    ok(sock != INVALID_SOCKET, "Expected socket to return a valid socket\n");
    ret = WSAIoctl(sock, SIO_ROUTING_INTERFACE_QUERY, NULL, 0, NULL, 0, NULL,
                   NULL, NULL);
    ok(ret == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT,
       "expected WSAEFAULT, got %d\n", WSAGetLastError());
    ret = WSAIoctl(sock, SIO_ROUTING_INTERFACE_QUERY, &sin, sizeof(sin),
                   NULL, 0, NULL, NULL, NULL);
    ok(ret == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT,
       "expected WSAEFAULT, got %d\n", WSAGetLastError());
    ret = WSAIoctl(sock, SIO_ROUTING_INTERFACE_QUERY, &sin, sizeof(sin),
                   NULL, 0, &bytesReturned, NULL, NULL);
    todo_wine ok(ret == SOCKET_ERROR && WSAGetLastError() == WSAEAFNOSUPPORT,
       "expected WSAEAFNOSUPPORT, got %d\n", WSAGetLastError());
    sin.sin_family = AF_INET;
    ret = WSAIoctl(sock, SIO_ROUTING_INTERFACE_QUERY, &sin, sizeof(sin),
                   NULL, 0, &bytesReturned, NULL, NULL);
    todo_wine ok(ret == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL,
       "expected WSAEINVAL, got %d\n", WSAGetLastError());
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ret = WSAIoctl(sock, SIO_ROUTING_INTERFACE_QUERY, &sin, sizeof(sin),
                   NULL, 0, &bytesReturned, NULL, NULL);
    ok(ret == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT,
       "expected WSAEFAULT, got %d\n", WSAGetLastError());
    ret = WSAIoctl(sock, SIO_ROUTING_INTERFACE_QUERY, &sin, sizeof(sin),
                   &sout, sizeof(sout), &bytesReturned, NULL, NULL);
    ok(!ret, "WSAIoctl failed: %d\n", WSAGetLastError());
    ok(sout.sin_family == AF_INET, "expected AF_INET, got %d\n", sout.sin_family);
    /* We expect the source address to be INADDR_LOOPBACK as well, but
     * there's no guarantee that a route to the loopback address exists,
     * so rather than introduce spurious test failures we do not test the
     * source address.
     */
    closesocket(sock);
}

static void test_sioAddressListChange(void)
{
    struct sockaddr_in bindAddress;
    struct in_addr net_address;
    WSAOVERLAPPED overlapped, *olp;
    struct hostent *h;
    DWORD num_bytes, error, tick;
    SOCKET sock, sock2, sock3;
    WSAEVENT event2, event3;
    HANDLE io_port;
    ULONG_PTR key;
    int acount;
    BOOL bret;
    int ret;

    /* Use gethostbyname to find the list of local network interfaces */
    h = gethostbyname("");
    ok(!!h, "failed to get interface list, error %u\n", WSAGetLastError());
    for (acount = 0; h->h_addr_list[acount]; acount++);
    if (acount == 0)
    {
        skip("Cannot test SIO_ADDRESS_LIST_CHANGE, test requires a network card.\n");
        return;
    }

    net_address.s_addr = *(ULONG *) h->h_addr_list[0];

    sock = socket(AF_INET, 0, IPPROTO_TCP);
    ok(sock != INVALID_SOCKET, "socket() failed\n");

    memset(&bindAddress, 0, sizeof(bindAddress));
    bindAddress.sin_family = AF_INET;
    bindAddress.sin_addr.s_addr = net_address.s_addr;
    SetLastError(0xdeadbeef);
    ret = bind(sock, (struct sockaddr*)&bindAddress, sizeof(bindAddress));
    ok (!ret, "bind() failed with error %d\n", GetLastError());
    set_blocking(sock, FALSE);

    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    SetLastError(0xdeadbeef);
    ret = WSAIoctl(sock, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &num_bytes, &overlapped, NULL);
    error = GetLastError();
    ok (ret == SOCKET_ERROR, "WSAIoctl(SIO_ADDRESS_LIST_CHANGE) failed with error %d\n", error);
    ok (error == ERROR_IO_PENDING, "expected 0x3e5, got 0x%x\n", error);

    CloseHandle(overlapped.hEvent);
    closesocket(sock);

    sock = socket(AF_INET, 0, IPPROTO_TCP);
    ok(sock != INVALID_SOCKET, "socket() failed\n");

    SetLastError(0xdeadbeef);
    ret = bind(sock, (struct sockaddr*)&bindAddress, sizeof(bindAddress));
    ok (!ret, "bind() failed with error %d\n", GetLastError());
    set_blocking(sock, TRUE);

    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    SetLastError(0xdeadbeef);
    ret = WSAIoctl(sock, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &num_bytes, &overlapped, NULL);
    error = GetLastError();
    ok (ret == SOCKET_ERROR, "WSAIoctl(SIO_ADDRESS_LIST_CHANGE) failed with error %d\n", error);
    ok (error == ERROR_IO_PENDING, "expected 0x3e5, got 0x%x\n", error);

    CloseHandle(overlapped.hEvent);
    closesocket(sock);

    sock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    ok(sock != INVALID_SOCKET, "socket() failed\n");

    SetLastError(0xdeadbeef);
    ret = bind(sock, (struct sockaddr*)&bindAddress, sizeof(bindAddress));
    ok (!ret, "bind() failed with error %d\n", GetLastError());
    set_blocking(sock, FALSE);

    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    SetLastError(0xdeadbeef);
    ret = WSAIoctl(sock, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &num_bytes, &overlapped, NULL);
    error = GetLastError();
    ok (ret == SOCKET_ERROR, "WSAIoctl(SIO_ADDRESS_LIST_CHANGE) failed with error %d\n", error);
    ok (error == ERROR_IO_PENDING, "expected 0x3e5, got 0x%x\n", error);

    CloseHandle(overlapped.hEvent);
    closesocket(sock);

    sock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    ok(sock != INVALID_SOCKET, "socket() failed\n");

    SetLastError(0xdeadbeef);
    ret = bind(sock, (struct sockaddr*)&bindAddress, sizeof(bindAddress));
    ok (!ret, "bind() failed with error %d\n", GetLastError());
    set_blocking(sock, TRUE);

    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    SetLastError(0xdeadbeef);
    ret = WSAIoctl(sock, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &num_bytes, &overlapped, NULL);
    error = GetLastError();
    ok (ret == SOCKET_ERROR, "WSAIoctl(SIO_ADDRESS_LIST_CHANGE) failed with error %d\n", error);
    ok (error == ERROR_IO_PENDING, "expected 0x3e5, got 0x%x\n", error);

    CloseHandle(overlapped.hEvent);
    closesocket(sock);

    /* When the socket is overlapped non-blocking and the list change is requested without
     * an overlapped structure the error will be different. */
    sock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    ok(sock != INVALID_SOCKET, "socket() failed\n");

    SetLastError(0xdeadbeef);
    ret = bind(sock, (struct sockaddr*)&bindAddress, sizeof(bindAddress));
    ok (!ret, "bind() failed with error %d\n", GetLastError());
    set_blocking(sock, FALSE);

    SetLastError(0xdeadbeef);
    ret = WSAIoctl(sock, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &num_bytes, NULL, NULL);
    error = GetLastError();
    ok (ret == SOCKET_ERROR, "WSAIoctl(SIO_ADDRESS_LIST_CHANGE) failed with error %d\n", error);
    ok (error == WSAEWOULDBLOCK, "expected 10035, got %d\n", error);

    io_port = CreateIoCompletionPort( (HANDLE)sock, NULL, 0, 0 );
    ok (io_port != NULL, "failed to create completion port %u\n", GetLastError());

    set_blocking(sock, FALSE);
    memset(&overlapped, 0, sizeof(overlapped));
    SetLastError(0xdeadbeef);
    ret = WSAIoctl(sock, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &num_bytes, &overlapped, NULL);
    error = GetLastError();
    ok (ret == SOCKET_ERROR, "WSAIoctl(SIO_ADDRESS_LIST_CHANGE) failed with error %u\n", error);
    ok (error == ERROR_IO_PENDING, "expected ERROR_IO_PENDING got %u\n", error);

    olp = (WSAOVERLAPPED *)0xdeadbeef;
    bret = GetQueuedCompletionStatus( io_port, &num_bytes, &key, &olp, 0 );
    ok(!bret, "failed to get completion status %u\n", bret);
    ok(GetLastError() == WAIT_TIMEOUT, "Last error was %d\n", GetLastError());
    ok(!olp, "Overlapped structure is at %p\n", olp);

    closesocket(sock);

    olp = (WSAOVERLAPPED *)0xdeadbeef;
    bret = GetQueuedCompletionStatus( io_port, &num_bytes, &key, &olp, 0 );
    ok(!bret, "failed to get completion status %u\n", bret);
    ok(GetLastError() == ERROR_OPERATION_ABORTED, "Last error was %u\n", GetLastError());
    ok(olp == &overlapped, "Overlapped structure is at %p\n", olp);

    CloseHandle(io_port);

    /* Misuse of the API by using a blocking socket and not using an overlapped structure,
     * this leads to a hang forever. */
    if (0)
    {
        sock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);

        SetLastError(0xdeadbeef);
        bind(sock, (struct sockaddr*)&bindAddress, sizeof(bindAddress));

        set_blocking(sock, TRUE);
        WSAIoctl(sock, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &num_bytes, NULL, NULL);
        /* hang */

        closesocket(sock);
    }

    if (!winetest_interactive)
    {
        skip("Cannot test SIO_ADDRESS_LIST_CHANGE, interactive tests must be enabled\n");
        return;
    }

    /* Bind an overlapped socket to the first found network interface */
    sock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    ok(sock != INVALID_SOCKET, "Expected socket to return a valid socket\n");
    sock2 = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    ok(sock2 != INVALID_SOCKET, "Expected socket to return a valid socket\n");
    sock3 = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    ok(sock3 != INVALID_SOCKET, "Expected socket to return a valid socket\n");

    ret = bind(sock, (struct sockaddr*)&bindAddress, sizeof(bindAddress));
    ok(!ret, "bind failed unexpectedly\n");
    ret = bind(sock2, (struct sockaddr*)&bindAddress, sizeof(bindAddress));
    ok(!ret, "bind failed unexpectedly\n");
    ret = bind(sock3, (struct sockaddr*)&bindAddress, sizeof(bindAddress));
    ok(!ret, "bind failed unexpectedly\n");

    set_blocking(sock2, FALSE);
    set_blocking(sock3, FALSE);

    /* Wait for address changes, request that the user connects/disconnects an interface */
    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    ret = WSAIoctl(sock, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &num_bytes, &overlapped, NULL);
    ok(ret == SOCKET_ERROR, "WSAIoctl succeeded unexpectedly\n");
    ok(WSAGetLastError() == WSA_IO_PENDING, "Expected pending last error, got %d\n", WSAGetLastError());

    ret = WSAIoctl(sock2, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &num_bytes, NULL, NULL);
    ok(ret == SOCKET_ERROR, "WSAIoctl succeeded unexpectedly\n");
    ok(WSAGetLastError() == WSAEWOULDBLOCK, "Expected would block last error, got %d\n", WSAGetLastError());

    event2 = WSACreateEvent();
    event3 = WSACreateEvent();
    ret = WSAEventSelect (sock2, event2, FD_ADDRESS_LIST_CHANGE);
    ok(!ret, "WSAEventSelect failed with %d\n", WSAGetLastError());
    /* sock3 did not request SIO_ADDRESS_LIST_CHANGE but it is trying to wait anyway */
    ret = WSAEventSelect (sock3, event3, FD_ADDRESS_LIST_CHANGE);
    ok(!ret, "WSAEventSelect failed with %d\n", WSAGetLastError());

    trace("Testing socket-based ipv4 address list change notification. Please connect/disconnect or"
          " change the ipv4 address of any of the local network interfaces (15 second timeout).\n");
    tick = GetTickCount();
    ret = WaitForSingleObject(overlapped.hEvent, 15000);
    ok(ret == WAIT_OBJECT_0, "failed to get overlapped event %u\n", ret);

    ret = WaitForSingleObject(event2, 500);
todo_wine
    ok(ret == WAIT_OBJECT_0, "failed to get change event %u\n", ret);

    ret = WaitForSingleObject(event3, 500);
    ok(ret == WAIT_TIMEOUT, "unexpected change event\n");

    trace("Spent %d ms waiting.\n", GetTickCount() - tick);

    WSACloseEvent(event2);
    WSACloseEvent(event3);

    closesocket(sock);
    closesocket(sock2);
    closesocket(sock3);
}

static void test_synchronous_WSAIoctl(void)
{
    HANDLE previous_port, io_port;
    WSAOVERLAPPED overlapped, *olp;
    SOCKET socket;
    ULONG on;
    ULONG_PTR key;
    DWORD num_bytes;
    BOOL ret;
    int res;

    previous_port = CreateIoCompletionPort( INVALID_HANDLE_VALUE, NULL, 0, 0 );
    ok( previous_port != NULL, "failed to create completion port %u\n", GetLastError() );

    socket = WSASocketW( AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED );
    ok( socket != INVALID_SOCKET, "failed to create socket %d\n", WSAGetLastError() );

    io_port = CreateIoCompletionPort( (HANDLE)socket, previous_port, 0, 0 );
    ok( io_port != NULL, "failed to create completion port %u\n", GetLastError() );

    on = 1;
    memset( &overlapped, 0, sizeof(overlapped) );
    res = WSAIoctl( socket, FIONBIO, &on, sizeof(on), NULL, 0, &num_bytes, &overlapped, NULL );
    ok( !res, "WSAIoctl failed %d\n", WSAGetLastError() );

    ret = GetQueuedCompletionStatus( io_port, &num_bytes, &key, &olp, 10000 );
    ok( ret, "failed to get completion status %u\n", GetLastError() );

    CloseHandle( io_port );
    closesocket( socket );
    CloseHandle( previous_port );
}

/*
 * Provide consistent initialization for the AcceptEx IOCP tests.
 */
static SOCKET setup_iocp_src(struct sockaddr_in *bindAddress)
{
    SOCKET src;
    int iret, socklen;

    src = socket(AF_INET, SOCK_STREAM, 0);
    ok(src != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());

    memset(bindAddress, 0, sizeof(*bindAddress));
    bindAddress->sin_family = AF_INET;
    bindAddress->sin_addr.s_addr = inet_addr("127.0.0.1");
    iret = bind(src, (struct sockaddr*)bindAddress, sizeof(*bindAddress));
    ok(!iret, "failed to bind, error %u\n", WSAGetLastError());

    socklen = sizeof(*bindAddress);
    iret = getsockname(src, (struct sockaddr*)bindAddress, &socklen);
    ok(!iret, "failed to get address, error %u\n", WSAGetLastError());

    iret = set_blocking(src, FALSE);
    ok(!iret, "failed to make socket non-blocking, error %u\n", WSAGetLastError());

    iret = listen(src, 5);
    ok(!iret, "failed to listen, error %u\n", WSAGetLastError());

    return src;
}

static void test_completion_port(void)
{
    HANDLE previous_port, io_port;
    WSAOVERLAPPED ov, *olp;
    SOCKET src, dest, dup, connector = INVALID_SOCKET;
    WSAPROTOCOL_INFOA info;
    char buf[1024];
    WSABUF bufs;
    DWORD num_bytes, flags;
    struct linger ling;
    int iret;
    BOOL bret;
    ULONG_PTR key;
    struct sockaddr_in bindAddress;
    GUID acceptExGuid = WSAID_ACCEPTEX;
    LPFN_ACCEPTEX pAcceptEx = NULL;
    fd_set fds_recv;

    memset(buf, 0, sizeof(buf));
    previous_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    ok( previous_port != NULL, "Failed to create completion port %u\n", GetLastError());

    memset(&ov, 0, sizeof(ov));

    tcp_socketpair(&src, &dest);

    bufs.len = sizeof(buf);
    bufs.buf = buf;
    flags = 0;

    ling.l_onoff = 1;
    ling.l_linger = 0;
    iret = setsockopt (src, SOL_SOCKET, SO_LINGER, (char *) &ling, sizeof(ling));
    ok(!iret, "Failed to set linger %d\n", GetLastError());

    io_port = CreateIoCompletionPort( (HANDLE)dest, previous_port, 125, 0 );
    ok(io_port != NULL, "Failed to create completion port %u\n", GetLastError());

    SetLastError(0xdeadbeef);

    iret = WSARecv(dest, &bufs, 1, &num_bytes, &flags, &ov, NULL);
    ok(iret == SOCKET_ERROR, "WSARecv returned %d\n", iret);
    ok(GetLastError() == ERROR_IO_PENDING, "Last error was %d\n", GetLastError());

    Sleep(100);

    closesocket(src);
    src = INVALID_SOCKET;

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;

    bret = GetQueuedCompletionStatus(io_port, &num_bytes, &key, &olp, 100);
    todo_wine ok(bret == FALSE, "GetQueuedCompletionStatus returned %d\n", bret);
    todo_wine ok(GetLastError() == ERROR_NETNAME_DELETED, "Last error was %d\n", GetLastError());
    ok(key == 125, "Key is %lu\n", key);
    ok(num_bytes == 0, "Number of bytes received is %u\n", num_bytes);
    ok(olp == &ov, "Overlapped structure is at %p\n", olp);

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;

    bret = GetQueuedCompletionStatus(io_port, &num_bytes, &key, &olp, 100);
    ok(bret == FALSE, "GetQueuedCompletionStatus returned %d\n", bret );
    ok(GetLastError() == WAIT_TIMEOUT, "Last error was %d\n", GetLastError());
    ok(key == 0xdeadbeef, "Key is %lu\n", key);
    ok(num_bytes == 0xdeadbeef, "Number of bytes transferred is %u\n", num_bytes);
    ok(!olp, "Overlapped structure is at %p\n", olp);

    if (dest != INVALID_SOCKET)
        closesocket(dest);

    memset(&ov, 0, sizeof(ov));

    tcp_socketpair(&src, &dest);

    bufs.len = sizeof(buf);
    bufs.buf = buf;
    flags = 0;

    ling.l_onoff = 1;
    ling.l_linger = 0;
    iret = setsockopt (src, SOL_SOCKET, SO_LINGER, (char *) &ling, sizeof(ling));
    ok(!iret, "Failed to set linger %d\n", GetLastError());

    io_port = CreateIoCompletionPort((HANDLE)dest, previous_port, 125, 0);
    ok(io_port != NULL, "failed to create completion port %u\n", GetLastError());

    set_blocking(dest, FALSE);

    closesocket(src);
    src = INVALID_SOCKET;

    Sleep(100);

    num_bytes = 0xdeadbeef;
    SetLastError(0xdeadbeef);

    iret = WSASend(dest, &bufs, 1, &num_bytes, 0, &ov, NULL);
    ok(iret == SOCKET_ERROR, "WSASend failed - %d\n", iret);
    ok(GetLastError() == WSAECONNRESET, "Last error was %d\n", GetLastError());
    ok(num_bytes == 0xdeadbeef, "Managed to send %d\n", num_bytes);

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;

    bret = GetQueuedCompletionStatus( io_port, &num_bytes, &key, &olp, 200 );
    ok(bret == FALSE, "GetQueuedCompletionStatus returned %u\n", bret );
    ok(GetLastError() == WAIT_TIMEOUT, "Last error was %d\n", GetLastError());
    ok(key == 0xdeadbeef, "Key is %lu\n", key);
    ok(num_bytes == 0xdeadbeef, "Number of bytes transferred is %u\n", num_bytes);
    ok(!olp, "Overlapped structure is at %p\n", olp);

    if (dest != INVALID_SOCKET)
        closesocket(dest);

    /* Test IOCP response on successful immediate read. */
    tcp_socketpair(&src, &dest);

    bufs.len = sizeof(buf);
    bufs.buf = buf;
    flags = 0;
    SetLastError(0xdeadbeef);

    iret = WSASend(src, &bufs, 1, &num_bytes, 0, &ov, NULL);
    ok(!iret, "WSASend failed - %d, last error %u\n", iret, GetLastError());
    ok(num_bytes == sizeof(buf), "Managed to send %d\n", num_bytes);

    io_port = CreateIoCompletionPort((HANDLE)dest, previous_port, 125, 0);
    ok(io_port != NULL, "failed to create completion port %u\n", GetLastError());
    set_blocking(dest, FALSE);

    FD_ZERO(&fds_recv);
    FD_SET(dest, &fds_recv);
    select(dest + 1, &fds_recv, NULL, NULL, NULL);

    num_bytes = 0xdeadbeef;
    flags = 0;

    iret = WSARecv(dest, &bufs, 1, &num_bytes, &flags, &ov, NULL);
    ok(!iret, "WSARecv failed - %d, last error %u\n", iret, GetLastError());
    ok(num_bytes == sizeof(buf), "Managed to read %d\n", num_bytes);

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;

    bret = GetQueuedCompletionStatus( io_port, &num_bytes, &key, &olp, 200 );
    ok(bret == TRUE, "failed to get completion status %u\n", bret);
    ok(GetLastError() == 0xdeadbeef, "Last error was %d\n", GetLastError());
    ok(key == 125, "Key is %lu\n", key);
    ok(num_bytes == sizeof(buf), "Number of bytes transferred is %u\n", num_bytes);
    ok(olp == &ov, "Overlapped structure is at %p\n", olp);

    /* Test IOCP response on graceful shutdown. */
    closesocket(src);

    FD_ZERO(&fds_recv);
    FD_SET(dest, &fds_recv);
    select(dest + 1, &fds_recv, NULL, NULL, NULL);

    num_bytes = 0xdeadbeef;
    flags = 0;
    memset(&ov, 0, sizeof(ov));

    iret = WSARecv(dest, &bufs, 1, &num_bytes, &flags, &ov, NULL);
    ok(!iret, "WSARecv failed - %d, last error %u\n", iret, GetLastError());
    ok(!num_bytes, "Managed to read %d\n", num_bytes);

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;

    bret = GetQueuedCompletionStatus( io_port, &num_bytes, &key, &olp, 200 );
    ok(bret == TRUE, "failed to get completion status %u\n", bret);
    ok(GetLastError() == 0xdeadbeef, "Last error was %d\n", GetLastError());
    ok(key == 125, "Key is %lu\n", key);
    ok(!num_bytes, "Number of bytes transferred is %u\n", num_bytes);
    ok(olp == &ov, "Overlapped structure is at %p\n", olp);

    closesocket(src);
    src = INVALID_SOCKET;
    closesocket(dest);
    dest = INVALID_SOCKET;

    /* Test IOCP response on hard shutdown. This was the condition that triggered
     * a crash in an actual app (bug 38980). */
    tcp_socketpair(&src, &dest);

    bufs.len = sizeof(buf);
    bufs.buf = buf;
    flags = 0;
    memset(&ov, 0, sizeof(ov));

    ling.l_onoff = 1;
    ling.l_linger = 0;
    iret = setsockopt (src, SOL_SOCKET, SO_LINGER, (char *) &ling, sizeof(ling));
    ok(!iret, "Failed to set linger %d\n", GetLastError());

    io_port = CreateIoCompletionPort((HANDLE)dest, previous_port, 125, 0);
    ok(io_port != NULL, "failed to create completion port %u\n", GetLastError());
    set_blocking(dest, FALSE);

    closesocket(src);
    src = INVALID_SOCKET;

    FD_ZERO(&fds_recv);
    FD_SET(dest, &fds_recv);
    select(dest + 1, &fds_recv, NULL, NULL, NULL);

    num_bytes = 0xdeadbeef;
    SetLastError(0xdeadbeef);

    /* Somehow a hard shutdown doesn't work on my Linux box. It seems SO_LINGER is ignored. */
    iret = WSARecv(dest, &bufs, 1, &num_bytes, &flags, &ov, NULL);
    todo_wine ok(iret == SOCKET_ERROR, "WSARecv failed - %d\n", iret);
    todo_wine ok(GetLastError() == WSAECONNRESET, "Last error was %d\n", GetLastError());
    todo_wine ok(num_bytes == 0xdeadbeef, "Managed to read %d\n", num_bytes);

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;

    bret = GetQueuedCompletionStatus( io_port, &num_bytes, &key, &olp, 200 );
    todo_wine ok(bret == FALSE, "GetQueuedCompletionStatus returned %u\n", bret );
    todo_wine ok(GetLastError() == WAIT_TIMEOUT, "Last error was %d\n", GetLastError());
    todo_wine ok(key == 0xdeadbeef, "Key is %lu\n", key);
    todo_wine ok(num_bytes == 0xdeadbeef, "Number of bytes transferred is %u\n", num_bytes);
    todo_wine ok(!olp, "Overlapped structure is at %p\n", olp);

    closesocket(dest);

    /* Test reading from a non-connected socket, mostly because the above test is marked todo. */
    dest = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(dest != INVALID_SOCKET, "socket() failed\n");

    io_port = CreateIoCompletionPort((HANDLE)dest, previous_port, 125, 0);
    ok(io_port != NULL, "failed to create completion port %u\n", GetLastError());
    set_blocking(dest, FALSE);

    num_bytes = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    memset(&ov, 0, sizeof(ov));

    iret = WSARecv(dest, &bufs, 1, &num_bytes, &flags, &ov, NULL);
    ok(iret == SOCKET_ERROR, "WSARecv failed - %d\n", iret);
    ok(GetLastError() == WSAENOTCONN, "Last error was %d\n", GetLastError());
    ok(num_bytes == 0xdeadbeef, "Managed to read %d\n", num_bytes);

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;

    bret = GetQueuedCompletionStatus( io_port, &num_bytes, &key, &olp, 200 );
    ok(bret == FALSE, "GetQueuedCompletionStatus returned %u\n", bret );
    ok(GetLastError() == WAIT_TIMEOUT, "Last error was %d\n", GetLastError());
    ok(key == 0xdeadbeef, "Key is %lu\n", key);
    ok(num_bytes == 0xdeadbeef, "Number of bytes transferred is %u\n", num_bytes);
    ok(!olp, "Overlapped structure is at %p\n", olp);

    num_bytes = 0xdeadbeef;
    closesocket(dest);

    dest = socket(AF_INET, SOCK_STREAM, 0);
    ok(dest != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());

    iret = WSAIoctl(dest, SIO_GET_EXTENSION_FUNCTION_POINTER, &acceptExGuid, sizeof(acceptExGuid),
            &pAcceptEx, sizeof(pAcceptEx), &num_bytes, NULL, NULL);
    ok(!iret, "failed to get AcceptEx, error %u\n", WSAGetLastError());

    /* Test IOCP response on socket close (IOCP created after AcceptEx) */

    src = setup_iocp_src(&bindAddress);

    SetLastError(0xdeadbeef);

    bret = pAcceptEx(src, dest, buf, sizeof(buf) - 2*(sizeof(struct sockaddr_in) + 16),
            sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
            &num_bytes, &ov);
    ok(bret == FALSE, "AcceptEx returned %d\n", bret);
    ok(GetLastError() == ERROR_IO_PENDING, "Last error was %d\n", GetLastError());

    io_port = CreateIoCompletionPort((HANDLE)src, previous_port, 125, 0);
    ok(io_port != NULL, "failed to create completion port %u\n", GetLastError());

    closesocket(src);
    src = INVALID_SOCKET;

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;

    bret = GetQueuedCompletionStatus(io_port, &num_bytes, &key, &olp, 100);
    ok(bret == FALSE, "failed to get completion status %u\n", bret);
    ok(GetLastError() == ERROR_OPERATION_ABORTED, "Last error was %d\n", GetLastError());
    ok(key == 125, "Key is %lu\n", key);
    ok(num_bytes == 0, "Number of bytes transferred is %u\n", num_bytes);
    ok(olp == &ov, "Overlapped structure is at %p\n", olp);
    ok(olp && (olp->Internal == (ULONG)STATUS_CANCELLED), "Internal status is %lx\n", olp ? olp->Internal : 0);

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;
    bret = GetQueuedCompletionStatus( io_port, &num_bytes, &key, &olp, 200 );
    ok(bret == FALSE, "failed to get completion status %u\n", bret);
    ok(GetLastError() == WAIT_TIMEOUT, "Last error was %d\n", GetLastError());
    ok(key == 0xdeadbeef, "Key is %lu\n", key);
    ok(num_bytes == 0xdeadbeef, "Number of bytes transferred is %u\n", num_bytes);
    ok(!olp, "Overlapped structure is at %p\n", olp);

    /* Test IOCP response on socket close (IOCP created before AcceptEx) */

    src = setup_iocp_src(&bindAddress);

    SetLastError(0xdeadbeef);

    io_port = CreateIoCompletionPort((HANDLE)src, previous_port, 125, 0);
    ok(io_port != NULL, "failed to create completion port %u\n", GetLastError());

    bret = pAcceptEx(src, dest, buf, sizeof(buf) - 2*(sizeof(struct sockaddr_in) + 16),
            sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
            &num_bytes, &ov);
    ok(bret == FALSE, "AcceptEx returned %d\n", bret);
    ok(GetLastError() == ERROR_IO_PENDING, "Last error was %d\n", GetLastError());

    closesocket(src);
    src = INVALID_SOCKET;

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;

    bret = GetQueuedCompletionStatus(io_port, &num_bytes, &key, &olp, 100);
    ok(bret == FALSE, "failed to get completion status %u\n", bret);
    ok(GetLastError() == ERROR_OPERATION_ABORTED, "Last error was %d\n", GetLastError());
    ok(key == 125, "Key is %lu\n", key);
    ok(num_bytes == 0, "Number of bytes transferred is %u\n", num_bytes);
    ok(olp == &ov, "Overlapped structure is at %p\n", olp);
    ok(olp && (olp->Internal == (ULONG)STATUS_CANCELLED), "Internal status is %lx\n", olp ? olp->Internal : 0);

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;
    bret = GetQueuedCompletionStatus( io_port, &num_bytes, &key, &olp, 200 );
    ok(bret == FALSE, "failed to get completion status %u\n", bret);
    ok(GetLastError() == WAIT_TIMEOUT, "Last error was %d\n", GetLastError());
    ok(key == 0xdeadbeef, "Key is %lu\n", key);
    ok(num_bytes == 0xdeadbeef, "Number of bytes transferred is %u\n", num_bytes);
    ok(!olp, "Overlapped structure is at %p\n", olp);

    /* Test IOCP with duplicated handle */

    src = setup_iocp_src(&bindAddress);

    SetLastError(0xdeadbeef);

    io_port = CreateIoCompletionPort((HANDLE)src, previous_port, 125, 0);
    ok(io_port != NULL, "failed to create completion port %u\n", GetLastError());

    WSADuplicateSocketA( src, GetCurrentProcessId(), &info );
    dup = WSASocketA(AF_INET, SOCK_STREAM, 0, &info, 0, WSA_FLAG_OVERLAPPED);
    ok(dup != INVALID_SOCKET, "failed to duplicate socket!\n");

    bret = pAcceptEx(dup, dest, buf, sizeof(buf) - 2*(sizeof(struct sockaddr_in) + 16),
            sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
            &num_bytes, &ov);
    ok(bret == FALSE, "AcceptEx returned %d\n", bret);
    ok(GetLastError() == ERROR_IO_PENDING, "Last error was %d\n", GetLastError());

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;
    bret = GetQueuedCompletionStatus( io_port, &num_bytes, &key, &olp, 200 );
    ok(bret == FALSE, "failed to get completion status %u\n", bret);
    ok(GetLastError() == WAIT_TIMEOUT, "Last error was %d\n", GetLastError());
    ok(key == 0xdeadbeef, "Key is %lu\n", key);
    ok(num_bytes == 0xdeadbeef, "Number of bytes transferred is %u\n", num_bytes);
    ok(!olp, "Overlapped structure is at %p\n", olp);

    closesocket(src);
    src = INVALID_SOCKET;
    closesocket(dup);
    dup = INVALID_SOCKET;

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;
    bret = GetQueuedCompletionStatus(io_port, &num_bytes, &key, &olp, 100);
    ok(bret == FALSE, "failed to get completion status %u\n", bret);
    ok(GetLastError() == ERROR_OPERATION_ABORTED, "Last error was %d\n", GetLastError());
    ok(key == 125, "Key is %lu\n", key);
    ok(num_bytes == 0, "Number of bytes transferred is %u\n", num_bytes);
    ok(olp == &ov, "Overlapped structure is at %p\n", olp);
    ok(olp && olp->Internal == (ULONG)STATUS_CANCELLED, "Internal status is %lx\n", olp ? olp->Internal : 0);

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;
    bret = GetQueuedCompletionStatus( io_port, &num_bytes, &key, &olp, 200 );
    ok(bret == FALSE, "failed to get completion status %u\n", bret);
    ok(GetLastError() == WAIT_TIMEOUT, "Last error was %d\n", GetLastError());
    ok(key == 0xdeadbeef, "Key is %lu\n", key);
    ok(num_bytes == 0xdeadbeef, "Number of bytes transferred is %u\n", num_bytes);
    ok(!olp, "Overlapped structure is at %p\n", olp);

    /* Test IOCP with duplicated handle (closing duplicated handle) */

    src = setup_iocp_src(&bindAddress);

    SetLastError(0xdeadbeef);

    io_port = CreateIoCompletionPort((HANDLE)src, previous_port, 125, 0);
    ok(io_port != NULL, "failed to create completion port %u\n", GetLastError());

    WSADuplicateSocketA( src, GetCurrentProcessId(), &info );
    dup = WSASocketA(AF_INET, SOCK_STREAM, 0, &info, 0, WSA_FLAG_OVERLAPPED);
    ok(dup != INVALID_SOCKET, "failed to duplicate socket!\n");

    bret = pAcceptEx(dup, dest, buf, sizeof(buf) - 2*(sizeof(struct sockaddr_in) + 16),
            sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
            &num_bytes, &ov);
    ok(bret == FALSE, "AcceptEx returned %d\n", bret);
    ok(GetLastError() == ERROR_IO_PENDING, "Last error was %d\n", GetLastError());

    closesocket(dup);
    dup = INVALID_SOCKET;

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;
    bret = GetQueuedCompletionStatus( io_port, &num_bytes, &key, &olp, 200 );
    ok(bret == FALSE, "failed to get completion status %u\n", bret);
    ok(GetLastError() == WAIT_TIMEOUT, "Last error was %d\n", GetLastError());
    ok(key == 0xdeadbeef, "Key is %lu\n", key);
    ok(num_bytes == 0xdeadbeef, "Number of bytes transferred is %u\n", num_bytes);
    ok(!olp, "Overlapped structure is at %p\n", olp);

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;
    bret = GetQueuedCompletionStatus( io_port, &num_bytes, &key, &olp, 200 );
    ok(bret == FALSE, "failed to get completion status %u\n", bret);
    ok(GetLastError() == WAIT_TIMEOUT, "Last error was %d\n", GetLastError());
    ok(key == 0xdeadbeef, "Key is %lu\n", key);
    ok(num_bytes == 0xdeadbeef, "Number of bytes transferred is %u\n", num_bytes);
    ok(!olp, "Overlapped structure is at %p\n", olp);

    closesocket(src);
    src = INVALID_SOCKET;

    bret = GetQueuedCompletionStatus(io_port, &num_bytes, &key, &olp, 100);
    ok(bret == FALSE, "failed to get completion status %u\n", bret);
    ok(GetLastError() == ERROR_OPERATION_ABORTED, "Last error was %d\n", GetLastError());
    ok(key == 125, "Key is %lu\n", key);
    ok(num_bytes == 0, "Number of bytes transferred is %u\n", num_bytes);
    ok(olp == &ov, "Overlapped structure is at %p\n", olp);
    ok(olp && (olp->Internal == (ULONG)STATUS_CANCELLED), "Internal status is %lx\n", olp ? olp->Internal : 0);

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;
    bret = GetQueuedCompletionStatus( io_port, &num_bytes, &key, &olp, 200 );
    ok(bret == FALSE, "failed to get completion status %u\n", bret);
    ok(GetLastError() == WAIT_TIMEOUT, "Last error was %d\n", GetLastError());
    ok(key == 0xdeadbeef, "Key is %lu\n", key);
    ok(num_bytes == 0xdeadbeef, "Number of bytes transferred is %u\n", num_bytes);
    ok(!olp, "Overlapped structure is at %p\n", olp);

    /* Test IOCP with duplicated handle (closing original handle) */

    src = setup_iocp_src(&bindAddress);

    SetLastError(0xdeadbeef);

    io_port = CreateIoCompletionPort((HANDLE)src, previous_port, 125, 0);
    ok(io_port != NULL, "failed to create completion port %u\n", GetLastError());

    WSADuplicateSocketA( src, GetCurrentProcessId(), &info );
    dup = WSASocketA(AF_INET, SOCK_STREAM, 0, &info, 0, WSA_FLAG_OVERLAPPED);
    ok(dup != INVALID_SOCKET, "failed to duplicate socket!\n");

    bret = pAcceptEx(dup, dest, buf, sizeof(buf) - 2*(sizeof(struct sockaddr_in) + 16),
            sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
            &num_bytes, &ov);
    ok(bret == FALSE, "AcceptEx returned %d\n", bret);
    ok(GetLastError() == ERROR_IO_PENDING, "Last error was %d\n", GetLastError());

    closesocket(src);
    src = INVALID_SOCKET;

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;
    bret = GetQueuedCompletionStatus( io_port, &num_bytes, &key, &olp, 200 );
    ok(bret == FALSE, "failed to get completion status %u\n", bret);
    ok(GetLastError() == WAIT_TIMEOUT, "Last error was %d\n", GetLastError());
    ok(key == 0xdeadbeef, "Key is %lu\n", key);
    ok(num_bytes == 0xdeadbeef, "Number of bytes transferred is %u\n", num_bytes);
    ok(!olp, "Overlapped structure is at %p\n", olp);

    closesocket(dup);
    dup = INVALID_SOCKET;

    bret = GetQueuedCompletionStatus(io_port, &num_bytes, &key, &olp, 100);
    ok(bret == FALSE, "failed to get completion status %u\n", bret);
    ok(GetLastError() == ERROR_OPERATION_ABORTED, "Last error was %d\n", GetLastError());
    ok(key == 125, "Key is %lu\n", key);
    ok(num_bytes == 0, "Number of bytes transferred is %u\n", num_bytes);
    ok(olp == &ov, "Overlapped structure is at %p\n", olp);
    ok(olp && (olp->Internal == (ULONG)STATUS_CANCELLED), "Internal status is %lx\n", olp ? olp->Internal : 0);

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;
    bret = GetQueuedCompletionStatus( io_port, &num_bytes, &key, &olp, 200 );
    ok(bret == FALSE, "failed to get completion status %u\n", bret);
    ok(GetLastError() == WAIT_TIMEOUT, "Last error was %d\n", GetLastError());
    ok(key == 0xdeadbeef, "Key is %lu\n", key);
    ok(num_bytes == 0xdeadbeef, "Number of bytes transferred is %u\n", num_bytes);
    ok(!olp, "Overlapped structure is at %p\n", olp);

    /* Test IOCP without AcceptEx */

    src = setup_iocp_src(&bindAddress);

    SetLastError(0xdeadbeef);

    io_port = CreateIoCompletionPort((HANDLE)src, previous_port, 125, 0);
    ok(io_port != NULL, "failed to create completion port %u\n", GetLastError());

    closesocket(src);
    src = INVALID_SOCKET;

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;
    bret = GetQueuedCompletionStatus( io_port, &num_bytes, &key, &olp, 200 );
    ok(bret == FALSE, "failed to get completion status %u\n", bret);
    ok(GetLastError() == WAIT_TIMEOUT, "Last error was %d\n", GetLastError());
    ok(key == 0xdeadbeef, "Key is %lu\n", key);
    ok(num_bytes == 0xdeadbeef, "Number of bytes transferred is %u\n", num_bytes);
    ok(!olp, "Overlapped structure is at %p\n", olp);

    /* */

    src = setup_iocp_src(&bindAddress);

    connector = socket(AF_INET, SOCK_STREAM, 0);
    ok(connector != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());

    io_port = CreateIoCompletionPort((HANDLE)src, previous_port, 125, 0);
    ok(io_port != NULL, "failed to create completion port %u\n", GetLastError());

    io_port = CreateIoCompletionPort((HANDLE)dest, previous_port, 236, 0);
    ok(io_port != NULL, "failed to create completion port %u\n", GetLastError());

    bret = pAcceptEx(src, dest, buf, sizeof(buf) - 2*(sizeof(struct sockaddr_in) + 16),
            sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
            &num_bytes, &ov);
    ok(bret == FALSE, "AcceptEx returned %d\n", bret);
    ok(GetLastError() == ERROR_IO_PENDING, "Last error was %d\n", GetLastError());

    iret = connect(connector, (struct sockaddr*)&bindAddress, sizeof(bindAddress));
    ok(iret == 0, "connecting to accepting socket failed, error %d\n", GetLastError());

    closesocket(connector);
    connector = INVALID_SOCKET;

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;

    bret = GetQueuedCompletionStatus(io_port, &num_bytes, &key, &olp, 100);
    ok(bret == TRUE, "failed to get completion status %u\n", bret);
    ok(GetLastError() == 0xdeadbeef, "Last error was %d\n", GetLastError());
    ok(key == 125, "Key is %lu\n", key);
    ok(num_bytes == 0, "Number of bytes transferred is %u\n", num_bytes);
    ok(olp == &ov, "Overlapped structure is at %p\n", olp);
    ok(olp && (olp->Internal == (ULONG)STATUS_SUCCESS), "Internal status is %lx\n", olp ? olp->Internal : 0);

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;
    bret = GetQueuedCompletionStatus( io_port, &num_bytes, &key, &olp, 200 );
    ok(bret == FALSE, "failed to get completion status %u\n", bret);
    ok(GetLastError() == WAIT_TIMEOUT, "Last error was %d\n", GetLastError());
    ok(key == 0xdeadbeef, "Key is %lu\n", key);
    ok(num_bytes == 0xdeadbeef, "Number of bytes transferred is %u\n", num_bytes);
    ok(!olp, "Overlapped structure is at %p\n", olp);

    if (dest != INVALID_SOCKET)
        closesocket(dest);
    if (src != INVALID_SOCKET)
        closesocket(dest);

    /* */

    src = setup_iocp_src(&bindAddress);

    dest = socket(AF_INET, SOCK_STREAM, 0);
    ok(dest != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());

    connector = socket(AF_INET, SOCK_STREAM, 0);
    ok(connector != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());

    io_port = CreateIoCompletionPort((HANDLE)src, previous_port, 125, 0);
    ok(io_port != NULL, "failed to create completion port %u\n", GetLastError());

    io_port = CreateIoCompletionPort((HANDLE)dest, previous_port, 236, 0);
    ok(io_port != NULL, "failed to create completion port %u\n", GetLastError());

    bret = pAcceptEx(src, dest, buf, sizeof(buf) - 2*(sizeof(struct sockaddr_in) + 16),
            sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
            &num_bytes, &ov);
    ok(bret == FALSE, "AcceptEx returned %d\n", bret);
    ok(GetLastError() == ERROR_IO_PENDING, "Last error was %d\n", GetLastError());

    iret = connect(connector, (struct sockaddr*)&bindAddress, sizeof(bindAddress));
    ok(iret == 0, "connecting to accepting socket failed, error %d\n", GetLastError());

    iret = send(connector, buf, 1, 0);
    ok(iret == 1, "could not send 1 byte: send %d errno %d\n", iret, WSAGetLastError());

    Sleep(100);

    closesocket(dest);
    dest = INVALID_SOCKET;

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;

    bret = GetQueuedCompletionStatus(io_port, &num_bytes, &key, &olp, 100);
    ok(bret == TRUE, "failed to get completion status %u\n", bret);
    ok(GetLastError() == 0xdeadbeef, "Last error was %d\n", GetLastError());
    ok(key == 125, "Key is %lu\n", key);
    ok(num_bytes == 1, "Number of bytes transferred is %u\n", num_bytes);
    ok(olp == &ov, "Overlapped structure is at %p\n", olp);
    ok(olp && (olp->Internal == (ULONG)STATUS_SUCCESS), "Internal status is %lx\n", olp ? olp->Internal : 0);

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;
    bret = GetQueuedCompletionStatus( io_port, &num_bytes, &key, &olp, 200 );
    ok(bret == FALSE, "failed to get completion status %u\n", bret);
    ok(GetLastError() == WAIT_TIMEOUT, "Last error was %d\n", GetLastError());
    ok(key == 0xdeadbeef, "Key is %lu\n", key);
    ok(num_bytes == 0xdeadbeef, "Number of bytes transferred is %u\n", num_bytes);
    ok(!olp, "Overlapped structure is at %p\n", olp);

    if (src != INVALID_SOCKET)
        closesocket(src);
    if (connector != INVALID_SOCKET)
        closesocket(connector);

    /* */

    src = setup_iocp_src(&bindAddress);

    dest = socket(AF_INET, SOCK_STREAM, 0);
    ok(dest != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());

    connector = socket(AF_INET, SOCK_STREAM, 0);
    ok(connector != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());

    io_port = CreateIoCompletionPort((HANDLE)src, previous_port, 125, 0);
    ok(io_port != NULL, "failed to create completion port %u\n", GetLastError());

    io_port = CreateIoCompletionPort((HANDLE)dest, previous_port, 236, 0);
    ok(io_port != NULL, "failed to create completion port %u\n", GetLastError());

    bret = pAcceptEx(src, dest, buf, sizeof(buf) - 2*(sizeof(struct sockaddr_in) + 16),
            sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
            &num_bytes, &ov);
    ok(bret == FALSE, "AcceptEx returned %d\n", bret);
    ok(GetLastError() == ERROR_IO_PENDING, "Last error was %d\n", GetLastError());

    iret = connect(connector, (struct sockaddr*)&bindAddress, sizeof(bindAddress));
    ok(iret == 0, "connecting to accepting socket failed, error %d\n", GetLastError());

    closesocket(dest);

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;

    bret = GetQueuedCompletionStatus(io_port, &num_bytes, &key, &olp, 100);
    ok(bret == FALSE, "failed to get completion status %u\n", bret);
    ok(GetLastError() == ERROR_OPERATION_ABORTED
            || GetLastError() == ERROR_CONNECTION_ABORTED, "got error %u\n", GetLastError());
    ok(key == 125, "Key is %lu\n", key);
    ok(num_bytes == 0, "Number of bytes transferred is %u\n", num_bytes);
    ok(olp == &ov, "Overlapped structure is at %p\n", olp);
    ok((NTSTATUS)olp->Internal == STATUS_CANCELLED
            || (NTSTATUS)olp->Internal == STATUS_CONNECTION_ABORTED, "got status %#lx\n", olp->Internal);

    SetLastError(0xdeadbeef);
    key = 0xdeadbeef;
    num_bytes = 0xdeadbeef;
    olp = (WSAOVERLAPPED *)0xdeadbeef;
    bret = GetQueuedCompletionStatus( io_port, &num_bytes, &key, &olp, 200 );
    ok(bret == FALSE, "failed to get completion status %u\n", bret);
    ok(GetLastError() == WAIT_TIMEOUT, "Last error was %d\n", GetLastError());
    ok(key == 0xdeadbeef, "Key is %lu\n", key);
    ok(num_bytes == 0xdeadbeef, "Number of bytes transferred is %u\n", num_bytes);
    ok(!olp, "Overlapped structure is at %p\n", olp);


    closesocket(src);
    closesocket(connector);
    CloseHandle(previous_port);
}

static void test_address_list_query(void)
{
    SOCKET_ADDRESS_LIST *address_list;
    DWORD bytes_returned, size;
    unsigned int i;
    SOCKET s;
    int ret;

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(s != INVALID_SOCKET, "Failed to create socket, error %d.\n", WSAGetLastError());

    bytes_returned = 0;
    ret = WSAIoctl(s, SIO_ADDRESS_LIST_QUERY, NULL, 0, NULL, 0, &bytes_returned, NULL, NULL);
    ok(ret == SOCKET_ERROR, "Got unexpected ret %d.\n", ret);
    ok(WSAGetLastError() == WSAEFAULT, "Got unexpected error %d.\n", WSAGetLastError());
    ok(bytes_returned >= FIELD_OFFSET(SOCKET_ADDRESS_LIST, Address[0]),
            "Got unexpected bytes_returned %u.\n", bytes_returned);

    size = bytes_returned;
    bytes_returned = 0;
    address_list = HeapAlloc(GetProcessHeap(), 0, size * 2);
    ret = WSAIoctl(s, SIO_ADDRESS_LIST_QUERY, NULL, 0, address_list, size * 2, &bytes_returned, NULL, NULL);
    ok(!ret, "Got unexpected ret %d, error %d.\n", ret, WSAGetLastError());
    ok(bytes_returned == size, "Got unexpected bytes_returned %u, expected %u.\n", bytes_returned, size);

    bytes_returned = FIELD_OFFSET(SOCKET_ADDRESS_LIST, Address[address_list->iAddressCount]);
    for (i = 0; i < address_list->iAddressCount; ++i)
    {
        bytes_returned += address_list->Address[i].iSockaddrLength;
    }
    ok(size == bytes_returned, "Got unexpected size %u, expected %u.\n", size, bytes_returned);

    ret = WSAIoctl(s, SIO_ADDRESS_LIST_QUERY, NULL, 0, address_list, size, NULL, NULL, NULL);
    ok(ret == SOCKET_ERROR, "Got unexpected ret %d.\n", ret);
    ok(WSAGetLastError() == WSAEFAULT, "Got unexpected error %d.\n", WSAGetLastError());

    bytes_returned = 0xdeadbeef;
    ret = WSAIoctl(s, SIO_ADDRESS_LIST_QUERY, NULL, 0, NULL, size, &bytes_returned, NULL, NULL);
    ok(ret == SOCKET_ERROR, "Got unexpected ret %d.\n", ret);
    ok(WSAGetLastError() == WSAEFAULT, "Got unexpected error %d.\n", WSAGetLastError());
    ok(bytes_returned == size, "Got unexpected bytes_returned %u, expected %u.\n", bytes_returned, size);

    ret = WSAIoctl(s, SIO_ADDRESS_LIST_QUERY, NULL, 0, address_list, 1, &bytes_returned, NULL, NULL);
    ok(ret == SOCKET_ERROR, "Got unexpected ret %d.\n", ret);
    ok(WSAGetLastError() == WSAEINVAL, "Got unexpected error %d.\n", WSAGetLastError());
    ok(bytes_returned == 0, "Got unexpected bytes_returned %u.\n", bytes_returned);

    ret = WSAIoctl(s, SIO_ADDRESS_LIST_QUERY, NULL, 0, address_list,
            FIELD_OFFSET(SOCKET_ADDRESS_LIST, Address[0]), &bytes_returned, NULL, NULL);
    ok(ret == SOCKET_ERROR, "Got unexpected ret %d.\n", ret);
    ok(WSAGetLastError() == WSAEFAULT, "Got unexpected error %d.\n", WSAGetLastError());
    ok(bytes_returned == size, "Got unexpected bytes_returned %u, expected %u.\n", bytes_returned, size);

    HeapFree(GetProcessHeap(), 0, address_list);
    closesocket(s);
}

static void sync_read(SOCKET src, SOCKET dst)
{
    int ret;
    char data[512];

    ret = send(dst, "Hello World!", 12, 0);
    ok(ret == 12, "send returned %d\n", ret);

    memset(data, 0, sizeof(data));
    ret = recv(src, data, sizeof(data), 0);
    ok(ret == 12, "expected 12, got %d\n", ret);
    ok(!memcmp(data, "Hello World!", 12), "got %u bytes (%*s)\n", ret, ret, data);
}

static void iocp_async_read(SOCKET src, SOCKET dst)
{
    HANDLE port;
    WSAOVERLAPPED ovl, *ovl_iocp;
    WSABUF buf;
    int ret;
    char data[512];
    DWORD flags, bytes;
    ULONG_PTR key;

    memset(data, 0, sizeof(data));
    memset(&ovl, 0, sizeof(ovl));

    port = CreateIoCompletionPort((HANDLE)src, 0, 0x12345678, 0);
    ok(port != 0, "CreateIoCompletionPort error %u\n", GetLastError());

    buf.len = sizeof(data);
    buf.buf = data;
    bytes = 0xdeadbeef;
    flags = 0;
    SetLastError(0xdeadbeef);
    ret = WSARecv(src, &buf, 1, &bytes, &flags, &ovl, NULL);
    ok(ret == SOCKET_ERROR, "got %d\n", ret);
    ok(GetLastError() == ERROR_IO_PENDING, "got %u\n", GetLastError());
    ok(bytes == 0xdeadbeef, "got bytes %u\n", bytes);

    bytes = 0xdeadbeef;
    key = 0xdeadbeef;
    ovl_iocp = (void *)0xdeadbeef;
    SetLastError(0xdeadbeef);
    ret = GetQueuedCompletionStatus(port, &bytes, &key, &ovl_iocp, 100);
    ok(!ret, "got %d\n", ret);
    ok(GetLastError() == WAIT_TIMEOUT, "got %u\n", GetLastError());
    ok(bytes == 0xdeadbeef, "got bytes %u\n", bytes);
    ok(key == 0xdeadbeef, "got key %#lx\n", key);
    ok(!ovl_iocp, "got ovl %p\n", ovl_iocp);

    ret = send(dst, "Hello World!", 12, 0);
    ok(ret == 12, "send returned %d\n", ret);

    bytes = 0xdeadbeef;
    key = 0xdeadbeef;
    ovl_iocp = NULL;
    SetLastError(0xdeadbeef);
    ret = GetQueuedCompletionStatus(port, &bytes, &key, &ovl_iocp, 100);
    ok(ret, "got %d\n", ret);
    ok(bytes == 12, "got bytes %u\n", bytes);
    ok(key == 0x12345678, "got key %#lx\n", key);
    ok(ovl_iocp == &ovl, "got ovl %p\n", ovl_iocp);
    if (ovl_iocp)
    {
        ok(ovl_iocp->InternalHigh == 12, "got %#lx\n", ovl_iocp->InternalHigh);
        ok(!ovl_iocp->Internal , "got %#lx\n", ovl_iocp->Internal);
        ok(!memcmp(data, "Hello World!", 12), "got %u bytes (%*s)\n", bytes, bytes, data);
    }

    bytes = 0xdeadbeef;
    key = 0xdeadbeef;
    ovl_iocp = (void *)0xdeadbeef;
    SetLastError(0xdeadbeef);
    ret = GetQueuedCompletionStatus(port, &bytes, &key, &ovl_iocp, 100);
    ok(!ret, "got %d\n", ret);
    ok(GetLastError() == WAIT_TIMEOUT, "got %u\n", GetLastError());
    ok(bytes == 0xdeadbeef, "got bytes %u\n", bytes);
    ok(key == 0xdeadbeef, "got key %#lx\n", key);
    ok(!ovl_iocp, "got ovl %p\n", ovl_iocp);

    CloseHandle(port);
}

static void iocp_async_read_closesocket(SOCKET src, int how_to_close)
{
    HANDLE port;
    WSAOVERLAPPED ovl, *ovl_iocp;
    WSABUF buf;
    int ret;
    char data[512];
    DWORD flags, bytes;
    ULONG_PTR key;
    HWND hwnd;
    MSG msg;

    hwnd = CreateWindowExA(0, "static", NULL, WS_POPUP,
                           0, 0, 0, 0, NULL, NULL, 0, NULL);
    ok(hwnd != 0, "CreateWindowEx failed\n");

    ret = WSAAsyncSelect(src, hwnd, WM_SOCKET, FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE);
    ok(!ret, "got %d\n", ret);

    Sleep(100);
    memset(&msg, 0, sizeof(msg));
    ret = PeekMessageA(&msg, hwnd, WM_SOCKET, WM_SOCKET, PM_REMOVE);
    ok(ret, "got %d\n", ret);
    ok(msg.hwnd == hwnd, "got %p\n", msg.hwnd);
    ok(msg.message == WM_SOCKET, "got %04x\n", msg.message);
    ok(msg.wParam == src, "got %08lx\n", msg.wParam);
    ok(msg.lParam == 2, "got %08lx\n", msg.lParam);

    memset(data, 0, sizeof(data));
    memset(&ovl, 0, sizeof(ovl));

    port = CreateIoCompletionPort((HANDLE)src, 0, 0x12345678, 0);
    ok(port != 0, "CreateIoCompletionPort error %u\n", GetLastError());

    Sleep(100);
    ret = PeekMessageA(&msg, hwnd, WM_SOCKET, WM_SOCKET, PM_REMOVE);
    ok(!ret, "got %04x,%08lx,%08lx\n", msg.message, msg.wParam, msg.lParam);

    buf.len = sizeof(data);
    buf.buf = data;
    bytes = 0xdeadbeef;
    flags = 0;
    SetLastError(0xdeadbeef);
    ret = WSARecv(src, &buf, 1, &bytes, &flags, &ovl, NULL);
    ok(ret == SOCKET_ERROR, "got %d\n", ret);
    ok(GetLastError() == ERROR_IO_PENDING, "got %u\n", GetLastError());
    ok(bytes == 0xdeadbeef, "got bytes %u\n", bytes);

    Sleep(100);
    ret = PeekMessageA(&msg, hwnd, WM_SOCKET, WM_SOCKET, PM_REMOVE);
    ok(!ret, "got %04x,%08lx,%08lx\n", msg.message, msg.wParam, msg.lParam);

    bytes = 0xdeadbeef;
    key = 0xdeadbeef;
    ovl_iocp = (void *)0xdeadbeef;
    SetLastError(0xdeadbeef);
    ret = GetQueuedCompletionStatus(port, &bytes, &key, &ovl_iocp, 100);
    ok(!ret, "got %d\n", ret);
    ok(GetLastError() == WAIT_TIMEOUT, "got %u\n", GetLastError());
    ok(bytes == 0xdeadbeef, "got bytes %u\n", bytes);
    ok(key == 0xdeadbeef, "got key %#lx\n", key);
    ok(!ovl_iocp, "got ovl %p\n", ovl_iocp);

    Sleep(100);
    ret = PeekMessageA(&msg, hwnd, WM_SOCKET, WM_SOCKET, PM_REMOVE);
    ok(!ret, "got %04x,%08lx,%08lx\n", msg.message, msg.wParam, msg.lParam);

    switch (how_to_close)
    {
    case 0:
        closesocket(src);
        break;
    case 1:
        CloseHandle((HANDLE)src);
        break;
    case 2:
        pNtClose((HANDLE)src);
        break;
    default:
        ok(0, "wrong value %d\n", how_to_close);
        break;
    }

    Sleep(200);
    memset(&msg, 0, sizeof(msg));
    ret = PeekMessageA(&msg, hwnd, WM_SOCKET, WM_SOCKET, PM_REMOVE);
    switch (how_to_close)
    {
    case 0:
        ok(!ret, "got %04x,%08lx,%08lx\n", msg.message, msg.wParam, msg.lParam);
        break;
    case 1:
    case 2:
todo_wine
{
        ok(ret, "got %d\n", ret);
        ok(msg.hwnd == hwnd, "got %p\n", msg.hwnd);
        ok(msg.message == WM_SOCKET, "got %04x\n", msg.message);
        ok(msg.wParam == src, "got %08lx\n", msg.wParam);
        ok(msg.lParam == 0x20, "got %08lx\n", msg.lParam);
}
        break;
    default:
        ok(0, "wrong value %d\n", how_to_close);
        break;
    }

    bytes = 0xdeadbeef;
    key = 0xdeadbeef;
    ovl_iocp = NULL;
    SetLastError(0xdeadbeef);
    ret = GetQueuedCompletionStatus(port, &bytes, &key, &ovl_iocp, 100);
    ok(!ret, "got %d\n", ret);
todo_wine
    ok(GetLastError() == ERROR_CONNECTION_ABORTED || GetLastError() == ERROR_NETNAME_DELETED /* XP */, "got %u\n", GetLastError());
    ok(!bytes, "got bytes %u\n", bytes);
    ok(key == 0x12345678, "got key %#lx\n", key);
    ok(ovl_iocp == &ovl, "got ovl %p\n", ovl_iocp);
    if (ovl_iocp)
    {
        ok(!ovl_iocp->InternalHigh, "got %#lx\n", ovl_iocp->InternalHigh);
todo_wine
        ok(ovl_iocp->Internal == (ULONG)STATUS_CONNECTION_ABORTED || ovl_iocp->Internal == (ULONG)STATUS_LOCAL_DISCONNECT /* XP */, "got %#lx\n", ovl_iocp->Internal);
    }

    bytes = 0xdeadbeef;
    key = 0xdeadbeef;
    ovl_iocp = (void *)0xdeadbeef;
    SetLastError(0xdeadbeef);
    ret = GetQueuedCompletionStatus(port, &bytes, &key, &ovl_iocp, 100);
    ok(!ret, "got %d\n", ret);
    ok(GetLastError() == WAIT_TIMEOUT, "got %u\n", GetLastError());
    ok(bytes == 0xdeadbeef, "got bytes %u\n", bytes);
    ok(key == 0xdeadbeef, "got key %#lx\n", key);
    ok(!ovl_iocp, "got ovl %p\n", ovl_iocp);

    CloseHandle(port);

    DestroyWindow(hwnd);
}

static void iocp_async_closesocket(SOCKET src)
{
    HANDLE port;
    WSAOVERLAPPED *ovl_iocp;
    int ret;
    DWORD bytes;
    ULONG_PTR key;
    HWND hwnd;
    MSG msg;

    hwnd = CreateWindowExA(0, "static", NULL, WS_POPUP,
                           0, 0, 0, 0, NULL, NULL, 0, NULL);
    ok(hwnd != 0, "CreateWindowEx failed\n");

    ret = WSAAsyncSelect(src, hwnd, WM_SOCKET, FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE);
    ok(!ret, "got %d\n", ret);

    Sleep(100);
    memset(&msg, 0, sizeof(msg));
    ret = PeekMessageA(&msg, hwnd, WM_SOCKET, WM_SOCKET, PM_REMOVE);
    ok(ret, "got %d\n", ret);
    ok(msg.hwnd == hwnd, "got %p\n", msg.hwnd);
    ok(msg.message == WM_SOCKET, "got %04x\n", msg.message);
    ok(msg.wParam == src, "got %08lx\n", msg.wParam);
    ok(msg.lParam == 2, "got %08lx\n", msg.lParam);

    port = CreateIoCompletionPort((HANDLE)src, 0, 0x12345678, 0);
    ok(port != 0, "CreateIoCompletionPort error %u\n", GetLastError());

    Sleep(100);
    ret = PeekMessageA(&msg, hwnd, WM_SOCKET, WM_SOCKET, PM_REMOVE);
    ok(!ret, "got %04x,%08lx,%08lx\n", msg.message, msg.wParam, msg.lParam);

    bytes = 0xdeadbeef;
    key = 0xdeadbeef;
    ovl_iocp = (void *)0xdeadbeef;
    SetLastError(0xdeadbeef);
    ret = GetQueuedCompletionStatus(port, &bytes, &key, &ovl_iocp, 100);
    ok(!ret, "got %d\n", ret);
    ok(GetLastError() == WAIT_TIMEOUT, "got %u\n", GetLastError());
    ok(bytes == 0xdeadbeef, "got bytes %u\n", bytes);
    ok(key == 0xdeadbeef, "got key %lu\n", key);
    ok(!ovl_iocp, "got ovl %p\n", ovl_iocp);

    Sleep(100);
    ret = PeekMessageA(&msg, hwnd, WM_SOCKET, WM_SOCKET, PM_REMOVE);
    ok(!ret, "got %04x,%08lx,%08lx\n", msg.message, msg.wParam, msg.lParam);

    closesocket(src);

    Sleep(100);
    memset(&msg, 0, sizeof(msg));
    ret = PeekMessageA(&msg, hwnd, WM_SOCKET, WM_SOCKET, PM_REMOVE);
    ok(!ret, "got %04x,%08lx,%08lx\n", msg.message, msg.wParam, msg.lParam);

    bytes = 0xdeadbeef;
    key = 0xdeadbeef;
    ovl_iocp = (void *)0xdeadbeef;
    SetLastError(0xdeadbeef);
    ret = GetQueuedCompletionStatus(port, &bytes, &key, &ovl_iocp, 100);
    ok(!ret, "got %d\n", ret);
    ok(GetLastError() == WAIT_TIMEOUT, "got %u\n", GetLastError());
    ok(bytes == 0xdeadbeef, "got bytes %u\n", bytes);
    ok(key == 0xdeadbeef, "got key %lu\n", key);
    ok(!ovl_iocp, "got ovl %p\n", ovl_iocp);

    CloseHandle(port);

    DestroyWindow(hwnd);
}

struct wsa_async_select_info
{
    SOCKET sock;
    HWND hwnd;
};

static DWORD WINAPI wsa_async_select_thread(void *param)
{
    struct wsa_async_select_info *info = param;
    int ret;

    ret = WSAAsyncSelect(info->sock, info->hwnd, WM_SOCKET, FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE);
    ok(!ret, "got %d\n", ret);

    return 0;
}

struct wsa_recv_info
{
    SOCKET sock;
    WSABUF wsa_buf;
    WSAOVERLAPPED ovl;
};

static DWORD WINAPI wsa_recv_thread(void *param)
{
    struct wsa_recv_info *info = param;
    int ret;
    DWORD flags, bytes;

    bytes = 0xdeadbeef;
    flags = 0;
    SetLastError(0xdeadbeef);
    ret = WSARecv(info->sock, &info->wsa_buf, 1, &bytes, &flags, &info->ovl, NULL);
    ok(ret == SOCKET_ERROR, "got %d\n", ret);
    ok(GetLastError() == ERROR_IO_PENDING, "got %u\n", GetLastError());
    ok(bytes == 0xdeadbeef, "got bytes %u\n", bytes);

    return 0;
}

static void iocp_async_read_thread_closesocket(SOCKET src)
{
    struct wsa_async_select_info select_info;
    struct wsa_recv_info recv_info;
    HANDLE port, thread;
    WSAOVERLAPPED *ovl_iocp;
    int ret;
    char data[512];
    DWORD bytes, tid;
    ULONG_PTR key;
    HWND hwnd;
    MSG msg;

    hwnd = CreateWindowExA(0, "static", NULL, WS_POPUP,
                           0, 0, 0, 0, NULL, NULL, 0, NULL);
    ok(hwnd != 0, "CreateWindowEx failed\n");

    select_info.sock = src;
    select_info.hwnd = hwnd;
    thread = CreateThread(NULL, 0, wsa_async_select_thread, &select_info, 0, &tid);
    ok(thread != 0, "CreateThread error %u\n", GetLastError());
    ret = WaitForSingleObject(thread, 10000);
    ok(ret == WAIT_OBJECT_0, "thread failed to terminate\n");

    Sleep(100);
    memset(&msg, 0, sizeof(msg));
    ret = PeekMessageA(&msg, hwnd, WM_SOCKET, WM_SOCKET, PM_REMOVE);
    ok(ret, "got %d\n", ret);
    ok(msg.hwnd == hwnd, "got %p\n", msg.hwnd);
    ok(msg.message == WM_SOCKET, "got %04x\n", msg.message);
    ok(msg.wParam == src, "got %08lx\n", msg.wParam);
    ok(msg.lParam == 2, "got %08lx\n", msg.lParam);

    port = CreateIoCompletionPort((HANDLE)src, 0, 0x12345678, 0);
    ok(port != 0, "CreateIoCompletionPort error %u\n", GetLastError());

    Sleep(100);
    ret = PeekMessageA(&msg, hwnd, WM_SOCKET, WM_SOCKET, PM_REMOVE);
    ok(!ret, "got %04x,%08lx,%08lx\n", msg.message, msg.wParam, msg.lParam);

    memset(data, 0, sizeof(data));
    memset(&recv_info.ovl, 0, sizeof(recv_info.ovl));
    recv_info.sock = src;
    recv_info.wsa_buf.len = sizeof(data);
    recv_info.wsa_buf.buf = data;
    thread = CreateThread(NULL, 0, wsa_recv_thread, &recv_info, 0, &tid);
    ok(thread != 0, "CreateThread error %u\n", GetLastError());
    ret = WaitForSingleObject(thread, 10000);
    ok(ret == WAIT_OBJECT_0, "thread failed to terminate\n");

    Sleep(100);
    ret = PeekMessageA(&msg, hwnd, WM_SOCKET, WM_SOCKET, PM_REMOVE);
    ok(!ret, "got %04x,%08lx,%08lx\n", msg.message, msg.wParam, msg.lParam);

    bytes = 0xdeadbeef;
    key = 0xdeadbeef;
    ovl_iocp = (void *)0xdeadbeef;
    SetLastError(0xdeadbeef);
    ret = GetQueuedCompletionStatus(port, &bytes, &key, &ovl_iocp, 100);
    ok(!ret, "got %d\n", ret);
    ok(GetLastError() == WAIT_TIMEOUT || broken(GetLastError() == ERROR_OPERATION_ABORTED) /* XP */,
       "got %u\n", GetLastError());
    if (GetLastError() == WAIT_TIMEOUT)
    {
        ok(bytes == 0xdeadbeef, "got bytes %u\n", bytes);
        ok(key == 0xdeadbeef, "got key %lx\n", key);
        ok(!ovl_iocp, "got ovl %p\n", ovl_iocp);
    }
    else /* document XP behaviour */
    {
        ok(!bytes, "got bytes %u\n", bytes);
        ok(key == 0x12345678, "got key %#lx\n", key);
        ok(ovl_iocp == &recv_info.ovl, "got ovl %p\n", ovl_iocp);
        if (ovl_iocp)
        {
            ok(!ovl_iocp->InternalHigh, "got %#lx\n", ovl_iocp->InternalHigh);
            ok(ovl_iocp->Internal == STATUS_CANCELLED, "got %#lx\n", ovl_iocp->Internal);
        }

        closesocket(src);
        goto xp_is_broken;
    }

    Sleep(100);
    ret = PeekMessageA(&msg, hwnd, WM_SOCKET, WM_SOCKET, PM_REMOVE);
    ok(!ret, "got %04x,%08lx,%08lx\n", msg.message, msg.wParam, msg.lParam);

    closesocket(src);

    Sleep(100);
    ret = PeekMessageA(&msg, hwnd, WM_SOCKET, WM_SOCKET, PM_REMOVE);
    ok(!ret, "got %04x,%08lx,%08lx\n", msg.message, msg.wParam, msg.lParam);

    bytes = 0xdeadbeef;
    key = 0xdeadbeef;
    ovl_iocp = NULL;
    SetLastError(0xdeadbeef);
    ret = GetQueuedCompletionStatus(port, &bytes, &key, &ovl_iocp, 100);
    ok(!ret, "got %d\n", ret);
todo_wine
    ok(GetLastError() == ERROR_CONNECTION_ABORTED || GetLastError() == ERROR_NETNAME_DELETED /* XP */, "got %u\n", GetLastError());
    ok(!bytes, "got bytes %u\n", bytes);
    ok(key == 0x12345678, "got key %#lx\n", key);
    ok(ovl_iocp == &recv_info.ovl, "got ovl %p\n", ovl_iocp);
    if (ovl_iocp)
    {
        ok(!ovl_iocp->InternalHigh, "got %#lx\n", ovl_iocp->InternalHigh);
todo_wine
        ok(ovl_iocp->Internal == (ULONG)STATUS_CONNECTION_ABORTED || ovl_iocp->Internal == (ULONG)STATUS_LOCAL_DISCONNECT /* XP */, "got %#lx\n", ovl_iocp->Internal);
    }

xp_is_broken:
    bytes = 0xdeadbeef;
    key = 0xdeadbeef;
    ovl_iocp = (void *)0xdeadbeef;
    SetLastError(0xdeadbeef);
    ret = GetQueuedCompletionStatus(port, &bytes, &key, &ovl_iocp, 100);
    ok(!ret, "got %d\n", ret);
    ok(GetLastError() == WAIT_TIMEOUT, "got %u\n", GetLastError());
    ok(bytes == 0xdeadbeef, "got bytes %u\n", bytes);
    ok(key == 0xdeadbeef, "got key %lu\n", key);
    ok(!ovl_iocp, "got ovl %p\n", ovl_iocp);

    CloseHandle(port);

    DestroyWindow(hwnd);
}

static void iocp_async_read_thread(SOCKET src, SOCKET dst)
{
    struct wsa_async_select_info select_info;
    struct wsa_recv_info recv_info;
    HANDLE port, thread;
    WSAOVERLAPPED *ovl_iocp;
    int ret;
    char data[512];
    DWORD bytes, tid;
    ULONG_PTR key;
    HWND hwnd;
    MSG msg;

    hwnd = CreateWindowExA(0, "static", NULL, WS_POPUP,
                           0, 0, 0, 0, NULL, NULL, 0, NULL);
    ok(hwnd != 0, "CreateWindowEx failed\n");

    select_info.sock = src;
    select_info.hwnd = hwnd;
    thread = CreateThread(NULL, 0, wsa_async_select_thread, &select_info, 0, &tid);
    ok(thread != 0, "CreateThread error %u\n", GetLastError());
    ret = WaitForSingleObject(thread, 10000);
    ok(ret == WAIT_OBJECT_0, "thread failed to terminate\n");

    Sleep(100);
    memset(&msg, 0, sizeof(msg));
    ret = PeekMessageA(&msg, hwnd, WM_SOCKET, WM_SOCKET, PM_REMOVE);
    ok(ret, "got %d\n", ret);
    ok(msg.hwnd == hwnd, "got %p\n", msg.hwnd);
    ok(msg.message == WM_SOCKET, "got %04x\n", msg.message);
    ok(msg.wParam == src, "got %08lx\n", msg.wParam);
    ok(msg.lParam == 2, "got %08lx\n", msg.lParam);

    port = CreateIoCompletionPort((HANDLE)src, 0, 0x12345678, 0);
    ok(port != 0, "CreateIoCompletionPort error %u\n", GetLastError());

    Sleep(100);
    ret = PeekMessageA(&msg, hwnd, WM_SOCKET, WM_SOCKET, PM_REMOVE);
    ok(!ret, "got %04x,%08lx,%08lx\n", msg.message, msg.wParam, msg.lParam);

    memset(data, 0, sizeof(data));
    memset(&recv_info.ovl, 0, sizeof(recv_info.ovl));
    recv_info.sock = src;
    recv_info.wsa_buf.len = sizeof(data);
    recv_info.wsa_buf.buf = data;
    thread = CreateThread(NULL, 0, wsa_recv_thread, &recv_info, 0, &tid);
    ok(thread != 0, "CreateThread error %u\n", GetLastError());
    ret = WaitForSingleObject(thread, 10000);
    ok(ret == WAIT_OBJECT_0, "thread failed to terminate\n");

    Sleep(100);
    ret = PeekMessageA(&msg, hwnd, WM_SOCKET, WM_SOCKET, PM_REMOVE);
    ok(!ret, "got %04x,%08lx,%08lx\n", msg.message, msg.wParam, msg.lParam);

    bytes = 0xdeadbeef;
    key = 0xdeadbeef;
    ovl_iocp = (void *)0xdeadbeef;
    SetLastError(0xdeadbeef);
    ret = GetQueuedCompletionStatus(port, &bytes, &key, &ovl_iocp, 100);
    ok(!ret, "got %d\n", ret);
    ok(GetLastError() == WAIT_TIMEOUT || broken(GetLastError() == ERROR_OPERATION_ABORTED) /* XP */, "got %u\n", GetLastError());
    if (GetLastError() == WAIT_TIMEOUT)
    {
        ok(bytes == 0xdeadbeef, "got bytes %u\n", bytes);
        ok(key == 0xdeadbeef, "got key %lu\n", key);
        ok(!ovl_iocp, "got ovl %p\n", ovl_iocp);
    }
    else /* document XP behaviour */
    {
        ok(bytes == 0, "got bytes %u\n", bytes);
        ok(key == 0x12345678, "got key %#lx\n", key);
        ok(ovl_iocp == &recv_info.ovl, "got ovl %p\n", ovl_iocp);
        if (ovl_iocp)
        {
            ok(!ovl_iocp->InternalHigh, "got %#lx\n", ovl_iocp->InternalHigh);
            ok(ovl_iocp->Internal == STATUS_CANCELLED, "got %#lx\n", ovl_iocp->Internal);
        }
    }

    Sleep(100);
    memset(&msg, 0, sizeof(msg));
    ret = PeekMessageA(&msg, hwnd, WM_SOCKET, WM_SOCKET, PM_REMOVE);
    ok(!ret || broken(msg.hwnd == hwnd) /* XP */, "got %04x,%08lx,%08lx\n", msg.message, msg.wParam, msg.lParam);
    if (ret) /* document XP behaviour */
    {
        ok(msg.message == WM_SOCKET, "got %04x\n", msg.message);
        ok(msg.wParam == src, "got %08lx\n", msg.wParam);
        ok(msg.lParam == 1, "got %08lx\n", msg.lParam);
    }

    ret = send(dst, "Hello World!", 12, 0);
    ok(ret == 12, "send returned %d\n", ret);

    Sleep(100);
    memset(&msg, 0, sizeof(msg));
    ret = PeekMessageA(&msg, hwnd, WM_SOCKET, WM_SOCKET, PM_REMOVE);
    ok(!ret || broken(msg.hwnd == hwnd) /* XP */, "got %04x,%08lx,%08lx\n", msg.message, msg.wParam, msg.lParam);
    if (ret) /* document XP behaviour */
    {
        ok(msg.hwnd == hwnd, "got %p\n", msg.hwnd);
        ok(msg.message == WM_SOCKET, "got %04x\n", msg.message);
        ok(msg.wParam == src, "got %08lx\n", msg.wParam);
        ok(msg.lParam == 1, "got %08lx\n", msg.lParam);
    }

    bytes = 0xdeadbeef;
    key = 0xdeadbeef;
    ovl_iocp = (void *)0xdeadbeef;
    SetLastError(0xdeadbeef);
    ret = GetQueuedCompletionStatus(port, &bytes, &key, &ovl_iocp, 100);
    ok(ret || broken(GetLastError() == WAIT_TIMEOUT) /* XP */, "got %u\n", GetLastError());
    if (ret)
    {
        ok(bytes == 12, "got bytes %u\n", bytes);
        ok(key == 0x12345678, "got key %#lx\n", key);
        ok(ovl_iocp == &recv_info.ovl, "got ovl %p\n", ovl_iocp);
        if (ovl_iocp)
        {
            ok(ovl_iocp->InternalHigh == 12, "got %#lx\n", ovl_iocp->InternalHigh);
            ok(!ovl_iocp->Internal , "got %#lx\n", ovl_iocp->Internal);
            ok(!memcmp(data, "Hello World!", 12), "got %u bytes (%*s)\n", bytes, bytes, data);
        }
    }
    else /* document XP behaviour */
    {
        ok(bytes == 0xdeadbeef, "got bytes %u\n", bytes);
        ok(key == 0xdeadbeef, "got key %lu\n", key);
        ok(!ovl_iocp, "got ovl %p\n", ovl_iocp);
    }

    CloseHandle(port);

    DestroyWindow(hwnd);
}

static void test_iocp(void)
{
    SOCKET src, dst;
    int i;

    tcp_socketpair(&src, &dst);
    sync_read(src, dst);
    iocp_async_read(src, dst);
    closesocket(src);
    closesocket(dst);

    tcp_socketpair(&src, &dst);
    iocp_async_read_thread(src, dst);
    closesocket(src);
    closesocket(dst);

    for (i = 0; i <= 2; i++)
    {
        tcp_socketpair(&src, &dst);
        iocp_async_read_closesocket(src, i);
        closesocket(dst);
    }

    tcp_socketpair(&src, &dst);
    iocp_async_closesocket(src);
    closesocket(dst);

    tcp_socketpair(&src, &dst);
    iocp_async_read_thread_closesocket(src);
    closesocket(dst);
}

static void test_wsaioctl(void)
{
    unsigned int i, count;
    INTERFACE_INFO *info;
    BOOL loopback_found;
    char buffer[4096];
    DWORD size;
    SOCKET s;
    int ret;

    s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    ok(s != INVALID_SOCKET, "failed to create socket, error %u\n", WSAGetLastError());

    size = 0xdeadbeef;
    ret = WSAIoctl(s, SIO_GET_INTERFACE_LIST, NULL, 0, buffer, sizeof(buffer), &size, NULL, NULL);
    ok(!ret, "Got unexpected ret %d.\n", ret);
    ok(size && size != 0xdeadbeef && !(size % sizeof(INTERFACE_INFO)), "Got unexpected size %u.\n", size);

    info = (INTERFACE_INFO *)buffer;
    count = size / sizeof(INTERFACE_INFO);
    loopback_found = FALSE;
    for (i = 0; i < count; ++i)
    {
        if (info[i].iiFlags & IFF_LOOPBACK)
            loopback_found = TRUE;

        ok(info[i].iiAddress.AddressIn.sin_family == AF_INET, "Got unexpected sin_family %#x.\n",
                info[i].iiAddress.AddressIn.sin_family);
        ok(info[i].iiNetmask.AddressIn.sin_family == AF_INET, "Got unexpected sin_family %#x.\n",
                info[i].iiNetmask.AddressIn.sin_family);
        ok(info[i].iiBroadcastAddress.AddressIn.sin_family
                == (info[i].iiFlags & IFF_BROADCAST) ? AF_INET : 0, "Got unexpected sin_family %#x.\n",
                info[i].iiBroadcastAddress.AddressIn.sin_family);
        ok(info[i].iiAddress.AddressIn.sin_addr.S_un.S_addr, "Got zero iiAddress.\n");
        ok(info[i].iiNetmask.AddressIn.sin_addr.S_un.S_addr, "Got zero iiNetmask.\n");
        ok((info[i].iiFlags & IFF_BROADCAST) ? info[i].iiBroadcastAddress.AddressIn.sin_addr.S_un.S_addr
                : !info[i].iiBroadcastAddress.AddressIn.sin_addr.S_un.S_addr,
                "Got unexpected iiBroadcastAddress %s.\n", inet_ntoa(info[i].iiBroadcastAddress.AddressIn.sin_addr));
    }

    ok(loopback_found, "Loopback interface not found.\n");

    size = 0xdeadbeef;
    ret = WSAIoctl(s, SIO_GET_INTERFACE_LIST, NULL, 0, buffer, sizeof(INTERFACE_INFO) - 1, &size, NULL, NULL);
    ok(ret == -1, "Got unexpected ret %d.\n", ret);
    ok(WSAGetLastError() == WSAEFAULT, "Got unexpected error %d.\n", WSAGetLastError());
    ok(!size, "Got unexpected size %u.\n", size);

    ret = WSAIoctl(s, SIO_GET_INTERFACE_LIST, NULL, 0, buffer, sizeof(buffer), NULL, NULL, NULL);
    ok(ret == -1, "Got unexpected ret %d.\n", ret);
    ok(WSAGetLastError() == WSAEFAULT, "Got unexpected error %d.\n", WSAGetLastError());

    closesocket(s);
}

static void test_bind(void)
{
    const struct sockaddr_in invalid_addr = {.sin_family = AF_INET, .sin_addr.s_addr = inet_addr("192.0.2.0")};
    const struct sockaddr_in bind_addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    struct sockaddr addr;
    SOCKET s, s2;
    int ret, len;

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    WSASetLastError(0xdeadbeef);
    ret = bind(s, NULL, 0);
    ok(ret == -1, "expected failure\n");
    todo_wine ok(WSAGetLastError() == WSAEFAULT, "got error %u\n", WSAGetLastError());

    addr.sa_family = 0xdead;
    WSASetLastError(0xdeadbeef);
    ret = bind(s, &addr, sizeof(addr));
    ok(ret == -1, "expected failure\n");
    ok(WSAGetLastError() == WSAEAFNOSUPPORT, "got error %u\n", WSAGetLastError());

    WSASetLastError(0xdeadbeef);
    ret = bind(s, (const struct sockaddr *)&bind_addr, sizeof(bind_addr) - 1);
    ok(ret == -1, "expected failure\n");
    ok(WSAGetLastError() == WSAEFAULT, "got error %u\n", WSAGetLastError());

    WSASetLastError(0xdeadbeef);
    ret = bind(s, (const struct sockaddr *)&invalid_addr, sizeof(invalid_addr));
    ok(ret == -1, "expected failure\n");
    todo_wine ok(WSAGetLastError() == WSAEADDRNOTAVAIL, "got error %u\n", WSAGetLastError());

    WSASetLastError(0xdeadbeef);
    ret = bind(s, (const struct sockaddr *)&bind_addr, sizeof(bind_addr));
    ok(!ret, "expected success\n");
    ok(!WSAGetLastError() || WSAGetLastError() == 0xdeadbeef /* win <7 */, "got error %u\n", WSAGetLastError());

    WSASetLastError(0xdeadbeef);
    ret = bind(s, (const struct sockaddr *)&bind_addr, sizeof(bind_addr));
    ok(ret == -1, "expected failure\n");
    ok(WSAGetLastError() == WSAEINVAL, "got error %u\n", WSAGetLastError());

    len = sizeof(addr);
    ret = getsockname(s, &addr, &len);
    ok(!ret, "got error %u\n", WSAGetLastError());

    s2 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    WSASetLastError(0xdeadbeef);
    ret = bind(s2, &addr, sizeof(addr));
    ok(ret == -1, "expected failure\n");
    ok(WSAGetLastError() == WSAEADDRINUSE, "got error %u\n", WSAGetLastError());

    closesocket(s2);
    closesocket(s);

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    WSASetLastError(0xdeadbeef);
    ret = bind(s, (const struct sockaddr *)&bind_addr, sizeof(bind_addr));
    ok(!ret, "expected success\n");
    ok(!WSAGetLastError() || WSAGetLastError() == 0xdeadbeef /* win <7 */, "got error %u\n", WSAGetLastError());

    closesocket(s);
}

/* Test calling methods on a socket which is currently connecting. */
static void test_connecting_socket(void)
{
    const struct sockaddr_in invalid_addr =
    {
        .sin_family = AF_INET,
        .sin_addr.s_addr = inet_addr("192.0.2.0"),
        .sin_port = 255
    };
    struct sockaddr_in addr;
    char buffer[4];
    SOCKET client;
    int ret, len;

    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(client != -1, "failed to create socket, error %u\n", WSAGetLastError());
    set_blocking(client, FALSE);

    ret = connect(client, (struct sockaddr *)&invalid_addr, sizeof(invalid_addr));
    ok(ret == -1, "got %d\n", ret);
    ok(WSAGetLastError() == WSAEWOULDBLOCK, "got %u\n", WSAGetLastError());

    len = sizeof(addr);
    ret = getsockname(client, (struct sockaddr *)&addr, &len);
    ok(!ret, "got error %u\n", WSAGetLastError());
    ok(addr.sin_family == AF_INET, "got family %u\n", addr.sin_family);
    ok(addr.sin_port, "expected nonzero port\n");

    len = sizeof(addr);
    ret = getpeername(client, (struct sockaddr *)&addr, &len);
    todo_wine ok(!ret, "got error %u\n", WSAGetLastError());
    if (!ret)
    {
        ok(addr.sin_family == AF_INET, "got family %u\n", addr.sin_family);
        ok(addr.sin_addr.s_addr == inet_addr("192.0.2.0"), "got address %#08x\n", addr.sin_addr.s_addr);
        ok(addr.sin_port == 255, "expected nonzero port\n");
    }

    ret = recv(client, buffer, sizeof(buffer), 0);
    ok(ret == -1, "got %d\n", ret);
    todo_wine ok(WSAGetLastError() == WSAENOTCONN, "got %u\n", WSAGetLastError());

    ret = send(client, "data", 5, 0);
    ok(ret == -1, "got %d\n", ret);
    todo_wine ok(WSAGetLastError() == WSAENOTCONN, "got %u\n", WSAGetLastError());

    closesocket(client);
}

static DWORD map_status( NTSTATUS status )
{
    static const struct
    {
        NTSTATUS status;
        DWORD error;
    }
    errors[] =
    {
        {STATUS_PENDING,                    ERROR_IO_INCOMPLETE},

        {STATUS_BUFFER_OVERFLOW,            WSAEMSGSIZE},

        {STATUS_NOT_IMPLEMENTED,            WSAEOPNOTSUPP},
        {STATUS_ACCESS_VIOLATION,           WSAEFAULT},
        {STATUS_PAGEFILE_QUOTA,             WSAENOBUFS},
        {STATUS_INVALID_HANDLE,             WSAENOTSOCK},
        {STATUS_NO_SUCH_DEVICE,             WSAENETDOWN},
        {STATUS_NO_SUCH_FILE,               WSAENETDOWN},
        {STATUS_NO_MEMORY,                  WSAENOBUFS},
        {STATUS_CONFLICTING_ADDRESSES,      WSAENOBUFS},
        {STATUS_ACCESS_DENIED,              WSAEACCES},
        {STATUS_BUFFER_TOO_SMALL,           WSAEFAULT},
        {STATUS_OBJECT_TYPE_MISMATCH,       WSAENOTSOCK},
        {STATUS_OBJECT_NAME_NOT_FOUND,      WSAENETDOWN},
        {STATUS_OBJECT_PATH_NOT_FOUND,      WSAENETDOWN},
        {STATUS_SHARING_VIOLATION,          WSAEADDRINUSE},
        {STATUS_QUOTA_EXCEEDED,             WSAENOBUFS},
        {STATUS_TOO_MANY_PAGING_FILES,      WSAENOBUFS},
        {STATUS_INSUFFICIENT_RESOURCES,     WSAENOBUFS},
        {STATUS_WORKING_SET_QUOTA,          WSAENOBUFS},
        {STATUS_DEVICE_NOT_READY,           WSAEWOULDBLOCK},
        {STATUS_PIPE_DISCONNECTED,          WSAESHUTDOWN},
        {STATUS_IO_TIMEOUT,                 WSAETIMEDOUT},
        {STATUS_NOT_SUPPORTED,              WSAEOPNOTSUPP},
        {STATUS_REMOTE_NOT_LISTENING,       WSAECONNREFUSED},
        {STATUS_BAD_NETWORK_PATH,           WSAENETUNREACH},
        {STATUS_NETWORK_BUSY,               WSAENETDOWN},
        {STATUS_INVALID_NETWORK_RESPONSE,   WSAENETDOWN},
        {STATUS_UNEXPECTED_NETWORK_ERROR,   WSAENETDOWN},
        {STATUS_REQUEST_NOT_ACCEPTED,       WSAEWOULDBLOCK},
        {STATUS_CANCELLED,                  ERROR_OPERATION_ABORTED},
        {STATUS_COMMITMENT_LIMIT,           WSAENOBUFS},
        {STATUS_LOCAL_DISCONNECT,           WSAECONNABORTED},
        {STATUS_REMOTE_DISCONNECT,          WSAECONNRESET},
        {STATUS_REMOTE_RESOURCES,           WSAENOBUFS},
        {STATUS_LINK_FAILED,                WSAECONNRESET},
        {STATUS_LINK_TIMEOUT,               WSAETIMEDOUT},
        {STATUS_INVALID_CONNECTION,         WSAENOTCONN},
        {STATUS_INVALID_ADDRESS,            WSAEADDRNOTAVAIL},
        {STATUS_INVALID_BUFFER_SIZE,        WSAEMSGSIZE},
        {STATUS_INVALID_ADDRESS_COMPONENT,  WSAEADDRNOTAVAIL},
        {STATUS_TOO_MANY_ADDRESSES,         WSAENOBUFS},
        {STATUS_ADDRESS_ALREADY_EXISTS,     WSAEADDRINUSE},
        {STATUS_CONNECTION_DISCONNECTED,    WSAECONNRESET},
        {STATUS_CONNECTION_RESET,           WSAECONNRESET},
        {STATUS_TRANSACTION_ABORTED,        WSAECONNABORTED},
        {STATUS_CONNECTION_REFUSED,         WSAECONNREFUSED},
        {STATUS_GRACEFUL_DISCONNECT,        WSAEDISCON},
        {STATUS_CONNECTION_ACTIVE,          WSAEISCONN},
        {STATUS_NETWORK_UNREACHABLE,        WSAENETUNREACH},
        {STATUS_HOST_UNREACHABLE,           WSAEHOSTUNREACH},
        {STATUS_PROTOCOL_UNREACHABLE,       WSAENETUNREACH},
        {STATUS_PORT_UNREACHABLE,           WSAECONNRESET},
        {STATUS_REQUEST_ABORTED,            WSAEINTR},
        {STATUS_CONNECTION_ABORTED,         WSAECONNABORTED},
        {STATUS_DATATYPE_MISALIGNMENT_ERROR,WSAEFAULT},
        {STATUS_HOST_DOWN,                  WSAEHOSTDOWN},
        {0x80070000 | ERROR_IO_INCOMPLETE,  ERROR_IO_INCOMPLETE},
        {0xc0010000 | ERROR_IO_INCOMPLETE,  ERROR_IO_INCOMPLETE},
        {0xc0070000 | ERROR_IO_INCOMPLETE,  ERROR_IO_INCOMPLETE},
    };

    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(errors); ++i)
    {
        if (errors[i].status == status)
            return errors[i].error;
    }

    return NT_SUCCESS(status) ? RtlNtStatusToDosErrorNoTeb(status) : WSAEINVAL;
}

static void test_WSAGetOverlappedResult(void)
{
    OVERLAPPED overlapped = {0};
    DWORD size, flags;
    NTSTATUS status;
    unsigned int i;
    SOCKET s;
    BOOL ret;

    static const NTSTATUS ranges[][2] =
    {
        {0x0, 0x10000},
        {0x40000000, 0x40001000},
        {0x80000000, 0x80001000},
        {0x80070000, 0x80080000},
        {0xc0000000, 0xc0001000},
        {0xc0070000, 0xc0080000},
        {0xd0000000, 0xd0001000},
        {0xd0070000, 0xd0080000},
    };

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    for (i = 0; i < ARRAY_SIZE(ranges); ++i)
    {
        for (status = ranges[i][0]; status < ranges[i][1]; ++status)
        {
            BOOL expect_ret = NT_SUCCESS(status) && status != STATUS_PENDING;
            DWORD expect = map_status(status);

            overlapped.Internal = status;
            WSASetLastError(0xdeadbeef);
            ret = WSAGetOverlappedResult(s, &overlapped, &size, FALSE, &flags);
            ok(ret == expect_ret, "status %#x: expected %d, got %d\n", status, expect_ret, ret);
            if (ret)
            {
                ok(WSAGetLastError() == expect /* >= win10 1809 */
                        || !WSAGetLastError() /* < win10 1809 */
                        || WSAGetLastError() == 0xdeadbeef, /* < win7 */
                        "status %#x: expected error %u, got %u\n", status, expect, WSAGetLastError());
            }
            else
            {
                ok(WSAGetLastError() == expect
                        || (status == (0xc0070000 | ERROR_IO_INCOMPLETE) && WSAGetLastError() == WSAEINVAL), /* < win8 */
                        "status %#x: expected error %u, got %u\n", status, expect, WSAGetLastError());
            }
        }
    }

    closesocket(s);
}

struct nonblocking_async_recv_params
{
    SOCKET client;
    HANDLE event;
};

static DWORD CALLBACK nonblocking_async_recv_thread(void *arg)
{
    const struct nonblocking_async_recv_params *params = arg;
    OVERLAPPED overlapped = {0};
    DWORD flags = 0, size;
    char buffer[5];
    WSABUF wsabuf;
    int ret;

    overlapped.hEvent = params->event;
    wsabuf.buf = buffer;
    wsabuf.len = sizeof(buffer);
    memset(buffer, 0, sizeof(buffer));
    ret = WSARecv(params->client, &wsabuf, 1, NULL, &flags, &overlapped, NULL);
    todo_wine_if (!params->event) ok(!ret, "got %d\n", ret);
    ret = GetOverlappedResult((HANDLE)params->client, &overlapped, &size, FALSE);
    ok(ret, "got error %u\n", GetLastError());
    todo_wine ok(size == 4, "got size %u\n", size);
    todo_wine_if (!params->event) ok(!strcmp(buffer, "data"), "got %s\n", debugstr_an(buffer, size));

    return 0;
}

static void test_nonblocking_async_recv(void)
{
    struct nonblocking_async_recv_params params;
    OVERLAPPED overlapped = {0};
    SOCKET client, server;
    DWORD flags = 0, size;
    HANDLE thread, event;
    char buffer[5];
    WSABUF wsabuf;
    int ret;

    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    wsabuf.buf = buffer;
    wsabuf.len = sizeof(buffer);

    tcp_socketpair(&client, &server);
    set_blocking(client, FALSE);
    set_blocking(server, FALSE);

    WSASetLastError(0xdeadbeef);
    ret = recv(client, buffer, sizeof(buffer), 0);
    ok(ret == -1, "got %d\n", ret);
    ok(WSAGetLastError() == WSAEWOULDBLOCK, "got error %u\n", WSAGetLastError());

    WSASetLastError(0xdeadbeef);
    overlapped.Internal = 0xdeadbeef;
    ret = WSARecv(client, &wsabuf, 1, &size, &flags, NULL, NULL);
    ok(ret == -1, "got %d\n", ret);
    ok(WSAGetLastError() == WSAEWOULDBLOCK, "got error %u\n", WSAGetLastError());
    ok(overlapped.Internal == 0xdeadbeef, "got status %#x\n", (NTSTATUS)overlapped.Internal);

    /* Overlapped, with a NULL event. */

    overlapped.hEvent = NULL;

    memset(buffer, 0, sizeof(buffer));
    WSASetLastError(0xdeadbeef);
    ret = WSARecv(client, &wsabuf, 1, NULL, &flags, &overlapped, NULL);
    ok(ret == -1, "got %d\n", ret);
    ok(WSAGetLastError() == ERROR_IO_PENDING, "got error %u\n", WSAGetLastError());
    ret = WaitForSingleObject((HANDLE)client, 0);
    ok(ret == WAIT_TIMEOUT, "expected timeout\n");

    ret = send(server, "data", 4, 0);
    ok(ret == 4, "got %d\n", ret);

    ret = WaitForSingleObject((HANDLE)client, 1000);
    ok(!ret, "wait timed out\n");
    ret = GetOverlappedResult((HANDLE)client, &overlapped, &size, FALSE);
    ok(ret, "got error %u\n", GetLastError());
    ok(size == 4, "got size %u\n", size);
    ok(!strcmp(buffer, "data"), "got %s\n", debugstr_an(buffer, size));

    /* Overlapped, with a non-NULL event. */

    overlapped.hEvent = event;

    memset(buffer, 0, sizeof(buffer));
    WSASetLastError(0xdeadbeef);
    ret = WSARecv(client, &wsabuf, 1, NULL, &flags, &overlapped, NULL);
    ok(ret == -1, "got %d\n", ret);
    ok(WSAGetLastError() == ERROR_IO_PENDING, "got error %u\n", WSAGetLastError());
    ret = WaitForSingleObject(event, 0);
    ok(ret == WAIT_TIMEOUT, "expected timeout\n");

    ret = send(server, "data", 4, 0);
    ok(ret == 4, "got %d\n", ret);

    ret = WaitForSingleObject(event, 1000);
    ok(!ret, "wait timed out\n");
    ret = GetOverlappedResult((HANDLE)client, &overlapped, &size, FALSE);
    ok(ret, "got error %u\n", GetLastError());
    ok(size == 4, "got size %u\n", size);
    ok(!strcmp(buffer, "data"), "got %s\n", debugstr_an(buffer, size));

    /* With data already in the pipe; usually this does return 0 (but not
     * reliably). */

    ret = send(server, "data", 4, 0);
    ok(ret == 4, "got %d\n", ret);

    memset(buffer, 0, sizeof(buffer));
    ret = WSARecv(client, &wsabuf, 1, NULL, &flags, &overlapped, NULL);
    ok(!ret || WSAGetLastError() == ERROR_IO_PENDING, "got error %u\n", WSAGetLastError());
    ret = WaitForSingleObject(event, 1000);
    ok(!ret, "wait timed out\n");
    ret = GetOverlappedResult((HANDLE)client, &overlapped, &size, FALSE);
    ok(ret, "got error %u\n", GetLastError());
    ok(size == 4, "got size %u\n", size);
    ok(!strcmp(buffer, "data"), "got %s\n", debugstr_an(buffer, size));

    closesocket(client);
    closesocket(server);

    /* With a non-overlapped socket, WSARecv() always blocks when passed an
     * overlapped structure, but returns WSAEWOULDBLOCK otherwise. */

    tcp_socketpair_flags(&client, &server, 0);
    set_blocking(client, FALSE);
    set_blocking(server, FALSE);

    WSASetLastError(0xdeadbeef);
    ret = recv(client, buffer, sizeof(buffer), 0);
    ok(ret == -1, "got %d\n", ret);
    ok(WSAGetLastError() == WSAEWOULDBLOCK, "got error %u\n", WSAGetLastError());

    WSASetLastError(0xdeadbeef);
    overlapped.Internal = 0xdeadbeef;
    ret = WSARecv(client, &wsabuf, 1, &size, &flags, NULL, NULL);
    ok(ret == -1, "got %d\n", ret);
    ok(WSAGetLastError() == WSAEWOULDBLOCK, "got error %u\n", WSAGetLastError());
    ok(overlapped.Internal == 0xdeadbeef, "got status %#x\n", (NTSTATUS)overlapped.Internal);

    /* Overlapped, with a NULL event. */

    params.client = client;
    params.event = NULL;
    thread = CreateThread(NULL, 0, nonblocking_async_recv_thread, &params, 0, NULL);

    ret = WaitForSingleObject(thread, 200);
    todo_wine ok(ret == WAIT_TIMEOUT, "expected timeout\n");

    ret = send(server, "data", 4, 0);
    ok(ret == 4, "got %d\n", ret);

    ret = WaitForSingleObject(thread, 200);
    ok(!ret, "wait timed out\n");
    CloseHandle(thread);

    /* Overlapped, with a non-NULL event. */

    params.client = client;
    params.event = event;
    thread = CreateThread(NULL, 0, nonblocking_async_recv_thread, &params, 0, NULL);

    ret = WaitForSingleObject(thread, 200);
    todo_wine ok(ret == WAIT_TIMEOUT, "expected timeout\n");

    ret = send(server, "data", 4, 0);
    ok(ret == 4, "got %d\n", ret);

    ret = WaitForSingleObject(thread, 200);
    ok(!ret, "wait timed out\n");
    CloseHandle(thread);

    /* With data already in the pipe. */

    ret = send(server, "data", 4, 0);
    ok(ret == 4, "got %d\n", ret);

    memset(buffer, 0, sizeof(buffer));
    ret = WSARecv(client, &wsabuf, 1, NULL, &flags, &overlapped, NULL);
    ok(!ret, "got %d\n", ret);
    ret = GetOverlappedResult((HANDLE)client, &overlapped, &size, FALSE);
    todo_wine ok(ret, "got error %u\n", GetLastError());
    ok(size == 4, "got size %u\n", size);
    todo_wine ok(!strcmp(buffer, "data"), "got %s\n", debugstr_an(buffer, size));

    closesocket(client);
    closesocket(server);

    CloseHandle(overlapped.hEvent);
}

START_TEST( sock )
{
    int i;

/* Leave these tests at the beginning. They depend on WSAStartup not having been
 * called, which is done by Init() below. */
    test_WithoutWSAStartup();
    test_WithWSAStartup();

    Init();

    test_set_getsockopt();
    test_so_reuseaddr();
    test_ip_pktinfo();
    test_extendedSocketOptions();

    for (i = 0; i < ARRAY_SIZE(tests); i++)
        do_test(&tests[i]);

    test_UDP();

    test_WSASocket();
    test_WSADuplicateSocket();
    test_WSAEnumNetworkEvents();

    test_errors();
    test_listen();
    test_select();
    test_accept();
    test_getpeername();
    test_getsockname();
    test_ioctlsocket();

    test_WSASendMsg();
    test_WSASendTo();
    test_WSARecv();
    test_WSAPoll();
    test_write_watch();
    test_iocp();

    test_events();

    test_ipv6only();
    test_TransmitFile();
    test_AcceptEx();
    test_ConnectEx();
    test_DisconnectEx();

    test_sioRoutingInterfaceQuery();
    test_sioAddressListChange();

    test_completion_port();
    test_address_list_query();
    test_bind();
    test_connecting_socket();
    test_WSAGetOverlappedResult();
    test_nonblocking_async_recv();

    /* this is an io heavy test, do it at the end so the kernel doesn't start dropping packets */
    test_send();
    test_synchronous_WSAIoctl();
    test_wsaioctl();

    Exit();
}
