/*
Copyright (c) 2004-2006 by Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include "polipo.h"

#ifdef NO_TUNNEL

void
do_tunnel(SOCKET_TYPE fd, char *buf, int offset, int len, AtomPtr url)
{
    int n;
    assert(buf);

    n = httpWriteErrorHeaders(buf, CHUNK_SIZE, 0, 1,
                              501, internAtom("CONNECT not available "
                                              "in this version."),
                              1, NULL, url->string, url->length, NULL);
    releaseAtom(url);
    if(n >= 0) {
        /* This is completely wrong.  The write is non-blocking, and we 
           don't reschedule it if it fails.  But then, if the write
           blocks, we'll simply drop the connection with no error message. */
        write(fd, buf, n);
    }
    dispose_chunk(buf);
    lingeringClose(fd);
    return;
}

#else

static void tunnelDispatch(TunnelPtr);
static int tunnelRead1Handler(SOCKET_TYPE, int, FdEventHandlerPtr, StreamRequestPtr);
static int tunnelRead2Handler(SOCKET_TYPE, int, FdEventHandlerPtr, StreamRequestPtr);
static int tunnelWrite1Handler(SOCKET_TYPE, int, FdEventHandlerPtr, StreamRequestPtr);
static int tunnelWrite2Handler(SOCKET_TYPE, int, FdEventHandlerPtr, StreamRequestPtr);
static int tunnelDnsHandler(SOCKET_TYPE, int, GethostbynameRequestPtr);
static int tunnelConnectionHandler(SOCKET_TYPE, int, FdEventHandlerPtr, ConnectRequestPtr);
static int tunnelSocksHandler(SOCKET_TYPE, int, SocksRequestPtr);
static int tunnelHandlerCommon(SOCKET_TYPE, TunnelPtr);
static int tunnelError(TunnelPtr, int, AtomPtr);

static int
circularBufferFull(CircularBufferPtr buf)
{
    if(buf->head == buf->tail - 1)
        return 1;
    if(buf->head == CHUNK_SIZE - 1 && buf->tail == 0)
        return 1;
    return 0;
}

static int
circularBufferEmpty(CircularBufferPtr buf)
{
     return buf->head == buf->tail;
}

static void
logTunnel(TunnelPtr tunnel, int blocked)
{
    do_log(L_TUNNEL,"tunnel %s:%d %s\n", tunnel->hostname->string, tunnel->port,
	   blocked ? "blocked" : "allowed");
}

static TunnelPtr
makeTunnel(SOCKET_TYPE fd, char *buf, int offset, int len)
{
    TunnelPtr tunnel;
    assert(offset < CHUNK_SIZE);

    tunnel = malloc(sizeof(TunnelRec));
    if(tunnel == NULL)
        return NULL;

    tunnel->hostname = NULL;
    tunnel->port = -1;
    tunnel->flags = 0;
    tunnel->fd1 = fd;
    tunnel->fd2 = SOCK_INVALID_VALUE;
    tunnel->buf1.buf = buf;
    if(offset == len) {
        tunnel->buf1.tail = 0;
        tunnel->buf1.head = 0;
    } else {
        tunnel->buf1.tail = offset;
        tunnel->buf1.head = len;
    }
    tunnel->buf2.buf = NULL;
    tunnel->buf2.tail = 0;
    tunnel->buf2.head = 0;
    return tunnel;
}

static void
destroyTunnel(TunnelPtr tunnel)
{
    assert(IS_SOCK_INVALID(tunnel->fd1) && IS_SOCK_INVALID(tunnel->fd2));
    releaseAtom(tunnel->hostname);
    if(tunnel->buf1.buf)
        dispose_chunk(tunnel->buf1.buf);
    if(tunnel->buf2.buf)
        dispose_chunk(tunnel->buf2.buf);
    free(tunnel);
}

void 
do_tunnel(SOCKET_TYPE fd, char *buf, int offset, int len, AtomPtr url)
{
    TunnelPtr tunnel;
    int port;
    char *p, *q;

    tunnel = makeTunnel(fd, buf, offset, len);
    if(tunnel == NULL) {
        do_log(L_ERROR, "Couldn't allocate tunnel.\n");
        releaseAtom(url);
        dispose_chunk(buf);
        CLOSE(fd);
        return;
    }

    if(proxyOffline) {
        do_log(L_INFO, "Attemted CONNECT when disconnected.\n");
        releaseAtom(url);
        tunnelError(tunnel, 502,
                    internAtom("Cannot CONNECT when disconnected."));
        return;
    }

    p = memrchr(url->string, ':', url->length);
    q = NULL;
    if(p)
        port = strtol(p + 1, &q, 10);
    if(!p || q != url->string + url->length) {
        do_log(L_ERROR, "Couldn't parse CONNECT.\n");
        releaseAtom(url);
        tunnelError(tunnel, 400, internAtom("Couldn't parse CONNECT"));
        return;
    }
    tunnel->hostname = internAtomLowerN(url->string, p - url->string);
    if(tunnel->hostname == NULL) {
        releaseAtom(url);
        tunnelError(tunnel, 501, internAtom("Couldn't allocate hostname"));
        return;
    }

    if(!intListMember(port, tunnelAllowedPorts)) {
        releaseAtom(url);
        tunnelError(tunnel, 403, internAtom("Forbidden port"));
        return;
    }
    tunnel->port = port;
    
    if (tunnelIsMatched(url->string, url->length, 
			tunnel->hostname->string, tunnel->hostname->length)) {
        releaseAtom(url);
        tunnelError(tunnel, 403, internAtom("Forbidden tunnel"));
	logTunnel(tunnel,1);
        return;
    }
    
    logTunnel(tunnel,0);
    
    releaseAtom(url);

    if(socksParentProxy)
        do_socks_connect(parentHost ?
                         parentHost->string : tunnel->hostname->string,
                         parentHost ? parentPort : tunnel->port,
                         tunnelSocksHandler, tunnel);
    else
        do_gethostbyname(parentHost ?
                         parentHost->string : tunnel->hostname->string, 0,
                         tunnelDnsHandler, tunnel);
}

static int
tunnelDnsHandler(SOCKET_TYPE fd, int errorno, GethostbynameRequestPtr request)
{
    TunnelPtr tunnel = request->data;

    if(IS_SOCK_INVALID(fd) || fd == 0) {
        tunnelError(tunnel, 504,
                    internAtomError(-errorno,
                                    "errorno %s lookup failed",
                                    atomString(tunnel->hostname)));
        return 1;
    }

    if(request->addr->string[0] == DNS_CNAME) {
        if(request->count > 10)
            tunnelError(tunnel, 504, internAtom("CNAME loop"));
        do_gethostbyname(request->addr->string + 1, request->count + 1,
                         tunnelDnsHandler, tunnel);
        return 1;
    }

    do_connect(retainAtom(request->addr), 0,
               parentHost ? parentPort : tunnel->port,
               tunnelConnectionHandler, tunnel);
    return 1;
}

static int
tunnelConnectionHandler(SOCKET_TYPE fd, int errorno,
                        FdEventHandlerPtr event,
                        ConnectRequestPtr request)
{
    TunnelPtr tunnel = request->data;
    int rc;

    if(IS_SOCK_INVALID(fd)) {
        tunnelError(tunnel, 504, internAtomError(-errorno, "Couldn't connect"));
        return 1;
    }

    rc = setNodelay(request->fd, 1);
    if(rc < 0)
        do_log_error(L_WARN, errno, "Couldn't disable Nagle's algorithm");

    return tunnelHandlerCommon(request->fd, tunnel);
}

static int
tunnelSocksHandler(SOCKET_TYPE fd, int errorno, SocksRequestPtr request)
{
    TunnelPtr tunnel = request->data;

    if(IS_SOCK_INVALID(fd)) {
        tunnelError(tunnel, 504, internAtomError(-errorno, "Couldn't connect"));
        return 1;
    }

    return tunnelHandlerCommon(request->fd, tunnel);
}

static int
tunnelHandlerParent(SOCKET_TYPE fd, TunnelPtr tunnel)
{
    char *message;
    int n;

    if(tunnel->buf1.buf == NULL)
        tunnel->buf1.buf = get_chunk();
    if(tunnel->buf1.buf == NULL) {
        message = "Couldn't allocate buffer";
        goto fail;
    }
    if(tunnel->buf1.tail != tunnel->buf1.head) {
        message = "Pipelined connect to parent proxy not implemented";
        goto fail;
    }

    n = snnprintf(tunnel->buf1.buf, tunnel->buf1.tail, CHUNK_SIZE,
                  "CONNECT %s:%d HTTP/1.1\r\nHost: %s",
                  tunnel->hostname->string, tunnel->port, tunnel->hostname->string);
    if (tunnel->port != 443)
        n = snnprintf(tunnel->buf1.buf, n, CHUNK_SIZE, ":%d", tunnel->port);
    if (parentAuthCredentials)
        n = buildServerAuthHeaders(tunnel->buf1.buf, n, CHUNK_SIZE,
                                   parentAuthCredentials);
    n = snnprintf(tunnel->buf1.buf, n, CHUNK_SIZE, "\r\n\r\n");

    if(n < 0) {
        message = "Buffer overflow";
        goto fail;
    }
    tunnel->buf1.head = n;
    tunnelDispatch(tunnel);
    return 1;

 fail:
    CLOSE(fd);
    tunnel->fd2 = -1;
    tunnelError(tunnel, 501, internAtom(message));
    return 1;
}

static int
tunnelHandlerCommon(SOCKET_TYPE fd, TunnelPtr tunnel)
{
    const char *message = "HTTP/1.1 200 Tunnel established\r\n\r\n";

    tunnel->fd2 = fd;

    if(parentHost)
        return tunnelHandlerParent(fd, tunnel);

    if(tunnel->buf2.buf == NULL)
        tunnel->buf2.buf = get_chunk();
    if(tunnel->buf2.buf == NULL) {
        CLOSE(fd);
        tunnelError(tunnel, 501, internAtom("Couldn't allocate buffer"));
        return 1;
    }

    memcpy(tunnel->buf2.buf, message, MIN(CHUNK_SIZE - 1, (int)strlen(message)));
    tunnel->buf2.head = MIN(CHUNK_SIZE - 1, (int)strlen(message));

    tunnelDispatch(tunnel);
    return 1;
}

static void
bufRead(SOCKET_TYPE fd, CircularBufferPtr buf,
        int (*handler)(SOCKET_TYPE, int, FdEventHandlerPtr, StreamRequestPtr),
        void *data)
{
    int tail;

    if(buf->tail == 0)
        tail = CHUNK_SIZE - 1;
    else
        tail = buf->tail - 1;

    if(buf->head == 0)
        do_stream_buf(IO_READ | IO_NOTNOW,
                      fd, 0,
                      &buf->buf, tail,
                      handler, data);
    else if(buf->tail > buf->head)
        do_stream(IO_READ | IO_NOTNOW,
                  fd, buf->head,
                  buf->buf, tail,
                  handler, data);
    else 
        do_stream_2(IO_READ | IO_NOTNOW,
                    fd, buf->head,
                    buf->buf, CHUNK_SIZE,
                    buf->buf, tail,
                    handler, data);
}

static void
bufWrite(SOCKET_TYPE fd, CircularBufferPtr buf,
        int (*handler)(SOCKET_TYPE, int, FdEventHandlerPtr, StreamRequestPtr),
        void *data)
{
    if(buf->head > buf->tail)
        do_stream(IO_WRITE,
                  fd, buf->tail,
                  buf->buf, buf->head,
                  handler, data);
    else
        do_stream_2(IO_WRITE,
                    fd, buf->tail,
                    buf->buf, CHUNK_SIZE,
                    buf->buf, buf->head,
                    handler, data);
}
                    
static void
tunnelDispatch(TunnelPtr tunnel)
{
    if(circularBufferEmpty(&tunnel->buf1)) {
        if(tunnel->buf1.buf && 
           !(tunnel->flags & (TUNNEL_READER1 | TUNNEL_WRITER2))) {
            dispose_chunk(tunnel->buf1.buf);
            tunnel->buf1.buf = NULL;
            tunnel->buf1.head = tunnel->buf1.tail = 0;
        }
    }

    if(circularBufferEmpty(&tunnel->buf2)) {
        if(tunnel->buf2.buf &&
           !(tunnel->flags & (TUNNEL_READER2 | TUNNEL_WRITER1))) {
            dispose_chunk(tunnel->buf2.buf);
            tunnel->buf2.buf = NULL;
            tunnel->buf2.head = tunnel->buf2.tail = 0;
        }
    }

    if(!IS_SOCK_INVALID(tunnel->fd1)) {
        if(!(tunnel->flags & (TUNNEL_READER1 | TUNNEL_EOF1)) && 
           !circularBufferFull(&tunnel->buf1)) {
            tunnel->flags |= TUNNEL_READER1;
            bufRead(tunnel->fd1, &tunnel->buf1, tunnelRead1Handler, tunnel);
        }
        if(!(tunnel->flags & (TUNNEL_WRITER1 | TUNNEL_EPIPE1)) &&
           !circularBufferEmpty(&tunnel->buf2)) {
            tunnel->flags |= TUNNEL_WRITER1;
            /* There's no IO_NOTNOW in bufWrite, so it might close the
               file descriptor straight away.  Wait until we're
               rescheduled. */
            bufWrite(tunnel->fd1, &tunnel->buf2, tunnelWrite1Handler, tunnel);
            return;
        }
        if(IS_SOCK_INVALID(tunnel->fd2) || (tunnel->flags & TUNNEL_EOF2)) {
            if(!(tunnel->flags & TUNNEL_EPIPE1))
                shutdown(tunnel->fd1, 1);
            tunnel->flags |= TUNNEL_EPIPE1;
        } else if(tunnel->fd1 < 0 || (tunnel->flags & TUNNEL_EPIPE2)) {
            if(!(tunnel->flags & TUNNEL_EOF1))
                shutdown(tunnel->fd1, 0);
            tunnel->flags |= TUNNEL_EOF1;
        }
        if((tunnel->flags & TUNNEL_EOF1) && (tunnel->flags & TUNNEL_EPIPE1)) {
            if(!(tunnel->flags & (TUNNEL_READER1 | TUNNEL_WRITER1))) {
                CLOSE(tunnel->fd1);
                tunnel->fd1 = SOCK_INVALID_VALUE;
            }
        }
    }

    if(!IS_SOCK_INVALID(tunnel->fd2)) {
        if(!(tunnel->flags & (TUNNEL_READER2 | TUNNEL_EOF2)) && 
           !circularBufferFull(&tunnel->buf2)) {
            tunnel->flags |= TUNNEL_READER2;
            bufRead(tunnel->fd2, &tunnel->buf2, tunnelRead2Handler, tunnel);
        }
        if(!(tunnel->flags & (TUNNEL_WRITER2 | TUNNEL_EPIPE2)) &&
           !circularBufferEmpty(&tunnel->buf1)) {
            tunnel->flags |= TUNNEL_WRITER2;
            bufWrite(tunnel->fd2, &tunnel->buf1, tunnelWrite2Handler, tunnel);
            return;
        }
        if(IS_SOCK_INVALID(tunnel->fd1) || (tunnel->flags & TUNNEL_EOF1)) {
            if(!(tunnel->flags & TUNNEL_EPIPE2))
                shutdown(tunnel->fd2, 1);
            tunnel->flags |= TUNNEL_EPIPE2;
        } else if(tunnel->fd1 < 0 || (tunnel->flags & TUNNEL_EPIPE1)) {
            if(!(tunnel->flags & TUNNEL_EOF2))
                shutdown(tunnel->fd2, 0);
            tunnel->flags |= TUNNEL_EOF2;
        }
        if((tunnel->flags & TUNNEL_EOF2) && (tunnel->flags & TUNNEL_EPIPE2)) {
            if(!(tunnel->flags & (TUNNEL_READER2 | TUNNEL_WRITER2))) {
                CLOSE(tunnel->fd2);
                tunnel->fd2 = SOCK_INVALID_VALUE;
            }
        }
    }

    if(IS_SOCK_INVALID(tunnel->fd1) && IS_SOCK_INVALID(tunnel->fd2))
        destroyTunnel(tunnel);
    else
        assert(tunnel->flags & (TUNNEL_READER1 | TUNNEL_WRITER1 |
                                TUNNEL_READER2 | TUNNEL_WRITER2));
}

static int
tunnelRead1Handler(SOCKET_TYPE fd, int errorno,
                   FdEventHandlerPtr event, StreamRequestPtr request)
{
    TunnelPtr tunnel = request->data;
    if(fd) {
        if(IS_SOCK_INVALID(fd) && errorno != -EPIPE && errorno != -ECONNRESET)
            do_log_error(L_ERROR, -errorno, "Couldn't read from client");
        tunnel->flags |= TUNNEL_EOF1;
        goto done;
    }
    tunnel->buf1.head = request->offset % CHUNK_SIZE;
 done:
    /* Keep buffer empty to avoid a deadlock */
    if((tunnel->flags & TUNNEL_EPIPE2))
        tunnel->buf1.tail = tunnel->buf1.head;
    tunnel->flags &= ~TUNNEL_READER1;
    tunnelDispatch(tunnel);
    return 1;
}

static int
tunnelRead2Handler(SOCKET_TYPE fd, int errorno,
                   FdEventHandlerPtr event, StreamRequestPtr request)
{
    TunnelPtr tunnel = request->data;
    if(fd) {
        if(IS_SOCK_INVALID(fd) && errorno != -EPIPE && errorno != -ECONNRESET)
            do_log_error(L_ERROR, -errorno, "Couldn't read from server");
        tunnel->flags |= TUNNEL_EOF2;
        goto done;
    }
    tunnel->buf2.head = request->offset % CHUNK_SIZE;
done:
    /* Keep buffer empty to avoid a deadlock */
    if((tunnel->flags & TUNNEL_EPIPE1))
        tunnel->buf2.tail = tunnel->buf2.head;
    tunnel->flags &= ~TUNNEL_READER2;
    tunnelDispatch(tunnel);
    return 1;
}

static int
tunnelWrite1Handler(SOCKET_TYPE fd, int errorno,
                   FdEventHandlerPtr event, StreamRequestPtr request)
{
    TunnelPtr tunnel = request->data;
    if(fd || (tunnel->flags & TUNNEL_EPIPE1)) {
        tunnel->flags |= TUNNEL_EPIPE1;
        if(IS_SOCK_INVALID(fd) && errorno != -EPIPE)
            do_log_error(L_ERROR, -errorno, "Couldn't write to client");
        /* Empty the buffer to avoid a deadlock */
        tunnel->buf2.tail = tunnel->buf2.head;
        goto done;
    }
    tunnel->buf2.tail = request->offset % CHUNK_SIZE;
 done:
    tunnel->flags &= ~TUNNEL_WRITER1;
    tunnelDispatch(tunnel);
    return 1;
}
        
static int
tunnelWrite2Handler(SOCKET_TYPE fd, int errorno,
                   FdEventHandlerPtr event, StreamRequestPtr request)
{
    TunnelPtr tunnel = request->data;
    if(fd || (tunnel->flags & TUNNEL_EPIPE2)) {
        tunnel->flags |= TUNNEL_EPIPE2;
        if(IS_SOCK_INVALID(fd) && errorno != -EPIPE)
            do_log_error(L_ERROR, -errorno, "Couldn't write to server");
        /* Empty the buffer to avoid a deadlock */
        tunnel->buf1.tail = tunnel->buf1.head;
        goto done;
    }
    tunnel->buf1.tail = request->offset % CHUNK_SIZE;
 done:
    tunnel->flags &= ~TUNNEL_WRITER2;
    tunnelDispatch(tunnel);
    return 1;
}
        
static int
tunnelError(TunnelPtr tunnel, int code, AtomPtr message)
{
    int n;
    if(!IS_SOCK_INVALID(tunnel->fd2)) {
        CLOSE(tunnel->fd2);
        tunnel->fd2 = SOCK_INVALID_VALUE;
    }

    if(tunnel->buf2.buf == NULL)
        tunnel->buf2.buf = get_chunk();
    if(tunnel->buf2.buf == NULL)
        goto fail;

    n = httpWriteErrorHeaders(tunnel->buf2.buf, CHUNK_SIZE - 1, 0,
                              1, code, message, 1, NULL,
                              NULL, 0, NULL);

    if(n <= 0) goto fail;

    tunnel->buf2.head = n;

    tunnelDispatch(tunnel);
    return 1;

 fail:
    CLOSE(tunnel->fd1);
    tunnel->fd1 = SOCK_INVALID_VALUE;
    tunnelDispatch(tunnel);
    return 1;
}
#endif
