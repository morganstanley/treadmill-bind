/*
  This preempts normal calls to `bind`. Should TREADMILL_EPH_PORTS_FILE
  (or if not the file defined by TREADMILL_EPH_PORTS_FILE_ENV) be set
  to a list of ports the new `bind` will look through that list of
  ports when attempting to bind to addr INADDR_ANY or
  TREADMILL_CONTAINER_IPV{4,6}_FILE and port 0. When it findsone free
  it will return successful. This allows us to control the known
  ephemeral ports. If EPH_PORTS is not set or the interface is not one
  we care about we'll perform a normal bind.

  If IPV6 is not set it will create an ipv6 address from _IPV4.

  If neither are set it defaults to INADDR_ANY and in6addr_any
  respectively.
*/

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define NUMOFPORTS 256
#define BASE10 10

static const char TREADMILL_EPH_TCP_PORTS_FILE_ENV[] =
    "TREADMILL_EPH_TCP_PORTS_FILE";
static const char TREADMILL_EPH_UDP_PORTS_FILE_ENV[] =
    "TREADMILL_EPH_UDP_PORTS_FILE";
static const char TREADMILL_CONTAINER_IPV4_FILE_ENV[] =
    "TREADMILL_CONTAINER_IPV4_FILE";
static const char TREADMILL_CONTAINER_IPV6_FILE_ENV[] =
    "TREADMILL_CONTAINER_IPV6_FILE";
static const char TREADMILL_HOST_IPV4_FILE_ENV[] =
    "TREADMILL_HOST_IPV4_FILE";
static const char TREADMILL_HOST_IPV6_FILE_ENV[] =
    "TREADMILL_HOST_IPV6_FILE";

static const char TREADMILL_EPH_TCP_PORTS_FILE[] =
    "/env/TREADMILL_EPHEMERAL_TCP_PORTS";
static const char TREADMILL_EPH_UDP_PORTS_FILE[] =
    "/env/TREADMILL_EPHEMERAL_UDP_PORTS";
static const char TREADMILL_CONTAINER_IPV4_FILE[] =
    "/env/TREADMILL_CONTAINER_IP";
static const char TREADMILL_CONTAINER_IPV6_FILE[] =
    "/env/TREADMILL_CONTAINER_IPV6";
static const char TREADMILL_HOST_IPV4_FILE[] =
    "/env/TREADMILL_HOST_IP";
static const char TREADMILL_HOST_IPV6_FILE[] =
    "/env/TREADMILL_HOST_IPV6";

static unsigned short  _tcp_ports[NUMOFPORTS]  = {0};
static unsigned short  _udp_ports[NUMOFPORTS]  = {0};
static struct in_addr  _container_in_addr;
static struct in6_addr _container_in6_addr;
static struct in_addr  _host_in_addr;
static struct in6_addr _host_in6_addr;

static int (*_real_bind)(int, const struct sockaddr *, socklen_t) = NULL;

static
const char *
_get_dlerror()
{
    const char *error;

    error = dlerror();
    if (error == NULL)
        error = "unknown error";

    return error;
}

static
void
_print_error(void)
{
    fprintf(stderr,
            "Error locating 'bind': %s\n",
            _get_dlerror());
}

static
void
_print_error_and__exit(int status)
{
    _print_error();
    _exit(status);
}

static
void
_set_sockaddr_port(struct sockaddr      *my_addr,
                   const unsigned short  port)
{
    switch (my_addr->sa_family) {
    case AF_INET:
        ((struct sockaddr_in*)my_addr)->sin_port = port;
        break;
    case AF_INET6:
        ((struct sockaddr_in6*)my_addr)->sin6_port = port;
        break;
    }
}

unsigned short
_get_next_port(unsigned short *ports)
{
    volatile unsigned static int offset = 0;
    unsigned short port = 0;

    while (port == 0)
        port = htons(ports[(offset++ % NUMOFPORTS)]);

    return port;
}

static
int
_bind_to_available_port(unsigned short        *ports,
                        int                    sockfd,
                        const struct sockaddr *my_addr,
                        socklen_t              addrlen)
{
    int i;
    int rv;
    struct sockaddr_storage addr;

    memcpy(&addr,my_addr,addrlen);
    for (i = 0; ((i < NUMOFPORTS) && (ports[i] != 0)); i++) {
        unsigned short port = _get_next_port(ports);

        _set_sockaddr_port((struct sockaddr*)&addr,port);

        rv = _real_bind(sockfd,(struct sockaddr*)&addr,addrlen);
        if (rv == 0)
            /* Reset errno and return success */
            return (errno = 0, 0);

        if (rv == -1 && errno != EADDRINUSE)
            return -1;
    }

    return (errno = EADDRNOTAVAIL, -1);
}

static
int
_valid_sockaddr(const struct sockaddr *my_addr,
                const socklen_t        addrlen)
{
    return ((my_addr != NULL) && (addrlen != 0));
}

static
int
_is_targetted_addr_or_any(const struct sockaddr *my_addr)
{
    const struct sockaddr_in *addr_in = (const struct sockaddr_in*)my_addr;

    return
        ((addr_in->sin_addr.s_addr == INADDR_ANY) ||
         (addr_in->sin_addr.s_addr == _container_in_addr.s_addr) ||
         (addr_in->sin_addr.s_addr == _host_in_addr.s_addr));
}

static
int
_is_targetted_addr6_or_any(const struct sockaddr *my_addr)
{
    const struct sockaddr_in6 *addr_in6 = (const struct sockaddr_in6*)my_addr;

    return
        ((memcmp(&addr_in6->sin6_addr.s6_addr,
                 &in6addr_any,
                 sizeof(struct in6_addr)) == 0) ||
         (memcmp(&addr_in6->sin6_addr.s6_addr,
                 &_container_in6_addr.s6_addr,
                 sizeof(struct in6_addr)) == 0) ||
         (memcmp(&addr_in6->sin6_addr.s6_addr,
                 &_host_in6_addr.s6_addr,
                 sizeof(struct in6_addr)) == 0));
}

static
int
_sockaddr_in_port_equals(const struct sockaddr *my_addr,
                         const unsigned short   port)
{
    return ((struct sockaddr_in*)my_addr)->sin_port == port;
}

static
int
_sockaddr_in6_port_equals(const struct sockaddr *my_addr,
                          const unsigned short   port)
{
    return ((struct sockaddr_in6*)my_addr)->sin6_port == port;
}

static
int
_sockaddr_in_port_equals_zero(const struct sockaddr *my_addr)
{
    return _sockaddr_in_port_equals(my_addr,0);
}

static
int
_sockaddr_in6_port_equals_zero(const struct sockaddr *my_addr)
{
    return _sockaddr_in6_port_equals(my_addr,0);
}

static
int
_is_in_targetted_socket(const struct sockaddr *my_addr,
                        const socklen_t       addrlen)
{
    if ((my_addr->sa_family == AF_INET) &&
        (_is_targetted_addr_or_any(my_addr)))
        return _sockaddr_in_port_equals_zero(my_addr);
    else
        return 0;
}

static
int
_is_in6_targetted_socket(const struct sockaddr *my_addr,
                         const socklen_t       addrlen)
{
    if ((my_addr->sa_family == AF_INET6) &&
        (_is_targetted_addr6_or_any(my_addr)))
        return _sockaddr_in6_port_equals_zero(my_addr);
    else
        return 0;
}

/*
  We are applying our special ephemeral ports iff:

  * It is a valid socket address
  * sa_family == AF_INET || AF_INET6
  * for each family the address being bound to is ANY or the container's
  * the port being bound is `0`
  * the socket is a TCP socket.
 */
static
int
_is_targetted_socket(const struct sockaddr *my_addr,
                     const socklen_t        addrlen)
{
    /* We pass through invalid sockaddr to "real" bind to error handling */
    if (!_valid_sockaddr(my_addr,addrlen))
        return 0;

    /* Only consider if binding to 0 on an interface we care about */
    return (_is_in_targetted_socket(my_addr,addrlen) ||
            _is_in6_targetted_socket(my_addr,addrlen)) ? 1 : 0;
}

int
_parse_list_of_unsigned_shorts(const char     *str,
                               unsigned short *shorts,
                               size_t          numofshorts)
{
    size_t i;

    i = 0;
    while(i < numofshorts) {
        int next;
        char *tail;

        while (isspace(*str))
            str++;
        if (*str == '\0')
            break;

        errno = 0;
        next = strtol(str,&tail,BASE10);
        if (errno != 0)
            break;

        shorts[i] = (unsigned short)next;

        str = tail;
        i++;
    }

    return i;
}

static
ssize_t
_read_file_to_buf(const char   *filepath,
                  char         *buf,
                  const size_t  bufsize)
{
    int fd;
    ssize_t bytesread;

    fd = open(filepath,O_RDONLY);
    if (fd == -1)
        return -1;

    bytesread = read(fd,buf,bufsize);
    if (bytesread == -1)
        return -1;

    close(fd);

    return bytesread;
}

static
ssize_t
_read_file_to_buf_zeroed(const char   *filepath,
                         char         *buf,
                         const size_t  bufsize)
{
    ssize_t bytesread;

    bytesread = _read_file_to_buf(filepath,buf,bufsize-1);
    if (bytesread >= 0)
        buf[bytesread] = '\0';

    return bytesread;
}

static
int
_populate_ports_via_file(const char     *filepath,
                         unsigned short *ports)
{
    char buf[8192];
    ssize_t bytesread;

    bytesread = _read_file_to_buf_zeroed(filepath,buf,sizeof(buf));
    if (bytesread == -1)
        return -1;

    _parse_list_of_unsigned_shorts(buf,ports,NUMOFPORTS);

    return 0;
}

static
void
_populate_ports(unsigned short *ports,
                const char     *ports_file_env,
                const char     *default_ports_file)
{
    const char *ports_file;

    ports_file = getenv(ports_file_env);
    if (ports_file == NULL)
        ports_file = default_ports_file;

    _populate_ports_via_file(ports_file, ports);
}

static
void
_populate_in_addr(struct in_addr *addr,
                  const char     *ipv4_file)
{
    char filebuf[256];
    ssize_t bytesread;

    addr->s_addr = INADDR_ANY;

    bytesread = _read_file_to_buf_zeroed(ipv4_file,
                                         filebuf,
                                         sizeof(filebuf));
    if (bytesread == -1)
        return;

    inet_pton(AF_INET,filebuf,addr);
}

static
void
_populate_in6_addr(struct in6_addr *addr6,
                   const char      *ipv6_file,
                   const char      *ipv4_file)
{
    char ipv6buf[256];
    ssize_t bytesread;

    (*addr6) = in6addr_any;

    bytesread = _read_file_to_buf_zeroed(ipv6_file,
                                         ipv6buf,
                                         sizeof(ipv6buf));
    if (bytesread == -1) {
        char filebuf[256];

        bytesread = _read_file_to_buf_zeroed(ipv4_file,
                                             filebuf,
                                             sizeof(filebuf));
        if (bytesread == -1)
            return;

        snprintf(ipv6buf,(sizeof(ipv6buf)-1),"::FFFF:%s",filebuf);
    }

    inet_pton(AF_INET6,ipv6buf,addr6);
}

static
void
_populate_container_in_addr(void)
{
    const char *container_ipv4_file;

    container_ipv4_file = getenv(TREADMILL_CONTAINER_IPV4_FILE_ENV);
    if (container_ipv4_file == NULL)
        container_ipv4_file = TREADMILL_CONTAINER_IPV4_FILE;

    _populate_in_addr(&_container_in_addr,
                      container_ipv4_file);
}

static
void
_populate_container_in6_addr(void)
{
    const char *container_ipv6_file;
    const char *container_ipv4_file;

    container_ipv6_file = getenv(TREADMILL_CONTAINER_IPV6_FILE_ENV);
    if (container_ipv6_file == NULL)
        container_ipv6_file = TREADMILL_CONTAINER_IPV6_FILE;

    container_ipv4_file = getenv(TREADMILL_CONTAINER_IPV4_FILE_ENV);
    if (container_ipv4_file == NULL)
        container_ipv4_file = TREADMILL_CONTAINER_IPV4_FILE;

    _populate_in6_addr(&_container_in6_addr,
                       container_ipv6_file,
                       container_ipv4_file);
}

static
void
_populate_host_in_addr(void)
{
    const char *host_ipv4_file;

    host_ipv4_file = getenv(TREADMILL_HOST_IPV4_FILE_ENV);
    if (host_ipv4_file == NULL)
        host_ipv4_file = TREADMILL_HOST_IPV4_FILE;

    _populate_in_addr(&_host_in_addr,
                      host_ipv4_file);
}

static
void
_populate_host_in6_addr(void)
{
    const char *host_ipv6_file;
    const char *host_ipv4_file;

    host_ipv6_file = getenv(TREADMILL_HOST_IPV6_FILE_ENV);
    if (host_ipv6_file == NULL)
        host_ipv6_file = TREADMILL_HOST_IPV6_FILE;

    host_ipv4_file = getenv(TREADMILL_HOST_IPV4_FILE_ENV);
    if (host_ipv4_file == NULL)
        host_ipv4_file = TREADMILL_HOST_IPV4_FILE;

    _populate_in6_addr(&_host_in6_addr,
                       host_ipv6_file,
                       host_ipv4_file);
}

static
void
_real_bind_init(void)
{
    _real_bind = dlsym(RTLD_NEXT,"bind");
    if (_real_bind == NULL)
        _print_error_and__exit(EXIT_FAILURE);

    _populate_ports(
        _tcp_ports,
        TREADMILL_EPH_TCP_PORTS_FILE_ENV,
        TREADMILL_EPH_TCP_PORTS_FILE
    );
    _populate_ports(
        _udp_ports,
        TREADMILL_EPH_UDP_PORTS_FILE_ENV,
        TREADMILL_EPH_UDP_PORTS_FILE
    );
    _populate_container_in_addr();
    _populate_container_in6_addr();
    _populate_host_in_addr();
    _populate_host_in6_addr();

    /* Reset errno to avoid polution from our _populate_*() functions. */
    errno = 0;
}

static
int
_new_bind(int                    sockfd,
          const struct sockaddr *my_addr,
          socklen_t              addrlen)
{
    if (_is_targetted_socket(my_addr, addrlen)) {
        int so_type;
        int res;
        socklen_t so_type_len;

        so_type_len = sizeof(so_type);
        /* Only consider TCP sockets.  On any error reading socket options, we
         * pass the socket to real bind for error handling. */
        res = getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &so_type, &so_type_len);
        if (res == -1)
            return _real_bind(sockfd,my_addr,addrlen);

        if (so_type == SOCK_STREAM && _tcp_ports[0])
            return _bind_to_available_port(_tcp_ports,sockfd,my_addr,addrlen);
        else if (so_type == SOCK_DGRAM && _udp_ports[0])
            return _bind_to_available_port(_udp_ports,sockfd,my_addr,addrlen);
        else
            return _real_bind(sockfd,my_addr,addrlen);
    }

    return _real_bind(sockfd,my_addr,addrlen);
}

int
bind(int                    sockfd,
     const struct sockaddr *my_addr,
     socklen_t              addrlen)
{
    if(_real_bind == NULL)
        _real_bind_init();

    return _new_bind(sockfd,my_addr,addrlen);
}
