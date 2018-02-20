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

#include <arpa/inet.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

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

/*
 * List of procnames to be exclusively intercepted or ignored.
 */
static const char TREADMILL_BIND_WHITELIST[] =
    "TREADMILL_BIND_WHITELIST";
static const char TREADMILL_BIND_WHITELIST_FILE[] =
    "/env/TREADMILL_BIND_WHITELIST";
static const char TREADMILL_BIND_BLACKLIST[] =
    "TREADMILL_BIND_BLACKLIST";
static const char TREADMILL_BIND_BLACKLIST_FILE[] =
    "/env/TREADMILL_BIND_BLACKLIST";

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
static const char TREADMILL_APP_FILE[] =
    "/env/TREADMILL_APP";
static const char TREADMILL_INSTANCE_FILE[] =
    "/env/TREADMILL_INSTANCEID";

static const int _SYSLOG_NOTICE = 141;
static const int _SYSLOG_INFO = 142;
static const int _SYSLOG_WARNING = 140;
static const int _SYSLOG_ERR = 139;

LIST_HEAD(ports_list, entry) _tcp_ports, _udp_ports;

volatile struct entry *_tcp_port_iter = NULL;
volatile struct entry *_udp_port_iter = NULL;

struct entry {
    unsigned short port;
    LIST_ENTRY(entry) entries;
};

static struct in_addr  _container_in_addr;
static struct in6_addr _container_in6_addr;
static struct in_addr  _host_in_addr;
static struct in6_addr _host_in6_addr;

static const char *_proc_name = NULL;

static int (*_real_bind)(int, const struct sockaddr *, socklen_t) = NULL;

static int _intercept = 1;

static int _syslog_sock = 0;
static struct sockaddr_un _syslog_sock_name;


static
ssize_t
_read_file_to_buf_zeroed(const char   *filepath,
                         char         *buf,
                         const size_t  bufsize);

static
const char *const _treadmill_app() {
    static char _buf[128];
    if (_buf[0]) return _buf;

    _read_file_to_buf_zeroed(TREADMILL_APP_FILE, _buf, sizeof(_buf));
    return _buf;
}

static
const char *const _treadmill_instance_id() {
    static char _buf[16];
    if (_buf[0]) return _buf;

    _read_file_to_buf_zeroed(TREADMILL_INSTANCE_FILE, _buf, sizeof(_buf));
    return _buf;
}

static
void _init_syslog()
{
    _syslog_sock_name.sun_family = AF_UNIX;
    strcpy(_syslog_sock_name.sun_path, "/dev/log");
    // If socket fails, we will not be able to sent syslog, which is benign,
    // Not checking error code.
    _syslog_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
}

static
void syslog(int lvl, const char *format, ...)
{
    struct tm tm;
    char buffer[512];
    char tm_string[128];
    time_t t;
    int errno_saved;

    va_list args;

    if (_syslog_sock == -1) {
        return;
    }

    errno_saved = errno;

    va_start(args, format);

    t = time(NULL);
    localtime_r(&t, &tm);

    strftime(tm_string, sizeof(tm_string), "%FT%TZ", &tm);
    snprintf(buffer,
             sizeof(buffer),
             "<%d>%s - treadmill-bind %s#%s %s[%d]: ",
             lvl,
             tm_string,
             _treadmill_app(),
             _treadmill_instance_id(),
             _proc_name,
             getpid());

    vsnprintf(buffer + strlen(buffer),
              sizeof(buffer) - strlen(buffer),
              format,
              args);
    va_end(args);

    // There is no point checking return code of sendto, as there is nowhere
    // to log it.
    sendto(_syslog_sock,
           buffer,
           strlen(buffer) + 1,
           0,
           (const struct sockaddr *)&_syslog_sock_name,
           sizeof(struct sockaddr_un));

    errno = errno_saved;
}

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

static
int
_bind_to_available_port(struct ports_list     *ports,
                        int                    sockfd,
                        const struct sockaddr *my_addr,
                        socklen_t              addrlen)
{
    int rc;
    struct sockaddr_storage addr;
    struct entry *next = NULL;
    int so_reuseaddr = 0;

    memcpy(&addr,my_addr,addrlen);

    rc = setsockopt(
        sockfd,
        SOL_SOCKET,
        SO_REUSEADDR,
        &so_reuseaddr,
        sizeof(so_reuseaddr)
    );

    if (rc != 0) {
        syslog(
            _SYSLOG_WARNING, "setsockopt SO_REUSEADDR: fd = %d, errno: %d",
            sockfd,
            errno
        );
        return rc;
    }

    for (next = ports->lh_first; next != NULL; next = next->entries.le_next) {
        _set_sockaddr_port((struct sockaddr *)&addr, htons(next->port));

        rc = _real_bind(sockfd, (struct sockaddr *)&addr, addrlen);
        if (rc == 0) {
            /* Reset errno and return success */
            syslog(_SYSLOG_INFO, "free port found: %d", next->port);
            return (errno = 0, 0);
        }

        if (rc == -1 && errno != EADDRINUSE) {
            syslog(
                _SYSLOG_INFO,
                "real bind failed: port = %d, errno = %d",
                next->port,
                errno
            );
            return rc;
        }
    }

    syslog(_SYSLOG_WARNING, "all ports in use, EADDFNOTAVAIL");
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
    const struct sockaddr_in *addr_in = (const struct sockaddr_in *)my_addr;

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
    return _sockaddr_in_port_equals(my_addr, 0);
}

static
int
_sockaddr_in6_port_equals_zero(const struct sockaddr *my_addr)
{
    return _sockaddr_in6_port_equals(my_addr, 0);
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
    if (!_valid_sockaddr(my_addr, addrlen))
        return 0;

    /* Only consider if binding to 0 on an interface we care about */
    return (_is_in_targetted_socket(my_addr, addrlen) ||
            _is_in6_targetted_socket(my_addr, addrlen)) ? 1 : 0;
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

    bytesread = _read_file_to_buf(filepath, buf, bufsize-1);
    if (bytesread >= 0)
        buf[bytesread] = '\0';

    return bytesread;
}

static
int
_populate_ports_via_file(const char        *filepath,
                         struct ports_list *ports)
{
    FILE *fp = NULL;
    syslog(_SYSLOG_INFO, "processing port file: %s", filepath);

    fp = fopen (filepath, "r");
    if (fp == 0) {
        syslog(
            _SYSLOG_WARNING,
            "unable to open file: %s, errno = %d",
            filepath,
            errno
        );
        return -1;
    }

    unsigned short p;
    while (fscanf(fp, "%hu", &p) == 1) {
        struct entry *e = malloc(sizeof(struct entry));
        e->port = p;
        syslog(_SYSLOG_INFO, "adding port: %d", p);
        LIST_INSERT_HEAD(ports, e, entries);
    }

    fclose(fp);
    return 0;
}

static
void
_populate_ports(struct ports_list *ports,
                const char        *ports_file_env,
                const char        *default_ports_file)
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
char* const
_get_process_name_by_pid(const int pid)
{
    FILE *f = NULL;
    static char name[256];
    if (name[0]) return name;

    sprintf(name, "/proc/%d/cmdline", pid);

    f = fopen(name, "r");
    if (f) {
        size_t size;
        size = fread(name, sizeof(char), sizeof(name) - 1, f);
        if (size > 0) {
            if ('\n' == name[size-1])
                name[size-1]='\0';
        }
        fclose(f);
    }
    return name;
}

static
int _is_in_list(const char *delim_string, const char *sep, const char *match)
{
    int found = 0;
    char *token = NULL;

    char *duplicate = strdup(delim_string);
    // It is safe to use non-reentrant version of strtok, as we work on
    // allocated string.
    token = strtok(duplicate, sep);
    while (token) {
        if (strcmp(token, match) == 0) {
            found = 1;
            break;
        }
        token = strtok(NULL, sep);
    }
    free(duplicate);
    return found;
}

static
void
_check_if_intercept()
{
    const char *whitelist_env = getenv(TREADMILL_BIND_WHITELIST);
    const char *blacklist_env = getenv(TREADMILL_BIND_BLACKLIST);

    char whitelist[256] = {0};
    char blacklist[256] = {0};


    if (whitelist_env)
        strncpy(whitelist, whitelist_env, sizeof(whitelist));
    else
        _read_file_to_buf_zeroed(TREADMILL_BIND_WHITELIST_FILE,
                                 whitelist, sizeof(whitelist));
    if (blacklist_env)
        strncpy(blacklist, blacklist_env, sizeof(blacklist));
    else
        _read_file_to_buf_zeroed(TREADMILL_BIND_BLACKLIST_FILE,
                                 blacklist, sizeof(blacklist));

    if (whitelist[0] && whitelist[strlen(whitelist) - 1] == '\n')
        whitelist[strlen(whitelist) - 1] = '\0';
    if (blacklist[0] && blacklist[strlen(blacklist) - 1] == '\n')
        blacklist[strlen(blacklist) - 1] = '\0';

    if (whitelist[0] && !_is_in_list(whitelist, ":", _proc_name)) {
        syslog(
            _SYSLOG_INFO,
            "not intercepting: %s, whitelist: %s",
            _proc_name,
            whitelist
        );
        _intercept = 0;
    }
    if (blacklist[0] && _is_in_list(blacklist, ":", _proc_name)) {
        syslog(
            _SYSLOG_INFO,
            "not intercepting: %s, blacklist: %s",
            _proc_name,
            blacklist
        );
        _intercept = 0;
    }
}

static
void
_real_bind_init(void)
{
    _real_bind = dlsym(RTLD_NEXT,"bind");
    if (_real_bind == NULL)
        _print_error_and__exit(EXIT_FAILURE);

    _init_syslog();

    if (_proc_name == NULL)
        _proc_name = basename(_get_process_name_by_pid(getpid()));

    LIST_INIT(&_tcp_ports);
    LIST_INIT(&_udp_ports);

    _check_if_intercept();

    if (_intercept) {
        _populate_ports(
                &_tcp_ports,
                TREADMILL_EPH_TCP_PORTS_FILE_ENV,
                TREADMILL_EPH_TCP_PORTS_FILE
                );
        _populate_ports(
                &_udp_ports,
                TREADMILL_EPH_UDP_PORTS_FILE_ENV,
                TREADMILL_EPH_UDP_PORTS_FILE
                );
        _populate_container_in_addr();
        _populate_container_in6_addr();
        _populate_host_in_addr();
        _populate_host_in6_addr();
    }

    /* Reset errno to avoid polution from our _populate_*() functions. */
    errno = 0;
}

static
int
_new_bind(int                    sockfd,
          const struct sockaddr *my_addr,
          socklen_t              addrlen)
{
    if (_intercept && _is_targetted_socket(my_addr, addrlen)) {
        int so_type;
        int res;
        socklen_t so_type_len;

        so_type_len = sizeof(so_type);

        /* Only consider TCP sockets.  On any error reading socket options, we
         * pass the socket to real bind for error handling. */
        res = getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &so_type, &so_type_len);
        if (res == -1)
            return _real_bind(sockfd,my_addr,addrlen);

        syslog(
            _SYSLOG_INFO,
            "bind: fd = %d, type = %d",
            sockfd,
            so_type
        );

        if (so_type == SOCK_STREAM && !LIST_EMPTY(&_tcp_ports))
            return _bind_to_available_port(
                &_tcp_ports,
                sockfd,
                my_addr,
                addrlen
            );
        else if (so_type == SOCK_DGRAM && !LIST_EMPTY(&_udp_ports))
            return _bind_to_available_port(
                &_udp_ports,
                sockfd,
                my_addr,
                addrlen
            );
        else
            return _real_bind(sockfd, my_addr, addrlen);
    }
    else
        return _real_bind(sockfd,my_addr,addrlen);
}

int
bind(int                    sockfd,
     const struct sockaddr *my_addr,
     socklen_t              addrlen)
{
    if(_real_bind == NULL)
        _real_bind_init();

    return _new_bind(sockfd, my_addr, addrlen);
}
