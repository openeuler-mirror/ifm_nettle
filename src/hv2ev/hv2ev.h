#ifndef HV_2_EV_H
#define HV_2_EV_H

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include "hv/hbase.h"
#include "hv/hbuf.h"
#include "hv/hexport.h"
#include "hv/hloop.h"
#include "hv/hsocket.h"

#ifdef __cplusplus
extern "C" {
#endif

#define evsignal_new hv2ev_evsignal_new
#define evsignal_add hv2ev_evsignal_add
#define evutil_socket_error_to_string hv2ev_evutil_socket_error_to_string
#define EVUTIL_ERR_CONNECT_RETRIABLE hv2ev_EVUTIL_ERR_CONNECT_RETRIABLE
#define EVUTIL_ERR_CONNECT_REFUSED hv2ev_EVUTIL_ERR_CONNECT_REFUSED
#define EVUTIL_ERR_RW_RETRIABLE hv2ev_EVUTIL_ERR_RW_RETRIABLE
#define EVUTIL_SET_SOCKET_ERROR hv2ev_EVUTIL_SET_SOCKET_ERROR
#define EVUTIL_ERR_IS_EAGAIN hv2ev_EVUTIL_ERR_IS_EAGAIN
#define EVUTIL_ERR_ACCEPT_RETRIABLE hv2ev_EVUTIL_ERR_ACCEPT_RETRIABLE
#define evtimer_add hv2ev_evtimer_add
#define evtimer_del hv2ev_evtimer_del
#define evtimer_new hv2ev_evtimer_new
#define evtimer_assign hv2ev_evtimer_assign
#define evtimer_pending hv2ev_evtimer_pending
#define evutil_timerclear hv2ev_evutil_timerclear
#define evutil_socket_geterror hv2ev_evutil_socket_geterror
#define evutil_gettimeofday hv2ev_evutil_gettimeofday
#define evutil_closesocket hv2ev_evutil_closesocket
#define evutil_make_socket_nonblocking hv2ev_evutil_make_socket_nonblocking
#define evutil_socketpair hv2ev_evutil_socketpair
#define evutil_make_socket_closeonexec hv2ev_evutil_make_socket_closeonexec
#define evutil_inet_pton hv2ev_evutil_inet_pton
#define evutil_inet_ntop hv2ev_evutil_inet_ntop
#define evbuffer_new hv2ev_evbuffer_new
#define evbuffer_free hv2ev_evbuffer_free
#define evbuffer_get_length hv2ev_evbuffer_get_length
#define evbuffer_chain_new hv2ev_evbuffer_chain_new
#define evbuffer_chain_free hv2ev_evbuffer_chain_free
#define clear_free_chains_list hv2ev_clear_free_chains_list
#define evbuffer_chain_insert hv2ev_evbuffer_chain_insert
#define evbuffer_add hv2ev_evbuffer_add
#define evbuffer_expand hv2ev_evbuffer_expand
#define evbuffer_prepend hv2ev_evbuffer_prepend
#define evbuffer_prepend_buffer hv2ev_evbuffer_prepend_buffer
#define evbuffer_drain hv2ev_evbuffer_drain
#define evbuffer_add_printf hv2ev_evbuffer_add_printf
#define evbuffer_add_buffer hv2ev_evbuffer_add_buffer
#define evbuffer_add_iovec hv2ev_evbuffer_add_iovec
#define evbuffer_pullup hv2ev_evbuffer_pullup
#define evbuffer_add_reference hv2ev_evbuffer_add_reference
#define evbuffer_remove hv2ev_evbuffer_remove
#define bufferevent_readcb hv2ev_bufferevent_readcb
#define bufferevent_socket_new hv2ev_bufferevent_socket_new
#define bufferevent_free hv2ev_bufferevent_free
#define bufferevent_write_buffer hv2ev_bufferevent_write_buffer
#define bufferevent_write hv2ev_bufferevent_write
#define bufferevent_get_input hv2ev_bufferevent_get_input
#define bufferevent_get_output hv2ev_bufferevent_get_output
#define bufferevent_enable hv2ev_bufferevent_enable
#define bufferevent_disable hv2ev_bufferevent_disable
#define bufferevent_get_enabled hv2ev_bufferevent_get_enabled
#define bufferevent_setcb hv2ev_bufferevent_setcb
#define bufferevent_set_timeouts hv2ev_bufferevent_set_timeouts
#define evutil_socket_connect hv2ev_evutil_socket_connect
#define bufferevent_socket_connect hv2ev_bufferevent_socket_connect
#define bufferevent_socket_connect_hostname hv2ev_bufferevent_socket_connect_hostname
#define evconnlistener_new hv2ev_evconnlistener_new
#define evconnlistener_free hv2ev_evconnlistener_free
#define evconnlistener_new_bind hv2ev_evconnlistener_new_bind
#define bufferevent_read hv2ev_bufferevent_read
#define evconnlistener_enable hv2ev_evconnlistener_enable
#define event_base_free hv2ev_event_base_free
#define event_base_loop hv2ev_event_base_loop
#define event_base_dispatch hv2ev_event_base_dispatch
#define event_base_loopbreak hv2ev_event_base_loopbreak
#define event_base_loopexit hv2ev_event_base_loopexit
#define event_assign hv2ev_event_assign
#define event_new hv2ev_event_new
#define event_add hv2ev_event_add
#define event_active hv2ev_event_active
#define event_del hv2ev_event_del
#define event_free hv2ev_event_free
#define event_set_mem_functions hv2ev_event_set_mem_functions
#define event_pending hv2ev_event_pending
#define evconnlistener_get_fd hv2ev_evconnlistener_get_fd
#define ev_token_bucket_cfg_free hv2ev_ev_token_bucket_cfg_free
#define ev_token_bucket_cfg_new hv2ev_ev_token_bucket_cfg_new
#define event_base_gettimeofday_cached hv2ev_event_base_gettimeofday_cached
#define bufferevent_set_rate_limit hv2ev_bufferevent_set_rate_limit
#define bufferevent_flush hv2ev_bufferevent_flush
#define event_base_new hv2ev_event_base_new

#define evutil_socket_t int
#define EV_READ HV_READ
#define EV_WRITE HV_WRITE
#define EV_SIGNAL 0x08
#define EV_PERSIST 0x0010
#define EV_TIMEOUT 0x0020
#define EVUTIL_SHUT_WR SHUT_WR
#define EVUTIL_SHUT_RD SHUT_RD

#define BEV_EVENT_READING 0x01   /**< error encountered while reading */
#define BEV_EVENT_WRITING 0x02   /**< error encountered while writing */
#define BEV_EVENT_EOF 0x10       /**< eof file reached */
#define BEV_EVENT_ERROR 0x20     /**< unrecoverable error encountered */
#define BEV_EVENT_TIMEOUT 0x40   /**< user-specified timeout reached */
#define BEV_EVENT_CONNECTED 0x80 /**< connect operation finished. */
#define EVUTIL_SOCK_CLOEXEC SOCK_CLOEXEC
#define EVUTIL_SOCK_NONBLOCK SOCK_NONBLOCK
#define ev_socklen_t socklen_t
#define MAX_TO_REALIGN_IN_EXPAND 2048
#define BEV_OPT_CLOSE_ON_FREE (1 << 0)
#define BEV_OPT_DEFER_CALLBACKS (1 << 2)
#define EVBUFFER_MAX_READ 4096
#define EVBUFFER_REFERENCE 0x0004
#define EVBUFFER_IMMUTABLE 0x0008
#define LEV_OPT_LEAVE_SOCKETS_BLOCKING (1u << 0)
#define LEV_OPT_CLOSE_ON_FREE (1u << 1)
#define LEV_OPT_CLOSE_ON_EXEC (1u << 2)
#define LEV_OPT_REUSEABLE (1u << 3)
#define LEV_OPT_DISABLED (1u << 5)
#define LEV_OPT_DEFERRED_ACCEPT (1u << 6)
#define LEV_OPT_REUSEABLE_PORT (1u << 7)
#define LEV_OPT_BIND_IPV6ONLY (1u << 8)
#define evbuffer_iovec iovec
#define EV_RATE_LIMIT_MAX INT64_MAX
#define COMMON_TIMEOUT_MICROSECONDS_MASK 0x000fffff

struct evconnlistener;
struct bufferevent;
typedef void (*event_callback_fn)(evutil_socket_t fd, short events,
                                  void *callback_arg);
typedef void (*evbuffer_ref_cleanup_cb)(const void *data, size_t datalen,
                                        void *extra);
typedef void (*evconnlistener_cb)(struct evconnlistener *, evutil_socket_t,
                                  struct sockaddr *, int socklen, void *);
typedef void (*evconnlistener_errorcb)(struct evconnlistener *, void *);
typedef void (*bufferevent_data_cb)(struct bufferevent *bev, void *ctx);
typedef void (*bufferevent_event_cb)(struct bufferevent *bev, short what,
                                     void *ctx);

struct queue_node {
    struct queue_node *pre;
    struct queue_node *next;
};

struct event {
    struct event_base *base;

    hio_t *io;
    int fd;
    short events;
    short events_pending;

    event_callback_fn callback;
    void *callback_arg;

    htimer_t *timer;
    int timeout;

    int num_calls;
    struct queue_node self_signal_node;
    struct queue_node self_awaken_signal_node;
};

struct event_base {
    hloop_t *loop;
    htimer_t *timer;
    int timeout;

    int enable_signal;
    struct event signal_monitor;
    int pair[2];
    struct queue_node signal_events_head[NSIG];
    struct queue_node awaken_signal_events_head;
};

struct evbuffer_chain {
    hbuf_t buf;
    size_t misalign;
    size_t off;
    struct evbuffer_chain *next;
    unsigned flags;
    evbuffer_ref_cleanup_cb cleanupfn;
    void *args;
};

struct evbuffer {
    struct evbuffer_chain *first;
    struct evbuffer_chain *last;
    struct evbuffer_chain *last_chain_with_data;
    size_t data_total_len;
};

struct evdns_base {
    char useless;
};

struct evconnlistener {
    struct evconnlistener_event *lev_e;
    evconnlistener_cb cb;
    evconnlistener_errorcb errorcb;
    void *user_data;
    unsigned flags;
    int accept4_flags;
    unsigned enabled : 1;
};

struct evconnlistener_event {
    struct evconnlistener base;
    struct event listener;
};

struct bufferevent {
    struct event_base *ev_base;
    struct event ev_read;
    struct event ev_write;
    struct event ev_err;
    struct evbuffer *input;
    struct evbuffer *output;
    bufferevent_data_cb readcb;
    bufferevent_data_cb writecb;
    bufferevent_event_cb errorcb;
    void *cbarg;
    struct timeval timeout_read;
    struct timeval timeout_write;
    short enabled;
    unsigned connecting;
    unsigned connection_refused;
    int options;
};

struct ev_token_bucket_cfg {
    size_t read_rate;
    size_t read_maximum;
    size_t write_rate;
    size_t write_maximum;
    struct timeval tick_timeout;
    unsigned msec_per_tick;
};

char *hv2ev_evutil_socket_error_to_string(int errcode);

struct event *hv2ev_evsignal_new(struct event_base *b, int x, event_callback_fn cb, void *arg);

int hv2ev_evsignal_add(struct event *ev, const struct timeval *tv);

int hv2ev_EVUTIL_ERR_CONNECT_RETRIABLE(int e);

int hv2ev_EVUTIL_ERR_CONNECT_REFUSED(int e);

int hv2ev_EVUTIL_ERR_RW_RETRIABLE(int e);

void hv2ev_EVUTIL_SET_SOCKET_ERROR(int errcode);

int hv2ev_EVUTIL_ERR_IS_EAGAIN(int e);

int hv2ev_EVUTIL_ERR_ACCEPT_RETRIABLE(int e);

int hv2ev_evtimer_add(struct event *ev, const struct timeval *tv);

int hv2ev_evconnlistener_enable(struct evconnlistener *lev);

int hv2ev_evtimer_del(struct event *ev);

struct event *hv2ev_evtimer_new(struct event_base *b, event_callback_fn cb, void *arg);

struct event_base *hv2ev_event_base_new(void);

int hv2ev_evtimer_assign(struct event *ev, struct event_base *b, event_callback_fn cb, void *arg);

int hv2ev_evtimer_pending(struct event *ev, struct timeval *tv);

struct evconnlistener *hv2ev_evconnlistener_new_bind(struct event_base *base,
                                                     evconnlistener_cb cb, void *ptr,
                                                     unsigned flags, int backlog,
                                                     const struct sockaddr *sa,
                                                     int socklen);

void hv2ev_evutil_timerclear(struct timeval *tvp);

int hv2ev_evutil_socket_geterror(evutil_socket_t sock);

int hv2ev_evutil_gettimeofday(struct timeval *tv, void *tz);

int hv2ev_evutil_closesocket(evutil_socket_t sock);

int hv2ev_evutil_make_socket_nonblocking(evutil_socket_t fd);

int hv2ev_evutil_gettimeofday(struct timeval *tv, void *tz);

int hv2ev_evutil_closesocket(evutil_socket_t sock);

int hv2ev_evutil_make_socket_nonblocking(evutil_socket_t fd);

int hv2ev_evutil_socketpair(int family, int type, int protocol, int sv[2]);

int hv2ev_evutil_make_socket_closeonexec(evutil_socket_t fd);

int hv2ev_evutil_inet_pton(int af, const char *source, void *destination);

const char *hv2ev_evutil_inet_ntop(int af, const void *source, char *destination, size_t len);

struct evbuffer *hv2ev_evbuffer_new(void);

void hv2ev_evbuffer_free(struct evbuffer *buffer);

size_t hv2ev_evbuffer_get_length(const struct evbuffer *buffer);

struct evbuffer_chain *hv2ev_evbuffer_chain_new(size_t size);

void hv2ev_evbuffer_chain_free(struct evbuffer_chain *chin_hv2ev);

void hv2ev_evbuffer_chain_insert(struct evbuffer *buf, struct evbuffer_chain *chin_hv2ev);

int hv2ev_evbuffer_add(struct evbuffer *buf, const void *data_in, size_t len_of_data);

int hv2ev_evbuffer_expand(struct evbuffer *buf, size_t len_of_data);

int hv2ev_evbuffer_prepend(struct evbuffer *buf, const void *data, size_t len_of_data);

int hv2ev_evbuffer_drain(struct evbuffer *buf, size_t len);

int hv2ev_evbuffer_add_printf(struct evbuffer *buf, const char *fmt, ...);

int hv2ev_evbuffer_add_buffer(struct evbuffer *destination, struct evbuffer *source);

size_t hv2ev_evbuffer_add_iovec(struct evbuffer *buf, struct evbuffer_iovec *vec,
                                int n_vec);

unsigned char *hv2ev_evbuffer_pullup(struct evbuffer *buf, ssize_t size);

int hv2ev_evbuffer_add_reference(struct evbuffer *buf, const void *data,
                                 size_t len_of_data, evbuffer_ref_cleanup_cb cleanupfn,
                                 void *args);

int hv2ev_evbuffer_remove(struct evbuffer *buf, void *data_out, size_t len_of_data);

struct bufferevent *hv2ev_bufferevent_socket_new(struct event_base *base, evutil_socket_t fd,
                                                 int options);

void hv2ev_bufferevent_free(struct bufferevent *bufev);

int hv2ev_bufferevent_write_buffer(struct bufferevent *bufev, struct evbuffer *buf);

int hv2ev_bufferevent_write(struct bufferevent *bufev, const void *data, size_t size);

struct evbuffer *hv2ev_bufferevent_get_input(struct bufferevent *bufev);

struct evbuffer *hv2ev_bufferevent_get_output(struct bufferevent *bufev);

int hv2ev_bufferevent_enable(struct bufferevent *bufev, short event);

int hv2ev_bufferevent_disable(struct bufferevent *bufev, short event);

short hv2ev_bufferevent_get_enabled(struct bufferevent *bufev);

int hv2ev_evutil_socket_connect(evutil_socket_t *fd_ptr, const struct sockaddr *sa, int socklen);

int hv2ev_bufferevent_socket_connect_hostname(struct bufferevent *bev,
                                              struct evdns_base *evdns_base,
                                              int family, const char *hostname,
                                              int port);

void hv2ev_evconnlistener_free(struct evconnlistener *lev);

int hv2ev_event_assign(struct event *ev, struct event_base *base, evutil_socket_t fd,
                       short events, event_callback_fn callback, void *callback_arg);

int hv2ev_event_base_loopbreak(struct event_base *base);

size_t hv2ev_bufferevent_read(struct bufferevent *bufev, void *data, size_t size);

void hv2ev_event_base_free(struct event_base *base);

int hv2ev_bufferevent_socket_connect(struct bufferevent *bufev,
                                     const struct sockaddr *sa, int socklen);

int hv2ev_event_base_loopexit(struct event_base *base, const struct timeval *tv);

struct event *hv2ev_event_new(struct event_base *base, evutil_socket_t fd,
                              short events, event_callback_fn callback,
                              void *callback_arg);

int hv2ev_event_del(struct event *ev);

void hv2ev_event_active(struct event *ev, int res, short ncalls);

void hv2ev_event_free(struct event *ev);

void hv2ev_event_set_mem_functions(void *(*malloc_fn)(size_t sz),
                                   void *(*realloc_fn)(void *ptr, size_t sz),
                                   void (*free_fn)(void *ptr));

int hv2ev_event_pending(const struct event *ev, short events, struct timeval *tv);

int hv2ev_evbuffer_prepend_buffer(struct evbuffer *destination, struct evbuffer *source);

evutil_socket_t hv2ev_evconnlistener_get_fd(struct evconnlistener *lev);

int hv2ev_event_base_dispatch(struct event_base *base);

int hv2ev_event_add(struct event *ev, const struct timeval *tv);

void hv2ev_ev_token_bucket_cfg_free(struct ev_token_bucket_cfg *cfg);

int hv2ev_event_base_loop(struct event_base *base, int flags);


void hv2ev_bufferevent_setcb(struct bufferevent *bufev, bufferevent_data_cb readcb,
                             bufferevent_data_cb writecb,
                             bufferevent_event_cb eventcb, void *cbarg);

int hv2ev_bufferevent_set_timeouts(struct bufferevent *bufev,
                                   const struct timeval *tv_read,
                                   const struct timeval *tv_write);

struct ev_token_bucket_cfg *hv2ev_ev_token_bucket_cfg_new(size_t read_rate, size_t read_burst,
                                                          size_t write_rate, size_t write_burst,
                                                          const struct timeval *tick_len);

struct evconnlistener *hv2ev_evconnlistener_new(struct event_base *base,
                                                evconnlistener_cb cb, void *ptr,
                                                unsigned flags, int backlog,
                                                evutil_socket_t fd);

// 未实现接口

// 仅仅出现在libevhtp提供的test.c中，且在test.c的作用可有可无
int hv2ev_bufferevent_set_rate_limit(struct bufferevent *bev,
                                     struct ev_token_bucket_cfg *cfg);

// 该函数对于socket-base的bufferevent没有任何作用，在libevent中的实现其实是一个空函数
enum bufferevent_flush_mode { BEV_NORMAL = 0, BEV_FLUSH = 1, BEV_FINISHED = 2 };
int hv2ev_bufferevent_flush(struct bufferevent *bufev, short iotype,
                            enum bufferevent_flush_mode mode);

#ifdef __cplusplus
}
#endif
#endif