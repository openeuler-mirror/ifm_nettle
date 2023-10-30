#include "hv2ev.h"
#include <string.h>

struct event *hv2ev_evsignal_new(struct event_base *b, int x, event_callback_fn cb, void *arg)
{
    return hv2ev_event_new(b, x, EV_SIGNAL | EV_PERSIST, cb, arg);
}

int hv2ev_evsignal_add(struct event *ev, const struct timeval *tv)
{
    return hv2ev_event_add(ev, tv);
}

char *hv2ev_evutil_socket_error_to_string(int errcode)
{
    return strerror(errcode);
}

int hv2ev_EVUTIL_ERR_CONNECT_RETRIABLE(int e)
{
    return (e == EINTR || e == EINPROGRESS);
}

int hv2ev_EVUTIL_ERR_CONNECT_REFUSED(int e)
{
    return (e == ECONNREFUSED);
}

int hv2ev_EVUTIL_ERR_RW_RETRIABLE(int e)
{
    return (e == EINTR || hv2ev_EVUTIL_ERR_IS_EAGAIN(e));
}

void hv2ev_EVUTIL_SET_SOCKET_ERROR(int errcode)
{
    errno = (errcode);
}

int hv2ev_EVUTIL_ERR_IS_EAGAIN(int e)
{
    return (e == EAGAIN);
}

int hv2ev_EVUTIL_ERR_ACCEPT_RETRIABLE(int e)
{
    return (e == EINTR || hv2ev_EVUTIL_ERR_IS_EAGAIN(e) || e == ECONNABORTED);
}

int hv2ev_evtimer_add(struct event *ev, const struct timeval *tv)
{
    return hv2ev_event_add(ev, tv);
}

int hv2ev_evtimer_del(struct event *ev)
{
    return hv2ev_event_del(ev);
}

struct event *hv2ev_evtimer_new(struct event_base *b, event_callback_fn cb, void *arg)
{
    return hv2ev_event_new(b, -1, 0, cb, arg);
}

int hv2ev_evtimer_assign(struct event *ev, struct event_base *b, event_callback_fn cb, void *arg)
{
    return hv2ev_event_assign(ev, b, -1, 0, cb, arg);
}

int hv2ev_evtimer_pending(struct event *ev, struct timeval *tv)
{
    return hv2ev_event_pending(ev, EV_TIMEOUT, tv);
}

void hv2ev_evutil_timerclear(struct timeval *tvp)
{
    timerclear(tvp);
}

int hv2ev_evutil_socket_geterror(evutil_socket_t sock)
{
    return errno;
}

int hv2ev_evutil_gettimeofday(struct timeval *tv, void *tz)
{
    return gettimeofday(tv, tz);
}

int hv2ev_evutil_closesocket(evutil_socket_t sock)
{
    SAFE_CLOSESOCKET(sock);
    return 0;
}

int hv2ev_evutil_make_socket_nonblocking(evutil_socket_t fd)
{
    return nonblocking(fd);
}

int hv2ev_evutil_socketpair(int family, int type, int protocol, int sv[2])
{
    return socketpair(AF_LOCAL, type, protocol, sv);
}

int hv2ev_evutil_make_socket_closeonexec(evutil_socket_t fd)
{
    int flags;
    if ((flags = fcntl(fd, F_GETFD, NULL)) < 0) {
        return -1;
    }
    if (!(flags & FD_CLOEXEC)) {
        if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1) {
            return -1;
        }
    }
    return 0;
}

int hv2ev_evutil_inet_pton(int af, const char *source, void *destination)
{
    return inet_pton(af, source, destination);
}

const char *hv2ev_evutil_inet_ntop(int af, const void *source, char *destination, size_t len)
{
    return inet_ntop(af, source, destination, len);
}

// evbuffer结构体及相关函数模仿并简化了libevent的实现
struct evbuffer *hv2ev_evbuffer_new(void)
{
    struct evbuffer *buffer = NULL;
    HV_ALLOC(buffer, sizeof(struct evbuffer));
    buffer->data_total_len = 0;
    buffer->first = NULL;
    buffer->last = NULL;
    buffer->last_chain_with_data = buffer->first;
    return buffer;
}

void hv2ev_evbuffer_free(struct evbuffer *buffer)
{
    if (buffer == NULL) {
        return;
    }
    struct evbuffer_chain *p = buffer->first;
    while (p != NULL) {
        struct evbuffer_chain *next = p->next;
        hv2ev_evbuffer_chain_free(p);
        p = next;
    }
    HV_FREE(buffer);
}

size_t hv2ev_evbuffer_get_length(const struct evbuffer *buffer)
{
    return buffer->data_total_len;
}

struct evbuffer_chain *hv2ev_evbuffer_chain_new(size_t size)
{
    size_t size_for_malloc = 1024;
    while (size_for_malloc < size) {
        size_for_malloc <<= 1;
    }
    size_for_malloc <<= 1;
    struct evbuffer_chain *chin_hv2ev = NULL;
    HV_ALLOC(chin_hv2ev, sizeof(struct evbuffer_chain));
    HV_ALLOC(chin_hv2ev->buf.base, size_for_malloc);
    chin_hv2ev->buf.len = size_for_malloc;
    chin_hv2ev->misalign = 0;
    chin_hv2ev->off = 0;
    chin_hv2ev->next = NULL;
    chin_hv2ev->flags = 0;
    chin_hv2ev->cleanupfn = NULL;
    chin_hv2ev->args = NULL;
    return chin_hv2ev;
}

void hv2ev_evbuffer_chain_free(struct evbuffer_chain *chin_hv2ev)
{
    if (chin_hv2ev->flags & EVBUFFER_REFERENCE) {
        evbuffer_ref_cleanup_cb cleanupfn = chin_hv2ev->cleanupfn;
        if (cleanupfn != NULL) {
            cleanupfn(chin_hv2ev->buf.base, chin_hv2ev->buf.len, chin_hv2ev->args);
        }
        return;
    } else {
        HV_FREE(chin_hv2ev->buf.base);
    }
    HV_FREE(chin_hv2ev);
}

static void hv2ev_clear_free_chains_list(struct evbuffer_chain *chin_hv2ev)
{
    struct evbuffer_chain *p = chin_hv2ev;
    struct evbuffer_chain *next;
    while (p) {
        next = p->next;
        hv2ev_evbuffer_chain_free(p);
        p = next;
    }
}

void hv2ev_evbuffer_chain_insert(struct evbuffer *buf, struct evbuffer_chain *chin_hv2ev)
{
    if (buf->last != NULL) {
        if (buf->data_total_len != 0) {
            hv2ev_clear_free_chains_list(buf->last_chain_with_data->next);
            buf->last_chain_with_data->next = chin_hv2ev;
            buf->last = chin_hv2ev;
            if (chin_hv2ev->off > 0) {
                buf->last_chain_with_data = chin_hv2ev;
            }
        } else {
            hv2ev_clear_free_chains_list(buf->first);
            buf->first = chin_hv2ev;
            buf->last = chin_hv2ev;
            buf->last_chain_with_data = chin_hv2ev;
        }
    } else {
        buf->first = chin_hv2ev;
        buf->last = chin_hv2ev;
        buf->last_chain_with_data = chin_hv2ev;
    }

    buf->data_total_len += chin_hv2ev->off;
}

int hv2ev_evbuffer_add(struct evbuffer *buf, const void *data_in, size_t len_of_data)
{
    struct evbuffer_chain *chin_hv2ev = buf->last_chain_with_data;

    if (chin_hv2ev != NULL) {
        size_t free_space = chin_hv2ev->buf.len - chin_hv2ev->misalign - chin_hv2ev->off;
        if (free_space < len_of_data) {
            size_t left_datalen = len_of_data - free_space;
            char *left_data = (char *)data_in + free_space;
            struct evbuffer_chain *new_chain = hv2ev_evbuffer_chain_new(left_datalen);
            if (new_chain == NULL) {
                return -1;
            }
            memcpy(chin_hv2ev->buf.base + chin_hv2ev->misalign + chin_hv2ev->off, data_in,
                   free_space);
            chin_hv2ev->off += free_space;
            hv2ev_evbuffer_chain_insert(buf, new_chain);
            memcpy(new_chain->buf.base + new_chain->misalign + new_chain->off,
                   left_data, left_datalen);
            new_chain->off += left_datalen;
            buf->last_chain_with_data = new_chain;
        } else {
            memcpy(chin_hv2ev->buf.base + chin_hv2ev->misalign + chin_hv2ev->off, data_in, len_of_data);
            chin_hv2ev->off += len_of_data;
        }
    } else {
        chin_hv2ev = hv2ev_evbuffer_chain_new(len_of_data);
        if (chin_hv2ev == NULL) {
            return -1;
        }
        hv2ev_evbuffer_chain_insert(buf, chin_hv2ev);
        memcpy(chin_hv2ev->buf.base + chin_hv2ev->misalign + chin_hv2ev->off, data_in, len_of_data);
        chin_hv2ev->off += len_of_data;
        // 注意：如果有chain，但没有数据，last_with_datap也应该指向first
        buf->last_chain_with_data = chin_hv2ev;
    }

    buf->data_total_len += len_of_data;
    return 0;
}

/** Helper: return true iff we should realign chin_hv2ev to fit len_of_data bytes of
                                data in it. */
static int should_realign(struct evbuffer_chain *chin_hv2ev,
                          size_t datlen)
{
    int half = 2;
    int condition_1 = chin_hv2ev->off <= MAX_TO_REALIGN_IN_EXPAND;
    int condition_2 = chin_hv2ev->off < chin_hv2ev->buf.len / half;
    int condition_3 = chin_hv2ev->buf.len - chin_hv2ev->off >= datlen;
    return condition_1 && condition_2 && condition_3;
}

/** Helper: realigns the memory in chin_hv2ev->buffer so that misalign is 0. */
static void align(struct evbuffer_chain *chin_hv2ev)
{
    char *dest = chin_hv2ev->buf.base;
    char *source =  chin_hv2ev->buf.base + chin_hv2ev->misalign;
    size_t n = chin_hv2ev->off;
    memmove(dest, source, n);
    chin_hv2ev->misalign = 0;
}

int hv2ev_evbuffer_expand(struct evbuffer *buf, size_t len_of_data)
{
    struct evbuffer_chain *chin_hv2ev = buf->last_chain_with_data;

    if (chin_hv2ev != NULL) {
        if (should_realign(chin_hv2ev, len_of_data)) {
            align(chin_hv2ev);
            return 0;
        }

        int total_free_space = 0;
        struct evbuffer_chain *p = chin_hv2ev;
        while (p != NULL) {
            total_free_space += (p->buf.len - p->misalign - p->off);
            p = p->next;
        }
        if (total_free_space < len_of_data) {
            struct evbuffer_chain *new_chain =
                    hv2ev_evbuffer_chain_new(len_of_data - total_free_space);
            if (new_chain == NULL) {
                return -1;
            }
            hv2ev_evbuffer_chain_insert(buf, new_chain);
        }
    } else {
        chin_hv2ev = hv2ev_evbuffer_chain_new(len_of_data);
        if (chin_hv2ev == NULL) {
            return -1;
        }
        hv2ev_evbuffer_chain_insert(buf, chin_hv2ev);
        // 注意：如果有chain，但没有数据，last_with_datap也应该指向first
        buf->last_chain_with_data = chin_hv2ev;
    }
    return 0;
}

int hv2ev_evbuffer_prepend(struct evbuffer *buf, const void *data, size_t len_of_data)
{
    struct evbuffer_chain *chin_hv2ev = buf->first;

    if (chin_hv2ev == NULL) {
        chin_hv2ev = hv2ev_evbuffer_chain_new(len_of_data);
        if (chin_hv2ev == NULL) {
            return -1;
        }
        hv2ev_evbuffer_chain_insert(buf, chin_hv2ev);
        // 注意：如果有chain，但没有数据，last_with_datap也应该指向first
        buf->last_chain_with_data = chin_hv2ev;
    }

    if (chin_hv2ev->off == 0) {
        chin_hv2ev->misalign = chin_hv2ev->buf.len;
    }

    if (chin_hv2ev->misalign >= len_of_data) {
        memcpy(chin_hv2ev->buf.base + chin_hv2ev->misalign - len_of_data, data, len_of_data);
        chin_hv2ev->misalign -= len_of_data;
        chin_hv2ev->off += len_of_data;
    } else {
        size_t free_space = chin_hv2ev->misalign;
        memcpy(chin_hv2ev->buf.base, (char *)data + len_of_data - free_space, free_space);
        chin_hv2ev->misalign -= free_space;
        chin_hv2ev->off += free_space;

        size_t left_datalen = len_of_data - free_space;
        struct evbuffer_chain *new_chain = hv2ev_evbuffer_chain_new(left_datalen);
        if (new_chain == NULL) {
            return -1;
        }
        buf->first = new_chain;
        new_chain->next = chin_hv2ev;
        new_chain->misalign = new_chain->buf.len - left_datalen;
        new_chain->off = left_datalen;
        memcpy(new_chain->buf.base + new_chain->misalign, data, left_datalen);
    }

    buf->data_total_len += len_of_data;
    return 0;
}

int hv2ev_evbuffer_prepend_buffer(struct evbuffer *destination, struct evbuffer *source)
{
    size_t dst_total_len = destination->data_total_len;
    size_t src_total_len = source->data_total_len;

    if (destination == source || src_total_len == 0) {
        return 0;
    }

    if (dst_total_len != 0) {
        source->last->next = destination->first;
        destination->first = source->first;
        destination->data_total_len += source->data_total_len;
    } else {
        hv2ev_clear_free_chains_list(destination->first);
        destination->first = source->first;
        destination->last = source->last;
        destination->last_chain_with_data = source->last_chain_with_data;
        destination->data_total_len = source->data_total_len;
    }

    source->first = source->last = source->last_chain_with_data = NULL;
    source->data_total_len = 0;

    return 0;
}

int hv2ev_evbuffer_drain(struct evbuffer *buf, size_t len)
{
    int buf_data_len = buf->data_total_len;
    struct evbuffer_chain *chin_hv2ev;
    struct evbuffer_chain *next;
    if (buf_data_len > len) {
        buf->data_total_len -= len;
        size_t remain_to_delete = len;
        for (chin_hv2ev = buf->first; remain_to_delete >= chin_hv2ev->off; chin_hv2ev = next) {
            next = chin_hv2ev->next;
            remain_to_delete -= chin_hv2ev->off;
            hv2ev_evbuffer_chain_free(chin_hv2ev);
        }
        buf->first = chin_hv2ev;
        if (chin_hv2ev != NULL) {
            chin_hv2ev->misalign += remain_to_delete;
            chin_hv2ev->off -= remain_to_delete;
        }
    } else {
        for (chin_hv2ev = buf->first; chin_hv2ev != NULL; chin_hv2ev = next) {
            next = chin_hv2ev->next;
            hv2ev_evbuffer_chain_free(chin_hv2ev);
        }
        buf->data_total_len = 0;
        buf->first = NULL;
        buf->last = NULL;
        buf->last_chain_with_data = buf->first;
    }
    return 0;
}

int hv2ev_evbuffer_add_printf(struct evbuffer *buf, const char *fmt, ...)
{
    char str[1024];
    memset(str, 0, sizeof(str));

    va_list args;
    va_start(args, fmt);
    int n = vsprintf(str, fmt, args);
    if (n < 0) {
        return n;
    }
    va_end(args);

    hv2ev_evbuffer_add(buf, str, strlen(str));
    return 0;
}

int hv2ev_evbuffer_add_buffer(struct evbuffer *destination, struct evbuffer *source)
{
    if (destination == source || source->data_total_len == 0) {
        return 0;
    }

    if (destination->data_total_len == 0) {
        struct evbuffer_chain *chin_hv2ev = destination->first;
        struct evbuffer_chain *next = NULL;
        while (chin_hv2ev != NULL) {
            next = chin_hv2ev->next;
            hv2ev_evbuffer_chain_free(chin_hv2ev);
            chin_hv2ev = next;
        }
        destination->first = NULL;
        destination->last = NULL;
        destination->last_chain_with_data = NULL;
    }

    if (destination->first != NULL) {
        struct evbuffer_chain *dst_last_datap = destination->last_chain_with_data;
        struct evbuffer_chain *src_last = source->last;
        struct evbuffer_chain *dst_first_no_datap = dst_last_datap->next;
        dst_last_datap->next = source->first;
        src_last->next = dst_first_no_datap;
        destination->last_chain_with_data = source->last_chain_with_data;
    } else {
        destination->first = source->first;
        destination->last = source->last;
        destination->last_chain_with_data = source->last_chain_with_data;
    }

    destination->data_total_len += source->data_total_len;

    source->first = NULL;
    source->last = NULL;
    source->last_chain_with_data = NULL;
    source->data_total_len = 0;

    struct evbuffer_chain *chin_hv2ev = destination->last_chain_with_data->next;
    struct evbuffer_chain *next = NULL;
    destination->last_chain_with_data->next = NULL;
    destination->last = destination->last_chain_with_data;
    while (chin_hv2ev != NULL) {
        next = chin_hv2ev->next;
        hv2ev_evbuffer_chain_free(chin_hv2ev);
        chin_hv2ev = next;
    }

    return 0;
}

size_t hv2ev_evbuffer_add_iovec(struct evbuffer *buf, struct evbuffer_iovec *vec,
                                int n_vec)
{
    int n;
    size_t res = 0;
    size_t size_for_malloc = 0;
    for (n = 0; n < n_vec; n++) {
        size_for_malloc += vec[n].iov_len;
    }
    hv2ev_evbuffer_expand(buf, size_for_malloc);
    for (n = 0; n < n_vec; n++) {
        if (hv2ev_evbuffer_add(buf, vec[n].iov_base, vec[n].iov_len) < 0) {
            return res;
        }
        res += vec[n].iov_len;
    }
    return res;
}

static struct evbuffer_chain *get_proper_chain(char **buffer,
                                               struct evbuffer_chain **first_chain,
                                               struct evbuffer_chain **chain_contiguous,
                                               ssize_t *remaining_to_copy, ssize_t size)
{
    struct evbuffer_chain *chin_hv2ev = NULL;
    if ((*first_chain)->buf.len - (*first_chain)->misalign < (*remaining_to_copy)) {
        (*chain_contiguous) = hv2ev_evbuffer_chain_new((*remaining_to_copy));
        if ((*chain_contiguous) == NULL) {
            return NULL;
        }
        (*chain_contiguous)->off = size;
        *buffer = (*chain_contiguous)->buf.base + (*chain_contiguous)->misalign;
        chin_hv2ev = (*first_chain);
    } else {
        (*chain_contiguous) = (*first_chain);
        (*remaining_to_copy) -= (*first_chain)->off;
        size_t old_off = (*first_chain)->off;
        (*chain_contiguous)->off = size;
        *buffer = (*first_chain)->buf.base + (*first_chain)->misalign + old_off;
        chin_hv2ev = (*first_chain)->next;
    }
    return chin_hv2ev;
}

unsigned char *hv2ev_evbuffer_pullup(struct evbuffer *buf, ssize_t size)
{
    ssize_t real_size = size;
    if (real_size < 0) {
        real_size = buf->data_total_len;
    } else if (real_size == 0 || real_size > buf->data_total_len) {
        return NULL;
    }
    struct evbuffer_chain *first_chain = buf->first;
    if (first_chain->off >= real_size) {
        return (unsigned char *)(first_chain->buf.base + first_chain->misalign);
    }

    char *buffer = NULL;
    struct evbuffer_chain *chain_contiguous = NULL;
    struct evbuffer_chain *chin_hv2ev = NULL;
    ssize_t remaining_to_copy = real_size;
    chin_hv2ev = get_proper_chain(&buffer, &first_chain, &chain_contiguous,
                                  &remaining_to_copy, real_size);

    while (remaining_to_copy > 0 && chin_hv2ev != NULL &&
                 chin_hv2ev->off <= remaining_to_copy) {
        struct evbuffer_chain *next = chin_hv2ev->next;
        memcpy(buffer, chin_hv2ev->buf.base + chin_hv2ev->misalign, chin_hv2ev->off);
        buffer += chin_hv2ev->off;
        remaining_to_copy -= chin_hv2ev->off;
        hv2ev_evbuffer_chain_free(chin_hv2ev);
        chin_hv2ev = next;
    }
    if (remaining_to_copy > 0) {
        memcpy(buffer, chin_hv2ev->buf.base + chin_hv2ev->misalign, remaining_to_copy);
        chin_hv2ev->misalign += remaining_to_copy;
        chin_hv2ev->off -= remaining_to_copy;
        remaining_to_copy = 0;
    }
    buf->first = chain_contiguous;
    if (chin_hv2ev == NULL) {
        buf->last = chain_contiguous;
    }
    if (real_size == buf->data_total_len) {
        buf->last_chain_with_data = chain_contiguous;
    }
    chain_contiguous->next = chin_hv2ev;
    return (unsigned char *)(chain_contiguous->buf.base +
                                                     chain_contiguous->misalign);
}

int hv2ev_evbuffer_add_reference(struct evbuffer *buf, const void *data,
                                 size_t len_of_data, evbuffer_ref_cleanup_cb cleanupfn,
                                 void *args)
{
    struct evbuffer_chain *chin_hv2ev = hv2ev_evbuffer_chain_new(len_of_data);
    chin_hv2ev->flags |= (EVBUFFER_REFERENCE | EVBUFFER_IMMUTABLE);
    chin_hv2ev->cleanupfn = cleanupfn;
    chin_hv2ev->args = args;
    chin_hv2ev->buf.base = (char *)data;
    chin_hv2ev->buf.len = len_of_data;
    chin_hv2ev->off = len_of_data;
    hv2ev_evbuffer_chain_insert(buf, chin_hv2ev);

    return 0;
}

int hv2ev_evbuffer_remove(struct evbuffer *buf, void *data_out, size_t len_of_data)
{
    struct evbuffer_chain *chin_hv2ev;
    char *data = (char *)data_out;
    size_t nread;
    ssize_t result = 0;

    chin_hv2ev = buf->first;
    int real_len_of_data = len_of_data;
    if (real_len_of_data > buf->data_total_len) {
        real_len_of_data = buf->data_total_len;
    }
    if (real_len_of_data == 0) {
        return result;
    }

    nread = real_len_of_data;

    while (real_len_of_data && real_len_of_data >= chin_hv2ev->off) {
        size_t copylen = chin_hv2ev->off;
        memcpy(data, chin_hv2ev->buf.base + chin_hv2ev->misalign, copylen);
        data += copylen;
        real_len_of_data -= copylen;
        chin_hv2ev = chin_hv2ev->next;
    }
    if (real_len_of_data) {
        memcpy(data, chin_hv2ev->buf.base + chin_hv2ev->misalign, real_len_of_data);
    }

    result = nread;
    if (result > 0) {
        hv2ev_evbuffer_drain(buf, result);
    }
    return result;
}

static void hv2ev_bufferevent_readcb(evutil_socket_t fd, short event, void *arg)
{
    struct bufferevent *bufev = (struct bufferevent *)arg;

    short what = BEV_EVENT_READING;
    if (event == EV_TIMEOUT) {
        what |= BEV_EVENT_TIMEOUT;
        hv2ev_bufferevent_disable(bufev, EV_READ);
        bufev->errorcb(bufev, what, bufev->cbarg);
        return;
    }

    size_t n = EVBUFFER_MAX_READ;
    ioctl(fd, FIONREAD, &n);
    if (n <= 0) {
        n = 1;
    }

    char *new_buf = NULL;
    HV_ALLOC(new_buf, n);
    ssize_t nread = read(fd, new_buf, n);
    if (nread <= 0) {
        if (nread == 0) {
            what |= BEV_EVENT_EOF;
        } else {
            int err = hv2ev_evutil_socket_geterror(fd);
            if (hv2ev_EVUTIL_ERR_RW_RETRIABLE(err)) {
                return;
            }
            if (hv2ev_EVUTIL_ERR_CONNECT_REFUSED(err)) {
                bufev->connection_refused = 1;
                return;
            }
            what |= BEV_EVENT_ERROR;
        }
        hv2ev_bufferevent_disable(bufev, EV_READ);
        bufev->errorcb(bufev, what, bufev->cbarg);
        return;
    }
    struct evbuffer *buffer = bufev->input;
    hv2ev_evbuffer_add(buffer, new_buf, nread);
    buffer->first->off += nread;
    HV_FREE(new_buf);

    if (bufev->readcb) {
        bufev->readcb(bufev, bufev->cbarg);
    }
}

int evutil_socket_finished_connecting(evutil_socket_t fd)
{
    int e;
    ev_socklen_t elen = sizeof(e);

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&e, &elen) < 0) {
        return -1;
    }

    if (e) {
        if (hv2ev_EVUTIL_ERR_CONNECT_RETRIABLE(e)) {
            return 0;
        }
        hv2ev_EVUTIL_SET_SOCKET_ERROR(e);
        return -1;
    }

    return 1;
}

static int deal_connecting(struct bufferevent *bufev, evutil_socket_t fd)
{
    if (bufev->connecting) {
        int c = evutil_socket_finished_connecting(fd);
        if (bufev->connection_refused) {
            bufev->connection_refused = 0;
            c = -1;
        }
        if (c == 0) {
            return -1;
        }
        bufev->connecting = 0;
        if (c < 0) {
            hv2ev_event_del(&bufev->ev_write);
            hv2ev_event_del(&bufev->ev_read);
            bufev->errorcb(bufev, BEV_EVENT_ERROR, bufev->cbarg);
            return -1;
        } else {
            bufev->errorcb(bufev, BEV_EVENT_CONNECTED, bufev->cbarg);
            if (!(bufev->enabled & EV_WRITE)) {
                hv2ev_event_del(&bufev->ev_write);
                return -1;
            }
        }
    }
    return 0;
}

static void deal_empty_output_buffer(struct bufferevent *bufev)
{
    if (hv2ev_evbuffer_get_length(bufev->output) == 0) {
        hv2ev_event_del(&(bufev->ev_write));
        if (bufev->writecb) {
            bufev->writecb(bufev, bufev->cbarg);
        }
    }
}

static void bufferevent_writecb(evutil_socket_t fd, short event, void *arg)
{
    struct bufferevent *bufev = (struct bufferevent *)arg;
    short what = BEV_EVENT_WRITING;
    if (event == EV_TIMEOUT) {
        what |= BEV_EVENT_TIMEOUT;
        hv2ev_bufferevent_disable(bufev, EV_WRITE);
        bufev->errorcb(bufev, what, bufev->cbarg);
        return;
    }

    if (deal_connecting(bufev, fd) == -1) {
        return;
    }

    size_t n = hv2ev_evbuffer_get_length(bufev->output);
    if (n == 0) {
        deal_empty_output_buffer(bufev);
        return;
    }

    unsigned char *buf = evbuffer_pullup(bufev->output, n);
    ssize_t nwrite = write(fd, buf, n);
    if (nwrite > 0) {
        evbuffer_drain(bufev->output, nwrite);
        deal_empty_output_buffer(bufev);
        return;
    }

    if (nwrite == 0) {
        what |= BEV_EVENT_EOF;
    } else {
        int err = evutil_socket_geterror(fd);
        if (EVUTIL_ERR_RW_RETRIABLE(err)) {
            if (evbuffer_get_length(bufev->output) == 0) {
                event_del(&bufev->ev_write);
            }
            return;
        }
        what |= BEV_EVENT_ERROR;
    }
    bufferevent_disable(bufev, EV_WRITE);
    bufev->errorcb(bufev, what, bufev->cbarg);
    return;
}

static void bufferevent_errcb(evutil_socket_t fd, short what, void *arg)
{
    struct bufferevent *bufev = (struct bufferevent *)arg;
    bufev->errorcb(bufev, what, bufev->cbarg);
}

// bufferevent结构体及相关函数模仿并简化了libevent的实现
struct bufferevent *hv2ev_bufferevent_socket_new(struct event_base *base,
                                                 evutil_socket_t fd, int options)
{
    struct bufferevent *bufev;
    HV_ALLOC(bufev, sizeof(struct bufferevent));

    bufev->ev_base = base;
    if (!bufev->input) {
        bufev->input = hv2ev_evbuffer_new();
    }
    if (!bufev->output) {
        bufev->output = hv2ev_evbuffer_new();
    }

    hv2ev_event_assign(&(bufev->ev_read), bufev->ev_base, fd, EV_READ | EV_PERSIST,
                       hv2ev_bufferevent_readcb, bufev);
    hv2ev_event_assign(&(bufev->ev_write), bufev->ev_base, fd, EV_WRITE | EV_PERSIST,
                       bufferevent_writecb, bufev);
    hv2ev_event_assign(&(bufev->ev_err), bufev->ev_base, fd, 0, bufferevent_errcb,
                       bufev);

    bufev->readcb = NULL;
    bufev->writecb = NULL;
    bufev->errorcb = NULL;
    bufev->cbarg = NULL;
    timerclear(&(bufev->timeout_read));
    timerclear(&(bufev->timeout_write));
    bufev->enabled = EV_WRITE;
    bufev->connecting = 0;
    bufev->connection_refused = 0;
    bufev->options = options;

    return bufev;
}

void hv2ev_bufferevent_free(struct bufferevent *bufev)
{
    int fd = bufev->ev_read.fd;

    hv2ev_event_del(&bufev->ev_read);
    hv2ev_event_del(&bufev->ev_write);
    hv2ev_event_del(&bufev->ev_err);
    if ((bufev->options & BEV_OPT_CLOSE_ON_FREE) && fd >= 0) {
        close(fd);
    }
    if (bufev->input) {
        hv2ev_evbuffer_free(bufev->input);
    }
    if (bufev->output) {
        hv2ev_evbuffer_free(bufev->output);
    }
    HV_FREE(bufev);
}

int hv2ev_bufferevent_write_buffer(struct bufferevent *bufev, struct evbuffer *buf)
{
    hv2ev_evbuffer_add_buffer(bufev->output, buf);
    if (hv2ev_evbuffer_get_length(bufev->output) > 0) {
        hv2ev_event_add(&(bufev->ev_write), &(bufev->timeout_write));
    }
    // bufev->enabled |= EV_WRITE;
    return 0;
}

int hv2ev_bufferevent_write(struct bufferevent *bufev, const void *data,
                            size_t size)
{
    hv2ev_evbuffer_add(bufev->output, data, size);
    if (size > 0) {
        hv2ev_event_add(&(bufev->ev_write), &(bufev->timeout_write));
    }
    return 0;
}

struct evbuffer *hv2ev_bufferevent_get_input(struct bufferevent *bufev)
{
    return bufev->input;
}

struct evbuffer *hv2ev_bufferevent_get_output(struct bufferevent *bufev)
{
    return bufev->output;
}

int hv2ev_bufferevent_enable(struct bufferevent *bufev, short event)
{
    if (event & EV_READ) {
        hv2ev_event_add(&(bufev->ev_read), &(bufev->timeout_read));
        bufev->enabled |= EV_READ;
    }
    if (event & EV_WRITE) {
        hv2ev_event_add(&(bufev->ev_write), &(bufev->timeout_write));
        bufev->enabled |= EV_WRITE;
    }
    return 0;
}

int hv2ev_bufferevent_disable(struct bufferevent *bufev, short event)
{
    if (event & EV_READ) {
        hv2ev_event_del(&(bufev->ev_read));
        bufev->enabled &= (~EV_READ);
    }
    if (event & EV_WRITE) {
        hv2ev_event_del(&(bufev->ev_write));
        bufev->enabled &= (~EV_WRITE);
    }
    return 0;
}

short hv2ev_bufferevent_get_enabled(struct bufferevent *bufev)
{
    return bufev->enabled;
}

void hv2ev_bufferevent_setcb(struct bufferevent *bufev, bufferevent_data_cb readcb,
                             bufferevent_data_cb writecb,
                             bufferevent_event_cb eventcb, void *cbarg)
{
    bufev->readcb = readcb;
    bufev->writecb = writecb;
    bufev->errorcb = eventcb;

    bufev->cbarg = cbarg;
}

int is_monitored(struct event *ev, short events)
{
    hio_t *io = hio_get(ev->base->loop, ev->fd);

    short hv_events = hio_events(io);
    if (hv_events & events) {
        return 1;
    }

    return 0;
}

int adj_timeouts(struct bufferevent *bev)
{
    int r = 0;
    if (is_monitored(&bev->ev_read, EV_READ)) {
        if (timerisset(&bev->timeout_read)) {
            if (hv2ev_event_add(&bev->ev_read, &bev->timeout_read) < 0) {
                r = -1;
            }
        } else {
            htimer_del((&(bev->ev_read))->timer);
            (&(bev->ev_read))->timer = NULL;
        }
    }
    if (is_monitored(&bev->ev_write, EV_WRITE)) {
        if (timerisset(&bev->timeout_write)) {
            if (hv2ev_event_add(&bev->ev_write, &bev->timeout_write) < 0) {
                r = -1;
            }
        } else {
            htimer_del((&(bev->ev_write))->timer);
            (&(bev->ev_write))->timer = NULL;
        }
    }
    return r;
}

int hv2ev_bufferevent_set_timeouts(struct bufferevent *bufev,
                                   const struct timeval *tv_read,
                                   const struct timeval *tv_write)
{
    int r = 0;
    if (tv_read) {
        bufev->timeout_read = *tv_read;
    } else {
        timerclear(&(bufev->timeout_read));
    }
    if (tv_write) {
        bufev->timeout_write = *tv_write;
    } else {
        timerclear(&(bufev->timeout_write));
    }

    r = adj_timeouts(bufev);

    return r;
}

int hv2ev_evutil_socket_connect(evutil_socket_t *fd_ptr, const struct sockaddr *sa,
                                int socklen)
{
    int made_fd = 0;

    if (*fd_ptr < 0) {
        if ((*fd_ptr = socket(sa->sa_family, SOCK_STREAM, 0)) < 0) {
            if (made_fd) {
                hv2ev_evutil_closesocket(*fd_ptr);
                *fd_ptr = -1;
            }
            return -1;
        }
        made_fd = 1;
        if (hv2ev_evutil_make_socket_nonblocking(*fd_ptr) < 0) {
            if (made_fd) {
                hv2ev_evutil_closesocket(*fd_ptr);
                *fd_ptr = -1;
            }
            return -1;
        }
    }

    if (connect(*fd_ptr, sa, socklen) < 0) {
        int e = hv2ev_evutil_socket_geterror(*fd_ptr);
        if (hv2ev_EVUTIL_ERR_CONNECT_RETRIABLE(e)) {
            return 0;
        }
        if (hv2ev_EVUTIL_ERR_CONNECT_REFUSED(e)) {
            int connect_refuse = 2;
            return connect_refuse;
        }
        if (made_fd) {
            hv2ev_evutil_closesocket(*fd_ptr);
            *fd_ptr = -1;
        }
        return -1;
    } else {
        return 1;
    }

    if (made_fd) {
        hv2ev_evutil_closesocket(*fd_ptr);
        *fd_ptr = -1;
    }
    return -1;
}

static void bufferevent_setfd(struct bufferevent *bufev, evutil_socket_t fd)
{
    hv2ev_event_del(&bufev->ev_read);
    hv2ev_event_del(&bufev->ev_write);
    hv2ev_event_assign(&bufev->ev_read, bufev->ev_base, fd, EV_READ | EV_PERSIST,
                       hv2ev_bufferevent_readcb, bufev);
    hv2ev_event_assign(&bufev->ev_write, bufev->ev_base, fd, EV_WRITE | EV_PERSIST,
                       bufferevent_writecb, bufev);
}

int hv2ev_bufferevent_socket_connect(struct bufferevent *bufev,
                                     const struct sockaddr *sa, int socklen)
{
    int result = -1;
    int ownfd = 0;
    int r = -1;
    evutil_socket_t fd = bufev->ev_read.fd;
    if (fd < 0) {
        if (!sa) {
            return result;
        }
        fd = socket(sa->sa_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (fd < 0) {
            if (ownfd) {
                hv2ev_evutil_closesocket(fd);
            }
            return result;
        }
        ownfd = 1;
    }
    if (sa) {
        r = hv2ev_evutil_socket_connect(&fd, sa, socklen);
        if (r < 0) {
            if (ownfd) {
                hv2ev_evutil_closesocket(fd);
            }
            return result;
        }
    }

    bufferevent_setfd(bufev, fd);
    if (fd >= 0) {
        hv2ev_bufferevent_enable(bufev, bufev->enabled);
    }

    if (r == 0) {
        hv2ev_event_add(&bufev->ev_write, &bufev->timeout_write);
        bufev->connecting = 1;
        result = 0;
        return result;
    } else if (r == 1) { // 连接已经建立
        result = 0;
        bufev->connecting = 1;
        hv2ev_event_active(&(bufev->ev_write), EV_WRITE, 1);
    } else { // 连接被拒绝
        result = 0;
        hv2ev_event_active(&(bufev->ev_err), BEV_EVENT_ERROR, 1);
        hv2ev_bufferevent_disable(bufev, EV_WRITE | EV_READ);
    }
    return result;
}

int hv2ev_bufferevent_socket_connect_hostname(struct bufferevent *bev,
                                              struct evdns_base *evdns_base,
                                              int family, const char *hostname,
                                              int port)
{
    int ret = 0;
    sockaddr_u addr;
    memset(&addr, 0, sizeof(addr));
    ret = sockaddr_set_ipport((sockaddr_u *)&addr, hostname, port);
    if (ret < 0) {
        return -1;
    }
    ret = hv2ev_bufferevent_socket_connect(bev, (struct sockaddr *)(&(addr.sin)),
                                           sizeof(addr.sin));
    return ret;
}

evutil_socket_t accept4(evutil_socket_t sockfd, struct sockaddr *addr,
                        ev_socklen_t *addrlen, int flags)
{
    evutil_socket_t result;
    result = accept(sockfd, addr, addrlen);
    if (result < 0) {
        return result;
    }

    if (flags & EVUTIL_SOCK_CLOEXEC) {
        if (hv2ev_evutil_make_socket_closeonexec(result) < 0) {
            hv2ev_evutil_closesocket(result);
            return -1;
        }
    }
    if (flags & EVUTIL_SOCK_NONBLOCK) {
        if (hv2ev_evutil_make_socket_nonblocking(result) < 0) {
            hv2ev_evutil_closesocket(result);
            return -1;
        }
    }
    return result;
}

static void listener_read_cb(evutil_socket_t fd, short what, void *p)
{
    struct evconnlistener *lev = (struct evconnlistener *)p;
    int err;
    evconnlistener_cb cb;
    evconnlistener_errorcb errorcb;
    void *user_data;
    int need_break = 0;
    while (need_break == 0) {
        struct sockaddr_storage ss;
        ev_socklen_t socklen = sizeof(ss);
        evutil_socket_t new_fd =
                accept4(fd, (struct sockaddr *)&ss, &socklen, lev->accept4_flags);
        if (new_fd < 0) {
            need_break = 1;
            break;
        }
        if (socklen == 0) {
            /* This can happen with some older linux kernels in
             * response to nmap. */
            hv2ev_evutil_closesocket(new_fd);
            continue;
        }

        if (lev->cb == NULL) {
            hv2ev_evutil_closesocket(new_fd);
            return;
        }
        cb = lev->cb;
        user_data = lev->user_data;
        cb(lev, new_fd, (struct sockaddr *)&ss, (int)socklen, user_data);

        if (!lev->enabled) {
            /* the callback could have disabled the listener */
            return;
        }
    }
    err = hv2ev_evutil_socket_geterror(fd);
    if (hv2ev_EVUTIL_ERR_ACCEPT_RETRIABLE(err)) {
        return;
    }
    if (lev->errorcb != NULL) {
        errorcb = lev->errorcb;
        user_data = lev->user_data;
        errorcb(lev, user_data);
    } else {
        return;
    }
}

// evconnlistener结构体及相关函数模仿并简化了libevent的实现
struct evconnlistener *hv2ev_evconnlistener_new(struct event_base *base,
                                                evconnlistener_cb cb, void *ptr,
                                                unsigned flags, int backlog,
                                                evutil_socket_t fd)
{
    struct evconnlistener_event *lev;
    if (backlog > 0) {
        if (listen(fd, backlog) < 0) {
            return NULL;
        }
    } else if (backlog < 0) {
        int temp_back_log = 128;
        if (listen(fd, temp_back_log) < 0) {
            return NULL;
        }
    }
    HV_ALLOC(lev, sizeof(struct evconnlistener_event));
    if (!lev) {
        return NULL;
    }

    lev->base.cb = cb;
    lev->base.user_data = ptr;
    lev->base.flags = flags;
    lev->base.lev_e = lev;

    lev->base.accept4_flags = 0;
    if (!(flags & LEV_OPT_LEAVE_SOCKETS_BLOCKING)) {
        lev->base.accept4_flags |= EVUTIL_SOCK_NONBLOCK;
    }
    if (flags & LEV_OPT_CLOSE_ON_EXEC) {
        lev->base.accept4_flags |= EVUTIL_SOCK_CLOEXEC;
    }

    hv2ev_event_assign(&lev->listener, base, fd, EV_READ | EV_PERSIST, listener_read_cb,
                       lev);

    if (!(flags & LEV_OPT_DISABLED)) {
        lev->base.enabled = 1;
        if (lev->base.cb) {
            hv2ev_event_add(&(lev->listener), NULL);
        }
    }

    return &lev->base;
}

void hv2ev_evconnlistener_free(struct evconnlistener *lev)
{
    struct evconnlistener_event *lev_e = lev->lev_e;
    hv2ev_event_del(&lev_e->listener);
    if (lev->flags & LEV_OPT_CLOSE_ON_FREE) {
        close(lev_e->listener.fd);
    }
    HV_FREE(lev);
}

static int deal_flags(unsigned flags, evutil_socket_t fd)
{
    if (flags & LEV_OPT_REUSEABLE) {
        int one = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&one,
                       (ev_socklen_t)sizeof(one)) < 0) {
            hv2ev_evutil_closesocket(fd);
            return -1;
        }
    }
    if (flags & LEV_OPT_REUSEABLE_PORT) {
        int one = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (void *)&one,
                       (ev_socklen_t)sizeof(one)) < 0) {
            hv2ev_evutil_closesocket(fd);
            return -1;
        }
    }
    if (flags & LEV_OPT_DEFERRED_ACCEPT) {
        int one = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &one,
                       (ev_socklen_t)sizeof(one)) < 0) {
            hv2ev_evutil_closesocket(fd);
            return -1;
        }
    }
    if (flags & LEV_OPT_BIND_IPV6ONLY) {
        int one = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &one,
                       (ev_socklen_t)sizeof(one)) < 0) {
            hv2ev_evutil_closesocket(fd);
            return -1;
        }
    }
    return 0;
}

struct evconnlistener *hv2ev_evconnlistener_new_bind(struct event_base *base,
                                                     evconnlistener_cb cb, void *ptr,
                                                     unsigned flags, int backlog,
                                                     const struct sockaddr *sa,
                                                     int socklen)
{
    struct evconnlistener *listener;
    evutil_socket_t fd;
    int on = 1;
    int family = sa ? sa->sa_family : AF_UNSPEC;
    int socktype = SOCK_STREAM | EVUTIL_SOCK_NONBLOCK;

    if (backlog == 0) {
        return NULL;
    }
    if (flags & LEV_OPT_CLOSE_ON_EXEC) {
        socktype |= EVUTIL_SOCK_CLOEXEC;
    }
    fd = socket(family, socktype, 0);
    if (fd == -1) {
        return NULL;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&on, sizeof(on)) < 0) {
        hv2ev_evutil_closesocket(fd);
        return NULL;
    }
    if (deal_flags(flags, fd) == -1) {
        return NULL;
    }
    if (sa) {
        if (bind(fd, sa, socklen) < 0) {
            hv2ev_evutil_closesocket(fd);
            return NULL;
        }
    }
    listener = hv2ev_evconnlistener_new(base, cb, ptr, flags, backlog, fd);
    if (!listener) {
        hv2ev_evutil_closesocket(fd);
        return NULL;
    }
    return listener;
}

size_t hv2ev_bufferevent_read(struct bufferevent *bufev, void *data, size_t size)
{
    return (hv2ev_evbuffer_remove(bufev->input, data, size));
}

int hv2ev_evconnlistener_enable(struct evconnlistener *lev)
{
    int r;
    lev->enabled = 1;
    if (lev->cb) {
        r = hv2ev_event_add(&lev->lev_e->listener, NULL);
    } else {
        r = 0;
    }
    return r;
}

void queue_node_reset(struct queue_node *queue_node)
{
    queue_node->next = queue_node;
    queue_node->pre = queue_node;
}

int queue_node_empty(struct queue_node *queue_node)
{
    return queue_node->next == queue_node;
}

void queue_node_insert_tail(struct queue_node *head, struct queue_node *node)
{
    node->next = head;
    node->pre = head->pre;
    node->pre->next = node;
    head->pre = node;
}

void queue_node_remove(struct queue_node *node)
{
    node->pre->next = node->next;
    node->next->pre = node->pre;
}

void run_signal_cb(hevent_t *hevent)
{
    struct event_base *base = (struct event_base *)hevent->userdata;
    struct queue_node *head = &(base->awaken_signal_events_head);
    if (base->enable_signal && !queue_node_empty(head)) {
        struct queue_node *ev_node = head->next;
        while (ev_node != head) {
            struct event *ev =
                    (struct event *)((char *)(ev_node) - offsetof(struct event, self_awaken_signal_node));
            for (int i = 0; i < ev->num_calls; i++) {
                ev->callback(ev->fd, EV_SIGNAL, ev->callback_arg);
            }
            struct queue_node *next = ev_node->next;
            queue_node_remove(ev_node);
            queue_node_reset(ev_node);
            ev_node = next;
        }
    }
}

static void sig_event_cb(int fd, short awakened_events_on_epoll, void *arg)
{
    char signals[1024];
    int n = 0;
    int ncaught[NSIG];
    memset(signals, 0, sizeof(signals));
    memset(ncaught, 0, sizeof(ncaught));

    struct event_base *base = (struct event_base *)arg;

    if (base == NULL) {
        return;
    }

    int need_break = 0;
    while (need_break == 0) {
        n = read(fd, signals, sizeof(signals));
        if (n <= 0) {
            need_break = 1;
            break;
        }
        for (int i = 0; i < n; ++i) {
            int sig = (int)signals[i];
            if (sig < NSIG)
                ncaught[sig]++;
        }
    }

    for (int i = 0; i < NSIG; i++) {
        if (ncaught[i] <= 0) {
            continue;
        }
        struct queue_node *events_at_sig = &(base->signal_events_head[i]);
        if (!queue_node_empty(events_at_sig)) {
            struct queue_node *ev_node = events_at_sig->next;
            while (ev_node != events_at_sig) {
                struct event *ev =
                        (struct event *)((char *)(ev_node) - offsetof(struct event, self_signal_node));
                // ev->awakened_events_ |= EV_SIGNAL;
                ev->num_calls = ncaught[i];
                queue_node_insert_tail(&(base->awaken_signal_events_head),
                                       &(ev->self_awaken_signal_node));
                ev_node = ev_node->next;
            }
        }
    }

    hevent_t hev;
    memset(&hev, 0, sizeof(hev));
    hev.cb = run_signal_cb;
    hev.userdata = base;
    hloop_post_event(base->loop, &hev);
}

struct event_base *hv2ev_event_base_new(void)
{
    struct event_base *base = NULL;
    HV_ALLOC(base, sizeof(struct event_base));
    base->loop = hloop_new(HLOOP_FLAG_QUIT_WHEN_NO_ACTIVE_EVENTS);
    base->timer = NULL;
    base->enable_signal = 0;

    return base;
}

void hv2ev_event_base_free(struct event_base *base)
{
    if (base->timer != NULL) {
        htimer_del(base->timer);
        base->timer = NULL;
    }
    if (base->loop != NULL) {
        hloop_free(&(base->loop));
        base->loop = NULL;
    }
    if (base->pair[0] > 0) {
        close(base->pair[0]);
    }
    if (base->pair[1] > 0) {
        close(base->pair[1]);
    }
    HV_FREE(base);
}

int hv2ev_event_base_loop(struct event_base *base, int flags)
{
    return hloop_run(base->loop);
}

int hv2ev_event_base_dispatch(struct event_base *base)
{
    return hv2ev_event_base_loop(base, 0);
}

int hv2ev_event_base_loopbreak(struct event_base *base)
{
    return hloop_stop(base->loop);
}

int timeval_to_ms(const struct timeval *tv)
{
    int one_thousand = 1000;
    return (tv->tv_sec * one_thousand) + (tv->tv_usec / one_thousand);
}

void on_loopexit_timeout(htimer_t *timer)
{
    hloop_stop(hevent_loop(timer));
}

void on_loopexit_directly(hevent_t *hevent)
{
    hloop_stop(hevent_loop(hevent));
}

int hv2ev_event_base_loopexit(struct event_base *base, const struct timeval *tv)
{
    if (tv != NULL) {
        if (base->timer != NULL) {
            htimer_del(base->timer);
            base->timer = NULL;
        }
        int timeout = timeval_to_ms(tv);
        base->timer =
                htimer_add(base->loop, on_loopexit_timeout, timeout, INFINITE);
        if (base->timer == NULL) {
            return -1;
        }
        base->timeout = timeout;
    } else {
        hevent_t hev;
        memset(&hev, 0, sizeof(hev));
        hev.cb = on_loopexit_directly;
        hloop_post_event(base->loop, &hev);
    }
    return 0;
}

HV_INLINE void on_readable(hio_t *io)
{
    struct event *ev = (struct event *)hio_getcb_read(io);
    if (ev == NULL) {
        return;
    }
    int fd = hio_fd(io);
    short events = ev->events;
    short revents = hio_revents(io);
    if (!((events & EV_READ) && (revents & EV_READ))) {
        return;
    }

    if (!(events & EV_PERSIST)) {
        hio_del(io, HV_READ);
        if (ev->timer != NULL) {
            htimer_del(ev->timer);
            ev->timer = NULL;
        }
    }

    event_callback_fn callback = ev->callback;
    void *callback_arg = ev->callback_arg;
    if (callback) {
        callback(fd, EV_READ, callback_arg);
    }

    if ((ev->timer != NULL) && (events & EV_PERSIST)) {
        htimer_reset(ev->timer, ev->timeout);
    }
}

HV_INLINE void on_writable(hio_t *io)
{
    struct event *ev = (struct event *)hio_getcb_write(io);
    if (ev == NULL) {
        return;
    }
    int fd = hio_fd(io);
    short events = ev->events;
    short revents = hio_revents(io);
    if (!((events & EV_WRITE) && (revents & EV_WRITE))) {
        return;
    }

    if (!(events & EV_PERSIST)) {
        hio_del(io, HV_WRITE);
        if (ev->timer != NULL) {
            htimer_del(ev->timer);
            ev->timer = NULL;
        }
    }

    event_callback_fn callback = ev->callback;
    void *callback_arg = ev->callback_arg;
    if (callback) {
        callback(fd, EV_WRITE, callback_arg);
    }

    if ((ev->timer != NULL) && (events & EV_PERSIST)) {
        htimer_reset(ev->timer, ev->timeout);
    }
}

void on_netio(hio_t *io)
{
    short revents = hio_revents(io);
    if (revents & EV_WRITE) {
        on_writable(io);
    }
    if (revents & EV_READ) {
        on_readable(io);
    }
}

void on_timeout(htimer_t *timer)
{
    struct event *ev = (struct event *)hevent_userdata(timer);
    short events = ev->events;

    if (!((events & EV_PERSIST))) {
        hv2ev_event_del(ev);
        if (ev->timer != NULL) {
            htimer_del(ev->timer);
            ev->timer = NULL;
        }
    }

    event_callback_fn callback = ev->callback;
    void *callback_arg = ev->callback_arg;
    if (callback) {
        callback(ev->fd, EV_TIMEOUT, callback_arg);
    }

    if ((ev->timer != NULL) && (events & EV_PERSIST)) {
        htimer_reset(ev->timer, ev->timeout);
    }
}

void on_active(hevent_t *hev)
{
    struct event *ev = (struct event *)hevent_userdata(hev);
    int active_events = (int)(intptr_t)hev->privdata;
    event_callback_fn callback = ev->callback;
    void *callback_arg = ev->callback_arg;
    if (callback) {
        callback(ev->fd, active_events, callback_arg);
    }

    if (ev->timer != NULL) {
        htimer_reset(ev->timer, ev->timeout);
    }
}

int hv2ev_event_assign(struct event *ev, struct event_base *base, evutil_socket_t fd,
                       short events, event_callback_fn callback, void *callback_arg)
{
    if (ev == NULL) {
        return -1;
    }
    ev->io = NULL;
    ev->timer = NULL;
    ev->base = base;
    ev->fd = fd;
    ev->events = events;
    ev->callback = callback;
    ev->callback_arg = callback_arg;
    return 0;
}

struct event *hv2ev_event_new(struct event_base *base, evutil_socket_t fd,
                              short events, event_callback_fn callback,
                              void *callback_arg)
{
    struct event *ev = NULL;
    HV_ALLOC(ev, sizeof(struct event));
    ev->io = NULL;
    ev->timer = NULL;
    ev->base = base;
    ev->fd = fd;
    ev->events = events;
    ev->events_pending = 0;
    ev->callback = callback;
    ev->callback_arg = callback_arg;
    ev->num_calls = 0;
    queue_node_reset(&(ev->self_signal_node));
    queue_node_reset(&(ev->self_awaken_signal_node));
    return ev;
}

static int g_sigWriteFd = -1;

static void sig_handler(int sig)
{
    int save_errno = errno;

    char signum = (char)sig;
    int n = write(g_sigWriteFd, &signum, 1);
    (void)n;

    errno = save_errno;
}

static void deal_signal_event(struct event_base *base, struct event *ev, int fd)
{
    if (base->enable_signal == 0) {
        base->enable_signal = 1;
        for (int i = 0; i < NSIG; i++) {
            queue_node_reset(&(base->signal_events_head[i]));
        }
        queue_node_reset(&(base->awaken_signal_events_head));
        socketpair(AF_UNIX, SOCK_STREAM, 0, base->pair);
        fcntl(base->pair[0], F_SETFL, O_NONBLOCK);
        fcntl(base->pair[1], F_SETFL, O_NONBLOCK);
        fcntl(base->pair[0], F_SETFD, FD_CLOEXEC);
        fcntl(base->pair[1], F_SETFD, FD_CLOEXEC);
        hv2ev_event_assign(&(base->signal_monitor), base, base->pair[0],
                           EV_READ | EV_PERSIST, sig_event_cb, base);
        hv2ev_event_add(&(base->signal_monitor), NULL);
    }
    struct queue_node *events_at_sig = &(base->signal_events_head[fd]);
    if (queue_node_empty(events_at_sig)) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sig_handler;
        sa.sa_flags |= SA_RESTART;
        sigfillset(&sa.sa_mask);
        g_sigWriteFd = base->pair[1];
        sigaction(fd, &sa, NULL);
    }
    queue_node_insert_tail(&(base->signal_events_head[fd]),
                           &(ev->self_signal_node));
}

int hv2ev_event_add(struct event *ev, const struct timeval *tv)
{
    int fd = ev->fd;
    struct event_base *base = ev->base;
    short events = ev->events;
    if (ev->events & EV_SIGNAL) {
        deal_signal_event(base, ev, fd);
        return 0;
    }
    ev->events_pending |= events;
    if (fd >= 0) {
        ev->io = hio_get(base->loop, fd);
        if (events & EV_READ) {
            hio_setcb_read(ev->io, (hread_cb)ev);
            hio_add(ev->io, on_netio, HV_READ);
        }
        if (events & EV_WRITE) {
            hio_setcb_write(ev->io, (hwrite_cb)ev);
            hio_add(ev->io, on_netio, HV_WRITE);
        }
    }
    if (tv != NULL) {
        if (ev->timer != NULL) {
            htimer_del(ev->timer);
            ev->timer = NULL;
        }
        ev->timeout = timeval_to_ms(tv);
        ev->timer = htimer_add(base->loop, on_timeout, ev->timeout, INFINITE);
        if (ev->timer != NULL) {
            hevent_set_userdata(ev->timer, ev);
        }
    }
    return 0;
}

void hv2ev_event_active(struct event *ev, int res, short ncalls)
{
    hidle_add(ev->base->loop, NULL, 1);

    hevent_t hev;
    memset(&hev, 0, sizeof(hev));
    hev.cb = on_active;
    hev.userdata = ev;
    hev.privdata = (void *)(intptr_t)res;
    hloop_post_event(ev->base->loop, &hev);
}

int hv2ev_event_del(struct event *ev)
{
    ev->events_pending &= (~ev->events);
    if (ev->io != NULL) {
        short events = ev->events;
        if (events & EV_READ) {
            hio_del(ev->io, HV_READ);
            hio_setcb_read(ev->io, NULL);
        }
        if (events & EV_WRITE) {
            hio_del(ev->io, HV_WRITE);
            hio_setcb_write(ev->io, NULL);
        }
    }
    if (ev->timer != NULL) {
        htimer_del(ev->timer);
        ev->timer = NULL;
    }
    return 0;
}

void hv2ev_event_free(struct event *ev)
{
    hv2ev_event_del(ev);
    if (ev->io != NULL) {
        hio_close(ev->io);
        ev->io = NULL;
    }
    HV_FREE(ev);
}

void hv2ev_event_set_mem_functions(void *(*malloc_fn)(size_t sz),
                                   void *(*realloc_fn)(void *ptr, size_t sz),
                                   void (*free_fn)(void *ptr))
{
    return;
}

int hv2ev_event_pending(const struct event *ev, short events, struct timeval *tv)
{
    return ev->events_pending & events;
}

evutil_socket_t hv2ev_evconnlistener_get_fd(struct evconnlistener *lev)
{
    return lev->lev_e->listener.fd;
}

void hv2ev_ev_token_bucket_cfg_free(struct ev_token_bucket_cfg *cfg)
{
    if (cfg != NULL) {
        free(cfg);
    }
}

struct ev_token_bucket_cfg *
hv2ev_ev_token_bucket_cfg_new(size_t read_rate, size_t read_burst, size_t write_rate,
                              size_t write_burst, const struct timeval *tick_len)
{
    return NULL;
}

int hv2ev_event_base_gettimeofday_cached(struct event_base *base,
                                         struct timeval *tv)
{
    return gettimeofday(tv, NULL);
}

int hv2ev_bufferevent_set_rate_limit(struct bufferevent *bev,
                                     struct ev_token_bucket_cfg *cfg)
{
    return 0;
}

int hv2ev_bufferevent_flush(struct bufferevent *bufev, short iotype,
                            enum bufferevent_flush_mode mode)
{
    return 0;
}