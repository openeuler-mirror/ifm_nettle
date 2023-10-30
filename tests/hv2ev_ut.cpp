#include "hv2ev.h"
#include <chrono>
#include <gtest/gtest.h>
#include <thread>

static void many_event_cb(evutil_socket_t fd, short event, void *arg)
{
    int *calledp = (int *)arg;
    *calledp += 1;
}

TEST(hv2ev_testcases, test_many_events) {
    const int MANY = 70;

    // event_base_new()
    struct event_base *base = event_base_new();

    evutil_socket_t sock[MANY];
    struct event *ev[MANY];
    int called[MANY];
    int i;

    for (i = 0; i < MANY; ++i) {
        sock[i] = socket(AF_INET, SOCK_DGRAM, 0);
        ASSERT_TRUE(sock[i] >= 0);
        ASSERT_TRUE(!evutil_make_socket_nonblocking(sock[i]));
        called[i] = 0;
        ev[i] = event_new(base, sock[i], EV_WRITE, many_event_cb, &called[i]);
        event_add(ev[i], NULL);
    }

    event_base_loop(base, 0);

    for (i = 0; i < MANY; ++i) {
        ASSERT_EQ(called[i], 1);
    }

    for (i = 0; i < MANY; ++i) {
        if (ev[i]) {
            event_free(ev[i]);
        }
        if (sock[i] >= 0) {
            evutil_closesocket(sock[i]);
        }
    }
    event_base_free(base);
}

TEST(hv2ev_testcases, test_many_events_one_at_a_time) {
    const int MANY = 70;

    // event_base_new()
    struct event_base *base = NULL;
    HV_ALLOC(base, sizeof(struct event_base));
    base->loop =
            hloop_new(HLOOP_FLAG_QUIT_WHEN_NO_ACTIVE_EVENTS | HLOOP_FLAG_RUN_ONCE);
    base->timer = NULL;

    evutil_socket_t sock[MANY];
    struct event *ev[MANY];
    int called[MANY];
    int i;
    int evflags = EV_PERSIST;

    for (i = 0; i < MANY; ++i) {
        sock[i] = socket(AF_INET, SOCK_DGRAM, 0);
        ASSERT_TRUE(sock[i] >= 0);
        ASSERT_TRUE(!evutil_make_socket_nonblocking(sock[i]));
        called[i] = 0;
        ev[i] =
                event_new(base, sock[i], EV_WRITE | evflags, many_event_cb, &called[i]);
        event_add(ev[i], NULL);
        event_base_loop(base, 0);
    }

    event_base_loop(base, 0);

    for (i = 0; i < MANY; ++i) {
        ASSERT_EQ(called[i], MANY - i + 1);
    }

    for (i = 0; i < MANY; ++i) {
        if (ev[i]) {
            event_free(ev[i]);
        }
        if (sock[i] >= 0) {
            evutil_closesocket(sock[i]);
        }
    }
    event_base_free(base);
}

const char *g_TEST1 = "this is a test";

static void basic_read_cb(evutil_socket_t fd, short event, void *data)
{
    char buf[256];
    int len;
    struct basic_cb_args {
        struct event_base *eb;
        struct event *ev;
        unsigned int callcount;
    };
    struct basic_cb_args *arg = (struct basic_cb_args *)data;

    len = read(fd, buf, sizeof(buf));

    ASSERT_FALSE(len < 0);

    switch (arg->callcount++) {
    case 0: /* first call: expect to read data; cycle */
        if (len > 0) {
            return;
        }
        FAIL() << "EOF before data read";
        break;

    case 1: /* second call: expect EOF; stop */
        if (len > 0) {
            FAIL() << "not all data read on first cycle";
        }
        break;

    default: /* third call: should not happen */
        FAIL() << "too many cycles";
    }

    event_del(arg->ev);
    hio_close(arg->ev->io);
    event_base_loopexit(arg->eb, NULL);
}

TEST(hv2ev_testcases, test_event_base_new) {
    evutil_socket_t spair[2] = {-1, -1};
    evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, spair);
    evutil_make_socket_nonblocking(spair[0]);
    evutil_make_socket_nonblocking(spair[1]);
    int towrite = static_cast<int>(strlen(g_TEST1)) + 1;
    ssize_t n = write(spair[0], g_TEST1, towrite);
    (void)n;
    shutdown(spair[0], EVUTIL_SHUT_WR);

    struct event_base *base = event_base_new();
    struct event ev1;
    struct basic_cb_args {
        struct event_base *eb;
        struct event *ev;
        unsigned int callcount;
    };
    struct basic_cb_args args;
    args.eb = base;
    args.ev = &ev1;
    args.callcount = 0;

    event_assign(&ev1, base, spair[1], EV_READ | EV_PERSIST, basic_read_cb,
                             &args);
    event_add(&ev1, NULL);
    event_base_loop(base, 0);

    event_base_free(base);
}

static char g_wbuf[4096];
static char g_rbuf[4096];
static int g_roff, g_woff;
static int g_usepersist;

static void multiple_read_cb(evutil_socket_t fd, short event, void *arg)
{
    struct event *ev = (struct event *)arg;
    int len;

    len = read(fd, g_rbuf + g_roff, sizeof(g_rbuf) - g_roff);
    if (len == -1)
        fprintf(stderr, "%s: read\n", __func__);
    if (len <= 0) {
        if (g_usepersist) {
            event_del(ev);
        }
        hio_close(ev->io);
        return;
    }

    g_roff += len;
    if (!g_usepersist) {
        event_add(ev, NULL);
    }
}

static void multiple_write_cb(evutil_socket_t fd, short event, void *arg)
{
    struct event *ev = (struct event *)arg;
    int len = 128;
    if (g_woff + len >= static_cast<int>(sizeof(g_wbuf))) {
        len = sizeof(g_wbuf) - g_woff;
    }

    len = write(fd, g_wbuf + g_woff, len);
    if (len == -1) {
        fprintf(stderr, "%s: write\n", __func__);
        if (g_usepersist) {
            event_del(ev);
        }
        hio_close(ev->io);
        return;
    }

    g_woff += len;

    if (g_woff >= static_cast<int>(sizeof(g_wbuf))) {
        shutdown(fd, EVUTIL_SHUT_WR);
        if (g_usepersist) {
            event_del(ev);
        }
        hio_close(ev->io);
        return;
    }

    if (!g_usepersist) {
        event_add(ev, NULL);
    }
}

TEST(hv2ev_testcases, test_persistent) {
    struct event ev, ev2;
    int i;
    evutil_socket_t spair[2] = {-1, -1};
    evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, spair);
    evutil_make_socket_nonblocking(spair[0]);
    evutil_make_socket_nonblocking(spair[1]);

    /* Multiple read and write test with persist */
    memset(g_rbuf, 0, sizeof(g_rbuf));
    for (i = 0; i < static_cast<int>(sizeof(g_wbuf)); i++) {
        g_wbuf[i] = i;
    }
    g_roff = g_woff = 0;
    g_usepersist = 1;

    struct event_base *base = event_base_new();

    event_assign(&ev, base, spair[0], EV_WRITE | EV_PERSIST, multiple_write_cb,
                             &ev);
    event_add(&ev, NULL);
    event_assign(&ev2, base, spair[1], EV_READ | EV_PERSIST, multiple_read_cb,
                             &ev2);
    event_add(&ev2, NULL);
    event_base_dispatch(base);
    event_base_free(base);

    ASSERT_EQ(g_roff, g_woff);
    ASSERT_EQ(memcmp(g_rbuf, g_wbuf, sizeof(g_wbuf)), 0);
}

TEST(hv2ev_testcases, test_multiple) {
    struct event ev, ev2;
    int i;
    evutil_socket_t spair[2] = {-1, -1};
    evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, spair);
    evutil_make_socket_nonblocking(spair[0]);
    evutil_make_socket_nonblocking(spair[1]);

    /* Multiple read and write test */
    memset(g_rbuf, 0, sizeof(g_rbuf));
    for (i = 0; i < static_cast<int>(sizeof(g_wbuf)); i++) {
        g_wbuf[i] = i;
    }

    g_roff = g_woff = 0;
    g_usepersist = 0;

    struct event_base *base = event_base_new();

    event_assign(&ev, base, spair[0], EV_WRITE, multiple_write_cb, &ev);
    event_add(&ev, NULL);
    event_assign(&ev2, base, spair[1], EV_READ, multiple_read_cb, &ev2);
    event_add(&ev2, NULL);
    event_base_dispatch(base);
    event_base_free(base);

    ASSERT_EQ(g_roff, g_woff);
    ASSERT_EQ(memcmp(g_rbuf, g_wbuf, sizeof(g_wbuf)), 0);
}

static struct timeval tset;
static struct timeval tcalled;

static long timeval_msec_diff(const struct timeval *start,
                              const struct timeval *end)
{
    long ms = end->tv_sec - start->tv_sec;
    int one_thousand = 1000;
    int half_thousand = 500;
    ms *= one_thousand;
    ms += ((end->tv_usec - start->tv_usec) + half_thousand) / one_thousand;
    return ms;
}

static void timeout_cb(evutil_socket_t fd, short event, void *arg)
{
    evutil_gettimeofday(&tcalled, NULL);
}

static void CHECK_TIME(struct timeval *start, struct timeval *end, int diff)
{
    int deviation = 50;
    ASSERT_LE(labs(timeval_msec_diff(start, end) - diff), deviation);
}

TEST(hv2ev_testcases, test_loopexit) {
    struct event_base *base = event_base_new();
    struct timeval tv, tv_start, tv_end;
    struct event ev;

    tv.tv_usec = 0;
    tv.tv_sec = 60 * 60 * 24;
    event_assign(&ev, base, -1, 0, timeout_cb, NULL);
    evtimer_add(&ev, &tv);

    tv.tv_usec = 300 * 1000;
    tv.tv_sec = 0;
    event_base_loopexit(base, &tv);

    evutil_gettimeofday(&tv_start, NULL);
    event_base_dispatch(base);
    evutil_gettimeofday(&tv_end, NULL);

    evtimer_del(&ev);

    event_base_free(base);

    CHECK_TIME(&tv_start, &tv_end, 300);
}

static void persist_active_timeout_cb(evutil_socket_t fd, short event, void *arg)
{
    struct persist_active_timeout_called {
        int n;
        short events[16];
        struct timeval tvs[16];
    };
    struct persist_active_timeout_called *c =
            (struct persist_active_timeout_called *)arg;
    int upper = 15;
    if (c->n < upper) {
        c->events[c->n] = event;
        evutil_gettimeofday(&c->tvs[c->n], NULL);
        ++c->n;
    }
}

static void activate_cb(evutil_socket_t fd, short event, void *arg)
{
    struct event *ev = (struct event *)arg;
    event_active(ev, EV_READ, 1);
}

TEST(hv2ev_testcases, test_persistent_active_timeout) {
    struct timeval tv, tv2, tv_exit, start;
    struct event ev;
    struct persist_active_timeout_called {
        int n;
        short events[16];
        struct timeval tvs[16];
    };
    struct persist_active_timeout_called res;

    struct event_base *base = event_base_new();

    memset(&res, 0, sizeof(res));

    tv.tv_sec = 0;
    tv.tv_usec = 200 * 1000;
    event_assign(&ev, base, -1, EV_TIMEOUT | EV_PERSIST,
                             persist_active_timeout_cb, &res);
    event_add(&ev, &tv);

    tv2.tv_sec = 0;
    tv2.tv_usec = 100 * 1000;
    struct event *once_event = event_new(base, -1, EV_TIMEOUT, activate_cb, &ev);
    event_add(once_event, &tv2);

    tv_exit.tv_sec = 0;
    tv_exit.tv_usec = 600 * 1000;
    event_base_loopexit(base, &tv_exit);

    evutil_gettimeofday(&start, NULL);
    event_base_dispatch(base);
    ASSERT_TRUE(res.n == 3);
    ASSERT_TRUE(res.events[0] == EV_READ);
    ASSERT_TRUE(res.events[1] == EV_TIMEOUT);
    ASSERT_TRUE(res.events[2] == EV_TIMEOUT);
    CHECK_TIME(&start, &res.tvs[0], 100);
    CHECK_TIME(&start, &res.tvs[1], 300);
    CHECK_TIME(&start, &res.tvs[2], 500);

    event_del(&ev);
    event_free(once_event);
    event_base_free(base);
}

static void read_not_timeout_cb(evutil_socket_t fd, short what, void *arg)
{
    struct read_not_timeout_param {
        struct event **ev;
        int events;
        int count;
    };
    struct read_not_timeout_param *rntp = (struct read_not_timeout_param *)arg;
    char c;
    int n;
    (void)fd;
    (void)what;
    n = read(fd, &c, 1);
    ASSERT_EQ(n, 1);
    rntp->events |= what;
    ++rntp->count;
    int count = 2;
    if (count == rntp->count) {
        event_del(rntp->ev[0]);
    }
}

static void incr_arg_cb(evutil_socket_t fd, short what, void *arg)
{
    int *intptr = (int *)arg;
    (void)fd;
    (void)what;
    ++*intptr;
}

static void remove_timers_cb(evutil_socket_t fd, short what, void *arg)
{
    struct event **ep = (struct event **)arg;
    (void)fd;
    (void)what;
    htimer_del(ep[0]->timer);
    htimer_del(ep[1]->timer);
}

static void send_a_byte_cb(evutil_socket_t fd, short what, void *arg)
{
    evutil_socket_t *sockp = (evutil_socket_t *)arg;
    (void)fd;
    (void)what;
    if (write(*sockp, "A", 1) < 0) {
        FAIL() << "write";
    }
}

TEST(hv2ev_testcases, test_event_remove_timeout) {
    struct event_base *base = event_base_new();
    struct event *ev[5];
    int ev1_fired = 0;
    struct timeval ms25 = {0, 25 * 1000}, ms40 = {0, 40 * 1000},
                                 ms75 = {0, 75 * 1000}, ms125 = {0, 125 * 1000};
    struct read_not_timeout_param {
        struct event **ev;
        int events;
        int count;
    };
    struct read_not_timeout_param rntp = {ev, 0, 0};
    evutil_socket_t spair[2] = {-1, -1};
    evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, spair);
    evutil_make_socket_nonblocking(spair[0]);
    evutil_make_socket_nonblocking(spair[1]);

    ev[0] = event_new(base, spair[0], EV_READ | EV_PERSIST, read_not_timeout_cb,
                                        &rntp);
    ev[1] = evtimer_new(base, incr_arg_cb, &ev1_fired);
    ev[2] = evtimer_new(base, remove_timers_cb, ev);
    ev[3] = evtimer_new(base, send_a_byte_cb, &spair[1]);
    ev[4] = evtimer_new(base, send_a_byte_cb, &spair[1]);
    event_add(ev[2], &ms25);    /* remove timers */
    event_add(ev[4], &ms40);    /* write to test if timer re-activates */
    event_add(ev[0], &ms75);    /* read */
    event_add(ev[1], &ms75);    /* timer */
    event_add(ev[3], &ms125); /* timeout. */

    event_base_dispatch(base);

    ASSERT_EQ(ev1_fired, 0);
    ASSERT_EQ(rntp.events, EV_READ);

    event_free(ev[0]);
    event_free(ev[1]);
    event_free(ev[2]);
    event_free(ev[3]);
    event_free(ev[4]);
    event_base_free(base);
}

TEST(hv2ev_testcases, test_simpletimeout) {
    struct event_base *base = event_base_new();
    struct timeval tv;
    struct event ev;

    tv.tv_usec = 200 * 1000;
    tv.tv_sec = 0;
    evutil_timerclear(&tcalled);
    event_assign(&ev, base, -1, 0, timeout_cb, NULL);
    evtimer_add(&ev, &tv);

    evutil_gettimeofday(&tset, NULL);
    event_base_dispatch(base);
    CHECK_TIME(&tset, &tcalled, 200);

    event_base_free(base);
}

static struct event_base *global_base = NULL;

static void periodic_timeout_cb(evutil_socket_t fd, short event, void *arg)
{
    int *count = (int *)arg;

    int most_called_times = 6;
    (*count)++;
    if (*count == most_called_times) {
        /* call loopexit only once - on slow machines(?), it is
         * apparently possible for this to get called twice. */
        event_base_loopexit(global_base, NULL);
    }
}

TEST(hv2ev_testcases, test_persistent_timeout) {
    struct event_base *base = event_base_new();
    global_base = base;
    struct timeval tv;
    struct event ev;
    int count = 0;

    evutil_timerclear(&tv);
    tv.tv_usec = 10000;

    event_assign(&ev, base, -1, EV_TIMEOUT | EV_PERSIST, periodic_timeout_cb,
                             &count);
    event_add(&ev, &tv);

    event_base_dispatch(base);

    ASSERT_EQ(count, 6);

    event_del(&ev);
    global_base = NULL;
    event_base_free(base);
}

TEST(hv2ev_testcases, test_persistent_timeout_jump) {
    struct event_base *base = event_base_new();
    struct event ev;
    int count = 0;
    struct timeval msec100 = {0, 100 * 1000};
    struct timeval msec50 = {0, 50 * 1000};

    event_assign(&ev, base, -1, EV_PERSIST, periodic_timeout_cb, &count);
    event_add(&ev, &msec100);
    /* Wait for a bit */
    hv_msleep(300);
    event_base_loopexit(base, &msec50);
    event_base_dispatch(base);
    ASSERT_EQ(count, 1);

    event_del(&ev);
    event_base_free(base);
}

static unsigned char *EVBUFFER_DATA(struct evbuffer *buf)
{
    return evbuffer_pullup(buf, -1);
}

static void evbuffer_validate(struct evbuffer *buf)
{
    struct evbuffer_chain *chain;
    size_t sum = 0;

    if (buf->first == NULL) {
        ASSERT_TRUE(buf->last == NULL);
        ASSERT_TRUE(buf->data_total_len == 0);
    }

    chain = buf->first;

    while (chain != NULL) {
        sum += chain->off;
        if (chain->next == NULL) {
            ASSERT_TRUE(buf->last == chain);
        }
        ASSERT_TRUE(chain->buf.len >= chain->misalign + chain->off);
        chain = chain->next;
    }

    if (buf->first) {
        ASSERT_TRUE(buf->last_chain_with_data);
    }

    if (buf->last_chain_with_data) {
        chain = buf->last_chain_with_data;
        if (chain->off == 0) {
            ASSERT_TRUE(buf->data_total_len == 0);
            ASSERT_TRUE(chain == buf->first);
        }
        chain = chain->next;
        while (chain != NULL) {
            ASSERT_TRUE(chain->off == 0);
            chain = chain->next;
        }
    } else {
        ASSERT_TRUE(buf->first == NULL);
        ASSERT_TRUE(buf->last == NULL);
        ASSERT_TRUE(buf->last_chain_with_data == NULL);
        ASSERT_TRUE(buf->data_total_len == 0);
    }

    ASSERT_TRUE(sum == buf->data_total_len);
}

TEST(hv2ev_testcases, test_evbuffer) {
    static char buffer[512], *tmp;
    struct evbuffer *evb = evbuffer_new();
    struct evbuffer *evb_two = evbuffer_new();
    int i;

    evbuffer_validate(evb);
    evbuffer_add_printf(evb, "%s/%d", "hello", 1);
    evbuffer_validate(evb);

    ASSERT_TRUE(evbuffer_get_length(evb) == 7);
    ASSERT_TRUE(!memcmp(EVBUFFER_DATA(evb), "hello/1",
                                            strlen("hello/1")));

    evbuffer_add_buffer(evb, evb_two);
    evbuffer_validate(evb);

    evbuffer_drain(evb, strlen("hello/"));
    evbuffer_validate(evb);
    ASSERT_TRUE(evbuffer_get_length(evb) == 1);
    ASSERT_TRUE(!memcmp(EVBUFFER_DATA(evb), "1", 1));

    evbuffer_add_printf(evb_two, "%s", "/hello");
    ASSERT_TRUE(evbuffer_get_length(evb_two) == strlen("/hello"));
    evbuffer_validate(evb);
    evbuffer_add_buffer(evb, evb_two);
    evbuffer_validate(evb);

    ASSERT_TRUE(evbuffer_get_length(evb_two) == 0);
    ASSERT_TRUE(evbuffer_get_length(evb) == 7);
    evbuffer_pullup((evb), -1);
    ASSERT_TRUE(!memcmp(EVBUFFER_DATA(evb), "1/hello",
                                            strlen("1/hello")));

    memset(buffer, 0, sizeof(buffer));
    evbuffer_add(evb, buffer, sizeof(buffer));
    evbuffer_validate(evb);
    ASSERT_TRUE(evbuffer_get_length(evb) == 7 + 512);

    tmp = reinterpret_cast<char *>(evbuffer_pullup(evb, 7 + 512));
    ASSERT_TRUE(tmp);
    ASSERT_TRUE(!strncmp(tmp, "1/hello", 7));
    ASSERT_TRUE(!memcmp(tmp + 7, buffer, sizeof(buffer)));
    evbuffer_validate(evb);

    evbuffer_prepend(evb, "something", 9);
    evbuffer_validate(evb);
    evbuffer_prepend(evb, "else", 4);
    evbuffer_validate(evb);

    tmp = reinterpret_cast<char *>(evbuffer_pullup(evb, 4 + 9 + 7));
    ASSERT_TRUE(!strncmp(tmp, "elsesomething1/hello", 4 + 9 + 7));
    evbuffer_validate(evb);

    evbuffer_drain(evb, -1);
    evbuffer_validate(evb);
    evbuffer_drain(evb_two, -1);
    evbuffer_validate(evb);

    for (i = 0; i < 3; ++i) {
        evbuffer_add(evb_two, buffer, sizeof(buffer));
        evbuffer_validate(evb_two);
        evbuffer_add_buffer(evb, evb_two);
        evbuffer_validate(evb);
        evbuffer_validate(evb_two);
    }

    ASSERT_TRUE(evbuffer_get_length(evb_two) == 0);
    ASSERT_TRUE(evbuffer_get_length(evb) == i * sizeof(buffer));

    evbuffer_free(evb);
    evbuffer_free(evb_two);
}

static void evbuffer_get_waste(struct evbuffer *buf, size_t *allocatedp,
                               size_t *wastedp, size_t *usedp)
{
    struct evbuffer_chain *chain;
    size_t a;
    size_t w;
    size_t u;
    int n = 0;
    u = a = w = 0;

    chain = buf->first;
    /* skip empty at start */
    while (chain && chain->off == 0) {
        ++n;
        a += chain->buf.len;
        chain = chain->next;
    }
    /* first nonempty chain: stuff at the end only is wasted. */
    if (chain) {
        ++n;
        a += chain->buf.len;
        u += chain->off;
        if (chain->next && chain->next->off)
            w += (size_t)(chain->buf.len - (chain->misalign + chain->off));
        chain = chain->next;
    }
    /* subsequent nonempty chains */
    while (chain && chain->off) {
        ++n;
        a += chain->buf.len;
        w += (size_t)chain->misalign;
        u += chain->off;
        if (chain->next && chain->next->off)
            w += (size_t)(chain->buf.len - (chain->misalign + chain->off));
        chain = chain->next;
    }
    /* subsequent empty chains */
    while (chain) {
        ++n;
        a += chain->buf.len;
    }
    *allocatedp = a;
    *wastedp = w;
    *usedp = u;
}

TEST(hv2ev_testcases, test_evbuffer_expand) {
    char data[4096];
    struct evbuffer *buf;
    size_t a;
    size_t w;
    size_t u;
    void *buffer;

    memset(data, 'X', sizeof(data));

    /* Make sure that expand() works on an empty buffer */
    buf = evbuffer_new();
    ASSERT_EQ(evbuffer_expand(buf, 20000), 0);
    evbuffer_validate(buf);
    a = w = u = 0;
    evbuffer_get_waste(buf, &a, &w, &u);
    ASSERT_TRUE(w == 0);
    ASSERT_TRUE(u == 0);
    ASSERT_TRUE(a >= 20000);
    ASSERT_TRUE(buf->first);
    ASSERT_TRUE(buf->first == buf->last);
    ASSERT_TRUE(buf->first->off == 0);
    ASSERT_TRUE(buf->first->buf.len >= 20000);

    /* Make sure that expand() works as a no-op when there's enough
     * contiguous space already. */
    buffer = buf->first->buf.base;
    evbuffer_add(buf, data, 1024);
    ASSERT_EQ(evbuffer_expand(buf, 1024), 0);
    ASSERT_TRUE(buf->first->buf.base == buffer);
    evbuffer_validate(buf);
    evbuffer_free(buf);

    /* Make sure that expand() can work by moving misaligned data
     * when it makes sense to do so. */
    buf = evbuffer_new();
    evbuffer_add(buf, data, 400);
    {
        int n = static_cast<int>((buf->first->buf.len - buf->first->off - 1));
        ASSERT_TRUE(n < static_cast<int>(sizeof(data)));
        evbuffer_add(buf, data, n);
    }
    ASSERT_TRUE(buf->first == buf->last);
    ASSERT_TRUE(buf->first->off == buf->first->buf.len - 1);
    evbuffer_drain(buf, buf->first->off - 1);
    ASSERT_TRUE(1 == evbuffer_get_length(buf));
    ASSERT_TRUE(buf->first->misalign > 0);
    ASSERT_TRUE(buf->first->off == 1);
    buffer = buf->first->buf.base;
    ASSERT_TRUE(evbuffer_expand(buf, 40) == 0);
    ASSERT_TRUE(buf->first == buf->last);
    ASSERT_TRUE(buf->first->off == 1);
    ASSERT_TRUE(buf->first->buf.base == buffer);
    ASSERT_TRUE(buf->first->misalign == 0);
    evbuffer_validate(buf);
    evbuffer_free(buf);

    /* add, expand, pull-up: This used to crash libevent. */
    buf = evbuffer_new();

    evbuffer_add(buf, data, sizeof(data));
    evbuffer_add(buf, data, sizeof(data));
    evbuffer_add(buf, data, sizeof(data));

    evbuffer_validate(buf);
    evbuffer_expand(buf, 1024);
    evbuffer_validate(buf);
    evbuffer_pullup(buf, -1);
    evbuffer_validate(buf);

    evbuffer_free(buf);
}

static void no_cleanup(const void *data, size_t datalen, void *extra) {}

TEST(hv2ev_testcases, test_evbuffer_remove_buffer_with_empty) {
    struct evbuffer *src = evbuffer_new();
    struct evbuffer *dst = evbuffer_new();
    char buf[2] = {'A', 'A'};

    evbuffer_validate(src);
    evbuffer_validate(dst);

    /* setup the buffers */
    /* we need more data in src than we will move later */
    evbuffer_add_reference(src, buf, sizeof(buf), no_cleanup, NULL);
    evbuffer_add_reference(src, buf, sizeof(buf), no_cleanup, NULL);
    /* we need one buffer in dst and one empty buffer at the end */
    evbuffer_add(dst, buf, sizeof(buf));
    evbuffer_add_reference(dst, buf, 0, no_cleanup, NULL);

    evbuffer_validate(src);
    evbuffer_validate(dst);
    ASSERT_EQ(memcmp(evbuffer_pullup(src, -1), "AAAA", 4), 0);
    ASSERT_EQ(memcmp(evbuffer_pullup(dst, -1), "AA", 2), 0);

    evbuffer_free(src);
    evbuffer_free(dst);
}

TEST(hv2ev_testcases, test_evbuffer_remove_buffer_with_empty2) {
    struct evbuffer *src = evbuffer_new();
    struct evbuffer *dst = evbuffer_new();
    struct evbuffer *buf = evbuffer_new();

    evbuffer_add(buf, "foo", 3);
    evbuffer_add_reference(buf, "foo", 3, NULL, NULL);

    evbuffer_add_reference(src, "foo", 3, NULL, NULL);
    evbuffer_add_reference(src, NULL, 0, NULL, NULL);
    evbuffer_add_buffer(src, buf);

    evbuffer_add(buf, "foo", 3);
    evbuffer_add_reference(buf, "foo", 3, NULL, NULL);

    evbuffer_add_reference(dst, "foo", 3, NULL, NULL);
    evbuffer_add_reference(dst, NULL, 0, NULL, NULL);
    evbuffer_add_buffer(dst, buf);

    ASSERT_TRUE(evbuffer_get_length(src) == 9);
    ASSERT_TRUE(evbuffer_get_length(dst) == 9);

    evbuffer_validate(src);
    evbuffer_validate(dst);

    ASSERT_EQ(memcmp(evbuffer_pullup(src, -1), "foofoofoo", 9), 0);
    ASSERT_EQ(memcmp(evbuffer_pullup(dst, -1), "foofoofoo", 9), 0);

    evbuffer_free(src);
    evbuffer_free(dst);
    evbuffer_free(buf);
}

static int g_nStringsRead = 0;
static int g_nReadsInvoked = 0;
static int g_buffereventConnectTestFlags = 0;
static int g_buffereventTriggerTestFlags = 0;

static void sender_writecb(struct bufferevent *bev, void *ctx)
{
    if (evbuffer_get_length(bufferevent_get_output(bev)) == 0) {
        bufferevent_disable(bev, EV_READ | EV_WRITE);
        bufferevent_free(bev);
    }
}

static void sender_errorcb(struct bufferevent *bev, short what, void *ctx)
{
    FAIL() << "Got sender error " << what;
}

static void listen_cb(struct evconnlistener *listener, evutil_socket_t fd,
                      struct sockaddr *sa, int socklen, void *arg)
{
    struct event_base *base = (struct event_base *)arg;
    struct bufferevent *bev;
    const char s[] = "Now is the time for all good events to signal for the good "
                                     "of their protocol";
    bev = bufferevent_socket_new(base, fd, g_buffereventConnectTestFlags);
    ASSERT_TRUE(bev);
    bufferevent_setcb(bev, NULL, sender_writecb, sender_errorcb, NULL);
    bufferevent_write(bev, s, sizeof(s));
}

static void reader_readcb(struct bufferevent *bev, void *ctx)
{
    g_nReadsInvoked++;
}

static void reader_eventcb(struct bufferevent *bev, short what, void *ctx)
{
    struct event_base *base = (struct event_base *)ctx;
    if (what & BEV_EVENT_ERROR) {
        perror("foobar");
        FAIL() << "got connector error " << what;
        return;
    }
    if (what & BEV_EVENT_CONNECTED) {
        bufferevent_enable(bev, EV_READ);
    }
    if (what & BEV_EVENT_EOF) {
        char buf[512];
        size_t n;
        n = bufferevent_read(bev, buf, sizeof(buf) - 1);
        ASSERT_TRUE(n >= 0);
        buf[n] = '\0';
        ASSERT_TRUE(strcmp(buf, "Now is the time for all good events to signal for "
                                                        "the good of their protocol") == 0);
        int most_read_times = 2;
        if (++g_nStringsRead == most_read_times)
            event_base_loopexit(base, NULL);
    }
}

TEST(hv2ev_testcases, test_bufferevent_connect) {
    g_nStringsRead = 0;
    g_nReadsInvoked = 0;
    g_buffereventConnectTestFlags = 0;

    struct event_base *base = event_base_new();
    struct evconnlistener *lev = NULL;
    struct bufferevent *bev1 = NULL, *bev2 = NULL;
    struct sockaddr_in localhost;
    struct sockaddr_storage ss;
    struct sockaddr *sa;
    ev_socklen_t slen;

    int be_flags = BEV_OPT_CLOSE_ON_FREE;
    g_buffereventConnectTestFlags = be_flags;

    memset(&localhost, 0, sizeof(localhost));

    localhost.sin_port = 0; /* pick-a-port */
    localhost.sin_addr.s_addr = htonl(0x7f000001L);
    localhost.sin_family = AF_INET;
    sa = reinterpret_cast<sockaddr *>(&localhost);
    lev = evconnlistener_new_bind(base, listen_cb, base,
                                  LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 16,
                                  sa, sizeof(localhost));
    ASSERT_TRUE(lev);

    sa = reinterpret_cast<sockaddr *>(&ss);
    slen = sizeof(ss);
    if (getsockname(lev->lev_e->listener.fd, sa, &slen) < 0) {
        FAIL() << "getsockname";
    }

    ASSERT_TRUE(!evconnlistener_enable(lev));
    bev1 = bufferevent_socket_new(base, -1, be_flags);
    bev2 = bufferevent_socket_new(base, -1, be_flags);
    ASSERT_TRUE(bev1);
    ASSERT_TRUE(bev2);
    bufferevent_setcb(bev1, reader_readcb, NULL, reader_eventcb, base);
    bufferevent_setcb(bev2, reader_readcb, NULL, reader_eventcb, base);

    bufferevent_enable(bev1, EV_READ);
    bufferevent_enable(bev2, EV_READ);

    ASSERT_TRUE(!bufferevent_socket_connect(bev1, sa, sizeof(localhost)));
    ASSERT_TRUE(!bufferevent_socket_connect(bev2, sa, sizeof(localhost)));

    event_base_dispatch(base);

    ASSERT_TRUE(g_nStringsRead == 2);
    ASSERT_TRUE(g_nReadsInvoked >= 2);

    if (lev) {
        evconnlistener_free(lev);
    }

    if (bev1) {
        bufferevent_free(bev1);
    }

    if (bev2) {
        bufferevent_free(bev2);
    }
    event_base_free(base);
}

static int g_nEventsInvoked = 0;

static void fake_listener_create(struct sockaddr_in *localhost, int &fd)
{
    struct sockaddr *sa = reinterpret_cast<sockaddr *>(localhost);
    fd = -1;
    ev_socklen_t slen = sizeof(*localhost);

    memset(localhost, 0, sizeof(*localhost));
    localhost->sin_port = 0; /* have the kernel pick a port */
    localhost->sin_addr.s_addr = htonl(0x7f000001L);
    localhost->sin_family = AF_INET;

    /* bind, but don't listen or accept. should trigger
                     "Connection refused" reliably on most platforms. */
    fd = socket(localhost->sin_family, SOCK_STREAM, 0);
    ASSERT_TRUE(fd >= 0);
    ASSERT_TRUE(bind(fd, sa, slen) == 0);
    ASSERT_TRUE(getsockname(fd, sa, &slen) == 0);
}

static void reader_eventcb_simple(struct bufferevent *bev, short what,
                                  void *ctx)
{
    g_nEventsInvoked++;
}

static void close_socket_cb(evutil_socket_t fd, short what, void *arg)
{
    evutil_socket_t *fdp = (evutil_socket_t *)arg;
    if (*fdp >= 0) {
        evutil_closesocket(*fdp);
        *fdp = -1;
    }
}

TEST(hv2ev_testcases, test_bufferevent_connect_fail_eventcb) {
    g_nStringsRead = 0;
    g_nReadsInvoked = 0;
    g_buffereventConnectTestFlags = 0;
    g_nEventsInvoked = 0;

    struct event_base *base = event_base_new();
    int flags = BEV_OPT_CLOSE_ON_FREE;
    struct event close_listener_event;
    struct bufferevent *bev = NULL;
    struct evconnlistener *lev = NULL;
    struct sockaddr_in localhost;
    struct timeval close_timeout = {0, 300000};
    ev_socklen_t slen = sizeof(localhost);
    evutil_socket_t fake_listener = -1;
    int r;

    fake_listener_create(&localhost, fake_listener);

    ASSERT_TRUE(g_nEventsInvoked == 0);

    bev = bufferevent_socket_new(base, -1, flags);
    ASSERT_TRUE(bev);
    bufferevent_setcb(bev, reader_readcb, reader_readcb, reader_eventcb_simple,
                                        base);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
    ASSERT_TRUE(g_nEventsInvoked == 0);
    ASSERT_TRUE(g_nReadsInvoked == 0);

    /** @see also test_bufferevent_connect_fail() */
    r = bufferevent_socket_connect(bev, reinterpret_cast<sockaddr *>(&localhost),
                                                                 slen);
    /* XXXX we'd like to test the '0' case everywhere, but FreeBSD tells
     * detects the error immediately, which is not really wrong of it. */
    short temp = (r == 0 /*|| r == -1*/);
    ASSERT_TRUE(temp);

    ASSERT_TRUE(g_nEventsInvoked == 0);
    ASSERT_TRUE(g_nReadsInvoked == 0);

    /* Close the listener socket after a delay. This should trigger
                     "connection refused" on some other platforms, including OSX. */
    evtimer_assign(&close_listener_event, base, close_socket_cb, &fake_listener);
    event_add(&close_listener_event, &close_timeout);

    event_base_dispatch(base);
    ASSERT_TRUE(g_nEventsInvoked == 1);
    ASSERT_TRUE(g_nReadsInvoked == 0);

    if (lev) {
        evconnlistener_free(lev);
    }
    if (bev) {
        bufferevent_free(bev);
    }
    if (fake_listener >= 0) {
        evutil_closesocket(fake_listener);
    }
    event_base_free(base);
}

static int g_testOk = 0;

static void want_fail_eventcb(struct bufferevent *bev, short what, void *ctx)
{
    struct event_base *base = (struct event_base *)ctx;

    if (what & BEV_EVENT_ERROR) {
        evutil_socket_error_to_string(evutil_socket_geterror(bev->ev_read.fd));
        g_testOk = 1;
    } else {
        FAIL() << "didn't fail? what " << what;
    }

    event_base_loopexit(base, NULL);
}

TEST(hv2ev_testcases, test_bufferevent_connect_fail) {
    struct event_base *base = event_base_new();
    struct bufferevent *bev = NULL;
    struct event close_listener_event;
    int close_listener_event_added = 0;
    struct timeval close_timeout = {0, 300000};
    struct sockaddr_in localhost;
    ev_socklen_t slen = sizeof(localhost);
    evutil_socket_t fake_listener = -1;
    int r;

    g_testOk = 0;

    fake_listener_create(&localhost, fake_listener);
    bev = bufferevent_socket_new(base, -1,
                                 BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    ASSERT_TRUE(bev);
    bufferevent_setcb(bev, NULL, NULL, want_fail_eventcb, base);

    r = bufferevent_socket_connect(bev, reinterpret_cast<sockaddr *>(&localhost),
                                   slen);
    /* XXXX we'd like to test the '0' case everywhere, but FreeBSD tells
     * detects the error immediately, which is not really wrong of it. */
    short temp = (r == 0 /*|| r == -1*/);
    ASSERT_TRUE(temp);

    /* Close the listener socket after a delay. This should trigger
                     "connection refused" on some other platforms, including OSX. */
    evtimer_assign(&close_listener_event, base, close_socket_cb, &fake_listener);
    event_add(&close_listener_event, &close_timeout);
    close_listener_event_added = 1;

    event_base_dispatch(base);

    ASSERT_TRUE(g_testOk == 1);

    if (fake_listener >= 0) {
        evutil_closesocket(fake_listener);
    }

    if (bev) {
        bufferevent_free(bev);
    }

    if (close_listener_event_added)
        event_del(&close_listener_event);
    event_base_free(base);
}

static int regress_get_listener_addr(struct evconnlistener *lev,
                                     struct sockaddr *sa,
                                     ev_socklen_t *socklen)
{
    evutil_socket_t s = lev->lev_e->listener.fd;
    if (s <= 0) {
        return -1;
    }
    return getsockname(s, sa, socklen);
}

static void trigger_eventcb(struct bufferevent *bev, short what, void *ctx)
{
    struct event_base *base = (struct event_base *)ctx;
    if (what == ~0) {
        event_base_loopexit(base, NULL);
        return;
    }
    reader_eventcb(bev, what, ctx);
}

static void trigger_readcb_triggered(struct bufferevent *bev, void *ctx)
{
    g_nReadsInvoked++;
    bev->errorcb(bev, ~0, bev->cbarg);
}

static void trigger_readcb(struct bufferevent *bev, void *ctx)
{
    int expected_reads;

    expected_reads = ++g_nReadsInvoked;
    bufferevent_setcb(bev, trigger_readcb_triggered, NULL, trigger_eventcb, ctx);
    size_t len = evbuffer_get_length(bufferevent_get_input(bev));
    (void)len;
    /* no callback expected */
    ASSERT_TRUE(g_nReadsInvoked == expected_reads);
    expected_reads++;

    bev->readcb(bev, bev->cbarg);
    ASSERT_TRUE(g_nReadsInvoked == expected_reads);
}

TEST(hv2ev_testcases, test_bufferevent_trigger) {
    struct event_base *base = event_base_new();
    struct evconnlistener *lev = NULL;
    struct bufferevent *bev = NULL;
    struct sockaddr_in localhost;
    struct sockaddr_storage ss;
    struct sockaddr *sa;
    ev_socklen_t slen;

    int be_flags = BEV_OPT_CLOSE_ON_FREE;
    int trig_flags = 0;

    g_buffereventConnectTestFlags = be_flags;
    g_buffereventTriggerTestFlags = trig_flags;

    memset(&localhost, 0, sizeof(localhost));

    localhost.sin_port = 0; /* pick-a-port */
    localhost.sin_addr.s_addr = htonl(0x7f000001L);
    localhost.sin_family = AF_INET;
    sa = reinterpret_cast<sockaddr *>(&localhost);
    lev = evconnlistener_new_bind(base, listen_cb, base,
                                  LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 16,
                                  sa, sizeof(localhost));
    ASSERT_TRUE(lev);

    sa = reinterpret_cast<sockaddr *>(&ss);
    slen = sizeof(ss);
    if (regress_get_listener_addr(lev, sa, &slen) < 0) {
        FAIL() << "getsockname";
    }

    ASSERT_TRUE(!evconnlistener_enable(lev));
    bev = bufferevent_socket_new(base, -1, be_flags);
    ASSERT_TRUE(bev);
    bufferevent_setcb(bev, trigger_readcb, NULL, trigger_eventcb, base);

    bufferevent_enable(bev, EV_READ);

    ASSERT_TRUE(!bufferevent_socket_connect(bev, sa, sizeof(localhost)));

    event_base_dispatch(base);

    ASSERT_TRUE(g_nReadsInvoked == 2);

    if (lev) {
        evconnlistener_free(lev);
    }

    if (bev) {
        bufferevent_free(bev);
    }
    event_base_free(base);
}

static int g_numSigCalled = 0;
static int g_numSigRaised = 10;

static void sig_cb(int sig, short events, void *arg)
{
    g_numSigCalled++;
    if (g_numSigCalled == g_numSigRaised) {
        event_base_loopbreak((struct event_base *)arg);
    }
}

TEST(hv2ev_testcases, test_signal) {
    pid_t pid{fork()};

    ASSERT_TRUE(pid >= 0);

    if (pid > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        for (int i = 0; i < g_numSigRaised; i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            kill(pid, SIGINT);
        }
        waitpid(pid, nullptr, 0);
    } else {
        struct event_base *base = event_base_new();
        struct event *event_sig = evsignal_new(base, SIGINT, sig_cb, base);
        evsignal_add(event_sig, NULL);

        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
        event_base_dispatch(base);

        event_free(event_sig);
        event_base_free(base);

        std::cout << "g_numSigCalled: " << g_numSigCalled << std::endl;
        ASSERT_TRUE(g_numSigCalled == g_numSigRaised);
    }
}