/*
 * Copyright 2011 Red Hat, Inc.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
/*
关键数据结构说明：
1、verto_ctx中的ctx存储的是hloop
2、verto_ev中的ctx存储的是verto_ctx
3、verto_ev中的ev存储的是hevent2verto_t(hio_t/htimer_t)
*/

#include <stdbool.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <verto.h>
#include <hv/hloop.h>
#include <hv/hmain.h>
#include "../ifm_utils.h"
#include "libhv_meta.h"

typedef hloop_t verto_mod_ctx;
typedef void verto_mod_ev;
typedef struct verto_ctx verto_ctx;
typedef struct verto_ev verto_ev;

struct verto_ctx {
    size_t ref;
    verto_mod_ctx *ctx;
    verto_ev *events;
    int deflt;
    int exit;
};

typedef struct {
    verto_proc proc;
    verto_proc_status status;
} verto_child;

typedef struct {
    int fd;
    verto_ev_flag state;
} verto_io;

struct verto_ev {
    verto_ev *next;
    verto_ctx *ctx;
    verto_ev_type type;
    verto_callback *callback;
    verto_callback *onfree;
    void *priv;
    verto_mod_ev *ev;
    verto_ev_flag flags;
    verto_ev_flag actual;
    size_t depth;
    int deleted;
    union {
        verto_io io;
        int signal;
        time_t interval;
        verto_child child;
    } option;
};

bool LibhvEnabled(void)
{
    static bool inited = false;
    static bool enabled = false;

    if (inited) {
        return enabled;
    }

    char *env_ifm_libhv_enable = getenv("IFM_LIBHV_ENABLE");
    if (env_ifm_libhv_enable != NULL && strcmp(env_ifm_libhv_enable, "NO") == 0) {
        inited = true;
        enabled = false;
    } else {
        inited = true;
        enabled = true;
    }
    IFM_ERR("LIBHV enbaled is %d\n", enabled);

    return enabled;
}

static void append_ev(verto_ctx *ctx, verto_ev *ev)
{
    verto_ev *tmp;

    if (!ctx || !ev)
        return;

    tmp = ctx->events;
    ctx->events = ev;
    ctx->events->next = tmp;
}

static void remove_ev(verto_ev **origin, verto_ev *item)
{
    if (!origin || !*origin || !item)
        return;

    if (*origin == item)
        *origin = (*origin)->next;
    else
        remove_ev(&((*origin)->next), item);
}

void free_ev(verto_ev *ev)
{
    if (ev && ev->priv) {
        free(ev->priv);
        ev->priv = NULL;
    }

    if (ev) {
        free(ev);
        ev = NULL;
    }
}

verto_ctx *libhv_verto_default(const char *impl, verto_ev_type reqtypes)
{
    verto_ctx *ctx = NULL;
    hloop_t* hv_loop = NULL;

    ctx = malloc(sizeof(verto_ctx));
    if (NULL == ctx) {
        IFM_ERR("libhv_verto_default malloc failed!");
        return NULL;
    }
    memset(ctx, 0, sizeof(verto_ctx));

    // Init the libhv loop
    hv_loop = hloop_new(0);
    hevent_set_priority(hv_loop, 0);
    ctx->ctx = (verto_mod_ctx*)hv_loop;
    ctx->ref = 1;

    return ctx;
}

verto_ctx *ifm_verto_default(const char *impl, verto_ev_type reqtypes)
{
    if (!LibhvEnabled()) {
        return libhv_verto_default(impl, reqtypes);
    } else {
        return verto_default(impl, reqtypes);
    }
}

verto_ctx *ifm_verto_new(const char *impl, verto_ev_type reqtypes)
{
    if (LibhvEnabled()) {
        return libhv_verto_default(impl, reqtypes);
    } else {
        return verto_new(impl, reqtypes);
    }
}

void libhv_verto_run(verto_ctx *ctx)
{
    if (NULL == ctx || NULL == ctx->ctx) {
        return;
    }

    hloop_run((hloop_t *)ctx->ctx);
}

void ifm_verto_run(verto_ctx *ctx)
{
    if (LibhvEnabled()) {
        libhv_verto_run(ctx);
    } else {
        verto_run(ctx);
    }
}

void libhv_verto_break(verto_ctx *ctx)
{
    if (NULL == ctx || NULL == ctx->ctx) {
        return;
    }

    hloop_stop((hloop_t *)ctx->ctx);
}

void ifm_verto_break(verto_ctx *ctx)
{
    if (LibhvEnabled()) {
        libhv_verto_break(ctx);
    } else {
        verto_break(ctx);
    }
}

void ifm_verto_del(verto_ev *ev)
{
    int event = 0;

    if (!LibhvEnabled()) {
        verto_del(ev);
        return;
    }

    if (!ev) {
        IFM_ERR("ifm_verto_del ev is null.");
        return;
    }

    /* depth is only used in verto_fire, this function is no used in gssproxy. */

    if (ev->onfree)
        ev->onfree(ev->ctx, ev);

    // delete the hv object.
    if (verto_get_flags(ev) & VERTO_EV_FLAG_IO_READ) {
        event = HV_READ;
    } else if (verto_get_flags(ev) & VERTO_EV_FLAG_IO_WRITE) {
        event = HV_WRITE;
    }
    hio_del((hio_t *)ev->ev, event);

    remove_ev(&(ev->ctx->events), ev);
    if ((ev->type == VERTO_EV_TYPE_IO) &&
        (ev->flags & VERTO_EV_FLAG_IO_CLOSE_FD) &&
        !(ev->actual & VERTO_EV_FLAG_IO_CLOSE_FD))
        close(ev->option.io.fd);

    free_ev(ev);
}

void ifm_verto_free(verto_ctx *ctx)
{
    if (!LibhvEnabled()) {
        verto_free(ctx);
        return;
    }

    if (!ctx) {
        IFM_ERR("ifm_verto_free ctx is null.");
        return;
    }

    ctx->ref = ctx->ref > 0 ? ctx->ref - 1 : 0;
    if (ctx->ref > 0)
        return;

    /* Cancel all pending events */
    while (ctx->events) {
        ifm_verto_del(ctx->events);
    }

    /* Free the hio */
    hloop_free((hloop_t **)(&(ctx->ctx)));

    free(ctx);
}

// 当前实现没有需要loadmodule的操作，因此cleanup无需做任何释放操作。
void ifm_verto_cleanup(void)
{
    if (!LibhvEnabled()) {
        verto_cleanup();
        return;
    }
}

verto_ev *libhv_make_ev(verto_ctx *ctx, verto_ev_flag flags,
             verto_callback *callback, verto_ev_type type)
{
    verto_ev *ev;

    if (!ctx || !callback) {
        IFM_ERR("ctx or callback is NULL.");
        return NULL;
    }

    ev = malloc(sizeof(verto_ev));
    if (NULL == ev) {
        IFM_ERR("ev malloc failed.");
        return NULL;
    }
    memset(ev, 0, sizeof(verto_ev));
    ev->ctx = ctx;
    ev->callback = callback;
    ev->flags = flags;
    ev->type = type;
    ev->actual = ((flags) & ~(VERTO_EV_FLAG_PERSIST|VERTO_EV_FLAG_IO_CLOSE_FD));

    return ev;
}

void libhv_callback_io(hio_t* io)
{
    verto_ev *ev = NULL;

    if (NULL == io) {
        IFM_ERR("io invalid.");
        return;
    }
    ev = (verto_ev*)hevent_userdata(io);
    if (NULL == ev || NULL == ev->callback) {
        IFM_ERR("ev or callback invalid.");
        return;
    }
    ev->callback(ev->ctx, ev);
}

verto_ev *ifm_verto_add_io(verto_ctx *ctx, verto_ev_flag flags,
             verto_callback *callback, int fd)
{
    verto_ev *ev = NULL;
    hevent2verto_t *hvEvent = NULL;
    int event = 0;
    if (!LibhvEnabled()) {
        return verto_add_io(ctx, flags, callback, fd);
    }

    if (fd < 0 || !(flags & (VERTO_EV_FLAG_IO_READ | VERTO_EV_FLAG_IO_WRITE))) {
        IFM_ERR("fd is invalid. must be read or write.");
        return NULL;
    }

    ev = libhv_make_ev(ctx, flags, callback, VERTO_EV_TYPE_IO);
    if (!ev) {
        IFM_ERR("libhv_make_ev failed.!");
        return NULL;
    }

    ev->option.io.fd = fd;
    // add hio
    hvEvent = malloc(sizeof(hevent2verto_t));
    if (!hvEvent) {
        IFM_ERR("malloc hvEvent failed.!");
        free_ev(ev);
        return NULL;
    }
    memset(hvEvent, 0, sizeof(hevent2verto_t));
    hvEvent->io = hio_get((hloop_t *)ctx->ctx, ev->option.io.fd);
    if(NULL == hvEvent->io){
        IFM_ERR("hio_get failed.!");
        free_ev(ev);
        return NULL;
    }
    if (verto_get_flags(ev) & VERTO_EV_FLAG_IO_READ) {
        event = HV_READ;
    } else if (verto_get_flags(ev) & VERTO_EV_FLAG_IO_WRITE) {
        event = HV_WRITE;
    }
    if (0 != hio_add(hvEvent->io, (hio_cb)libhv_callback_io, event)) {
        IFM_ERR("hio_add failed.!");
        free_ev(ev);
        return NULL;
    }
    ev->ev = hvEvent;
    hevent_set_userdata(hvEvent->io, ev);
    
    append_ev(ctx, ev);

    return ev;
}

// TODO(hdr): This function is same as hio_cb.
void libhv_callback_timer(htimer_t* timer)
{
    verto_ev *ev = NULL;

    if (NULL == timer) {
        IFM_ERR("timer invalid.");
        return;
    }
    ev = (verto_ev*)hevent_userdata(timer);
    if (NULL == ev || NULL == ev->callback) {
        IFM_ERR("ev or callback invalid.");
        return;
    }
    ev->callback(ev->ctx, ev);
}

verto_ev *ifm_verto_add_timeout(verto_ctx *ctx, verto_ev_flag flags,
                  verto_callback *callback, time_t interval)
{
    hevent2verto_t *hvEvent;
    verto_ev *ev = NULL;
    if (!LibhvEnabled()) {
        return verto_add_timeout(ctx, flags, callback, interval);
    }

    ev = libhv_make_ev(ctx, flags, callback, VERTO_EV_TYPE_TIMEOUT);
    if (!ev) {
        IFM_ERR("ifm_verto_add_timeout libhv_make_ev failed.!");
        return NULL;
    }

    ev->option.interval = interval;
    // add htimer
    hvEvent = malloc(sizeof(hevent2verto_t));
    if (!hvEvent) {
        IFM_ERR("ifm_verto_add_timeout malloc hvEvent failed.!");
        free_ev(ev);
        return NULL;
    }
    memset(hvEvent, 0, sizeof(hevent2verto_t));
    hvEvent->timer = htimer_add((hloop_t *)ctx->ctx, (htimer_cb)libhv_callback_timer, interval, INFINITE);
    if (NULL != hvEvent->timer) {
        IFM_ERR("htimer_add failed.!");
        free_ev(ev);
        return NULL;
    }
    ev->ev = hvEvent;
    hevent_set_userdata(hvEvent->timer, ev);
    append_ev(ctx, ev);

    return ev;
}

void ifm_verto_set_private(verto_ev *ev, void *priv, verto_callback *free)
{
    if (!ev)
        return;
    if (ev->onfree && free)
        ev->onfree(ev->ctx, ev);
    ev->priv = priv;
    ev->onfree = free;
}

void *ifm_verto_get_private(const verto_ev *ev)
{
    return ev->priv;
}
