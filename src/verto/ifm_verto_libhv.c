/******************************************************************************
 * ifm_verto_libhv.c: adaptation layer of libhv based on libverto
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 *
 * Authors:
 * Zixiang Yan <ujm456@126.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 ********************************************************************************/

#include "ifm_verto_libhv.h"
#include <hv/hloop.h>
#include <hv/hmain.h>

#define VERTO_MODULE_TYPES
struct hevent2verto {
    verto_ev* ev;
    hio_t* io;
    htimer_t* timer;
};
typedef struct hloop_t verto_mod_ctx;
typedef struct hevent2verto verto_mod_ev;
#include "ifm_verto_module.h"

static verto_mod_ctx* libhv_ctx_default(void)
{
    hloop_t* loop;
    
    loop = hloop_new(0);
    hevent_set_priority(loop, 0);
    return (verto_mod_ctx*)loop;
}


static void libhv_ctx_free(verto_mod_ctx *ctx)
{
    hloop_free((hloop_t**)&ctx);
}


static void libhv_ctx_run(verto_mod_ctx *ctx)
{
    hloop_run((hloop_t*)ctx);
}


static void libhv_ctx_break(verto_mod_ctx *ctx)
{
    hloop_stop((hloop_t*)ctx);
}


static void libhv_ctx_del(verto_mod_ctx *ctx, const verto_ev *ev, verto_mod_ev *evpriv)
{
    bool is_io_read = ifm_verto_get_flags(ev) & VERTO_EV_FLAG_IO_READ;
    bool is_io_write = ifm_verto_get_flags(ev) & VERTO_EV_FLAG_IO_WRITE;
    switch (ifm_verto_get_type(ev)) {
        case VERTO_EV_TYPE_IO:
            if (is_io_read) {
                hio_del(evpriv->io, HV_READ);
            }
            if (is_io_write) {
                hio_del(evpriv->io, HV_WRITE);
            }
            break;
        case VERTO_EV_TYPE_TIMEOUT:
            if (evpriv->timer != NULL) {
                htimer_del(evpriv->timer);
                evpriv->timer = NULL;
            }
            break;
        case VERTO_EV_TYPE_SIGNAL:
            break;
        default:
            break;
    }
}


static void libhv_callback_io(hio_t* io)
{
    struct hevent2verto *h2ve = (struct hevent2verto *)hevent_userdata(io);
    verto_ev_flag state = VERTO_EV_FLAG_NONE;

    bool is_io_read = ifm_verto_get_flags(h2ve->ev) & VERTO_EV_FLAG_IO_READ;
    bool is_io_write = ifm_verto_get_flags(h2ve->ev) & VERTO_EV_FLAG_IO_WRITE;
    if (is_io_read) {
        state = state | VERTO_EV_FLAG_IO_READ;
    }
    if (is_io_write) {
        state = state | VERTO_EV_FLAG_IO_WRITE;
    }

#ifdef EV_ERROR

#endif
    ifm_verto_set_fd_state(h2ve->ev, state);
    ifm_verto_fire(h2ve->ev);
}


static void libhv_callback_timer(htimer_t* timer)
{
    struct hevent2verto *h2ve = (struct hevent2verto *)hevent_userdata(timer);
    verto_ev_flag state = VERTO_EV_FLAG_NONE;

    ifm_verto_set_fd_state(h2ve->ev, state);
    ifm_verto_fire(h2ve->ev);
}


static verto_mod_ev* libhv_ctx_add(verto_mod_ctx *ctx, const verto_ev *ev, verto_ev_flag *flags)
{
    struct hevent2verto *priv = NULL;
    priv = malloc(sizeof(struct hevent2verto*));
    priv->ev = (verto_ev*)ev;
    time_t time_interval;
    bool is_io_read = ifm_verto_get_flags(ev) & VERTO_EV_FLAG_IO_READ;
    bool is_io_write = ifm_verto_get_flags(ev) & VERTO_EV_FLAG_IO_WRITE;

    // control actual to ensure no repeated calls
    *flags = *flags | (ifm_verto_get_flags(ev) & VERTO_EV_FLAG_PERSIST);

    switch (ifm_verto_get_type(ev)) {
        case VERTO_EV_TYPE_IO:
            priv->io = hio_get((hloop_t*)ctx, ifm_verto_get_fd(ev));
            if (is_io_read) {
                hio_add(priv->io, (hio_cb)libhv_callback_io, HV_READ);
            }
            if (is_io_write) {
                hio_add(priv->io, (hio_cb)libhv_callback_io, HV_WRITE);
            }
            if (priv->io != NULL) {
                hevent_set_userdata(priv->io, priv);
            }
            break;
        case VERTO_EV_TYPE_TIMEOUT:
            time_interval = ifm_verto_get_interval(ev);
            priv->timer = (htimer_t*)htimer_add((hloop_t*)ctx, (htimer_cb)libhv_callback_timer, 
                                                time_interval, INFINITE);
            if (priv->timer != NULL) {
                hevent_set_userdata(priv->timer, priv);
            }
            break;
        case VERTO_EV_TYPE_SIGNAL:
            /* libhv not supported */
            break;
        case VERTO_EV_TYPE_IDLE:
        case VERTO_EV_TYPE_CHILD:
        default:
            return NULL; /* Not supported */
    }

    if (ifm_verto_get_flags(ev) & VERTO_EV_FLAG_PRIORITY_HIGH)
        hevent_set_priority(ctx, HEVENT_HIGHEST_PRIORITY);
    else if (ifm_verto_get_flags(ev) & VERTO_EV_FLAG_PRIORITY_MEDIUM)
        hevent_set_priority(ctx, HEVENT_HIGH_PRIORITY);
    else if (ifm_verto_get_flags(ev) & VERTO_EV_FLAG_PRIORITY_LOW)
        hevent_set_priority(ctx, HEVENT_NORMAL_PRIORITY);

    return priv;
}

#define libhv_ctx_new NULL
#define libhv_ctx_run_once NULL
#define libhv_ctx_reinitialize NULL
#define libhv_ctx_set_flags NULL
VERTO_MODULE(libhv, event_base_init,
             VERTO_EV_TYPE_IO |
             VERTO_EV_TYPE_TIMEOUT |
             VERTO_EV_TYPE_SIGNAL);
