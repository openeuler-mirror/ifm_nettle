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

#ifndef IFM_VERTO_H_INCLUDED
#define IFM_VERTO_H_INCLUDED

#include <stdlib.h>

#define BUILTIN_MODULE libhv

#define VERTO_SIG_IGN ((verto_callback *) 1)

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

typedef struct verto_ctx verto_ctx;
typedef struct verto_ev verto_ev;

typedef enum {
    VERTO_EV_TYPE_NONE = 0,
    VERTO_EV_TYPE_IO = 1,
    VERTO_EV_TYPE_TIMEOUT = 1 << 1,
    VERTO_EV_TYPE_IDLE = 1 << 2,
    VERTO_EV_TYPE_SIGNAL = 1 << 3,
    VERTO_EV_TYPE_CHILD = 1 << 4
} verto_ev_type;

typedef enum {
    VERTO_EV_FLAG_NONE = 0,
    VERTO_EV_FLAG_PERSIST = 1,
    VERTO_EV_FLAG_PRIORITY_LOW = 1 << 1,
    VERTO_EV_FLAG_PRIORITY_MEDIUM = 1 << 2,
    VERTO_EV_FLAG_PRIORITY_HIGH = 1 << 3,
    VERTO_EV_FLAG_IO_READ = 1 << 4,
    VERTO_EV_FLAG_IO_WRITE = 1 << 5,
    VERTO_EV_FLAG_IO_ERROR = 1 << 7,
    VERTO_EV_FLAG_IO_CLOSE_FD = 1 << 8,
    VERTO_EV_FLAG_REINITIABLE = 1 << 6,
    _VERTO_EV_FLAG_MUTABLE_MASK = VERTO_EV_FLAG_PRIORITY_LOW
                                  | VERTO_EV_FLAG_PRIORITY_MEDIUM
                                  | VERTO_EV_FLAG_PRIORITY_HIGH
                                  | VERTO_EV_FLAG_IO_READ
                                  | VERTO_EV_FLAG_IO_WRITE,
    _VERTO_EV_FLAG_MAX = VERTO_EV_FLAG_IO_CLOSE_FD
} verto_ev_flag;

typedef void (verto_callback)(verto_ctx *ctx, verto_ev *ev);

verto_ctx *
ifm_verto_default(const char *impl, verto_ev_type reqtypes);

void
ifm_verto_run(verto_ctx *ctx);

void
ifm_verto_break(verto_ctx *ctx);

void
ifm_verto_del(verto_ev *ev);

void
ifm_verto_free(verto_ctx *ctx);

void
ifm_verto_cleanup(void);

verto_ev *
ifm_verto_add_signal(verto_ctx *ctx, verto_ev_flag flags,
                 verto_callback *callback, int signal);

verto_ev *
ifm_verto_add_io(verto_ctx *ctx, verto_ev_flag flags,
             verto_callback *callback, int fd);

verto_ev *
ifm_verto_add_timeout(verto_ctx *ctx, verto_ev_flag flags,
                  verto_callback *callback, time_t interval);

void
ifm_verto_fire(verto_ev *ev);

int
ifm_verto_get_fd(const verto_ev *ev);

verto_ev_type
ifm_verto_get_type(const verto_ev *ev);

void *
ifm_verto_get_private(const verto_ev *ev);

time_t
ifm_verto_get_interval(const verto_ev *ev);

verto_ev_flag
ifm_verto_get_fd_state(const verto_ev *ev);

verto_ev_type
ifm_verto_get_supported_types(verto_ctx *ctx);

verto_ev_flag
ifm_verto_get_flags(const verto_ev *ev);

verto_ev_type
ifm_verto_get_type(const verto_ev *ev);

int
ifm_verto_get_signal(const verto_ev *ev);

void
ifm_verto_set_private(verto_ev *ev, void *priv, verto_callback *free);

void
ifm_verto_set_fd_state(verto_ev *ev, verto_ev_flag state);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* IFM_VERTO_H_ */