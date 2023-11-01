/******************************************************************************
 * verto.h: This ifm verto include for libhv
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * Huangduirong <huangduirong@huawei.com>
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

#ifndef _IFM_VERTO_H_
#define _IFM_VERTO_H_

#include <stdlib.h>
#include <verto.h>

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

verto_ctx *ifm_verto_default(const char *impl, verto_ev_type reqtypes);

verto_ctx *ifm_verto_new(const char *impl, verto_ev_type reqtypes);

void ifm_verto_run(verto_ctx *ctx);

void ifm_verto_break(verto_ctx *ctx);

void ifm_verto_del(verto_ev *ev);

void ifm_verto_free(verto_ctx *ctx);

void ifm_verto_cleanup(void);

// TODO: To be add in futurl.
// verto_ev *verto_add_signal(verto_ctx *ctx, verto_ev_flag flags,
//                  verto_callback *callback, int signal);

verto_ev *ifm_verto_add_io(verto_ctx *ctx, verto_ev_flag flags,
             verto_callback *callback, int fd);

verto_ev *ifm_verto_add_timeout(verto_ctx *ctx, verto_ev_flag flags,
                  verto_callback *callback, time_t interval);

void ifm_verto_set_private(verto_ev *ev, void *priv, verto_callback *free);

void *ifm_verto_get_private(const verto_ev *ev);

#ifdef __cplusplus
} /* extern "C" */
#endif


#endif