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

#ifndef IFM_VERTO_MODULE_TYPES
#define IFM_VERTO_MODULE_TYPES

#include "ifm_verto.h"

#include <sys/types.h>
typedef pid_t verto_proc;
typedef int verto_proc_status;

#ifndef VERTO_MODULE_TYPES
#define VERTO_MODULE_TYPES
typedef void verto_mod_ctx;
typedef void verto_mod_ev;
#endif

#define VERTO_MODULE_VERSION 3
#define VERTO_MODULE_TABLE(name) verto_module_table_ ## name
#define VERTO_MODULE(name, symb, types) \
    static verto_ctx_funcs name ## _funcs = { \
        name ## _ctx_new, \
        name ## _ctx_default, \
        name ## _ctx_free, \
        name ## _ctx_run, \
        name ## _ctx_run_once, \
        name ## _ctx_break, \
        name ## _ctx_reinitialize, \
        name ## _ctx_set_flags, \
        name ## _ctx_add, \
        name ## _ctx_del \
    }; \
    verto_module VERTO_MODULE_TABLE(name) = { \
        VERTO_MODULE_VERSION, \
        # name, \
        # symb, \
        types, \
        &name ## _funcs, \
    }; \
    verto_ctx * \
    verto_new_ ## name() \
    { \
        return verto_convert(name, 0, NULL); \
    } \
    verto_ctx * \
    verto_default_ ## name() \
    { \
        return verto_convert(name, 1, NULL); \
    }


typedef struct {
    /* Required */ verto_mod_ctx *(*ctx_new)();
    /* Optional */ verto_mod_ctx *(*ctx_default)();
    /* Required */ void (*ctx_free)(verto_mod_ctx *ctx);
    /* Optional */ void (*ctx_run)(verto_mod_ctx *ctx);
    /* Required */ void (*ctx_run_once)(verto_mod_ctx *ctx);
    /* Optional */ void (*ctx_break)(verto_mod_ctx *ctx);
    /* Optional */ void (*ctx_reinitialize)(verto_mod_ctx *ctx);
    /* Optional */ void (*ctx_set_flags)(verto_mod_ctx *ctx,
                                         const verto_ev *ev,
                                         verto_mod_ev *modev);
    /* Required */ verto_mod_ev *(*ctx_add)(verto_mod_ctx *ctx,
                                            const verto_ev *ev,
                                            verto_ev_flag *flags);
    /* Required */ void (*ctx_del)(verto_mod_ctx *ctx,
                                   const verto_ev *ev,
                                   verto_mod_ev *modev);
} verto_ctx_funcs;

typedef struct {
    unsigned int vers;
    const char *name;
    const char *symb;
    verto_ev_type types;
    verto_ctx_funcs *funcs;
} verto_module;

#define verto_convert(name, deflt, ctx) \
        verto_convert_module(&VERTO_MODULE_TABLE(name), deflt, ctx)

verto_ctx *
verto_convert_module(const verto_module *module, int deflt, verto_mod_ctx *ctx);

#endif /* _IFM_VERTO_MODULE_TYPES */