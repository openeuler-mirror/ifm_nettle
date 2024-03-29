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

#include <pthread.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "ifm_verto.h"
#include "ifm_verto_module.h"
#include "module.h"

struct verto_ctx {
    size_t ref;
    verto_mod_ctx *ctx;
    const verto_module *module;
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


typedef struct module_record module_record;
struct module_record {
    module_record *next;
    const verto_module *module;
    void *dll;
    char *filename;
    verto_ctx *defctx;
};

#ifdef BUILTIN_MODULE
#define _MODTABLE(n) verto_module_table_ ## n
#define MODTABLE(n) _MODTABLE(n)
/*
 * This symbol can be used when embedding verto.c in a library along with a
 * built-in private module, to preload the module instead of dynamically
 * linking it in later.  Define to <modulename>.
 */
extern verto_module MODTABLE(BUILTIN_MODULE);
static module_record builtin_record = {
    NULL, &MODTABLE(BUILTIN_MODULE), NULL, "", NULL
};
static module_record *loaded_modules = &builtin_record;
#else
static module_record *loaded_modules;
#endif


static void *(*resize_cb)(void *mem, size_t size);
#define vfree(mem) vresize(mem, 0)
static void *
vresize(void *mem, size_t size)
{
    if (!resize_cb)
        resize_cb = &realloc;
    if (size == 0 && resize_cb == &realloc) {
        /* Avoid memleak as realloc(X, 0) can return a free-able pointer. */
        free(mem);
        return NULL;
    }
    return (*resize_cb)(mem, size);
}


/* Remove flags we can emulate */
#define make_actual(flags) ((flags) & ~(VERTO_EV_FLAG_PERSIST|VERTO_EV_FLAG_IO_CLOSE_FD))

static pthread_mutex_t loaded_modules_mutex = PTHREAD_MUTEX_INITIALIZER;

#define mutex_lock(x) { \
        int c = pthread_mutex_lock(x); \
        if (c != 0) { \
            fprintf(stderr, "pthread_mutex_lock returned %d (%s) in %s", \
                    c, strerror(c), __FUNCTION__); \
        } \
        assert(c == 0); \
    }
#define mutex_unlock(x) { \
        int c = pthread_mutex_unlock(x); \
        if (c != 0) { \
            fprintf(stderr, "pthread_mutex_unlock returned %d (%s) in %s", \
                    c, strerror(c), __FUNCTION__); \
        } \
        assert(c == 0); \
    }
#define mutex_destroy(x) { \
        int c = pthread_mutex_destroy(x); \
        if (c != 0) { \
            fprintf(stderr, "pthread_mutex_destroy returned %d (%s) in %s", \
                    c, strerror(c), __FUNCTION__); \
        } \
        assert(c == 0); \
    }


#ifndef BUILTIN_MODULE
static char *
string_aconcat(const char *first, const char *second, const char *third) {
    char *ret;
    size_t len;

    len = strlen(first) + strlen(second);
    if (third)
        len += strlen(third);

    ret = malloc(len + 1);
    if (!ret)
        return NULL;

    strncpy(ret, first, strlen(first));
    strncpy(ret + strlen(first), second, strlen(second));
    if (third)
        strncpy(ret + strlen(first) + strlen(second), third, strlen(third));

    ret[len] = '\0';
    return ret;
}

static char *
int_get_table_name_from_filename(const char *filename)
{
    char *bn = NULL, *tmp = NULL;

    if (!filename)
        return NULL;

    tmp = strdup(filename);
    if (!tmp)
        return NULL;

    bn = basename(tmp);
    if (bn)
        bn = strdup(bn);
    free(tmp);
    if (!bn)
        return NULL;

    tmp = strchr(bn, '-');
    if (tmp) {
        if (strchr(tmp+1, '.')) {
            *strchr(tmp+1, '.') = '\0';
            tmp = string_aconcat(__str(VERTO_MODULE_TABLE()), tmp + 1, NULL);
        } else
            tmp = NULL;
    }

    free(bn);
    return tmp;
}

typedef struct {
    int reqsym;
    verto_ev_type reqtypes;
} shouldload_data;

static int
shouldload(void *symb, void *misc, char **err)
{
    verto_module *table = (verto_module*) symb;
    shouldload_data *data = (shouldload_data*) misc;

    /* Make sure we have the proper version */
    if (table->vers != VERTO_MODULE_VERSION) {
        if (err)
            *err = strdup("Invalid module version!");
        return 0;
    }

    /* Check to make sure that we have our required symbol if reqsym == true */
    if (table->symb && data->reqsym
            && !module_symbol_is_present(NULL, table->symb)) {
        if (err)
            *err = string_aconcat("Symbol not found: ", table->symb, "!");
        return 0;
    }

    /* Check to make sure that this module supports our required features */
    if (data->reqtypes != VERTO_EV_TYPE_NONE
            && (table->types & data->reqtypes) != data->reqtypes) {
        if (err)
            *err = strdup("Module does not support required features!");
        return 0;
    }

    return 1;
}

static int
do_load_file(const char *filename, int reqsym, verto_ev_type reqtypes,
             module_record **record)
{
    char *tblname = NULL, *error = NULL;
    module_record *tmp;
    shouldload_data data  = { reqsym, reqtypes };

    /* Check the loaded modules to see if we already loaded one */
    mutex_lock(&loaded_modules_mutex);
    for (*record = loaded_modules ; *record ; *record = (*record)->next) {
        if (!strcmp((*record)->filename, filename)) {
            mutex_unlock(&loaded_modules_mutex);
            return 1;
        }
    }
    mutex_unlock(&loaded_modules_mutex);

    /* Create our module record */
    tmp = *record = vresize(NULL, sizeof(module_record));
    if (!tmp)
        return 0;
    memset(tmp, 0, sizeof(module_record));
    tmp->filename = strdup(filename);
    if (!tmp->filename) {
        vfree(tmp);
        return 0;
    }

    /* Get the name of the module struct in the library */
    tblname = int_get_table_name_from_filename(filename);
    if (!tblname) {
        free(tblname);
        free(tmp->filename);
        vfree(tmp);
        return 0;
    }

    /* Load the module */
    error = module_load(filename, tblname, shouldload, &data, &tmp->dll,
                        (void **) &tmp->module);
    if (error || !tmp->dll || !tmp->module) {
        /*if (error)
            fprintf(stderr, "%s\n", error);*/
        free(error);
        module_close(tmp->dll);
        free(tblname);
        free(tmp->filename);
        vfree(tmp);
        return 0;
    }

    /* Append the new module to the end of the loaded modules */
    mutex_lock(&loaded_modules_mutex);
    for (tmp = loaded_modules ; tmp && tmp->next; tmp = tmp->next)
        continue;
    if (tmp)
        tmp->next = *record;
    else
        loaded_modules = *record;
    mutex_unlock(&loaded_modules_mutex);

    free(tblname);
    return 1;
}

static int
do_load_dir(const char *dirname, const char *prefix, const char *suffix,
            int reqsym, verto_ev_type reqtypes, module_record **record)
{
    DIR *dir;
    struct dirent *ent = NULL;

    *record = NULL;
    dir = opendir(dirname);
    if (!dir)
        return 0;


    while ((ent = readdir(dir))) {
        char *tmp = NULL;
        int success;
        size_t flen, slen;

        flen = strlen(ent->d_name);
        slen = strlen(suffix);

        if (!strcmp(".", ent->d_name) || !strcmp("..", ent->d_name))
            continue;
        if (strstr(ent->d_name, prefix) != ent->d_name)
            continue;
        if (flen < slen || strcmp(ent->d_name + flen - slen, suffix))
            continue;

        tmp = string_aconcat(dirname, "/", ent->d_name);
        if (!tmp)
            continue;

        success = do_load_file(tmp, reqsym, reqtypes, record);
        free(tmp);
        if (success)
            break;
        *record = NULL;
    }

    closedir(dir);
    return *record != NULL;
}
#endif


static int
load_module(const char *impl, verto_ev_type reqtypes, module_record **record)
{
    int success = 0;
#ifndef BUILTIN_MODULE
    char *prefix = NULL;
    char *suffix = NULL;
    char *tmp = NULL;
#endif

    /* Check the cache */
    mutex_lock(&loaded_modules_mutex);
    if (impl) {
        for (*record = loaded_modules ; *record ; *record = (*record)->next) {
            const char* first_slash = strchr(impl, '/');
            int filename_same = strcmp(impl, (*record)->filename);
            int module_name_same = strcmp(impl, (*record)->module->name);
            if ((first_slash && !filename_same) || !module_name_same) {
                mutex_unlock(&loaded_modules_mutex);
                return 1;
            }
        }
    } else if (loaded_modules) {
        for (*record = loaded_modules ; *record ; *record = (*record)->next) {
            if (reqtypes == VERTO_EV_TYPE_NONE
                    || ((*record)->module->types & reqtypes) == reqtypes) {
                mutex_unlock(&loaded_modules_mutex);
                return 1;
            }
        }
    }
    mutex_unlock(&loaded_modules_mutex);

#ifndef BUILTIN_MODULE
    if (!module_get_filename_for_symbol(verto_convert_module, &prefix))
        return 0;

    /* Example output:
     *    prefix == /usr/lib/libverto-
     *    impl == glib
     *    suffix == .so.0
     * Put them all together: /usr/lib/libverto-glib.so.0 */
    tmp = strdup(prefix);
    if (!tmp) {
        free(prefix);
        return 0;
    }

    suffix = basename(tmp);
    suffix = strchr(suffix, '.');
    if (!suffix || strlen(suffix) < 1 || !(suffix = strdup(suffix))) {
        free(prefix);
        free(tmp);
        return 0;
    }
    strcpy(prefix + strlen(prefix) - strlen(suffix), "-");
    free(tmp);

    if (impl) {
        /* Try to do a load by the path */
        if (!success && strchr(impl, '/'))
            success = do_load_file(impl, 0, reqtypes, record);
        if (!success) {
            /* Try to do a load by the name */
            tmp = string_aconcat(prefix, impl, suffix);
            if (tmp) {
                success = do_load_file(tmp, 0, reqtypes, record);
                free(tmp);
            }
        }
    } else {
        /* NULL was passed, so we will use the dirname of
         * the prefix to try and find any possible plugins */
        tmp = strdup(prefix);
        if (tmp) {
            char *dname = strdup(dirname(tmp));
            free(tmp);

            tmp = strdup(basename(prefix));
            free(prefix);
            prefix = tmp;

            if (dname && prefix) {
                /* Attempt to find a module we are already linked to */
                success = do_load_dir(dname, prefix, suffix, 1, reqtypes,
                                      record);
                if (!success) {
#ifdef DEFAULT_MODULE
                    /* Attempt to find the default module */
                    success = load_module(DEFAULT_MODULE, reqtypes, record);
                    if (!success)
#endif /* DEFAULT_MODULE */
                        /* Attempt to load any plugin (we're desperate) */
                        success = do_load_dir(dname, prefix, suffix, 0,
                                              reqtypes, record);
                }
            }

            free(dname);
        }
    }

    free(suffix);
    free(prefix);
#endif /* BUILTIN_MODULE */
    return success;
}


static void
remove_ev(verto_ev **origin, verto_ev *item)
{
    if (!origin || !*origin || !item)
        return;

    if (*origin == item)
        *origin = (*origin)->next;
    else
        remove_ev(&((*origin)->next), item);
}


verto_ctx *
verto_convert_module(const verto_module *module, int deflt, verto_mod_ctx *mctx)
{
    verto_ctx *ctx = NULL;
    module_record *mr;

    if (!module)
        return NULL;

    if (deflt) {
        mutex_lock(&loaded_modules_mutex);
        for (mr = loaded_modules ; mr ; mr = mr->next) {
            verto_ctx *tmp;
            if (mr->module == module && mr->defctx) {
                if (mctx)
                    module->funcs->ctx_free(mctx);
                tmp = mr->defctx;
                tmp->ref++;
                mutex_unlock(&loaded_modules_mutex);
                return tmp;
            }
        }
        mutex_unlock(&loaded_modules_mutex);
    }

    if (!mctx) {
        if (deflt){
            if (module->funcs->ctx_default)
                mctx = module->funcs->ctx_default();
            else
                mctx = module->funcs->ctx_new();
        } else {
            mctx = module->funcs->ctx_new();
        }
        if (!mctx)
            goto error;
    }

    ctx = vresize(NULL, sizeof(verto_ctx));
    if (!ctx)
        goto error;
    memset(ctx, 0, sizeof(verto_ctx));

    ctx->ref = 1;
    ctx->ctx = mctx;
    ctx->module = module;
    ctx->deflt = deflt;

    if (deflt) {
        module_record **tmp;

        mutex_lock(&loaded_modules_mutex);
        tmp = &loaded_modules;
        for (mr = loaded_modules ; mr ; mr = mr->next) {
            if (mr->module == module) {
                assert(mr->defctx == NULL);
                // mr->defctx = ctx;    /* from libverto source code */
                mutex_unlock(&loaded_modules_mutex);
                return ctx;
            }

            if (!mr->next) {
                tmp = &mr->next;
                break;
            }
        }
        mutex_unlock(&loaded_modules_mutex);

        *tmp = vresize(NULL, sizeof(module_record));
        if (!*tmp) {
            vfree(ctx);
            goto error;
        }

        memset(*tmp, 0, sizeof(module_record));
        (*tmp)->defctx = ctx;
        (*tmp)->module = module;
    }

    return ctx;

error:
    if (mctx)
        module->funcs->ctx_free(mctx);
    return NULL;
}


verto_ctx *
ifm_verto_default(const char *impl, verto_ev_type reqtypes)
{
    module_record *mr = NULL;

    if (!load_module(impl, reqtypes, &mr))
        return NULL;

    return verto_convert_module(mr->module, 1, NULL);
}


void
ifm_verto_run(verto_ctx *ctx)
{
    if (!ctx)
        return;

    if (ctx->module->funcs->ctx_break && ctx->module->funcs->ctx_run)
        ctx->module->funcs->ctx_run(ctx->ctx);
    else {
        while (!ctx->exit)
            ctx->module->funcs->ctx_run_once(ctx->ctx);
        ctx->exit = 0;
    }
}


void
ifm_verto_break(verto_ctx *ctx)
{
    if (!ctx)
        return;

    if (ctx->module->funcs->ctx_break && ctx->module->funcs->ctx_run)
        ctx->module->funcs->ctx_break(ctx->ctx);
    else
        ctx->exit = 1;
}


void
ifm_verto_del(verto_ev *ev)
{
    if (!ev)
        return;

    /* If the event is freed in the callback, we just set a flag so that
     * ifm_verto_fire() can actually do the delete when the callback completes.
     *
     * If we don't do this, than ifm_verto_fire() will access freed memory. */
    if (ev->depth > 0) {
        ev->deleted = 1;
        return;
    }

    if (ev->onfree)
        ev->onfree(ev->ctx, ev);
    ev->ctx->module->funcs->ctx_del(ev->ctx->ctx, ev, ev->ev);
    remove_ev(&(ev->ctx->events), ev);

    if ((ev->type == VERTO_EV_TYPE_IO) &&
        (ev->flags & VERTO_EV_FLAG_IO_CLOSE_FD) &&
        !(ev->actual & VERTO_EV_FLAG_IO_CLOSE_FD))
        close(ev->option.io.fd);

    vfree(ev);
}


void
ifm_verto_free(verto_ctx *ctx)
{
    verto_ev *cur, *next;

    if (!ctx)
        return;

    ctx->ref = ctx->ref > 0 ? ctx->ref - 1 : 0;
    if (ctx->ref > 0)
        return;

    /* Cancel all pending events */
    next = NULL;
    for (cur = ctx->events; cur != NULL; cur = next) {
        next = cur->next;
        ifm_verto_del(cur);
    }
    ctx->events = NULL;

    /* Free the private */
    if (!ctx->deflt || !ctx->module->funcs->ctx_default)
        ctx->module->funcs->ctx_free(ctx->ctx);

    vfree(ctx);
}


void
ifm_verto_cleanup(void)
{
    module_record *record;

    mutex_lock(&loaded_modules_mutex);

    for (record = loaded_modules; record; record = record->next) {
        module_close(record->dll);
        // free(record->filename);   /* from libverto source code */
    }

    // vfree(loaded_modules); /* from libverto source code */
    loaded_modules = NULL;

    mutex_unlock(&loaded_modules_mutex);
    // mutex_destroy(&loaded_modules_mutex); /* from libverto source code */
}


static verto_ev *
make_ev(verto_ctx *ctx, verto_callback *callback,
        verto_ev_type type, verto_ev_flag flags)
{
    verto_ev *ev = NULL;

    if (!ctx || !callback)
        return NULL;

    ev = vresize(NULL, sizeof(verto_ev));
    if (ev) {
        memset(ev, 0, sizeof(verto_ev));
        ev->ctx        = ctx;
        ev->type       = type;
        ev->callback   = callback;
        ev->flags      = flags;
    }

    return ev;
}

static void
push_ev(verto_ctx *ctx, verto_ev *ev)
{
    verto_ev *tmp;

    if (!ctx || !ev)
        return;

    tmp = ctx->events;
    ctx->events = ev;
    ctx->events->next = tmp;
}

static void
signal_ignore(verto_ctx *ctx, verto_ev *ev)
{
    (void) ctx;
    (void) ev;
}


verto_ev *
ifm_verto_add_signal(verto_ctx *ctx, verto_ev_flag flags,
                 verto_callback *callback, int signal)
{
    verto_ev *ev;

    if (signal < 0)
        return NULL;
        
    if (callback == VERTO_SIG_IGN) {
        callback = signal_ignore;
        if (!(flags & VERTO_EV_FLAG_PERSIST))
            return NULL;
    }

    /* expand doadd macro */
    ev = make_ev(ctx, callback, VERTO_EV_TYPE_SIGNAL, flags); 
    if (ev) { 
        ev->option.signal = signal;
        ev->actual = make_actual(ev->flags); 
        ev->ev = ctx->module->funcs->ctx_add(ctx->ctx, ev, &ev->actual); 
        if (!ev->ev) { 
            vfree(ev); 
            return NULL; 
        } 
        push_ev(ctx, ev); 
    }
    /* expand doadd macro */
    return ev;
}


verto_ev *
ifm_verto_add_io(verto_ctx *ctx, verto_ev_flag flags,
             verto_callback *callback, int fd)
{
    verto_ev *ev;

    if (fd < 0 || !(flags & (VERTO_EV_FLAG_IO_READ | VERTO_EV_FLAG_IO_WRITE)))
        return NULL;
    /* expand doadd macro */
    ev = make_ev(ctx, callback, VERTO_EV_TYPE_IO, flags); 
    if (ev) { 
        ev->option.io.fd = fd;
        ev->actual = make_actual(ev->flags); 
        ev->ev = ctx->module->funcs->ctx_add(ctx->ctx, ev, &ev->actual); 
        if (!ev->ev) { 
            vfree(ev); 
            return NULL; 
        } 
        push_ev(ctx, ev); 
    }
    /* expand doadd macro */
    return ev;
}


verto_ev *
ifm_verto_add_timeout(verto_ctx *ctx, verto_ev_flag flags,
                  verto_callback *callback, time_t interval)
{
    verto_ev *ev;
    /* expand doadd macro */
    ev = make_ev(ctx, callback, VERTO_EV_TYPE_TIMEOUT, flags); 
    if (ev) { 
        ev->option.interval = interval;
        ev->actual = make_actual(ev->flags); 
        ev->ev = ctx->module->funcs->ctx_add(ctx->ctx, ev, &ev->actual); 
        if (!ev->ev) { 
            vfree(ev); 
            return NULL; 
        } 
        push_ev(ctx, ev); 
    }
    /* expand doadd macro */
    return ev;
}


void
ifm_verto_set_private(verto_ev *ev, void *priv, verto_callback *free)
{
    if (!ev)
        return;
    if (ev->onfree && free)
        ev->onfree(ev->ctx, ev);
    ev->priv = priv;
    ev->onfree = free;
}


verto_ev_type
ifm_verto_get_type(const verto_ev *ev)
{
    return ev->type;
}


time_t
ifm_verto_get_interval(const verto_ev *ev)
{
    if (ev && (ev->type == VERTO_EV_TYPE_TIMEOUT))
        return ev->option.interval;
    return 0;
}


verto_ev_flag
ifm_verto_get_flags(const verto_ev *ev)
{
    return ev->flags;
}


verto_ev_type
ifm_verto_get_supported_types(verto_ctx *ctx)
{
    return ctx->module->types;
}


void *
ifm_verto_get_private(const verto_ev *ev)
{
    return ev->priv;
}


int
ifm_verto_get_fd(const verto_ev *ev)
{
    if (ev && (ev->type == VERTO_EV_TYPE_IO))
        return ev->option.io.fd;
    return -1;
}


int
ifm_verto_get_signal(const verto_ev *ev)
{
    if (ev && (ev->type == VERTO_EV_TYPE_SIGNAL))
        return ev->option.signal;
    return -1;
}


verto_ev_flag
ifm_verto_get_fd_state(const verto_ev *ev)
{
    return ev->option.io.state;
}


void
ifm_verto_fire(verto_ev *ev)
{
    void *priv;

    ev->depth++;
    ev->callback(ev->ctx, ev);
    ev->depth--;

    if (ev->depth == 0) {
        if (!(ev->flags & VERTO_EV_FLAG_PERSIST) || ev->deleted)
            ifm_verto_del(ev);
        else {
            if (!(ev->actual & VERTO_EV_FLAG_PERSIST)) {
                ev->actual = make_actual(ev->flags);
                priv = ev->ctx->module->funcs->ctx_add(ev->ctx->ctx, ev, &ev->actual);
                assert(priv); /* TODO: create an error callback */
                ev->ctx->module->funcs->ctx_del(ev->ctx->ctx, ev, ev->ev);
                ev->ev = priv;
            }

            if (ev->type == VERTO_EV_TYPE_IO)
                ev->option.io.state = VERTO_EV_FLAG_NONE;
            if (ev->type == VERTO_EV_TYPE_CHILD)
                ev->option.child.status = 0;
        }
    }
}


void
ifm_verto_set_fd_state(verto_ev *ev, verto_ev_flag state)
{
    /* Filter out only the io flags */
    state = state & (VERTO_EV_FLAG_IO_READ |
                     VERTO_EV_FLAG_IO_WRITE |
                     VERTO_EV_FLAG_IO_ERROR);

    /* Don't report read/write if the socket is closed */
    if (state & VERTO_EV_FLAG_IO_ERROR)
        state = VERTO_EV_FLAG_IO_ERROR;

    if (ev && ev->type == VERTO_EV_TYPE_IO)
        ev->option.io.state = state;
}

/* libverto original doadd macro definition */
/*
#define doadd(ev, set, type) \
    ev = make_ev(ctx, callback, type, flags); \
    if (ev) { \
        set; \
        ev->actual = make_actual(ev->flags); \
        ev->ev = ctx->module->funcs->ctx_add(ctx->ctx, ev, &ev->actual); \
        if (!ev->ev) { \
            vfree(ev); \
            return NULL; \
        } \
        push_ev(ctx, ev); \
    }
*/