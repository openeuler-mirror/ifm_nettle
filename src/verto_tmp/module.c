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

#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#define dlltype void *
#define dllerror() strdup(dlerror())


int
module_symbol_is_present(const char *modname, const char *symbname)
{
    void *mod;
    (void) modname;

    mod = dlopen(NULL, RTLD_LAZY | RTLD_LOCAL);
    if (mod) {
        void* sym = dlsym(mod, symbname);
        dlclose(mod);
        return sym != NULL;
    }

    return 0;
}


void
module_close(void *dll)
{
    if (!dll)
        return;
    dlclose((dlltype) dll);
}


char *
module_load(const char *filename, const char *symbname,
            int (*shouldload)(void *symb, void *misc, char **err), void *misc,
            void **dll, void **symb)
{
    dlltype intdll = NULL;
    void *  intsym = NULL;
    char *  interr = NULL;

    if (dll)
        *dll = NULL;
    if (symb)
        *symb = NULL;

    intdll = dlopen(filename, RTLD_LAZY | RTLD_LOCAL);
    if (!intdll)
        goto fail;

    /* Get the module symbol */
    intsym = dlsym(intdll, symbname);
    if (!intsym)
        goto fail;

    /* Figure out whether or not to load this module */
    if (!shouldload(intsym, misc, &interr))
        goto fail;

    /* Re-open the module */
    module_close(intdll);
    intdll = dlopen(filename, RTLD_NOW | RTLD_LOCAL);
    if (!intdll)
        goto fail;

    /* Get the symbol again */
    intsym = dlsym(intdll, symbname);
    if (!intsym)
        goto fail;

    if (dll)
        *dll = intdll;
    if (symb)
        *symb = intsym;
    return NULL;

fail:
    if (!interr)
        interr = dllerror();
    module_close(intdll);
    return interr;
}
