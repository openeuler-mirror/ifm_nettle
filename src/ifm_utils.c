/******************************************************************************
 * ifm_utils.c: utils common func in IFM
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 *
 * Authors:
 * huangduirong <huangduirong@huawei.com>
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
#include <stdbool.h>
#ifdef __aarch64__
#include <stdlib.h>
#include <string.h>
#endif

/**
 * @ingroup UadkEnabled
 * @par 返回当前是否开启UADK的配置，可以通过环境变量IFM_UADK_ENABLE控制，环境变量值为NO的时候，不启用，返回false。
 * 否则默认返回true。
 */
bool UadkEnabled(void)
{
#ifdef __aarch64__
    static bool inited = false;
    static bool enabled = false;

    if (inited) {
        return enabled;
    }

    char *env_ifm_uadk_enable = getenv("IFM_UADK_ENABLE");
    if (env_ifm_uadk_enable != NULL && strcmp(env_ifm_uadk_enable, "NO") == 0) {
        inited = true;
        enabled = false;
    } else {
        inited = true;
        enabled = true;
    }
    return enabled;
#else
    return false;
#endif
}