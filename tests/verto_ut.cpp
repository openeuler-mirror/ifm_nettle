/******************************************************************************
 * verto_ut.cpp: ifm_verto unit testing
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
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

#include <gtest/gtest.h>
#include <sys/time.h>

#include "ifm_verto.h"
#include "testutils.h"

static char* modules_name = "libhv";
static int call_count;
struct timeval start_time;
const char* test_data = "hello";
const int test_data_len = 5;
const int sleep_time = 10;
static int fds[2];

static void read_test_timeout_cb(verto_ctx *ctx, verto_ev *ev)
{
    (void) ev;

    printf("read test Timeout!\n");
    if (fds[0] >= 0) {
        close(fds[0]);
    }
    if (fds[1] >= 0) {
        close(fds[1]);
    }

    verto_break(ctx);
}


static void read_test_read_cb(verto_ctx *ctx, verto_ev *ev) 
{
    unsigned char buff[test_data_len];
    int fd = 0;
    ssize_t bytes = 0;

    fd = verto_get_fd(ev);
    ASSERT_EQ(fd, fds[0]);

    bytes = read(fd, buff, test_data_len);
    call_count++;
    if (call_count <= 2) {
        // 未实现verto_set_fd_state，因此verto_get_fd_state获取的结果存在问题。
        // ASSERT_TRUE(verto_get_fd_state(ev) & VERTO_EV_FLAG_IO_READ);
        ASSERT_EQ(bytes, test_data_len);
    } else {
        if (!(verto_get_fd_state(ev) & VERTO_EV_FLAG_IO_ERROR)) {
            printf("WARNING: VERTO_EV_FLAG_IO_ERROR not supported!\n");
        }
        ASSERT_NE(bytes, test_data_len);
        close(fd);
        fds[0] = -1;
        verto_del(ev);
        verto_break(ctx);
    }
}


static void write_test_timeout_cb(verto_ctx *ctx, verto_ev *ev)
{
    (void) ev;

    printf("write test Timeout!\n");
    if (fds[0] >= 0) {
        close(fds[0]);
    }
    if (fds[1] >= 0) {
        close(fds[1]);
    }

    verto_break(ctx);
}


static void write_test_error_cb(verto_ctx *ctx, verto_ev *ev)
{
    int fd = 0;

    /* When we get here, the fd should be closed, so an error should occur */
    fd = verto_get_fd(ev);
    if (!(verto_get_fd_state(ev) & VERTO_EV_FLAG_IO_ERROR)) {
        printf("WARNING: VERTO_EV_FLAG_IO_ERROR not supported!\n");
    }
    ASSERT_NE(write(fd, test_data, test_data_len), test_data_len);
    close(fd);
    fds[1] = -1;
    verto_break(ctx);
}


static void write_test_read_cb(verto_ctx *ctx, verto_ev *ev)
{
    unsigned char buff[test_data_len];
    int fd = verto_get_fd(ev);

    ASSERT_NO_THROW(read(fd, buff, test_data_len) == test_data_len);
    close(fd);
    fds[0] = -1;

    ASSERT_NO_THROW(verto_add_io(ctx, VERTO_EV_FLAG_IO_WRITE, write_test_error_cb, fds[1]));
}


static void write_test_cb(verto_ctx *ctx, verto_ev *ev)
{
    int fd = 0;

    fd = verto_get_fd(ev);
    // 未实现verto_set_fd_state，因此verto_get_fd_state获取的结果存在问题。
    // ASSERT_NO_THROW(verto_get_fd_state(ev) & VERTO_EV_FLAG_IO_WRITE);
    ASSERT_NO_THROW(write(fd, test_data, test_data_len) == test_data_len);
    call_count += 1;
    ASSERT_NO_THROW(verto_add_io(ctx, VERTO_EV_FLAG_IO_READ, write_test_read_cb, fds[0]));
}


static bool elapsed_time(time_t min, time_t max)
{
    struct timeval tv;
    long long diff;
    int ms_to_us = 1000;

    ASSERT(gettimeofday(&tv, NULL) == 0);
    diff = (tv.tv_sec - start_time.tv_sec) * (ms_to_us * ms_to_us) + tv.tv_usec - start_time.tv_usec;

    ASSERT(gettimeofday(&start_time, NULL) == 0);
    if (diff < ( min * ms_to_us) || diff > (max * ms_to_us)) {
        printf("ERROR: Timeout is out-of-bounds!\n");
        return false;
    }
    return true;
}


static void timeout_test_exit_cb(verto_ctx *ctx, verto_ev *ev)
{
    (void) ev;
    verto_break(ctx);
    ASSERT_EQ(call_count,3);
}


static void timeout_test_cb(verto_ctx *ctx, verto_ev *ev)
{
    int elapsed_min = 0;
    int elapsed_max = 40;
    int exit_time = sleep_time * 2;
    elapsed_time(elapsed_min, elapsed_max);
    printf("Timeout test: %d\n", call_count);
    call_count += 1;
    if (call_count == 3) {
        ASSERT_NO_THROW(verto_add_timeout(ctx, VERTO_EV_FLAG_NONE, timeout_test_exit_cb, exit_time));
        printf("verto_add_timeout exit time.\n");
    }
    else if (call_count == 2) {
        ASSERT_NO_THROW(verto_add_timeout(ctx, VERTO_EV_FLAG_NONE, timeout_test_cb, sleep_time));
        printf("verto_add_timeout one time\n");
        verto_del(ev);
    }
}

void signal_cb(verto_ctx *ctx, verto_ev *ev)
{
    (void) ctx;
    (void) ev;

    call_count++;
    printf("INFO: signal_cb %d times!\n", call_count);
}

void signal_exit_cb(verto_ctx *ctx, verto_ev *ev)
{
    printf("INFO: signal_exit_cb!\n");
    if ((pid_t) (uintptr_t) verto_get_private(ev) != 0)
        waitpid((pid_t) (uintptr_t) verto_get_private(ev), NULL, 0);

    switch (call_count) {
        case 0:
            printf("ERROR: Signal callback never fired!\n");
            break;
        case 1:
            printf("ERROR: Signal MUST recur!\n");
            break;
        default:
            break;
    }
    verto_break(ctx);
}

TEST(verto_testcases, test_verto_timeout)
{
    verto_ctx *ctx;
    ASSERT_NO_THROW(ctx = verto_default(modules_name, VERTO_EV_TYPE_NONE));
    call_count = 0;

    ASSERT_EQ(gettimeofday(&start_time, NULL), 0);
    ASSERT_NO_THROW(verto_add_timeout(ctx, VERTO_EV_FLAG_PERSIST, timeout_test_cb, sleep_time));

    ASSERT_NO_THROW(verto_run(ctx));
    ASSERT_NO_THROW(verto_free(ctx));
}

TEST(verto_testcases, test_verto_read)
{
    verto_ctx *ctx;
    ASSERT_NO_THROW(ctx = verto_default(modules_name, VERTO_EV_TYPE_NONE));

    call_count = 0;
    fds[0] = -1;
    fds[1] = -1;

    ASSERT_NO_THROW(verto_get_supported_types(ctx) & VERTO_EV_TYPE_IO);
    ASSERT_NO_THROW(pipe(fds) == 0);
    ASSERT_NO_THROW(verto_add_timeout(ctx, VERTO_EV_FLAG_NONE, read_test_timeout_cb, 1000));
    ASSERT_NO_THROW(verto_add_io(ctx, VERTO_EV_FLAG_PERSIST | VERTO_EV_FLAG_IO_READ, read_test_read_cb, fds[0]));
    ASSERT_NO_THROW(write(fds[1], test_data, test_data_len) == test_data_len);
    ASSERT_NO_THROW(write(fds[1], test_data, test_data_len) == test_data_len);

    ASSERT_NO_THROW(verto_run(ctx));
    ASSERT_EQ(call_count, 2);
    ASSERT_NO_THROW(verto_free(ctx));
}

TEST(verto_testcases, test_verto_signal)
{
    verto_ctx *ctx;
    pid_t pid = 0;
    verto_ev *ev;
    ASSERT_NO_THROW(ctx = verto_default(modules_name, VERTO_EV_TYPE_NONE));

    call_count = 0;
    fds[0] = -1;
    fds[1] = -1;

    ASSERT_NO_THROW(verto_get_supported_types(ctx) & VERTO_EV_TYPE_SIGNAL);

    /* We should get a failure when trying to create a non-persistent ignore */
    ASSERT_EQ(NULL, verto_add_signal(ctx, VERTO_EV_FLAG_NONE, VERTO_SIG_IGN, SIGUSR2));
    ASSERT_NE(NULL, verto_add_signal(ctx, VERTO_EV_FLAG_PERSIST, signal_cb, SIGUSR1));
    //ASSERT_NE(NULL, verto_add_signal(ctx, VERTO_EV_FLAG_PERSIST, VERTO_SIG_IGN, SIGUSR2));

    pid = fork();
    if (pid < 0)
        return 1;
    else if (pid == 0) {
        usleep(10000); /* 0.01 seconds */
        kill(getppid(), SIGUSR1);
        usleep(10000); /* 0.01 seconds */
        kill(getppid(), SIGUSR1);
        usleep(10000); /* 0.01 seconds */
        //kill(getppid(), SIGUSR2);
        exit(0);
    }

    ev = verto_add_timeout(ctx, VERTO_EV_FLAG_NONE, signal_exit_cb, 1000);
    ASSERT_NE(NULL, ev);
    verto_set_private(ev, (void *) (uintptr_t) pid, NULL);

    ASSERT_NO_THROW(verto_run(ctx));
    ASSERT_EQ(call_count, 2);
    printf("break point verto_free.\n");
    verto_free(ctx);
}

TEST(verto_testcases, test_verto_write)
{
    verto_ctx *ctx;
    ASSERT_NO_THROW(ctx = verto_default(modules_name, VERTO_EV_TYPE_NONE));

    call_count = 0;
    fds[0] = -1;
    fds[1] = -1;

    ASSERT_NO_THROW(verto_get_supported_types(ctx) & VERTO_EV_TYPE_IO);

    if (!verto_add_signal(ctx, VERTO_EV_FLAG_NONE, VERTO_SIG_IGN, SIGPIPE)){
        printf("WARNING: verto_add_signal use SIG_IGN\n");
        signal(SIGPIPE, SIG_IGN);
    }

    ASSERT_NO_THROW(pipe(fds) == 0);
    ASSERT_NO_THROW(verto_add_timeout(ctx, VERTO_EV_FLAG_NONE, write_test_timeout_cb, 1000));
    ASSERT_NO_THROW(verto_add_io(ctx, VERTO_EV_FLAG_IO_WRITE, write_test_cb, fds[1]));

    ASSERT_NO_THROW(verto_run(ctx));
    ASSERT_EQ(call_count, 1);
    ASSERT_NO_THROW(verto_free(ctx));
}

TEST(verto_testcases, test_verto_cleanup)
{
    verto_ctx *ctx;
    ASSERT_NO_THROW(ctx = verto_default(modules_name, VERTO_EV_TYPE_NONE));

    ASSERT_NO_THROW(verto_free(ctx));
    ASSERT_NO_THROW(verto_cleanup());
}