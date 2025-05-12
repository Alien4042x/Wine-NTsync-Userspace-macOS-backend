/*
 * ntsync - userspace synchronization primitives (macOS-compatible)
 * Userspace backend similar to esync, no server, no kernel module
 *
 * Originally inspired by the Linux ntsync implementation introduced in Wine 9.x.
 * Adapted and reworked for macOS by Radim Veselý (@alien4042x).
 *
 * This is an experimental prototype for research and compatibility purposes.
 */


#if 0
#pragma makedep unix
#endif

#ifdef __WINE_PE_BUILD__
#error "ntsync.c is for Unix only, not for PE build"
#endif

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "wine/debug.h"

#include "ntsync.h"

WINE_DEFAULT_DEBUG_CHANNEL(ntsync);

enum ntsync_type
{
    NTSYNC_TYPE_EVENT,
    NTSYNC_TYPE_MUTEX,
    NTSYNC_TYPE_SEMAPHORE,
};

struct ntsync_object
{
    enum ntsync_type type;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int signaled;          /* for events */
    bool manual_reset;     /* for events only */
    DWORD owner_tid;       /* for mutex */
    int count;             /* for semaphores and mutexes */
    int max;               /* for traffic lights */
    int refcount;
    bool abandoned;        /* for mutex */
    char *name;            /* for named objects */
};


int do_ntsync(void)
{
    static int cached = -1;
    if (cached == -1)
    {
        const char *env = getenv("WINENTSYNC");
        cached = (env && atoi(env)) ? 1 : 0;
        TRACE("WINENTSYNC = %s => do_ntsync = %d\n", env, cached);

        if (cached)
        TRACE("✅ [ntsync] WINENTSYNC active — userspace backend started.\n");
    }
    return cached;
}

#define MAX_NTSYNC_OBJECTS  32768
static struct ntsync_object *object_table[MAX_NTSYNC_OBJECTS];
static pthread_mutex_t table_lock = PTHREAD_MUTEX_INITIALIZER;

static inline HANDLE make_handle(int index)
{
    return (HANDLE)(uintptr_t)((index + 1) << 2);
}

static inline int handle_to_index(HANDLE handle)
{
    return (((uintptr_t)handle) >> 2) - 1;
}

NTSTATUS ntsync_create_event(HANDLE *handle, ACCESS_MASK access,
    const OBJECT_ATTRIBUTES *attr, EVENT_TYPE type, BOOLEAN initial)
{
    struct ntsync_object *obj = NULL;
    struct object_attributes *objattr = NULL;
    data_size_t len;
    int i;

    TRACE("creating %s-reset event, initial=%d\n",
        type == NotificationEvent ? "manual" : "auto", initial);

    obj = calloc(1, sizeof(*obj));
    if (!obj) return STATUS_NO_MEMORY;

    if (alloc_object_attributes(attr, &objattr, &len)) {
        free(obj);
        return STATUS_INVALID_PARAMETER;
    }

    if (objattr->name)
        obj->name = strdup(objattr->name);

    obj->type = NTSYNC_TYPE_EVENT;
    obj->signaled = initial;
    obj->manual_reset = (type == NotificationEvent);
    obj->refcount = 1;

    pthread_mutex_init(&obj->lock, NULL);
    pthread_cond_init(&obj->cond, NULL);

    pthread_mutex_lock(&table_lock);
    for (i = 0; i < MAX_NTSYNC_OBJECTS; ++i)
    {
        if (!object_table[i])
        {
            object_table[i] = obj;
            *handle = make_handle(i);
            pthread_mutex_unlock(&table_lock);
            free(objattr);  // don't forget to release
            TRACE("created handle %p\n", *handle);
            return STATUS_SUCCESS;
        }
    }
    pthread_mutex_unlock(&table_lock);

    // cleaning when you can't go
    pthread_mutex_destroy(&obj->lock);
    pthread_cond_destroy(&obj->cond);
    free(obj->name);
    free(obj);
    free(objattr);
    return STATUS_TOO_MANY_OPENED_FILES;
}

NTSTATUS ntsync_set_event(HANDLE handle)
{
    int index = handle_to_index(handle);
    struct ntsync_object *obj;

    if (index < 0 || index >= MAX_NTSYNC_OBJECTS)
        return STATUS_INVALID_HANDLE;

    pthread_mutex_lock(&table_lock);
    obj = object_table[index];
    if (!obj || obj->type != NTSYNC_TYPE_EVENT)
    {
        pthread_mutex_unlock(&table_lock);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    pthread_mutex_lock(&obj->lock);
    pthread_mutex_unlock(&table_lock);

    obj->signaled = 1;

    if (obj->manual_reset)
        pthread_cond_broadcast(&obj->cond);
    else
        pthread_cond_signal(&obj->cond);

    pthread_mutex_unlock(&obj->lock);
    return STATUS_SUCCESS;
}

NTSTATUS ntsync_reset_event(HANDLE handle)
{
    int index = handle_to_index(handle);
    struct ntsync_object *obj;

    if (index < 0 || index >= MAX_NTSYNC_OBJECTS)
        return STATUS_INVALID_HANDLE;

    pthread_mutex_lock(&table_lock);
    obj = object_table[index];
    if (!obj || obj->type != NTSYNC_TYPE_EVENT)
    {
        pthread_mutex_unlock(&table_lock);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    pthread_mutex_lock(&obj->lock);
    pthread_mutex_unlock(&table_lock);

    obj->signaled = 0;

    pthread_mutex_unlock(&obj->lock);
    return STATUS_SUCCESS;
}

NTSTATUS ntsync_close(HANDLE handle) {
    int index = handle_to_index(handle);
    struct ntsync_object *obj;

    if (index < 0 || index >= MAX_NTSYNC_OBJECTS) return STATUS_INVALID_HANDLE;

    pthread_mutex_lock(&table_lock);
    obj = object_table[index];
    if (!obj) {
        pthread_mutex_unlock(&table_lock);
        return STATUS_INVALID_HANDLE;
    }

    obj->refcount--;
    if (obj->refcount <= 0) {
        object_table[index] = NULL;
        pthread_mutex_unlock(&table_lock);

        pthread_mutex_destroy(&obj->lock);
        pthread_cond_destroy(&obj->cond);

        if (obj->name)
            free(obj->name);

        free(obj);
    } else {
        pthread_mutex_unlock(&table_lock);
    }

    return STATUS_SUCCESS;
}

NTSTATUS ntsync_wait_objects(DWORD count, const HANDLE *handles, BOOLEAN wait_any,
                             BOOLEAN alertable, const LARGE_INTEGER *timeout)
{
    struct ntsync_object *objs[MAX_NTSYNC_OBJECTS];
    struct timespec ts;
    struct timeval tv;
    LONGLONG now_us, abs_us;
    DWORD tid = GetCurrentThreadId();
    NTSTATUS status = STATUS_SUCCESS;
    int i, ret;

    TRACE("[ntsync] Wait Objects (count=%u, wait_any=%d)\n", count, wait_any);

    if (!count || count > MAX_NTSYNC_OBJECTS)
        return STATUS_INVALID_PARAMETER;

    /* Lock global table and resolve all handles */
    pthread_mutex_lock(&table_lock);
    for (i = 0; i < count; i++) {
        int index = handle_to_index(handles[i]);
        if (index < 0 || index >= MAX_NTSYNC_OBJECTS || !object_table[index]) {
            pthread_mutex_unlock(&table_lock);
            return STATUS_INVALID_HANDLE;
        }
        objs[i] = object_table[index];
        pthread_mutex_lock(&objs[i]->lock);
    }
    pthread_mutex_unlock(&table_lock);

    if (wait_any) {
        while (1) {
            for (i = 0; i < count; i++) {
                struct ntsync_object *obj = objs[i];
                if ((obj->type == NTSYNC_TYPE_EVENT && obj->signaled) ||
                    (obj->type == NTSYNC_TYPE_SEMAPHORE && obj->count > 0) ||
                    (obj->type == NTSYNC_TYPE_MUTEX && (obj->owner_tid == 0 || obj->owner_tid == tid))) {
                    goto satisfied;
                }
            }

            // Wait only for the first object (simplified implementation)
            struct ntsync_object *wait_obj = objs[0];

            if (timeout) {
                gettimeofday(&tv, NULL);
                now_us = tv.tv_sec * 1000000LL + tv.tv_usec;
                abs_us = now_us + (-timeout->QuadPart / 10);
                ts.tv_sec = abs_us / 1000000;
                ts.tv_nsec = (abs_us % 1000000) * 1000;

                ret = pthread_cond_timedwait(&wait_obj->cond, &wait_obj->lock, &ts);
                if (ret == ETIMEDOUT) {
                    status = STATUS_TIMEOUT;
                    goto done;
                }
            } else {
                pthread_cond_wait(&wait_obj->cond, &wait_obj->lock);
            }
        }
    }
    else
    {
        while (1) {
            bool all_ready = true;
            for (i = 0; i < count; i++) {
                struct ntsync_object *obj = objs[i];

                if (obj->type == NTSYNC_TYPE_MUTEX && obj->owner_tid != 0 && obj->owner_tid != tid) {
                    // TODO: real thread ownership detection on macOS
                    obj->abandoned = true;
                    obj->owner_tid = 0;
                    obj->count = 0;
                }

                if ((obj->type == NTSYNC_TYPE_EVENT && !obj->signaled) ||
                    (obj->type == NTSYNC_TYPE_SEMAPHORE && obj->count == 0) ||
                    (obj->type == NTSYNC_TYPE_MUTEX && obj->owner_tid != 0 && obj->owner_tid != tid)) {
                    all_ready = false;
                    break;
                }
            }
            if (all_ready) goto satisfied;

            struct ntsync_object *wait_obj = objs[0];

            if (timeout) {
                gettimeofday(&tv, NULL);
                now_us = tv.tv_sec * 1000000LL + tv.tv_usec;
                abs_us = now_us + (-timeout->QuadPart / 10);
                ts.tv_sec = abs_us / 1000000;
                ts.tv_nsec = (abs_us % 1000000) * 1000;

                ret = pthread_cond_timedwait(&wait_obj->cond, &wait_obj->lock, &ts);
                if (ret == ETIMEDOUT) {
                    status = STATUS_TIMEOUT;
                    goto done;
                }
            } else {
                pthread_cond_wait(&wait_obj->cond, &wait_obj->lock);
            }
        }
    }
    satisfied:
        for (i = 0; i < count; i++) {
            struct ntsync_object *obj = objs[i];
            switch (obj->type) {
            case NTSYNC_TYPE_EVENT:
                if (!obj->manual_reset)
                    obj->signaled = 0;
                break;
            case NTSYNC_TYPE_SEMAPHORE:
                obj->count--;
                break;
            case NTSYNC_TYPE_MUTEX:
                if (obj->owner_tid == tid)
                    obj->count++;
                else {
                    obj->owner_tid = tid;
                    obj->count = 1;
                    obj->abandoned = false;
                }
                break;
            }
        }
        status = STATUS_SUCCESS;

        for (i = 0; i < count; i++)
            pthread_mutex_unlock(&objs[i]->lock);

        return status;
}


NTSTATUS ntsync_create_mutex(HANDLE *handle, ACCESS_MASK access,
    const OBJECT_ATTRIBUTES *attr, BOOLEAN initial)
{
    struct ntsync_object *obj;
    TRACE("✅ [ntsync]Create Mutex\n");
    obj = calloc(1, sizeof(*obj));
    if (!obj) return STATUS_NO_MEMORY;

    obj->type = NTSYNC_TYPE_MUTEX;
    obj->refcount = 1;
    obj->count = initial ? 0 : 1;
    obj->owner_tid = initial ? GetCurrentThreadId() : 0;

    pthread_mutex_init(&obj->lock, NULL);
    pthread_cond_init(&obj->cond, NULL);

    pthread_mutex_lock(&table_lock);
    for (int i = 0; i < MAX_NTSYNC_OBJECTS; ++i)
    {
        if (!object_table[i])
        {
            object_table[i] = obj;
            *handle = make_handle(i);
            pthread_mutex_unlock(&table_lock);
            TRACE("created mutex handle %p (initial = %d)\n", *handle, initial);
            return STATUS_SUCCESS;
        }
    }
    pthread_mutex_unlock(&table_lock);

    pthread_mutex_destroy(&obj->lock);
    pthread_cond_destroy(&obj->cond);
    free(obj);
    return STATUS_TOO_MANY_OPENED_FILES;
}

NTSTATUS ntsync_release_mutex(HANDLE handle, LONG *prev)
{
    int index = handle_to_index(handle);
    struct ntsync_object *obj;
    TRACE("✅ [ntsync] Release Mutex\n");
    if (index < 0 || index >= MAX_NTSYNC_OBJECTS)
        return STATUS_INVALID_HANDLE;

    pthread_mutex_lock(&table_lock);
    obj = object_table[index];
    if (!obj || obj->type != NTSYNC_TYPE_MUTEX)
    {
        pthread_mutex_unlock(&table_lock);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    pthread_mutex_lock(&obj->lock);
    pthread_mutex_unlock(&table_lock);

    if (obj->owner_tid != GetCurrentThreadId())
    {
        pthread_mutex_unlock(&obj->lock);
        return STATUS_MUTANT_NOT_OWNED;
    }

    if (prev) *prev = obj->count;

    if (--obj->count == 0)
    {
        obj->owner_tid = 0;
        pthread_cond_signal(&obj->cond);
    }

    pthread_mutex_unlock(&obj->lock);
    return STATUS_SUCCESS;
}

NTSTATUS ntsync_create_semaphore(HANDLE *handle, ACCESS_MASK access,
    const OBJECT_ATTRIBUTES *attr, LONG initial, LONG max)
{
    struct ntsync_object *obj;
    int i;
    TRACE("✅ [ntsync] Create Semaphore\n");
    if (initial < 0 || max <= 0 || initial > max)
        return STATUS_INVALID_PARAMETER;

    obj = calloc(1, sizeof(*obj));
    if (!obj) return STATUS_NO_MEMORY;

    obj->type = NTSYNC_TYPE_SEMAPHORE;
    obj->refcount = 1;
    obj->count = initial;
    obj->max = max;

    pthread_mutex_init(&obj->lock, NULL);
    pthread_cond_init(&obj->cond, NULL);

    pthread_mutex_lock(&table_lock);
    for (i = 0; i < MAX_NTSYNC_OBJECTS; ++i)
    {
        if (!object_table[i])
        {
            object_table[i] = obj;
            *handle = make_handle(i);
            pthread_mutex_unlock(&table_lock);
            TRACE("created semaphore handle %p (init = %ld, max = %ld)\n", *handle, (long)initial, (long)max);
            return STATUS_SUCCESS;
        }
    }
    pthread_mutex_unlock(&table_lock);

    pthread_mutex_destroy(&obj->lock);
    pthread_cond_destroy(&obj->cond);
    free(obj);
    return STATUS_TOO_MANY_OPENED_FILES;
}

NTSTATUS ntsync_release_semaphore(HANDLE handle, ULONG count, ULONG *prev)
{
    int index = handle_to_index(handle);
    struct ntsync_object *obj;
    TRACE("✅ [ntsync] Realease Semaphore\n");
    if (index < 0 || index >= MAX_NTSYNC_OBJECTS)
        return STATUS_INVALID_HANDLE;

    pthread_mutex_lock(&table_lock);
    obj = object_table[index];
    if (!obj || obj->type != NTSYNC_TYPE_SEMAPHORE)
    {
        pthread_mutex_unlock(&table_lock);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    pthread_mutex_lock(&obj->lock);
    pthread_mutex_unlock(&table_lock);

    if ((obj->count + count) > obj->max)
    {
        pthread_mutex_unlock(&obj->lock);
        return STATUS_SEMAPHORE_LIMIT_EXCEEDED;
    }

    if (prev) *prev = obj->count;

    obj->count += count;
    pthread_cond_broadcast(&obj->cond);

    pthread_mutex_unlock(&obj->lock);
    return STATUS_SUCCESS;
}

NTSTATUS ntsync_query_event(HANDLE handle, void *info, ULONG *ret_len)
{
    int index = handle_to_index(handle);
    struct ntsync_object *obj;
    EVENT_BASIC_INFORMATION *out = info;

    if (index < 0 || index >= MAX_NTSYNC_OBJECTS) return STATUS_INVALID_HANDLE;

    pthread_mutex_lock(&table_lock);
    obj = object_table[index];
    if (!obj || obj->type != NTSYNC_TYPE_EVENT)
    {
        pthread_mutex_unlock(&table_lock);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    pthread_mutex_lock(&obj->lock);
    pthread_mutex_unlock(&table_lock);

    out->EventType = obj->manual_reset ? NotificationEvent : SynchronizationEvent;
    out->EventState = obj->signaled;

    if (ret_len) *ret_len = sizeof(*out);

    pthread_mutex_unlock(&obj->lock);
    return STATUS_SUCCESS;
}

NTSTATUS ntsync_query_mutex(HANDLE handle, void *info, ULONG *ret_len)
{
    int index = handle_to_index(handle);
    struct ntsync_object *obj;
    MUTANT_BASIC_INFORMATION *out = info;

    if (index < 0 || index >= MAX_NTSYNC_OBJECTS)
        return STATUS_INVALID_HANDLE;

    pthread_mutex_lock(&table_lock);
    obj = object_table[index];
    if (!obj || obj->type != NTSYNC_TYPE_MUTEX)
    {
        pthread_mutex_unlock(&table_lock);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    pthread_mutex_lock(&obj->lock);
    pthread_mutex_unlock(&table_lock);

    out->CurrentCount = obj->owner_tid ? 0 : 1;
    out->OwnedByCaller = (obj->owner_tid == GetCurrentThreadId());
    out->AbandonedState = obj->abandoned ? TRUE : FALSE;

    if (ret_len)
        *ret_len = sizeof(*out);

    pthread_mutex_unlock(&obj->lock);
    return STATUS_SUCCESS;
}

NTSTATUS ntsync_query_semaphore(HANDLE handle, void *info, ULONG *ret_len)
{
    int index = handle_to_index(handle);
    struct ntsync_object *obj;
    SEMAPHORE_BASIC_INFORMATION *out = info;
    TRACE("✅ [ntsync] Query Semaphore\n");
    if (index < 0 || index >= MAX_NTSYNC_OBJECTS) return STATUS_INVALID_HANDLE;

    pthread_mutex_lock(&table_lock);
    obj = object_table[index];
    if (!obj || obj->type != NTSYNC_TYPE_SEMAPHORE)
    {
        pthread_mutex_unlock(&table_lock);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    pthread_mutex_lock(&obj->lock);
    pthread_mutex_unlock(&table_lock);

    out->CurrentCount = obj->count;
    out->MaximumCount = obj->max;

    if (ret_len) *ret_len = sizeof(*out);

    pthread_mutex_unlock(&obj->lock);
    return STATUS_SUCCESS;
}

NTSTATUS ntsync_signal_and_wait(HANDLE signal, HANDLE wait, BOOLEAN alertable,
                                const LARGE_INTEGER *timeout)
{
    int index;
    struct ntsync_object *sig;
    TRACE("✅ [ntsync] Signal Wait\n");
    index = handle_to_index(signal);
    if (index < 0 || index >= MAX_NTSYNC_OBJECTS)
        return STATUS_INVALID_HANDLE;

    pthread_mutex_lock(&table_lock);
    sig = object_table[index];
    if (!sig)
    {
        pthread_mutex_unlock(&table_lock);
        return STATUS_INVALID_HANDLE;
    }


    pthread_mutex_lock(&sig->lock);
    pthread_mutex_unlock(&table_lock);

    if (sig->type == NTSYNC_TYPE_EVENT)
    {
        sig->signaled = 1;
        if (sig->manual_reset)
            pthread_cond_broadcast(&sig->cond);
        else
            pthread_cond_signal(&sig->cond);
    }
    else if (sig->type == NTSYNC_TYPE_MUTEX)
    {
        if (sig->owner_tid != GetCurrentThreadId())
        {
            pthread_mutex_unlock(&sig->lock);
            return STATUS_MUTANT_NOT_OWNED;
        }

        if (--sig->count == 0)
        {
            sig->owner_tid = 0;
            pthread_cond_signal(&sig->cond);
        }
    }
    else if (sig->type == NTSYNC_TYPE_SEMAPHORE)
    {
        if (sig->count + 1 > sig->max)
        {
            pthread_mutex_unlock(&sig->lock);
            return STATUS_SEMAPHORE_LIMIT_EXCEEDED;
        }
        sig->count++;
        pthread_cond_signal(&sig->cond);
    }
    else
    {
        pthread_mutex_unlock(&sig->lock);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    pthread_mutex_unlock(&sig->lock);

    // Wait
    return ntsync_wait_objects(1, &wait, TRUE, alertable, timeout);
}

NTSTATUS ntsync_open_event(HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr)
{
    data_size_t len;
    struct object_attributes *objattr;
    struct ntsync_object *obj = NULL;

    TRACE("[ntsync] OpenEvent\n");

    *handle = 0;

    if (!handle || !attr)
        return STATUS_INVALID_PARAMETER;

    if (alloc_object_attributes(attr, &objattr, &len))
        return STATUS_INSUFFICIENT_RESOURCES;

    pthread_mutex_lock(&table_lock);

    for (int i = 0; i < MAX_NTSYNC_OBJECTS; i++) {
        struct ntsync_object *candidate = object_table[i];

        if (!candidate || candidate->type != NTSYNC_TYPE_EVENT || !candidate->name)
            continue;

        if (objattr->name && strcmp(candidate->name, objattr->name) == 0) {
            candidate->refcount++;
            *handle = index_to_handle(i);
            obj = candidate;
            break;
        }
    }

    pthread_mutex_unlock(&table_lock);
    free(objattr);

    if (!obj)
        return STATUS_OBJECT_NAME_NOT_FOUND;

    return STATUS_SUCCESS;
}

NTSTATUS ntsync_open_mutex(HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr)
{
    data_size_t len;
    struct object_attributes *objattr;
    struct ntsync_object *obj = NULL;

    TRACE("[ntsync] OpenMutex\n");

    *handle = 0;

    if (!handle || !attr)
        return STATUS_INVALID_PARAMETER;

    if (alloc_object_attributes(attr, &objattr, &len))
        return STATUS_INSUFFICIENT_RESOURCES;

    pthread_mutex_lock(&table_lock);

    for (int i = 0; i < MAX_NTSYNC_OBJECTS; i++) {
        struct ntsync_object *candidate = object_table[i];

        if (!candidate || candidate->type != NTSYNC_TYPE_MUTEX || !candidate->name)
            continue;

        if (objattr->name && strcmp(candidate->name, objattr->name) == 0) {
            candidate->refcount++;
            *handle = index_to_handle(i);
            obj = candidate;
            break;
        }
    }

    pthread_mutex_unlock(&table_lock);
    free(objattr);

    return obj ? STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND;
}

NTSTATUS ntsync_open_semaphore(HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr)
{
    data_size_t len;
    struct object_attributes *objattr;
    struct ntsync_object *obj = NULL;

    TRACE("[ntsync] Open Semaphore\n");

    *handle = 0;

    if (!handle || !attr)
        return STATUS_INVALID_PARAMETER;

    if (alloc_object_attributes(attr, &objattr, &len))
        return STATUS_INSUFFICIENT_RESOURCES;

    pthread_mutex_lock(&table_lock);

    for (int i = 0; i < MAX_NTSYNC_OBJECTS; i++) {
        struct ntsync_object *candidate = object_table[i];

        if (!candidate || candidate->type != NTSYNC_TYPE_SEMAPHORE || !candidate->name)
            continue;

        if (objattr->name && strcmp(candidate->name, objattr->name) == 0) {
            candidate->refcount++;
            *handle = index_to_handle(i);
            obj = candidate;
            break;
        }
    }

    pthread_mutex_unlock(&table_lock);
    free(objattr);

    return obj ? STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND;
}

NTSTATUS ntsync_query_object(HANDLE handle, void *info, ULONG *ret_len, OBJECT_INFORMATION_CLASS info_class)
{
    TRACE("[ntsync] QueryObject\n");

    if (!info || !ret_len)
        return STATUS_INVALID_PARAMETER;

    int index = handle_to_index(handle);
    if (index < 0 || index >= MAX_NTSYNC_OBJECTS)
        return STATUS_INVALID_HANDLE;

    pthread_mutex_lock(&table_lock);
    struct ntsync_object *obj = object_table[index];
    if (!obj) {
        pthread_mutex_unlock(&table_lock);
        return STATUS_INVALID_HANDLE;
    }

    switch (info_class) {
        case ObjectTypeInformation: {
            const char *type_str = NULL;
            switch (obj->type) {
                case NTSYNC_TYPE_EVENT:     type_str = "Event"; break;
                case NTSYNC_TYPE_MUTEX:     type_str = "Mutant"; break;
                case NTSYNC_TYPE_SEMAPHORE: type_str = "Semaphore"; break;
                default: type_str = "Unknown"; break;
            }
            size_t len = strlen(type_str);
            memcpy(info, type_str, len);
            *ret_len = len;
            break;
        }

        case ObjectNameInformation: {
            if (obj->name) {
                size_t len = strlen(obj->name);
                memcpy(info, obj->name, len);
                *ret_len = len;
            } else {
                *ret_len = 0;
            }
            break;
        }

        default:
            pthread_mutex_unlock(&table_lock);
            return STATUS_NOT_IMPLEMENTED;
    }

    pthread_mutex_unlock(&table_lock);
    return STATUS_SUCCESS;
}

NTSTATUS ntsync_pulse_event(HANDLE handle)
{
    int index = handle_to_index(handle);
    struct ntsync_object *obj;

    TRACE("PulseEvent on handle %p\n", handle);

    if (index < 0 || index >= MAX_NTSYNC_OBJECTS)
        return STATUS_INVALID_HANDLE;

    pthread_mutex_lock(&table_lock);
    obj = object_table[index];
    if (!obj || obj->type != NTSYNC_TYPE_EVENT)
    {
        pthread_mutex_unlock(&table_lock);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    pthread_mutex_lock(&obj->lock);
    pthread_mutex_unlock(&table_lock);

    obj->signaled = 1;

    if (obj->manual_reset)
        pthread_cond_broadcast(&obj->cond);
    else
        pthread_cond_signal(&obj->cond);

    obj->signaled = 0;

    pthread_mutex_unlock(&obj->lock);
    return STATUS_SUCCESS;
}

#ifndef __WINE_PE_BUILD__
static pthread_once_t ntsync_once = PTHREAD_ONCE_INIT;

static void ntsync_lazy_init(void)
{
    if (!do_ntsync())
    {
        TRACE("ntsync is disabled via WINENTSYNC\n");
        return;
    }

    TRACE("✅ ntsync userspace backend active\n");
}

void ntsync_init(void)
{
    pthread_once(&ntsync_once, ntsync_lazy_init);
}
#else
#error "ntsync.c is only for UNIX, not for PE builds"
#endif
