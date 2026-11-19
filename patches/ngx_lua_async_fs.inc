
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#include <sys/stat.h>

#include <ngx_thread.h>
#include <ngx_thread_pool.h>


#define NGX_LUA_FS_OP_OPEN         0
#define NGX_LUA_FS_OP_READ         1
#define NGX_LUA_FS_OP_WRITE        2
#define NGX_LUA_FS_OP_STAT         3
#define NGX_LUA_FS_OP_READ_FILE    4
#define NGX_LUA_FS_OP_APPEND_FILE  5

#define NGX_LUA_FS_FILE_MT         "ngx_lua_fs_file"
#define NGX_LUA_FS_POOL_NAME_MAX   64
#define NGX_LUA_FS_FILE_SIZE       ((size_t) -1)

/* LuaJIT strings are smaller than 0x7fffff00 bytes. */
#define NGX_LUA_FS_MAX_SIZE        0x7ffffeff


typedef struct {
    ngx_fd_t     fd;
    ngx_uint_t   ninflight;
    unsigned     append:1;
    unsigned     closed:1;
    unsigned     orphaned:1;
} ngx_lua_fs_fd_ref_t;


typedef struct {
    ngx_lua_fs_fd_ref_t  *ref;
    u_char                     pool_name[NGX_LUA_FS_POOL_NAME_MAX];
    size_t                     pool_name_len;
} ngx_lua_fs_file_t;


typedef struct {
    ngx_uint_t               op;

    /* open params */
    u_char                  *path;
    int                      flags;

    /* read/write params */
    ngx_fd_t                 fd;
    u_char                  *buf;
    size_t                   size;
    off_t                    offset;

    ngx_lua_fs_fd_ref_t  *ref;

    ssize_t                  nbytes;
    ngx_fd_t                 result_fd;
    ngx_err_t                err;
    struct stat              fi;

    u_char                   pool_name[NGX_LUA_FS_POOL_NAME_MAX];
    size_t                   pool_name_len;

    ngx_lua_fs_co_ctx_t   *wait_co_ctx;
    int                      nresults;

    unsigned                 is_abort:1;
} ngx_lua_fs_ctx_t;


static int ngx_lua_fs_result(lua_State *L);
static ngx_str_t ngx_lua_fs_check_pool(lua_State *L, int index);
static off_t ngx_lua_fs_check_offset(lua_State *L, int index);
static int ngx_lua_fs_open(lua_State *L);
static int ngx_lua_fs_stat(lua_State *L);
static int ngx_lua_fs_read_file(lua_State *L);
static int ngx_lua_fs_append_file(lua_State *L);

static int ngx_lua_fs_file_read(lua_State *L);
static int ngx_lua_fs_file_write(lua_State *L);
static int ngx_lua_fs_file_close(lua_State *L);
static int ngx_lua_fs_file_gc(lua_State *L);
static int ngx_lua_fs_file_tostring(lua_State *L);

static void ngx_lua_fs_read_file_handler(ngx_lua_fs_ctx_t *fs_ctx,
    ngx_log_t *log);
static void ngx_lua_fs_thread_handler(void *data, ngx_log_t *log);
static void ngx_lua_fs_event_handler(ngx_event_t *ev);
static void ngx_lua_fs_cleanup(void *data);
static ngx_lua_fs_co_ctx_t *ngx_lua_fs_check_context(lua_State *L);
static void ngx_lua_fs_complete(ngx_lua_fs_ctx_t *fs_ctx);


static void
ngx_lua_fs_fd_ref_release(ngx_lua_fs_fd_ref_t *ref)
{
    if (!ref->closed) {
        if (ngx_close_file(ref->fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                          "lua async fs: close(%d) failed", ref->fd);
        }
    }

    ngx_free(ref);
}


static ngx_thread_task_t *
ngx_lua_fs_task_alloc(size_t size)
{
    ngx_thread_task_t      *task;
    ngx_lua_fs_ctx_t  *fs_ctx;

    task = ngx_calloc(sizeof(ngx_thread_task_t) + size, ngx_cycle->log);
    if (task == NULL) {
        return NULL;
    }

    fs_ctx = (void *) (task + 1);
    fs_ctx->result_fd = NGX_INVALID_FILE;
    task->ctx = fs_ctx;

    return task;
}


static void
ngx_lua_fs_task_free(ngx_lua_fs_ctx_t *fs_ctx)
{
    ngx_thread_task_t        *task;
    ngx_lua_fs_fd_ref_t  *ref;

    ref = fs_ctx->ref;

    if (ref != NULL) {
        ref->ninflight--;

        if (ref->orphaned && ref->ninflight == 0) {
            ngx_lua_fs_fd_ref_release(ref);
        }
    }

    if (fs_ctx->result_fd != NGX_INVALID_FILE
        && ngx_close_file(fs_ctx->result_fd) == NGX_FILE_ERROR)
    {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      "lua async fs: close(%d) failed", fs_ctx->result_fd);
    }

    if (fs_ctx->path != NULL) {
        ngx_free(fs_ctx->path);
    }

    if (fs_ctx->buf != NULL) {
        ngx_free(fs_ctx->buf);
    }

    task = (ngx_thread_task_t *) fs_ctx - 1;
    ngx_free(task);
}


static ngx_fd_t
ngx_lua_fs_open_fd(u_char *path, int flags)
{
    ngx_fd_t  fd;

    flags |= NGX_FILE_NONBLOCK;

#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif

    do {
        fd = ngx_open_file(path, flags, 0, NGX_FILE_DEFAULT_ACCESS);
    } while (fd == NGX_INVALID_FILE && ngx_errno == NGX_EINTR);

    return fd;
}


static void
ngx_lua_fs_read_file_handler(ngx_lua_fs_ctx_t *fs_ctx, ngx_log_t *log)
{
    u_char           *buf;
    size_t            capacity, len, limit;
    ssize_t           n;
    ngx_fd_t          fd;
    ngx_file_info_t   fi;

    fd = ngx_lua_fs_open_fd(fs_ctx->path, NGX_FILE_RDONLY);
    if (fd == NGX_INVALID_FILE) {
        fs_ctx->err = ngx_errno;
        return;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        fs_ctx->err = ngx_errno;
        goto done;
    }

    if (!ngx_is_file(&fi)) {
        fs_ctx->err = NGX_EINVAL;
        goto done;
    }

    limit = fs_ctx->size;

    if (ngx_file_size(&fi) < 0
        || ngx_file_size(&fi) > NGX_LUA_FS_MAX_SIZE
        || (limit != NGX_LUA_FS_FILE_SIZE
            && (uint64_t) ngx_file_size(&fi) > limit))
    {
        fs_ctx->err = EFBIG;
        goto done;
    }

    capacity = (size_t) ngx_file_size(&fi) + 1;

    if (limit == NGX_LUA_FS_FILE_SIZE) {
        limit = capacity - 1;
    }

    limit = ngx_min(limit, NGX_LUA_FS_MAX_SIZE);

    buf = ngx_alloc(capacity, log);
    if (buf == NULL) {
        fs_ctx->err = NGX_ENOMEM;
        goto done;
    }

    fs_ctx->buf = buf;
    len = 0;

    for ( ;; ) {
        n = ngx_read_fd(fd, buf + len, capacity - len);

        if (n == NGX_FILE_ERROR) {
            if (ngx_errno == NGX_EINTR) {
                continue;
            }

            fs_ctx->err = ngx_errno;
            goto done;
        }

        if (n == 0) {
            fs_ctx->nbytes = len;
            break;
        }

        len += n;

        if (len < capacity) {
            continue;
        }

        if (len > limit) {
            fs_ctx->err = EFBIG;
            goto done;
        }

        capacity += ngx_min(capacity, limit + 1 - capacity);
        buf = ngx_alloc(capacity, log);
        if (buf == NULL) {
            fs_ctx->err = NGX_ENOMEM;
            goto done;
        }

        ngx_memcpy(buf, fs_ctx->buf, len);
        ngx_free(fs_ctx->buf);
        fs_ctx->buf = buf;
    }

done:

    if (ngx_close_file(fd) == NGX_FILE_ERROR && fs_ctx->err == 0) {
        fs_ctx->err = ngx_errno;
    }
}


static void
ngx_lua_fs_thread_handler(void *data, ngx_log_t *log)
{
    ngx_lua_fs_ctx_t  *fs_ctx = data;

    int       rc;
    ngx_fd_t  fd;

    switch (fs_ctx->op) {

    case NGX_LUA_FS_OP_OPEN:
        ngx_log_debug1(NGX_LUA_FS_DEBUG, log, 0,
                       "lua async fs: open \"%s\"", fs_ctx->path);

        fs_ctx->result_fd = ngx_lua_fs_open_fd(fs_ctx->path,
                                                   fs_ctx->flags);

        if (fs_ctx->result_fd == -1) {
            fs_ctx->err = ngx_errno;
        }

        break;

    case NGX_LUA_FS_OP_READ:
        ngx_log_debug3(NGX_LUA_FS_DEBUG, log, 0,
                       "lua async fs: pread fd=%d size=%uz offset=%O",
                       fs_ctx->fd, fs_ctx->size, fs_ctx->offset);

        fs_ctx->buf = ngx_alloc(fs_ctx->size, log);
        if (fs_ctx->buf == NULL) {
            fs_ctx->err = NGX_ENOMEM;
            break;
        }

        do {
            fs_ctx->nbytes = pread(fs_ctx->fd, fs_ctx->buf, fs_ctx->size,
                                  fs_ctx->offset);
        } while (fs_ctx->nbytes == -1 && ngx_errno == NGX_EINTR);

        if (fs_ctx->nbytes == -1) {
            fs_ctx->err = ngx_errno;
        }

        break;

    case NGX_LUA_FS_OP_WRITE:
        ngx_log_debug3(NGX_LUA_FS_DEBUG, log, 0,
                       "lua async fs: pwrite fd=%d size=%uz offset=%O",
                       fs_ctx->fd, fs_ctx->size, fs_ctx->offset);

        do {
            if (fs_ctx->flags & O_APPEND) {
                fs_ctx->nbytes = ngx_write_fd(fs_ctx->fd, fs_ctx->buf,
                                             fs_ctx->size);
            } else {
                fs_ctx->nbytes = pwrite(fs_ctx->fd, fs_ctx->buf, fs_ctx->size,
                                       fs_ctx->offset);
            }
        } while (fs_ctx->nbytes == -1 && ngx_errno == NGX_EINTR);

        if (fs_ctx->nbytes == -1) {
            fs_ctx->err = ngx_errno;
        }

        break;

    case NGX_LUA_FS_OP_STAT:
        ngx_log_debug1(NGX_LUA_FS_DEBUG, log, 0,
                       "lua async fs: lstat \"%s\"", fs_ctx->path);

        do {
            rc = lstat((const char *) fs_ctx->path, &fs_ctx->fi);
        } while (rc == -1 && ngx_errno == NGX_EINTR);

        if (rc == -1) {
            fs_ctx->err = ngx_errno;
        }

        break;

    case NGX_LUA_FS_OP_READ_FILE:
        ngx_lua_fs_read_file_handler(fs_ctx, log);
        break;

    case NGX_LUA_FS_OP_APPEND_FILE:
        fd = ngx_lua_fs_open_fd(fs_ctx->path,
                                    NGX_FILE_APPEND | NGX_FILE_CREATE_OR_OPEN);
        if (fd == NGX_INVALID_FILE) {
            fs_ctx->err = ngx_errno;
            break;
        }

        do {
            fs_ctx->nbytes = ngx_write_fd(fd, fs_ctx->buf, fs_ctx->size);
        } while (fs_ctx->nbytes == NGX_FILE_ERROR && ngx_errno == NGX_EINTR);

        if (fs_ctx->nbytes == NGX_FILE_ERROR) {
            fs_ctx->err = ngx_errno;
        }

        if (ngx_close_file(fd) == NGX_FILE_ERROR && fs_ctx->err == 0) {
            fs_ctx->err = ngx_errno;
        }

        break;

    default:
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "lua async fs: unknown op %ui", fs_ctx->op);
        break;
    }
}


static void
ngx_lua_fs_push_stat_table(lua_State *L, struct stat *fi)
{
    lua_createtable(L, 0, 12);

    lua_pushinteger(L, (lua_Integer) fi->st_size);
    lua_setfield(L, -2, "size");

    lua_pushinteger(L, (lua_Integer) fi->st_mtime);
    lua_setfield(L, -2, "mtime");

    lua_pushinteger(L, (lua_Integer) fi->st_atime);
    lua_setfield(L, -2, "atime");

    lua_pushinteger(L, (lua_Integer) fi->st_ctime);
    lua_setfield(L, -2, "ctime");

    lua_pushinteger(L, (lua_Integer) fi->st_mode);
    lua_setfield(L, -2, "mode");

    lua_pushinteger(L, (lua_Integer) fi->st_ino);
    lua_setfield(L, -2, "ino");

    lua_pushinteger(L, (lua_Integer) fi->st_nlink);
    lua_setfield(L, -2, "nlink");

    lua_pushinteger(L, (lua_Integer) fi->st_uid);
    lua_setfield(L, -2, "uid");

    lua_pushinteger(L, (lua_Integer) fi->st_gid);
    lua_setfield(L, -2, "gid");

    lua_pushboolean(L, S_ISDIR(fi->st_mode));
    lua_setfield(L, -2, "is_dir");

    lua_pushboolean(L, S_ISREG(fi->st_mode));
    lua_setfield(L, -2, "is_file");

    lua_pushboolean(L, S_ISLNK(fi->st_mode));
    lua_setfield(L, -2, "is_link");
}


static int
ngx_lua_fs_result(lua_State *L)
{
    int                       nresults;
    u_char                    msg[NGX_INT_T_LEN + 40], *last;
    ngx_lua_fs_ctx_t     *fs_ctx;
    ngx_lua_fs_file_t    *file;
    ngx_lua_fs_fd_ref_t  *ref;

    fs_ctx = lua_touserdata(L, 1);

    switch (fs_ctx->op) {

    case NGX_LUA_FS_OP_OPEN:
        if (fs_ctx->err) {
            lua_pushnil(L);
            lua_pushfstring(L, "open() \"%s\" failed (%d: %s)",
                            fs_ctx->path, (int) fs_ctx->err,
                            strerror(fs_ctx->err));
            nresults = 2;

        } else {
            file = lua_newuserdata(L, sizeof(ngx_lua_fs_file_t));
            file->ref = NULL;
            luaL_getmetatable(L, NGX_LUA_FS_FILE_MT);
            lua_setmetatable(L, -2);

            ref = ngx_calloc(sizeof(ngx_lua_fs_fd_ref_t),
                             ngx_cycle->log);

            if (ref == NULL) {
                lua_pop(L, 1);
                lua_pushnil(L);
                lua_pushliteral(L, "no memory for fd ref");
                nresults = 2;
                break;
            }

            ref->fd = fs_ctx->result_fd;
            ref->append = (fs_ctx->flags & O_APPEND) != 0;

            file->ref = ref;
            fs_ctx->result_fd = NGX_INVALID_FILE;
            file->pool_name_len = fs_ctx->pool_name_len;
            ngx_memcpy(file->pool_name, fs_ctx->pool_name,
                       fs_ctx->pool_name_len);
            file->pool_name[file->pool_name_len] = '\0';

            nresults = 1;
        }

        break;

    case NGX_LUA_FS_OP_READ:
        if (fs_ctx->err) {
            lua_pushnil(L);
            lua_pushfstring(L, "pread() failed (%d: %s)",
                            (int) fs_ctx->err, strerror(fs_ctx->err));
            nresults = 2;

        } else if (fs_ctx->nbytes == 0) {
            lua_pushliteral(L, "");
            nresults = 1;

        } else {
            lua_pushlstring(L, (const char *) fs_ctx->buf,
                            (size_t) fs_ctx->nbytes);
            nresults = 1;
        }

        break;

    case NGX_LUA_FS_OP_READ_FILE:
        if (fs_ctx->err) {
            lua_pushnil(L);

            if (fs_ctx->err == EFBIG
                && fs_ctx->size != NGX_LUA_FS_FILE_SIZE)
            {
                last = ngx_snprintf(msg, sizeof(msg),
                                    "file exceeds the maximum size %uz",
                                    fs_ctx->size);
                lua_pushlstring(L, (char *) msg, last - msg);

            } else {
                lua_pushfstring(L, "read_file() failed (%d: %s)",
                                (int) fs_ctx->err, strerror(fs_ctx->err));
            }

            nresults = 2;

        } else {
            lua_pushlstring(L, (char *) fs_ctx->buf, fs_ctx->nbytes);
            nresults = 1;
        }

        break;

    case NGX_LUA_FS_OP_APPEND_FILE:
        if (fs_ctx->err) {
            lua_pushnil(L);
            lua_pushfstring(L, "append_file() failed (%d: %s)",
                            (int) fs_ctx->err, strerror(fs_ctx->err));
            nresults = 2;

        } else {
            lua_pushinteger(L, (lua_Integer) fs_ctx->nbytes);
            nresults = 1;
        }

        break;

    case NGX_LUA_FS_OP_WRITE:
        if (fs_ctx->err) {
            lua_pushnil(L);
            lua_pushfstring(L, "pwrite() failed (%d: %s)",
                            (int) fs_ctx->err, strerror(fs_ctx->err));
            nresults = 2;

        } else {
            lua_pushinteger(L, (lua_Integer) fs_ctx->nbytes);
            nresults = 1;
        }

        break;

    case NGX_LUA_FS_OP_STAT:
        if (fs_ctx->err) {
            lua_pushnil(L);
            lua_pushfstring(L, "stat() \"%s\" failed (%d: %s)",
                            fs_ctx->path, (int) fs_ctx->err,
                            strerror(fs_ctx->err));
            nresults = 2;

        } else {
            ngx_lua_fs_push_stat_table(L, &fs_ctx->fi);
            nresults = 1;
        }

        break;

    default:
        lua_pushnil(L);
        lua_pushliteral(L, "unknown fs operation");
        nresults = 2;
        break;
    }

    lua_xmove(L, fs_ctx->wait_co_ctx->co, nresults);
    fs_ctx->nresults = nresults;

    return 0;
}


static int
ngx_lua_fs_deliver(lua_State *vm, ngx_lua_fs_ctx_t *fs_ctx)
{
    int         nresults;
    lua_State  *L;

    /*
     * Build results on the main Lua thread inside a protected call.
     * The waiting coroutine is suspended.
     */
    L = fs_ctx->wait_co_ctx->co;

    if (lua_cpcall(vm, ngx_lua_fs_result, fs_ctx) != 0) {
        lua_pushnil(L);
        lua_xmove(vm, L, 1);
        fs_ctx->nresults = 2;
    }

    nresults = fs_ctx->nresults;
    ngx_lua_fs_task_free(fs_ctx);

    return nresults;
}


static void
ngx_lua_fs_event_handler(ngx_event_t *ev)
{
    ngx_lua_fs_ctx_t     *fs_ctx;
    ngx_lua_fs_co_ctx_t  *coctx;

    fs_ctx = ev->data;

    if (fs_ctx->is_abort) {
        ngx_lua_fs_task_free(fs_ctx);
        return;
    }

    coctx = fs_ctx->wait_co_ctx;
    coctx->cleanup = NULL;
    coctx->data = NULL;

    ngx_lua_fs_complete(fs_ctx);
}


static void
ngx_lua_fs_cleanup(void *data)
{
    ngx_lua_fs_co_ctx_t      *coctx = data;
    ngx_lua_fs_ctx_t      *fs_ctx;

    fs_ctx = coctx->data;
    fs_ctx->is_abort = 1;
    coctx->data = NULL;
}


static int
ngx_lua_fs_post_task(lua_State *L, ngx_lua_fs_co_ctx_t *coctx,
    ngx_lua_fs_ctx_t *fs_ctx, ngx_str_t *pool_name)
{
    ngx_thread_pool_t          *tp;
    ngx_thread_task_t          *task;

    tp = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, pool_name);

    if (tp == NULL) {
        ngx_lua_fs_task_free(fs_ctx);

        lua_pushnil(L);
        lua_pushliteral(L, "thread pool \"");
        lua_pushlstring(L, (char *) pool_name->data, pool_name->len);
        lua_pushliteral(L, "\" not found");
        lua_concat(L, 3);
        return 2;
    }

    task = (ngx_thread_task_t *) fs_ctx - 1;

    fs_ctx->wait_co_ctx = coctx;

    ngx_lua_fs_cleanup_pending_operation(coctx);
    coctx->cleanup = ngx_lua_fs_cleanup;
    coctx->data = fs_ctx;

    task->handler = ngx_lua_fs_thread_handler;
    task->event.handler = ngx_lua_fs_event_handler;
    task->event.data = fs_ctx;

    if (ngx_thread_task_post(tp, task) != NGX_OK) {
        coctx->cleanup = NULL;
        coctx->data = NULL;

        ngx_lua_fs_task_free(fs_ctx);

        lua_pushnil(L);
        lua_pushliteral(L, "thread pool task post failed");
        return 2;
    }

    return lua_yield(L, 0);
}


static ngx_str_t
ngx_lua_fs_check_pool(lua_State *L, int index)
{
    ngx_str_t  pool;

    pool.data = (u_char *) luaL_optlstring(L, index, "default_lua_io",
                                         &pool.len);

    luaL_argcheck(L, ngx_strlchr(pool.data, pool.data + pool.len, '\0') == NULL,
                  index, "thread pool name contains a zero byte");

    return pool;
}


static off_t
ngx_lua_fs_check_offset(lua_State *L, int index)
{
    lua_Number  n;

    n = luaL_optnumber(L, index, 0);
    luaL_argcheck(L, n >= 0 && n < (lua_Number) NGX_MAX_OFF_T_VALUE
                  && (lua_Number) (off_t) n == n, index, "invalid offset");

    return (off_t) n;
}


static int
ngx_lua_fs_open(lua_State *L)
{
    ngx_lua_fs_co_ctx_t  *coctx;
    ngx_thread_task_t          *task;
    ngx_lua_fs_ctx_t      *fs_ctx;
    const char                 *path;
    const char                 *mode;
    size_t                      path_len, mode_len;
    int                         flags;
    ngx_str_t                   pool_name;

    coctx = ngx_lua_fs_check_context(L);

    if (lua_gettop(L) < 1) {
        return luaL_error(L, "expecting at least 1 argument (path)");
    }

    path = luaL_checklstring(L, 1, &path_len);
    luaL_argcheck(L, ngx_strlchr((u_char *) path,
                  (u_char *) path + path_len, '\0') == NULL, 1,
                  "path contains a zero byte");

    mode = luaL_optlstring(L, 2, "r", &mode_len);
    pool_name = ngx_lua_fs_check_pool(L, 3);
    luaL_argcheck(L, pool_name.len < NGX_LUA_FS_POOL_NAME_MAX, 3,
                  "thread pool name too long");

    if (mode_len == 1 && mode[0] == 'r') {
        flags = O_RDONLY;

    } else if (mode_len == 1 && mode[0] == 'w') {
        flags = O_WRONLY | O_CREAT | O_TRUNC;

    } else if (mode_len == 1 && mode[0] == 'a') {
        flags = O_WRONLY | O_CREAT | O_APPEND;

    } else if (mode_len == 2 && mode[0] == 'r' && mode[1] == '+') {
        flags = O_RDWR;

    } else if (mode_len == 2 && mode[0] == 'w' && mode[1] == '+') {
        flags = O_RDWR | O_CREAT | O_TRUNC;

    } else {
        return luaL_error(L, "invalid mode \"%s\" "
                          "(expected \"r\", \"w\", \"a\", \"r+\", or \"w+\")",
                          mode);
    }

    task = ngx_lua_fs_task_alloc(sizeof(ngx_lua_fs_ctx_t));
    if (task == NULL) {
        return luaL_error(L, "no memory");
    }

    fs_ctx = task->ctx;

    fs_ctx->op = NGX_LUA_FS_OP_OPEN;
    fs_ctx->flags = flags;

    fs_ctx->path = ngx_alloc(path_len + 1, ngx_cycle->log);
    if (fs_ctx->path == NULL) {
        ngx_lua_fs_task_free(fs_ctx);
        return luaL_error(L, "no memory");
    }

    ngx_memcpy(fs_ctx->path, path, path_len);
    fs_ctx->path[path_len] = '\0';

    ngx_memcpy(fs_ctx->pool_name, pool_name.data, pool_name.len);
    fs_ctx->pool_name_len = pool_name.len;

    return ngx_lua_fs_post_task(L, coctx, fs_ctx, &pool_name);
}


static int
ngx_lua_fs_file_read(lua_State *L)
{
    ngx_lua_fs_co_ctx_t  *coctx;
    ngx_thread_task_t          *task;
    ngx_lua_fs_ctx_t      *fs_ctx;
    ngx_lua_fs_file_t     *file;
    lua_Number                  size;
    off_t                       offset;
    ngx_str_t                   pool_name;

    coctx = ngx_lua_fs_check_context(L);

    file = (ngx_lua_fs_file_t *)
               luaL_checkudata(L, 1, NGX_LUA_FS_FILE_MT);

    if (file->ref == NULL || file->ref->closed) {
        return luaL_error(L, "attempt to read from a closed file");
    }

    size = luaL_checknumber(L, 2);
    luaL_argcheck(L, size > 0 && size <= NGX_LUA_FS_MAX_SIZE
                  && (lua_Number) (size_t) size == size, 2, "invalid size");
    offset = ngx_lua_fs_check_offset(L, 3);

    pool_name.data = file->pool_name;
    pool_name.len = file->pool_name_len;

    task = ngx_lua_fs_task_alloc(sizeof(ngx_lua_fs_ctx_t));
    if (task == NULL) {
        return luaL_error(L, "no memory");
    }

    fs_ctx = task->ctx;

    fs_ctx->op = NGX_LUA_FS_OP_READ;
    fs_ctx->fd = file->ref->fd;
    fs_ctx->size = (size_t) size;
    fs_ctx->offset = (off_t) offset;
    fs_ctx->ref = file->ref;

    file->ref->ninflight++;

    return ngx_lua_fs_post_task(L, coctx, fs_ctx, &pool_name);
}


static int
ngx_lua_fs_file_write(lua_State *L)
{
    ngx_lua_fs_co_ctx_t  *coctx;
    ngx_thread_task_t          *task;
    ngx_lua_fs_ctx_t      *fs_ctx;
    ngx_lua_fs_file_t     *file;
    const char                 *data;
    size_t                      data_len;
    off_t                       offset;
    ngx_str_t                   pool_name;

    coctx = ngx_lua_fs_check_context(L);

    file = (ngx_lua_fs_file_t *)
               luaL_checkudata(L, 1, NGX_LUA_FS_FILE_MT);

    if (file->ref == NULL || file->ref->closed) {
        return luaL_error(L, "attempt to write to a closed file");
    }

    data = luaL_checklstring(L, 2, &data_len);
    offset = ngx_lua_fs_check_offset(L, 3);

    if (data_len == 0) {
        lua_pushinteger(L, 0);
        return 1;
    }

    pool_name.data = file->pool_name;
    pool_name.len = file->pool_name_len;

    task = ngx_lua_fs_task_alloc(sizeof(ngx_lua_fs_ctx_t));
    if (task == NULL) {
        return luaL_error(L, "no memory");
    }

    fs_ctx = task->ctx;

    fs_ctx->buf = ngx_alloc(data_len, ngx_cycle->log);
    if (fs_ctx->buf == NULL) {
        ngx_lua_fs_task_free(fs_ctx);
        return luaL_error(L, "no memory");
    }

    ngx_memcpy(fs_ctx->buf, data, data_len);

    fs_ctx->op = NGX_LUA_FS_OP_WRITE;
    fs_ctx->flags = file->ref->append ? O_APPEND : 0;
    fs_ctx->fd = file->ref->fd;
    fs_ctx->size = data_len;
    fs_ctx->offset = (off_t) offset;
    fs_ctx->ref = file->ref;

    file->ref->ninflight++;

    return ngx_lua_fs_post_task(L, coctx, fs_ctx, &pool_name);
}


static int
ngx_lua_fs_file_close(lua_State *L)
{
    ngx_err_t                err;
    ngx_lua_fs_file_t  *file;

    file = luaL_checkudata(L, 1, NGX_LUA_FS_FILE_MT);

    if (file->ref == NULL || file->ref->closed) {
        lua_pushboolean(L, 0);
        lua_pushliteral(L, "file already closed");
        return 2;
    }

    if (file->ref->ninflight > 0) {
        lua_pushboolean(L, 0);
        lua_pushfstring(L, "file has %d in-flight operation(s)",
                        (int) file->ref->ninflight);
        return 2;
    }

    file->ref->closed = 1;

    if (ngx_close_file(file->ref->fd) == NGX_FILE_ERROR) {
        err = ngx_errno;
        lua_pushboolean(L, 0);
        lua_pushfstring(L, "close() failed (%d: %s)", (int) err, strerror(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}


static int
ngx_lua_fs_stat(lua_State *L)
{
    ngx_lua_fs_co_ctx_t  *coctx;
    ngx_thread_task_t          *task;
    ngx_lua_fs_ctx_t      *fs_ctx;
    const char                 *path;
    size_t                      path_len;
    ngx_str_t                   pool_name;

    coctx = ngx_lua_fs_check_context(L);

    if (lua_gettop(L) < 1) {
        return luaL_error(L, "expecting at least 1 argument: path");
    }

    path = luaL_checklstring(L, 1, &path_len);
    luaL_argcheck(L, ngx_strlchr((u_char *) path,
                  (u_char *) path + path_len, '\0') == NULL, 1,
                  "path contains a zero byte");


    pool_name = ngx_lua_fs_check_pool(L, 2);

    task = ngx_lua_fs_task_alloc(sizeof(ngx_lua_fs_ctx_t));
    if (task == NULL) {
        return luaL_error(L, "no memory");
    }

    fs_ctx = task->ctx;

    fs_ctx->op = NGX_LUA_FS_OP_STAT;

    fs_ctx->path = ngx_alloc(path_len + 1, ngx_cycle->log);
    if (fs_ctx->path == NULL) {
        ngx_lua_fs_task_free(fs_ctx);
        return luaL_error(L, "no memory");
    }

    ngx_memcpy(fs_ctx->path, path, path_len);
    fs_ctx->path[path_len] = '\0';

    return ngx_lua_fs_post_task(L, coctx, fs_ctx, &pool_name);
}


static int
ngx_lua_fs_path_operation(lua_State *L, ngx_uint_t op)
{
    size_t                  path_len, size;
    ngx_str_t               pool;
    const char             *path, *data;
    lua_Number              max_size;
    ngx_thread_task_t      *task;
    ngx_lua_fs_co_ctx_t  *coctx;
    ngx_lua_fs_ctx_t  *fs_ctx;

    coctx = ngx_lua_fs_check_context(L);

    path = luaL_checklstring(L, 1, &path_len);
    luaL_argcheck(L, ngx_strlchr((u_char *) path,
                  (u_char *) path + path_len, '\0') == NULL, 1,
                  "path contains a zero byte");

    pool = ngx_lua_fs_check_pool(L, 3);

    data = NULL;

    if (op == NGX_LUA_FS_OP_READ_FILE) {
        if (lua_isnoneornil(L, 2)) {
            size = NGX_LUA_FS_FILE_SIZE;

        } else {
            max_size = luaL_checknumber(L, 2);
            luaL_argcheck(L, max_size >= 0
                          && max_size <= NGX_LUA_FS_MAX_SIZE
                          && (lua_Number) (size_t) max_size == max_size,
                          2, "invalid size limit");
            size = (size_t) max_size;
        }

    } else {
        data = luaL_checklstring(L, 2, &size);
    }

    task = ngx_lua_fs_task_alloc(sizeof(ngx_lua_fs_ctx_t));
    if (task == NULL) {
        return luaL_error(L, "no memory");
    }

    fs_ctx = task->ctx;
    fs_ctx->op = op;
    fs_ctx->size = size;
    fs_ctx->path = ngx_alloc(path_len + 1, ngx_cycle->log);

    if (fs_ctx->path == NULL) {
        ngx_lua_fs_task_free(fs_ctx);
        return luaL_error(L, "no memory");
    }

    ngx_memcpy(fs_ctx->path, path, path_len + 1);

    if (data != NULL) {
        fs_ctx->buf = ngx_alloc(size == 0 ? 1 : size, ngx_cycle->log);
        if (fs_ctx->buf == NULL) {
            ngx_lua_fs_task_free(fs_ctx);
            return luaL_error(L, "no memory");
        }

        ngx_memcpy(fs_ctx->buf, data, size);
    }

    return ngx_lua_fs_post_task(L, coctx, fs_ctx, &pool);
}


static int
ngx_lua_fs_read_file(lua_State *L)
{
    return ngx_lua_fs_path_operation(L, NGX_LUA_FS_OP_READ_FILE);
}


static int
ngx_lua_fs_append_file(lua_State *L)
{
    return ngx_lua_fs_path_operation(L, NGX_LUA_FS_OP_APPEND_FILE);
}


static int
ngx_lua_fs_file_gc(lua_State *L)
{
    ngx_lua_fs_file_t  *file;

    file = (ngx_lua_fs_file_t *)
               luaL_checkudata(L, 1, NGX_LUA_FS_FILE_MT);

    if (file->ref == NULL) {
        return 0;
    }

    if (file->ref->ninflight == 0) {
        ngx_lua_fs_fd_ref_release(file->ref);

    } else {
        file->ref->orphaned = 1;
    }

    file->ref = NULL;

    return 0;
}


static int
ngx_lua_fs_file_tostring(lua_State *L)
{
    ngx_lua_fs_file_t  *file;

    file = (ngx_lua_fs_file_t *)
               luaL_checkudata(L, 1, NGX_LUA_FS_FILE_MT);

    if (file->ref == NULL || file->ref->closed) {
        lua_pushliteral(L, "file (closed)");

    } else {
        lua_pushfstring(L, "file (fd=%d)", file->ref->fd);
    }

    return 1;
}


static void
ngx_lua_fs_inject_api(lua_State *L)
{
    luaL_newmetatable(L, NGX_LUA_FS_FILE_MT);

    lua_pushcfunction(L, ngx_lua_fs_file_gc);
    lua_setfield(L, -2, "__gc");

    lua_pushcfunction(L, ngx_lua_fs_file_tostring);
    lua_setfield(L, -2, "__tostring");

    lua_createtable(L, 0, 3);

    lua_pushcfunction(L, ngx_lua_fs_file_read);
    lua_setfield(L, -2, "read");

    lua_pushcfunction(L, ngx_lua_fs_file_write);
    lua_setfield(L, -2, "write");

    lua_pushcfunction(L, ngx_lua_fs_file_close);
    lua_setfield(L, -2, "close");

    lua_setfield(L, -2, "__index");

    lua_pop(L, 1);

    lua_createtable(L, 0, 4);

    lua_pushcfunction(L, ngx_lua_fs_open);
    lua_setfield(L, -2, "open");

    lua_pushcfunction(L, ngx_lua_fs_stat);
    lua_setfield(L, -2, "stat");

    lua_pushcfunction(L, ngx_lua_fs_read_file);
    lua_setfield(L, -2, "read_file");

    lua_pushcfunction(L, ngx_lua_fs_append_file);
    lua_setfield(L, -2, "append_file");

    lua_setfield(L, -2, "fs");
}
