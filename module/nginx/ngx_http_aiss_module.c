/*
 * ngx_http_aiss_module.c — AI Security Shield module for Nginx
 *
 * Features:
 *   - Intercepts every HTTP request at NGX_HTTP_PREACCESS_PHASE.
 *   - Captures the first AISS_BODY_SAMPLE_BYTES of the request body for
 *     dynamic content-types (JSON, form-data, XML, multipart).
 *   - Sends a JSON payload to the AISS Go agent over a Unix Domain Socket.
 *   - Acts on the PERMIT / BLOCK verdict.
 *   - POSIX shared-memory verdict cache: known-safe IPs bypass the UDS call
 *     for up to AISS_SHM_TTL_SEC seconds.
 *   - Fail-Open: if the agent is unreachable or times out, the request is
 *     passed to the next handler (NGX_DECLINED) — web server never stalls.
 *
 * Build:
 *   ./configure --add-module=/path/to/aiss/module/nginx
 *   make -j$(nproc)
 *
 * nginx.conf:
 *   aiss_enable  on;
 *   aiss_socket  /tmp/aiss.sock;
 *   aiss_timeout 10;   # ms
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <time.h>

/* ── Constants ───────────────────────────────────────────────────────────── */
#define AISS_MODULE_VERSION     "1.1.0"
#define AISS_MAX_REQUEST_JSON   16384
#define AISS_MAX_RESPONSE_JSON  1024
#define AISS_BODY_SAMPLE_BYTES  4096
#define AISS_SHM_NAME           "/aiss_verdict_cache"
#define AISS_SHM_BUCKETS        65536   /* must be a power of 2 */
#define AISS_SHM_TTL_SEC        60

/* ── Shared-memory verdict cache ──────────────────────────────────────────── */

typedef struct {
    char    ip[46];         /* INET6_ADDRSTRLEN */
    uint8_t verdict;        /* 0 = PERMIT, 1 = BLOCK */
    time_t  expires_at;
} aiss_shm_entry_t;

typedef struct {
    aiss_shm_entry_t buckets[AISS_SHM_BUCKETS];
} aiss_shm_t;

static aiss_shm_t *g_shm = NULL;

/* FNV-1a 32-bit hash for the IP string */
static uint32_t aiss_fnv1a(const char *s) {
    uint32_t h = 0x811c9dc5u;
    while (*s) {
        h ^= (uint8_t)*s++;
        h *= 0x01000193u;
    }
    return h;
}

static void aiss_shm_init(ngx_log_t *log) {
    int fd = shm_open(AISS_SHM_NAME, O_CREAT | O_RDWR, 0660);
    if (fd < 0) {
        ngx_log_error(NGX_LOG_WARN, log, errno, "aiss: shm_open failed");
        return;
    }
    if (ftruncate(fd, sizeof(aiss_shm_t)) < 0) {
        ngx_log_error(NGX_LOG_WARN, log, errno, "aiss: ftruncate shm failed");
        close(fd);
        return;
    }
    void *ptr = mmap(NULL, sizeof(aiss_shm_t),
                     PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (ptr == MAP_FAILED) {
        ngx_log_error(NGX_LOG_WARN, log, errno, "aiss: mmap shm failed");
        return;
    }
    g_shm = (aiss_shm_t *)ptr;
}

/* Returns 1 if a cached PERMIT is found (and not expired), 0 otherwise. */
static int aiss_shm_check(const char *ip) {
    if (!g_shm) return 0;
    uint32_t idx = aiss_fnv1a(ip) & (AISS_SHM_BUCKETS - 1);
    aiss_shm_entry_t *e = &g_shm->buckets[idx];
    if (e->expires_at == 0) return 0;
    if (time(NULL) >= e->expires_at) return 0;
    if (strncmp(e->ip, ip, sizeof(e->ip) - 1) != 0) return 0;
    return (e->verdict == 0) ? 1 : 0; /* only cache PERMIT */
}

/* Write a verdict into the shm cache. */
static void aiss_shm_store(const char *ip, int block) {
    if (!g_shm) return;
    uint32_t idx = aiss_fnv1a(ip) & (AISS_SHM_BUCKETS - 1);
    aiss_shm_entry_t *e = &g_shm->buckets[idx];
    strncpy(e->ip, ip, sizeof(e->ip) - 1);
    e->ip[sizeof(e->ip) - 1] = '\0';
    e->verdict    = block ? 1 : 0;
    e->expires_at = time(NULL) + AISS_SHM_TTL_SEC;
}

/* ── Per-location config ──────────────────────────────────────────────────── */
typedef struct {
    ngx_flag_t  enable;
    ngx_str_t   socket_path;
    ngx_uint_t  timeout_ms;
} ngx_http_aiss_loc_conf_t;

/* ── Per-request context (body buffer) ───────────────────────────────────── */
typedef struct {
    ngx_str_t body_sample;
} ngx_http_aiss_ctx_t;

/* ── Module forward declarations ─────────────────────────────────────────── */
static ngx_int_t ngx_http_aiss_init(ngx_conf_t *cf);
static void     *ngx_http_aiss_create_loc_conf(ngx_conf_t *cf);
static char     *ngx_http_aiss_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_aiss_handler(ngx_http_request_t *r);
static void      ngx_http_aiss_body_cb(ngx_http_request_t *r);
static ngx_int_t ngx_http_aiss_check_request(ngx_http_request_t *r,
                                               const char *body_sample,
                                               size_t body_len);

/* ── UDS helpers ──────────────────────────────────────────────────────────── */
static int  aiss_connect_uds(const char *socket_path, int timeout_ms);
static int  aiss_send_request(int fd, const char *json, size_t len);
static int  aiss_recv_response(int fd, char *buf, size_t bufsz);
static int  aiss_parse_action(const char *json);
static void aiss_escape_json_str(ngx_pool_t *pool, ngx_str_t *src,
                                  u_char *dst, size_t dstsz, size_t *outlen);
static void aiss_generate_request_id(char *buf, size_t bufsz);
static int  aiss_is_dynamic_content(ngx_http_request_t *r);

/* ── Directives ───────────────────────────────────────────────────────────── */
static ngx_command_t ngx_http_aiss_commands[] = {
    { ngx_string("aiss_enable"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_aiss_loc_conf_t, enable), NULL },
    { ngx_string("aiss_socket"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_aiss_loc_conf_t, socket_path), NULL },
    { ngx_string("aiss_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_aiss_loc_conf_t, timeout_ms), NULL },
    ngx_null_command
};

/* ── Module context ───────────────────────────────────────────────────────── */
static ngx_http_module_t ngx_http_aiss_module_ctx = {
    NULL,                           /* preconfiguration  */
    ngx_http_aiss_init,             /* postconfiguration */
    NULL, NULL, NULL, NULL,
    ngx_http_aiss_create_loc_conf,
    ngx_http_aiss_merge_loc_conf
};

/* ── Module definition ────────────────────────────────────────────────────── */
ngx_module_t ngx_http_aiss_module = {
    NGX_MODULE_V1,
    &ngx_http_aiss_module_ctx,
    ngx_http_aiss_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

/* ── Config lifecycle ─────────────────────────────────────────────────────── */

static void *ngx_http_aiss_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_aiss_loc_conf_t *conf =
        ngx_pcalloc(cf->pool, sizeof(ngx_http_aiss_loc_conf_t));
    if (!conf) return NULL;
    conf->enable     = NGX_CONF_UNSET;
    conf->timeout_ms = NGX_CONF_UNSET_UINT;
    return conf;
}

static char *ngx_http_aiss_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_aiss_loc_conf_t *prev = parent;
    ngx_http_aiss_loc_conf_t *conf = child;
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_uint_value(conf->timeout_ms, prev->timeout_ms, 10);
    ngx_conf_merge_str_value(conf->socket_path, prev->socket_path, "/tmp/aiss.sock");
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_aiss_init(ngx_conf_t *cf) {
    ngx_http_handler_pt       *h;
    ngx_http_core_main_conf_t *cmcf;

    /* Initialise the shared-memory verdict cache once during config load */
    aiss_shm_init(cf->log);

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (!h) return NGX_ERROR;
    *h = ngx_http_aiss_handler;
    return NGX_OK;
}

/* ── Main handler ─────────────────────────────────────────────────────────── */

static ngx_int_t ngx_http_aiss_handler(ngx_http_request_t *r) {
    ngx_http_aiss_loc_conf_t *alcf =
        ngx_http_get_module_loc_conf(r, ngx_http_aiss_module);

    if (!alcf->enable || r != r->main)
        return NGX_DECLINED;

    /* ── Shared-memory fast path ── */
    u_char client_ip[NGX_SOCKADDR_STRLEN];
    size_t ip_len = ngx_sock_ntop(r->connection->sockaddr,
                                   r->connection->socklen,
                                   client_ip, sizeof(client_ip), 0);
    client_ip[ip_len] = '\0';

    if (aiss_shm_check((const char *)client_ip)) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "aiss: shm cache PERMIT for %s", client_ip);
        return NGX_DECLINED;
    }

    /* ── For dynamic content-types, read the body first ── */
    if (aiss_is_dynamic_content(r) && r->headers_in.content_length_n > 0) {
        /* Allocate per-request context so the body callback can reach it */
        ngx_http_aiss_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_aiss_module);
        if (!ctx) {
            ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_aiss_ctx_t));
            if (!ctx) return NGX_HTTP_INTERNAL_SERVER_ERROR;
            ngx_http_set_ctx(r, ctx, ngx_http_aiss_module);
        }

        /* Prevent Nginx from discarding the request before the callback fires */
        r->main->count++;

        ngx_int_t rc = ngx_http_read_client_request_body(r, ngx_http_aiss_body_cb);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            r->main->count--;
            return rc;
        }
        /* NGX_OK → body already buffered → callback called synchronously */
        /* NGX_AGAIN → async, callback will be invoked later               */
        return NGX_DONE;
    }

    /* Header-only check (no body) */
    return ngx_http_aiss_check_request(r, "", 0);
}

/* ── Body read callback ───────────────────────────────────────────────────── */

static void ngx_http_aiss_body_cb(ngx_http_request_t *r) {
    r->main->count--;

    /* Collect up to AISS_BODY_SAMPLE_BYTES from the chain of body buffers */
    char body_sample[AISS_BODY_SAMPLE_BYTES] = {0};
    size_t collected = 0;

    if (r->request_body && r->request_body->bufs) {
        ngx_chain_t *cl;
        for (cl = r->request_body->bufs; cl && collected < AISS_BODY_SAMPLE_BYTES; cl = cl->next) {
            ngx_buf_t *b = cl->buf;
            size_t avail = (size_t)(b->last - b->pos);
            size_t take  = avail < (AISS_BODY_SAMPLE_BYTES - collected)
                           ? avail : (AISS_BODY_SAMPLE_BYTES - collected);
            ngx_memcpy(body_sample + collected, b->pos, take);
            collected += take;
        }
    }

    ngx_int_t rc = ngx_http_aiss_check_request(r, body_sample, collected);
    ngx_http_finalize_request(r,
        (rc == NGX_HTTP_FORBIDDEN) ? NGX_HTTP_FORBIDDEN : NGX_DECLINED);
}

/* ── Core security check ──────────────────────────────────────────────────── */

static ngx_int_t ngx_http_aiss_check_request(ngx_http_request_t *r,
                                               const char *body_sample,
                                               size_t body_len)
{
    ngx_http_aiss_loc_conf_t *alcf =
        ngx_http_get_module_loc_conf(r, ngx_http_aiss_module);

    char json_buf[AISS_MAX_REQUEST_JSON];
    char resp_buf[AISS_MAX_RESPONSE_JSON];
    char req_id[64];
    char esc_uri[2048], esc_ua[512], esc_query[1024];
    char esc_ct[256], esc_referer[512], esc_body[AISS_BODY_SAMPLE_BYTES * 2];

    u_char client_ip[NGX_SOCKADDR_STRLEN];
    size_t ip_len = ngx_sock_ntop(r->connection->sockaddr,
                                   r->connection->socklen,
                                   client_ip, sizeof(client_ip), 0);
    client_ip[ip_len] = '\0';

    aiss_generate_request_id(req_id, sizeof(req_id));

    size_t ul, ql, ual, ctl, refl, bl;
    aiss_escape_json_str(r->pool, &r->uri,  (u_char *)esc_uri,     sizeof(esc_uri),     &ul);
    aiss_escape_json_str(r->pool, &r->args, (u_char *)esc_query,   sizeof(esc_query),   &ql);

    ngx_str_t ua = ngx_null_string;
    if (r->headers_in.user_agent) ua = r->headers_in.user_agent->value;
    aiss_escape_json_str(r->pool, &ua, (u_char *)esc_ua, sizeof(esc_ua), &ual);

    ngx_str_t ct = ngx_null_string;
    if (r->headers_in.content_type) ct = r->headers_in.content_type->value;
    aiss_escape_json_str(r->pool, &ct, (u_char *)esc_ct, sizeof(esc_ct), &ctl);

    ngx_str_t referer = ngx_null_string;
    if (r->headers_in.referer) referer = r->headers_in.referer->value;
    aiss_escape_json_str(r->pool, &referer, (u_char *)esc_referer, sizeof(esc_referer), &refl);

    /* Escape body sample */
    if (body_len > 0) {
        ngx_str_t body_str = {body_len, (u_char *)body_sample};
        aiss_escape_json_str(r->pool, &body_str, (u_char *)esc_body, sizeof(esc_body), &bl);
    } else {
        esc_body[0] = '\0';
        bl = 0;
    }

    char method[16];
    ngx_snprintf((u_char *)method, sizeof(method), "%V%c", &r->method_name, '\0');

    int n = ngx_snprintf(
        (u_char *)json_buf, sizeof(json_buf) - 1,
        "{"
        "\"request_id\":\"%s\","
        "\"client_ip\":\"%s\","
        "\"method\":\"%s\","
        "\"uri\":\"%s\","
        "\"query_string\":\"%s\","
        "\"content_type\":\"%s\","
        "\"content_length\":%O,"
        "\"user_agent\":\"%s\","
        "\"server_type\":\"nginx\","
        "\"headers\":{"
            "\"referer\":\"%s\","
            "\"x-forwarded-for\":\"%s\","
            "\"cookie\":\"\""
        "},"
        "\"body\":\"%s\""
        "}\n",
        req_id,
        client_ip,
        method,
        esc_uri,
        esc_query,
        esc_ct,
        r->headers_in.content_length_n,
        esc_ua,
        esc_referer,
        r->headers_in.x_forwarded_for
            ? (char *)r->headers_in.x_forwarded_for->value.data : "",
        esc_body
    );
    json_buf[n] = '\0';

    int sockfd = aiss_connect_uds((const char *)alcf->socket_path.data,
                                   (int)alcf->timeout_ms);
    if (sockfd < 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "aiss: agent unreachable at %V — fail-open", &alcf->socket_path);
        aiss_shm_store((const char *)client_ip, 0); /* cache as PERMIT so we stop retrying */
        return NGX_DECLINED;
    }

    if (aiss_send_request(sockfd, json_buf, (size_t)n) < 0 ||
        aiss_recv_response(sockfd, resp_buf, sizeof(resp_buf)) < 0)
    {
        close(sockfd);
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "aiss: transaction failed — fail-open");
        return NGX_DECLINED;
    }
    close(sockfd);

    int action = aiss_parse_action(resp_buf);

    /* Store verdict in shm cache */
    aiss_shm_store((const char *)client_ip, action == 0 ? 1 : 0);

    if (action == 0) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "aiss: BLOCK %V %V (ip=%s)", &r->method_name, &r->uri, client_ip);
        return NGX_HTTP_FORBIDDEN;
    }
    return NGX_DECLINED;
}

/* ── Helpers ──────────────────────────────────────────────────────────────── */

static int aiss_is_dynamic_content(ngx_http_request_t *r) {
    if (!r->headers_in.content_type) return 0;
    ngx_str_t *ct = &r->headers_in.content_type->value;
    static const char *dynamic[] = {
        "application/json",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "application/xml",
        "text/xml",
        "text/plain",
        "application/octet-stream",
        NULL
    };
    for (int i = 0; dynamic[i]; i++) {
        size_t dl = strlen(dynamic[i]);
        if (ct->len >= dl && ngx_strncasecmp(ct->data, (u_char *)dynamic[i], dl) == 0)
            return 1;
    }
    return 0;
}

static int aiss_connect_uds(const char *socket_path, int timeout_ms) {
    struct sockaddr_un addr;
    struct timeval tv;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    tv.tv_sec  = 0;
    tv.tv_usec = timeout_ms * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int aiss_send_request(int fd, const char *json, size_t len) {
    ssize_t sent = 0, total = 0;
    while ((size_t)total < len) {
        sent = write(fd, json + total, len - (size_t)total);
        if (sent <= 0) return -1;
        total += sent;
    }
    return 0;
}

static int aiss_recv_response(int fd, char *buf, size_t bufsz) {
    ssize_t n = 0;
    size_t total = 0;
    while (total < bufsz - 1) {
        n = read(fd, buf + total, 1);
        if (n <= 0) break;
        if (buf[total] == '\n') { total++; break; }
        total++;
    }
    buf[total] = '\0';
    return (total > 0) ? 0 : -1;
}

static int aiss_parse_action(const char *json) {
    const char *p = strstr(json, "\"action\"");
    if (!p) return 1;
    p = strchr(p, ':');
    if (!p) return 1;
    while (*p == ':' || *p == ' ' || *p == '"') p++;
    return (strncmp(p, "BLOCK", 5) != 0);
}

static void aiss_escape_json_str(ngx_pool_t *pool, ngx_str_t *src,
                                  u_char *dst, size_t dstsz, size_t *outlen) {
    size_t i, j = 0;
    u_char c;
    (void)pool;
    if (!src || src->len == 0) {
        dst[0] = '\0';
        if (outlen) *outlen = 0;
        return;
    }
    for (i = 0; i < src->len && j < dstsz - 2; i++) {
        c = src->data[i];
        switch (c) {
        case '"':  if (j+2 < dstsz) { dst[j++]='\\'; dst[j++]='"';  } break;
        case '\\': if (j+2 < dstsz) { dst[j++]='\\'; dst[j++]='\\'; } break;
        case '\n': if (j+2 < dstsz) { dst[j++]='\\'; dst[j++]='n';  } break;
        case '\r': if (j+2 < dstsz) { dst[j++]='\\'; dst[j++]='r';  } break;
        case '\t': if (j+2 < dstsz) { dst[j++]='\\'; dst[j++]='t';  } break;
        default:   if (c >= 0x20) dst[j++] = c; break;
        }
    }
    dst[j] = '\0';
    if (outlen) *outlen = j;
}

static void aiss_generate_request_id(char *buf, size_t bufsz) {
    static volatile uint64_t counter = 0;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t ns  = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    uint64_t cnt = __sync_fetch_and_add(&counter, 1);
    snprintf(buf, bufsz, "%016llx-%016llx",
             (unsigned long long)ns, (unsigned long long)cnt);
}
