/*
 * mod_aiss.c — AI Security Shield module for Apache 2.4
 *
 * Features:
 *   - Hooks into the access-check phase (APR_HOOK_FIRST).
 *   - Reads up to AISS_BODY_SAMPLE_BYTES of request body for dynamic content-types.
 *   - Sends a JSON payload to the AISS Go agent over a Unix Domain Socket.
 *   - Acts on the PERMIT / BLOCK verdict (HTTP 403 on BLOCK).
 *   - POSIX shared-memory verdict cache: known-safe IPs bypass the UDS call
 *     for up to AISS_SHM_TTL_SEC seconds.
 *   - Fail-Open: agent unreachable → DECLINED so Apache continues normally.
 *
 * Build:
 *   apxs -c -i mod_aiss.c
 *
 * httpd.conf / .htaccess:
 *   LoadModule aiss_module modules/mod_aiss.so
 *   <Location />
 *       AISSEnable  On
 *       AISSSocket  /tmp/aiss.sock
 *       AISSTimeout 10
 *   </Location>
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_network_io.h"

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

/* ── Constants ───────────────────────────────────────────────────────────── */
#define AISS_MODULE_VERSION    "1.1.0"
#define AISS_MAX_JSON          16384
#define AISS_MAX_RESP          1024
#define AISS_BODY_SAMPLE_BYTES 4096
#define AISS_SHM_NAME          "/aiss_verdict_cache"
#define AISS_SHM_BUCKETS       65536   /* must be power of 2 */
#define AISS_SHM_TTL_SEC       60

module AP_MODULE_DECLARE_DATA aiss_module;

/* ── Shared-memory verdict cache (same layout as Nginx module) ───────────── */

typedef struct {
    char    ip[46];
    uint8_t verdict;    /* 0 = PERMIT, 1 = BLOCK */
    time_t  expires_at;
} aiss_shm_entry_t;

typedef struct {
    aiss_shm_entry_t buckets[AISS_SHM_BUCKETS];
} aiss_shm_t;

static aiss_shm_t *g_shm = NULL;

static uint32_t aiss_fnv1a(const char *s) {
    uint32_t h = 0x811c9dc5u;
    while (*s) { h ^= (uint8_t)*s++; h *= 0x01000193u; }
    return h;
}

static void aiss_shm_init(server_rec *s) {
    int fd = shm_open(AISS_SHM_NAME, O_CREAT | O_RDWR, 0660);
    if (fd < 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, s,
                     "mod_aiss: shm_open failed — shm cache disabled");
        return;
    }
    if (ftruncate(fd, sizeof(aiss_shm_t)) < 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, s,
                     "mod_aiss: ftruncate shm failed");
        close(fd);
        return;
    }
    void *ptr = mmap(NULL, sizeof(aiss_shm_t),
                     PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (ptr == MAP_FAILED) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, s,
                     "mod_aiss: mmap shm failed");
        return;
    }
    g_shm = (aiss_shm_t *)ptr;
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                 "mod_aiss: shm verdict cache ready (%lu KB)",
                 (unsigned long)(sizeof(aiss_shm_t) / 1024));
}

static int aiss_shm_check(const char *ip) {
    if (!g_shm) return 0;
    uint32_t idx = aiss_fnv1a(ip) & (AISS_SHM_BUCKETS - 1);
    aiss_shm_entry_t *e = &g_shm->buckets[idx];
    if (e->expires_at == 0 || time(NULL) >= e->expires_at) return 0;
    if (strncmp(e->ip, ip, sizeof(e->ip) - 1) != 0) return 0;
    return (e->verdict == 0) ? 1 : 0;
}

static void aiss_shm_store(const char *ip, int block) {
    if (!g_shm) return;
    uint32_t idx = aiss_fnv1a(ip) & (AISS_SHM_BUCKETS - 1);
    aiss_shm_entry_t *e = &g_shm->buckets[idx];
    strncpy(e->ip, ip, sizeof(e->ip) - 1);
    e->ip[sizeof(e->ip) - 1] = '\0';
    e->verdict    = block ? 1 : 0;
    e->expires_at = time(NULL) + AISS_SHM_TTL_SEC;
}

/* ── Per-directory config ─────────────────────────────────────────────────── */

typedef struct {
    int         enabled;
    const char *socket_path;
    int         timeout_ms;
} aiss_dir_config_t;

/* ── Forward declarations ─────────────────────────────────────────────────── */
static int  aiss_access_handler(request_rec *r);
static int  aiss_connect_uds(const char *path, int timeout_ms);
static int  aiss_transact(int fd, const char *req, char *resp, size_t rsz);
static int  aiss_parse_action(const char *json);
static void aiss_escape_json(const char *src, char *dst, size_t dstsz);
static void aiss_generate_id(char *buf, size_t bufsz);
static int  aiss_is_dynamic_content(request_rec *r);
static int  aiss_read_body_sample(request_rec *r, char *buf, size_t bufsz);

/* ── Config creation and merge ────────────────────────────────────────────── */

static void *aiss_create_dir_config(apr_pool_t *p, char *dir) {
    aiss_dir_config_t *cfg = apr_pcalloc(p, sizeof(aiss_dir_config_t));
    cfg->enabled     = 0;
    cfg->socket_path = "/tmp/aiss.sock";
    cfg->timeout_ms  = 10;
    return cfg;
}

static void *aiss_merge_dir_config(apr_pool_t *p, void *basev, void *addv) {
    aiss_dir_config_t *base = basev, *add = addv;
    aiss_dir_config_t *cfg  = apr_pcalloc(p, sizeof(aiss_dir_config_t));
    cfg->enabled     = add->enabled     ? add->enabled     : base->enabled;
    cfg->socket_path = add->socket_path ? add->socket_path : base->socket_path;
    cfg->timeout_ms  = add->timeout_ms  ? add->timeout_ms  : base->timeout_ms;
    return cfg;
}

/* ── Post-config hook: init shm ───────────────────────────────────────────── */
static int aiss_post_config(apr_pool_t *p, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s) {
    aiss_shm_init(s);
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                 "mod_aiss: version %s loaded", AISS_MODULE_VERSION);
    return OK;
}

/* ── Directive handlers ───────────────────────────────────────────────────── */

static const char *aiss_set_enable(cmd_parms *cmd, void *cfg_, int flag) {
    ((aiss_dir_config_t *)cfg_)->enabled = flag; return NULL; }
static const char *aiss_set_socket(cmd_parms *cmd, void *cfg_, const char *path) {
    ((aiss_dir_config_t *)cfg_)->socket_path = path; return NULL; }
static const char *aiss_set_timeout(cmd_parms *cmd, void *cfg_, const char *val) {
    ((aiss_dir_config_t *)cfg_)->timeout_ms = atoi(val); return NULL; }

static const command_rec aiss_cmds[] = {
    AP_INIT_FLAG  ("AISSEnable",   aiss_set_enable,  NULL, ACCESS_CONF|RSRC_CONF, "Enable AISS (On/Off)"),
    AP_INIT_TAKE1 ("AISSSocket",   aiss_set_socket,  NULL, ACCESS_CONF|RSRC_CONF, "Unix socket path"),
    AP_INIT_TAKE1 ("AISSTimeout",  aiss_set_timeout, NULL, ACCESS_CONF|RSRC_CONF, "Timeout ms"),
    { NULL }
};

/* ── Access check handler ─────────────────────────────────────────────────── */

static int aiss_access_handler(request_rec *r) {
    aiss_dir_config_t *cfg =
        ap_get_module_config(r->per_dir_config, &aiss_module);
    if (!cfg || !cfg->enabled || r->main) return DECLINED;

    const char *client_ip = r->useragent_ip ? r->useragent_ip
                                             : r->connection->client_ip;

    /* ── Shared-memory fast path ── */
    if (aiss_shm_check(client_ip)) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "mod_aiss: shm PERMIT for %s", client_ip);
        return DECLINED;
    }

    /* ── Read body sample for dynamic content ── */
    char body_sample[AISS_BODY_SAMPLE_BYTES] = {0};
    size_t body_len = 0;

    if (aiss_is_dynamic_content(r)) {
        body_len = (size_t)aiss_read_body_sample(r, body_sample, sizeof(body_sample));
        if (body_len < 0) body_len = 0;
    }

    /* ── Build JSON ── */
    char json_buf[AISS_MAX_JSON];
    char resp_buf[AISS_MAX_RESP];
    char req_id[64];
    char esc_uri[2048], esc_ua[512], esc_qs[1024];
    char esc_ct[256], esc_referer[512], esc_body[AISS_BODY_SAMPLE_BYTES * 2];

    aiss_generate_id(req_id, sizeof(req_id));

    const char *ua      = apr_table_get(r->headers_in, "User-Agent");
    const char *ct      = apr_table_get(r->headers_in, "Content-Type");
    const char *referer = apr_table_get(r->headers_in, "Referer");
    const char *xfwd    = apr_table_get(r->headers_in, "X-Forwarded-For");

    aiss_escape_json(r->uri,                 esc_uri,     sizeof(esc_uri));
    aiss_escape_json(r->args ? r->args : "", esc_qs,      sizeof(esc_qs));
    aiss_escape_json(ua      ? ua      : "", esc_ua,      sizeof(esc_ua));
    aiss_escape_json(ct      ? ct      : "", esc_ct,      sizeof(esc_ct));
    aiss_escape_json(referer ? referer : "", esc_referer, sizeof(esc_referer));
    aiss_escape_json(body_len > 0 ? body_sample : "", esc_body, sizeof(esc_body));

    int n = apr_snprintf(json_buf, sizeof(json_buf),
        "{"
        "\"request_id\":\"%s\","
        "\"client_ip\":\"%s\","
        "\"method\":\"%s\","
        "\"uri\":\"%s\","
        "\"query_string\":\"%s\","
        "\"content_type\":\"%s\","
        "\"content_length\":%ld,"
        "\"user_agent\":\"%s\","
        "\"server_type\":\"apache\","
        "\"headers\":{"
            "\"referer\":\"%s\","
            "\"x-forwarded-for\":\"%s\""
        "},"
        "\"body\":\"%s\""
        "}\n",
        req_id,
        client_ip,
        r->method,
        esc_uri,
        esc_qs,
        esc_ct,
        (long)(r->clength > 0 ? r->clength : 0),
        esc_ua,
        esc_referer,
        xfwd ? xfwd : "",
        esc_body
    );

    /* ── UDS round-trip ── */
    int sockfd = aiss_connect_uds(cfg->socket_path, cfg->timeout_ms);
    if (sockfd < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "mod_aiss: agent unreachable at %s — fail-open",
                      cfg->socket_path);
        aiss_shm_store(client_ip, 0);
        return DECLINED;
    }

    if (aiss_transact(sockfd, json_buf, resp_buf, sizeof(resp_buf)) < 0) {
        close(sockfd);
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "mod_aiss: transaction failed — fail-open");
        return DECLINED;
    }
    close(sockfd);

    int action = aiss_parse_action(resp_buf);
    aiss_shm_store(client_ip, action ? 0 : 1);

    if (!action) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                      "mod_aiss: BLOCK %s %s (ip=%s)",
                      r->method, r->uri, client_ip);
        return HTTP_FORBIDDEN;
    }
    return DECLINED;
}

/* ── Body reading helper ──────────────────────────────────────────────────── */

static int aiss_is_dynamic_content(request_rec *r) {
    const char *ct = apr_table_get(r->headers_in, "Content-Type");
    if (!ct) return 0;
    static const char *types[] = {
        "application/json", "application/x-www-form-urlencoded",
        "multipart/form-data", "application/xml", "text/xml",
        "text/plain", "application/octet-stream", NULL
    };
    for (int i = 0; types[i]; i++)
        if (strncasecmp(ct, types[i], strlen(types[i])) == 0) return 1;
    return 0;
}

static int aiss_read_body_sample(request_rec *r, char *buf, size_t bufsz) {
    /* ap_setup_client_block returns OK if there may be a body */
    if (ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK) != OK)
        return 0;
    if (!ap_should_client_block(r))
        return 0;

    long total = 0;
    long n;
    char tmp[1024];
    while (total < (long)bufsz &&
           (n = ap_get_client_block(r, tmp, sizeof(tmp))) > 0) {
        long take = n < (long)(bufsz - (size_t)total)
                    ? n : (long)(bufsz - (size_t)total);
        memcpy(buf + total, tmp, (size_t)take);
        total += take;
    }
    return (int)total;
}

/* ── UDS helpers ──────────────────────────────────────────────────────────── */

static int aiss_connect_uds(const char *path, int timeout_ms) {
    struct sockaddr_un addr;
    struct timeval tv;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (timeout_ms > 0) {
        tv.tv_sec = 0; tv.tv_usec = timeout_ms * 1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }
    return fd;
}

static int aiss_transact(int fd, const char *req, char *resp, size_t rsz) {
    size_t reqlen = strlen(req), sent = 0;
    ssize_t n;
    while (sent < reqlen) {
        n = write(fd, req + sent, reqlen - sent);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    size_t total = 0;
    while (total < rsz - 1) {
        n = read(fd, resp + total, 1);
        if (n <= 0) break;
        if (resp[total] == '\n') { total++; break; }
        total++;
    }
    resp[total] = '\0';
    return (total > 0) ? 0 : -1;
}

static int aiss_parse_action(const char *json) {
    const char *p = strstr(json, "\"action\"");
    if (!p) return 1;
    p = strchr(p, ':'); if (!p) return 1;
    while (*p == ':' || *p == ' ' || *p == '"') p++;
    return (strncmp(p, "BLOCK", 5) != 0);
}

static void aiss_escape_json(const char *src, char *dst, size_t dstsz) {
    size_t j = 0;
    unsigned char c;
    if (!src) { dst[0] = '\0'; return; }
    while (*src && j < dstsz - 2) {
        c = (unsigned char)*src++;
        switch (c) {
        case '"':  if (j+2<dstsz) { dst[j++]='\\'; dst[j++]='"';  } break;
        case '\\': if (j+2<dstsz) { dst[j++]='\\'; dst[j++]='\\'; } break;
        case '\n': if (j+2<dstsz) { dst[j++]='\\'; dst[j++]='n';  } break;
        case '\r': if (j+2<dstsz) { dst[j++]='\\'; dst[j++]='r';  } break;
        case '\t': if (j+2<dstsz) { dst[j++]='\\'; dst[j++]='t';  } break;
        default:   if (c >= 0x20) dst[j++] = c; break;
        }
    }
    dst[j] = '\0';
}

static void aiss_generate_id(char *buf, size_t bufsz) {
    struct timespec ts;
    static volatile uint64_t seq = 0;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t ns  = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    uint64_t cnt = __sync_fetch_and_add(&seq, 1);
    snprintf(buf, bufsz, "%016llx-%016llx",
             (unsigned long long)ns, (unsigned long long)cnt);
}

/* ── Module registration ──────────────────────────────────────────────────── */

static void aiss_register_hooks(apr_pool_t *p) {
    ap_hook_post_config(aiss_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_access_checker(aiss_access_handler, NULL, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA aiss_module = {
    STANDARD20_MODULE_STUFF,
    aiss_create_dir_config,
    aiss_merge_dir_config,
    NULL, NULL,
    aiss_cmds,
    aiss_register_hooks
};
