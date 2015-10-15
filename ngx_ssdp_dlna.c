
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <nginx.h>
#include <ifaddrs.h>
#include "ngx_ssdp_dlna.h"


#define NGX_DLNA_SSDP_PORT      1900
#define NGX_DLNA_SSDP_ADDR      "239.255.255.250"
#define NGX_DLNA_SSDP_UUID      "uuid:57ad7ec9-f4f8-4c33-8028-274b057b4983"
#define NGX_DLNA_SSDP_UDP_SIZE  512


static void *ngx_ssdp_dlna_create_conf(ngx_cycle_t *cycle);
static ngx_int_t ngx_ssdp_dlna_init_module(ngx_cycle_t *cycle);
static void ngx_ssdp_dlna_reply(struct sockaddr_in *sin, uint32_t iface,
    ngx_str_t *st, ngx_uint_t append_st);
static void ngx_ssdp_dlna_read_request(ngx_event_t *rev);


static ngx_socket_t   ngx_ssdp_dlna_socket = -1;


static ngx_str_t  ngx_dlna_ssdp_service_types[] = {
    ngx_string(NGX_DLNA_SSDP_UUID),
    ngx_string("upnp:rootdevice"),
    ngx_string("urn:schemas-upnp-org:device:MediaServer:1"),
    ngx_string("urn:schemas-upnp-org:service:ContentDirectory:1"),
    ngx_null_string
};


static ngx_core_module_t  ngx_ssdp_dlna_module_ctx = {
    ngx_string("ssdp_dlna"),
    ngx_ssdp_dlna_create_conf,
    NULL
};


ngx_module_t  ngx_ssdp_dlna_module = {
    NGX_MODULE_V1,
    &ngx_ssdp_dlna_module_ctx,             /* module context */
    NULL,                                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_ssdp_dlna_init_module,             /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_ssdp_dlna_create_conf(ngx_cycle_t *cycle)
{
    ngx_ssdp_dlna_conf_t  *sdcf;

    sdcf = ngx_pcalloc(cycle->pool, sizeof(ngx_ssdp_dlna_conf_t));
    if (sdcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&sdcf->roots, cycle->pool, 1,
                       sizeof(ngx_ssdp_dlna_root_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    
    if (ngx_array_init(&sdcf->iface, cycle->pool, 1,
                       sizeof(ngx_ssdp_dlna_iface_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return sdcf;
}


static ngx_int_t
ngx_ssdp_dlna_init_module(ngx_cycle_t *cycle)
{
    int                     v;
    ngx_socket_t            s;
    struct ip_mreq          imr;
    struct ifaddrs         *ifap, *p;
    struct sockaddr        *sa, *sam;
    struct sockaddr_in      sock, *sin, *sinm;
    ngx_ssdp_dlna_conf_t   *sdcf;
    ngx_ssdp_dlna_iface_t  *iface;

    sdcf = (ngx_ssdp_dlna_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                 ngx_ssdp_dlna_module);

    if (ngx_ssdp_dlna_socket != -1) {

        if (sdcf->roots.nelts == 0) {
            ngx_close_socket(ngx_ssdp_dlna_socket);
            ngx_ssdp_dlna_socket = -1;
        }

        return NGX_OK;
    }

    if (sdcf->roots.nelts == 0) {
        return NGX_OK;
    }
    
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "dlna ssdp nroots:%uz", sdcf->roots.nelts);

    s = ngx_socket(PF_INET, SOCK_DGRAM, 0);
    if (s == (ngx_socket_t) -1) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_socket_errno,
                      "dlna ssdp " ngx_socket_n " failed");
        return NGX_ERROR;
    }

    v = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(int))) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_socket_errno,
                      "dlna ssdp setsockopt()failed");
        return NGX_ERROR;
    }

    ngx_memzero(&sock, sizeof(struct sockaddr_in));

    sock.sin_family = AF_INET;
    sock.sin_port = htons(NGX_DLNA_SSDP_PORT);
    sock.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s, (struct sockaddr *) &sock, sizeof(struct sockaddr_in))) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                      "dlna ssdp bind() failed");

        ngx_close_socket(s);

        return NGX_ERROR;
    }

    if (getifaddrs(&ifap)) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_socket_errno,
                      "dlna ssdp getifaddrs() failed");

        ngx_close_socket(s);

        return NGX_ERROR;
    }

    for (p = ifap; p; p = p->ifa_next) {
        sa = p->ifa_addr;

        if (sa == NULL || sa->sa_family != AF_INET) {
            continue;
        }

        sin = (struct sockaddr_in *) sa;

        imr.imr_multiaddr.s_addr = inet_addr(NGX_DLNA_SSDP_ADDR);
        imr.imr_interface.s_addr = sin->sin_addr.s_addr;

        if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *) &imr,
                       sizeof(struct ip_mreq)))
        {
            ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_socket_errno,
                          "dlna ssdp setsockopt() failed");

            ngx_close_socket(s);

            return NGX_ERROR;
        }

        sam = p->ifa_netmask;

        if (sam == NULL || sam->sa_family != AF_INET) {
            continue;
        }

        sinm = (struct sockaddr_in *) sam;

        iface = ngx_array_push(&sdcf->iface);
        if (iface == NULL) {
            return NGX_ERROR;
        }

        iface->addr = sin->sin_addr.s_addr;
        iface->mask = sinm->sin_addr.s_addr;
    }

    freeifaddrs(ifap);

    if (ngx_nonblocking(s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
                      "dlna ssdp " ngx_nonblocking_n " failed");

        ngx_close_socket(s);

        return NGX_ERROR;
    }

    ngx_ssdp_dlna_socket = s;

    return NGX_OK;
}


ngx_int_t
ngx_ssdp_dlna_init()
{
    ngx_event_t       *rev;
    ngx_connection_t  *c;

    if (ngx_ssdp_dlna_socket == -1 || ngx_process != NGX_PROCESS_WORKER) {
        return NGX_OK;
    }

    c = ngx_get_connection(ngx_ssdp_dlna_socket, ngx_cycle->log);

    if (c == NULL) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                      "dlna ssdp ngx_get_connection() failed");
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "dlna ssdp init");

    rev = c->read;
    rev->log = ngx_cycle->log;
    rev->handler = ngx_ssdp_dlna_read_request;

    ngx_handle_read_event(c->read, 0);

    return NGX_OK;
}


static void
ngx_ssdp_dlna_read_request(ngx_event_t *rev)
{
    u_char                  in[NGX_DLNA_SSDP_UDP_SIZE];
    ssize_t                 n, i;
    ngx_str_t               st, *p;
    socklen_t               socklen;
    ngx_uint_t              j;
    ngx_connection_t       *c;
    struct sockaddr_in      sin;
    ngx_ssdp_dlna_conf_t   *sdcf;
    ngx_ssdp_dlna_iface_t  *iface;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "dlna ssdp request");

    c = rev->data;

    sdcf = (ngx_ssdp_dlna_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                                 ngx_ssdp_dlna_module);

    do {
        socklen = sizeof(struct sockaddr);

        n = recvfrom(c->fd, in, NGX_DLNA_SSDP_UDP_SIZE, 0, (struct sockaddr *)&sin, &socklen);

        if (n < 0) {
            ngx_handle_read_event(rev, 0);
            return;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                       "dlna ssdp received %z bytes", n);

        if (socklen > sizeof(struct sockaddr_in) || sin.sin_family != AF_INET) {
            continue;
        }

        if (n < 8 || ngx_strncasecmp(in, (u_char *) "M-SEARCH", 8)) {
            continue;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                       "dlna ssdp received M-SEARCH n:%ui", (ngx_uint_t) n);

        i = 0;

        for ( ;; ) {
            while (i < n && in[i] != '\n') {
                i++;
            }

            i++;

            if (i >= n) {
                break;
            }

            if (i + 3 < n && ngx_strncasecmp(&in[i], (u_char *) "ST:", 3) == 0)
            {
                i += 3;
                
                while (i < n && (in[i] == ' ' || in[i] == '\t')) {
                    i++;
                }

                st.data = &in[i];

                while (i < n && in[i] != '\r' && in[i] != '\n') {
                    i++;
                }

                st.len = (size_t) (&in[i] - st.data);
            }
        }

        if (st.len == 0) {
            continue;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                       "dlna ssdp ST:\"%V\"", &st);

        iface = sdcf->iface.elts;

        for (j = 0; j < sdcf->iface.nelts; j++) {
            if ((sin.sin_addr.s_addr & iface[j].mask) ==
                (iface[j].addr & iface[j].mask))
            {
                break;
            }
        }

        if (j == sdcf->iface.nelts) {
            continue;
        }

        ngx_log_debug4(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                       "dlna ssdp iface:%ui.%ui.%ui.%ui",
                       (ngx_uint_t) (0xff & iface[j].addr),
                       (ngx_uint_t) (0xff & (iface[j].addr >> 8)),
                       (ngx_uint_t) (0xff & (iface[j].addr >> 16)),
                       (ngx_uint_t) (iface[j].addr >> 24));

        for (p = ngx_dlna_ssdp_service_types; p->len; p++) {
            if (st.len == p->len
                && ngx_strncasecmp(st.data, p->data, st.len) == 0)
            {
                break;
            }
        }

        if (p->len) {
            ngx_ssdp_dlna_reply(&sin, iface[j].addr, &st,
                                p != ngx_dlna_ssdp_service_types);
            continue;
        }

        if (st.len != 8 || ngx_strncasecmp(st.data, (u_char *) "ssdp:all", 8)) {
            continue;
        }

        for (p = ngx_dlna_ssdp_service_types; p->len; p++) {
            ngx_ssdp_dlna_reply(&sin, iface[j].addr, p,
                                p != ngx_dlna_ssdp_service_types);
        }

    } while (rev->ready);
}


static void
ngx_ssdp_dlna_reply(struct sockaddr_in *sin, uint32_t iface, ngx_str_t *st,
    ngx_uint_t append_st)
{
    u_char                 out[NGX_DLNA_SSDP_UDP_SIZE], *p;
    ngx_str_t              addon;
    ngx_uint_t             n;
    ngx_ssdp_dlna_root_t  *root;
    ngx_ssdp_dlna_conf_t  *sdcf;

    if (append_st) {
        addon = *st;
    } else {
        ngx_str_null(&addon);
    }

    sdcf = (ngx_ssdp_dlna_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                                 ngx_ssdp_dlna_module);
    root = sdcf->roots.elts;

    for (n = 0; n < sdcf->roots.nelts; n++) {

        p = ngx_snprintf(out, NGX_DLNA_SSDP_UDP_SIZE,
                         "HTTP/1.1 200 OK\r\n"
                         "CACHE-CONTROL: max-age=60\r\n"
                         "DATE: %V\r\n"
                         "EXT:\r\n"
                         "LOCATION: http://%ui.%ui.%ui.%ui:%ui%V"
                                                  NGX_SSDP_DLNA_ROOT_URI "\r\n"
                         "SERVER: OS/1.0 UPnP/1.0 " NGINX_VER "\r\n"
                         "CONTENT-LENGTH: 0\r\n"
                         "ST: %V\r\n"
                         "USN: %s%s%V\r\n\r\n",
                         &ngx_cached_http_time,
                         (ngx_uint_t) (0xff & iface),
                         (ngx_uint_t) (0xff & (iface >> 8)),
                         (ngx_uint_t) (0xff & (iface >> 16)),
                         (ngx_uint_t) (iface >> 24),
                         (ngx_uint_t) root[n].port,
                         &root[n].location,
                         st,
                         NGX_DLNA_SSDP_UUID,
                         append_st ? "::" : "",
                         &addon);

        if (sendto(ngx_ssdp_dlna_socket, out, (size_t) (p - out), 0, (struct sockaddr *)sin,
                   sizeof(struct sockaddr))
            == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_socket_errno,
                    "dlna ssdp sendto() failed");
        }
    }
}
