
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <expat.h>
#include "ngx_ssdp_dlna.h"


typedef enum {
    NGX_HTTP_DLNA_BROWSE,
    NGX_HTTP_DLNA_GETSYSTEMUPDATEID,
    NGX_HTTP_DLNA_GETSORTCAPABILITIES,
    NGX_HTTP_DLNA_GETSEARCHCAPABILITIES,
    NGX_HTTP_DLNA_XGETFEATURELIST
} ngx_http_dlna_action_e;


typedef enum {
    NGX_HTTP_DLNA_BROWSE_DIRECT_CHILDREN = 0,
    NGX_HTTP_DLNA_BROWSE_METADATA,
} ngx_http_dlna_browse_flag_e;


typedef struct {
    ngx_http_core_srv_conf_t    *cscf;
    ngx_str_t                    location;
    in_port_t                    port;
    uint32_t                     addr;
} ngx_http_dlna_root_t;


typedef struct {
    ngx_array_t                  roots; /* ngx_http_dlna_root_t */
} ngx_http_dlna_main_conf_t;


typedef struct {
    ngx_str_t                    name;
    ngx_http_dlna_root_t        *root;
} ngx_http_dlna_loc_conf_t;


typedef struct {
    ngx_chain_t                 *out;
    ngx_chain_t                 *last;
    off_t                        out_len;
    ngx_uint_t                   node;
    ngx_str_t                    value;
    ngx_str_t                    object_id;
    ngx_str_t                    starting_index;
    ngx_str_t                    requested_count;
    ngx_str_t                    filter;
    ngx_str_t                    sort_criteria;
    ngx_str_t                    browse_flag;
    ngx_http_dlna_action_e       action;
} ngx_http_dlna_ctx_t;


#define NGX_HTTP_DLNA_BUFSIZE               4096


#define NGX_HTTP_DLNA_XML_OBJECT_ID         0x01
#define NGX_HTTP_DLNA_XML_STARTING_INDEX    0x02
#define NGX_HTTP_DLNA_XML_REQUESTED_COUNT   0x04
#define NGX_HTTP_DLNA_XML_FILTER            0x08
#define NGX_HTTP_DLNA_XML_SORT_CRITERIA     0x10
#define NGX_HTTP_DLNA_XML_BROWSE_FLAG       0x20


static ngx_int_t ngx_http_dlna_handler(ngx_http_request_t *r);
static void ngx_http_dlna_soap_handler(ngx_http_request_t *r);
static void XMLCALL ngx_http_dlna_xml_start(void *user_data,
    const XML_Char *name, const XML_Char **atts);
static void XMLCALL ngx_http_dlna_xml_end(void *user_data,
    const XML_Char *name);
static void XMLCALL ngx_http_dlna_xml_data(void *user_data, const XML_Char *s,
    int len);
static void ngx_http_dlna_append_data(ngx_http_request_t *r, ngx_str_t *base,
    ngx_str_t *add);
static void ngx_http_dlna_xor_node(ngx_http_request_t *r, u_char *name);
static void ngx_http_dlna_browse(ngx_http_request_t *r);
static ngx_int_t ngx_http_dlna_sprintf(ngx_http_request_t *r,
    const char *fmt, ...);
static ngx_int_t ngx_http_dlna_new_buf(ngx_http_request_t *r);
static ngx_int_t ngx_http_dlna_root(ngx_http_request_t *r);
static void ngx_http_dlna_get_system_update_id(ngx_http_request_t *r);
static void ngx_http_dlna_get_sort_capabilities(ngx_http_request_t *r);
static void ngx_http_dlna_get_search_capabilities(ngx_http_request_t *r);
static void ngx_http_dlna_x_get_feature_list(ngx_http_request_t *r);
static void ngx_http_dlna_send(ngx_http_request_t *r, u_char *data, size_t len);
static char *ngx_http_dlna(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_dlna_postconfiguration(ngx_conf_t *cf);
static void *ngx_http_dlna_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_dlna_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_dlna_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_dlna_init_process(ngx_cycle_t *cycle);


static ngx_command_t  ngx_http_dlna_commands[] = {

    { ngx_string("dlna"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
      ngx_http_dlna,
      0,
      0,
      NULL },

    ngx_null_command
};

static ngx_http_module_t  ngx_http_dlna_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_dlna_postconfiguration,       /* postconfiguration */

    ngx_http_dlna_create_main_conf,        /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_dlna_create_loc_conf,         /* create location configuration */
    ngx_http_dlna_merge_loc_conf,          /* merge location configuration */
};


ngx_module_t  ngx_http_dlna_module = {
    NGX_MODULE_V1,
    &ngx_http_dlna_module_ctx,             /* module context */
    ngx_http_dlna_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_dlna_init_process,            /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


#define NGX_HTTP_DLNA_CDIR  "urn:schemas-upnp-org:service:ContentDirectory:1"


static ngx_int_t
ngx_http_dlna_handler(ngx_http_request_t *r)
{
    ngx_str_t                  name, value;
    ngx_int_t                  rc;
    ngx_table_elt_t           *h;
    ngx_http_dlna_ctx_t       *ctx;
    ngx_http_dlna_action_e     action;
    ngx_http_variable_value_t  v;

    if (r->uri.len >= sizeof(NGX_SSDP_DLNA_ROOT_URI) - 1
        && ngx_strncasecmp(r->uri.data + r->uri.len -
                           (sizeof(NGX_SSDP_DLNA_ROOT_URI) - 1),
                           (u_char *) NGX_SSDP_DLNA_ROOT_URI,
                           sizeof(NGX_SSDP_DLNA_ROOT_URI) - 1)
           == 0)
    {
        return ngx_http_dlna_root(r);
    }

    if (r->method != NGX_HTTP_POST) {

        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->hash = 1;

        ngx_str_set(&h->key, "contentFeatures.dlna.org");
        ngx_str_set(&h->value, "DLNA.ORG_OP=01;DLNA.ORG_CI=0;DLNA.ORG_FLAGS="
                               "01700000000000000000000000000000");

        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->hash = 1;

        ngx_str_set(&h->key, "transferMode.dlna.org");
        ngx_str_set(&h->value, "Streaming");

        return NGX_DECLINED;
    }

    ngx_str_set(&name, "soapaction");

    if (ngx_http_variable_unknown_header(&v, &name,
                                         &r->headers_in.headers.part, 0)
        != NGX_OK || !v.valid)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http dlna missing soap action");

        return NGX_DECLINED;
    }

    if (v.len && v.data[0] == (u_char) '"') {
        v.len--;
        v.data++;
    }

    if (v.len && v.data[v.len - 1] == (u_char) '"') {
        v.len--;
    }

    if (v.len <= sizeof(NGX_HTTP_DLNA_CDIR)
        || ngx_strncmp(v.data, NGX_HTTP_DLNA_CDIR,
                       sizeof(NGX_HTTP_DLNA_CDIR) - 1)
        || v.data[sizeof(NGX_HTTP_DLNA_CDIR) - 1] != '#')
    {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http dlna unsupported interface: \"%*s\"",
                       v.len, v.data);

        return NGX_DECLINED;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "dlna soap interface \"%s\"", NGX_HTTP_DLNA_CDIR);

    value.len = v.len - sizeof(NGX_HTTP_DLNA_CDIR);
    value.data = v.data + sizeof(NGX_HTTP_DLNA_CDIR);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dlna soap action: \"%V\"", &value);

    if (value.len == 6 && ngx_strncasecmp(value.data, (u_char *) "Browse", 6)
                       == 0)
    {
        action = NGX_HTTP_DLNA_BROWSE;

    } else if (value.len == 17 && ngx_strncasecmp(value.data,
                                             (u_char *) "GetSystemUpdateID", 17)
                               == 0)
    {
        action = NGX_HTTP_DLNA_GETSYSTEMUPDATEID;

    } else if (value.len == 19 && ngx_strncasecmp(value.data,
                                           (u_char *) "GetSortCapabilities", 19)
                               == 0)
    {
        action = NGX_HTTP_DLNA_GETSORTCAPABILITIES;

    } else if (value.len == 21 && ngx_strncasecmp(value.data,
                                         (u_char *) "GetSearchCapabilities", 21)
                               == 0)
    {
        action = NGX_HTTP_DLNA_GETSEARCHCAPABILITIES;

    } else if (value.len == 16 && ngx_strncasecmp(value.data,
                                              (u_char *) "X_GetFeatureList", 16)
                               == 0)
    {
        action = NGX_HTTP_DLNA_XGETFEATURELIST;

    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "unsupported soap action: \"%V\"", &value);

        return NGX_DECLINED;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dlna_ctx_t));

    ngx_http_set_ctx(r, ctx, ngx_http_dlna_module);

    ctx->action = action;

    rc = ngx_http_read_client_request_body(r, ngx_http_dlna_soap_handler);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;   
}


static void
ngx_http_dlna_soap_handler(ngx_http_request_t *r)
{
    ngx_chain_t          *c;
    ngx_buf_t            *b;
    XML_Parser            parser;
    ngx_http_dlna_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dlna soap handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_dlna_module);

    parser = XML_ParserCreate(NULL);

    XML_SetUserData(parser, r);

    XML_SetElementHandler(parser, ngx_http_dlna_xml_start,
                          ngx_http_dlna_xml_end);

    XML_SetCharacterDataHandler(parser, ngx_http_dlna_xml_data);

    c = r->request_body->bufs;

    for ( ;; ) {

        b = c->buf;

        if (XML_Parse(parser, (const char *) b->pos, (int) (b->last - b->pos),
                      b->last_buf)
            == 0)
        {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "dlna XML error");

            XML_ParserFree(parser);

            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);

            return;
        }

        if (b->last_buf) {
            break;
        }

        c = c->next;
    }

    XML_ParserFree(parser);

    switch (ctx->action) {
    case NGX_HTTP_DLNA_BROWSE:
        ngx_http_dlna_browse(r);
        break;

    case NGX_HTTP_DLNA_GETSYSTEMUPDATEID:
        ngx_http_dlna_get_system_update_id(r);
        break;

    case NGX_HTTP_DLNA_GETSORTCAPABILITIES:
        ngx_http_dlna_get_sort_capabilities(r);
        break;

    case NGX_HTTP_DLNA_GETSEARCHCAPABILITIES:
        ngx_http_dlna_get_search_capabilities(r);
        break;

    case NGX_HTTP_DLNA_XGETFEATURELIST:
        ngx_http_dlna_x_get_feature_list(r);
        break;
    }
}


static void XMLCALL
ngx_http_dlna_xml_start(void *user_data, const XML_Char *name,
    const XML_Char **atts)
{
    ngx_http_dlna_xor_node(user_data, (u_char *) name);
}


static void XMLCALL
ngx_http_dlna_xml_end(void *user_data, const XML_Char *name)
{
    ngx_http_dlna_xor_node(user_data, (u_char *) name);
}


static void XMLCALL
ngx_http_dlna_xml_data(void *user_data, const XML_Char *s, int len)
{
    ngx_http_request_t  *r = user_data;

    ngx_str_t             value;
    ngx_http_dlna_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_dlna_module);

    value.data = (u_char *) s;
    value.len = (size_t) len;

#define NGX_HTTP_DLNA_XML_DATA(flag, field)                                   \
    if (ctx->node & flag) {                                                   \
        ngx_http_dlna_append_data(r, &ctx->field, &value);                    \
        return;                                                               \
    }

    NGX_HTTP_DLNA_XML_DATA(NGX_HTTP_DLNA_XML_OBJECT_ID, object_id);
    NGX_HTTP_DLNA_XML_DATA(NGX_HTTP_DLNA_XML_STARTING_INDEX, starting_index);
    NGX_HTTP_DLNA_XML_DATA(NGX_HTTP_DLNA_XML_REQUESTED_COUNT, requested_count);
    NGX_HTTP_DLNA_XML_DATA(NGX_HTTP_DLNA_XML_FILTER, filter);
    NGX_HTTP_DLNA_XML_DATA(NGX_HTTP_DLNA_XML_SORT_CRITERIA, sort_criteria);
    NGX_HTTP_DLNA_XML_DATA(NGX_HTTP_DLNA_XML_BROWSE_FLAG, browse_flag);

#undef NGX_HTTP_DLNA_XML_DATA
}


static void
ngx_http_dlna_append_data(ngx_http_request_t *r, ngx_str_t *base,
    ngx_str_t *add)
{
    u_char  *data, *p;

    data = ngx_palloc(r->pool, base->len + add->len + 1);
    if (data == NULL) {
        return;
    }

    p = data;

    if (base->len) {
        p = ngx_cpymem(p, add->data, add->len);
    }

    p = ngx_cpymem(p, add->data, add->len);
    *p = 0;

    base->data = data;
    base->len += add->len;
}


static void
ngx_http_dlna_xor_node(ngx_http_request_t *r, u_char *name)
{
    ngx_http_dlna_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_dlna_module);

#define NGX_HTTP_DLNA_XML_NODE(flag, title)                                   \
    if (ngx_strcasecmp(name, (u_char *) title) == 0) {                        \
        ctx->node ^= flag;                                                    \
    }

    NGX_HTTP_DLNA_XML_NODE(NGX_HTTP_DLNA_XML_OBJECT_ID, "ObjectID");
    NGX_HTTP_DLNA_XML_NODE(NGX_HTTP_DLNA_XML_STARTING_INDEX, "StartingIndex");
    NGX_HTTP_DLNA_XML_NODE(NGX_HTTP_DLNA_XML_REQUESTED_COUNT, "RequestedCount");
    NGX_HTTP_DLNA_XML_NODE(NGX_HTTP_DLNA_XML_FILTER, "Filter");
    NGX_HTTP_DLNA_XML_NODE(NGX_HTTP_DLNA_XML_SORT_CRITERIA, "SortCriteria");
    NGX_HTTP_DLNA_XML_NODE(NGX_HTTP_DLNA_XML_BROWSE_FLAG, "BrowseFlag");

#undef NGX_HTTP_DLNA_XML_NODE
}


#define NGX_HTTP_DLNA_BROWSE_HEADER                                           \
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"                            \
    "<s:Envelope \n"                                                          \
    "    xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \n"            \
    "    s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n"    \
    "  <s:Body>\n"                                                            \
    "    <u:BrowseResponse\n"                                                 \
    "        xmlns:u=\"urn:schemas-upnp-org:service:ContentDirectory:1\">\n"  \
    "      <Result>\n"                                                        \
    "        &lt;DIDL-Lite\n"                                                 \
    "            xmlns:dc=\"http://purl.org/dc/elements/1.1/\"\n"             \
    "            xmlns:upnp=\"urn:schemas-upnp-org:metadata-1-0/upnp/\"\n"    \
    "            xmlns=\"urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/\"\n"    \
    "            xmlns:dlna=\"urn:schemas-dlna-org:metadata-1-0/\"&gt;\n"


#define NGX_HTTP_DLNA_BROWSE_CONTAINER                                        \
    "          &lt;container\n"                                               \
    "              id=\"%V/%s\"\n"                                            \
    "              parentID=\"%V\"\n"                                         \
    "              restricted=\"false\"\n"                                    \
    "              childCount=\"100\"&gt;\n"                                  \
    "            &lt;dc:title&gt;\n"                                          \
    "              %s\n"                                                      \
    "            &lt;/dc:title&gt;\n"                                         \
    "            &lt;upnp:class&gt;\n"                                        \
    "              object.container.storageFolder\n"                          \
    "            &lt;/upnp:class&gt;\n"                                       \
    "            &lt;upnp:storageUsed&gt;\n"                                  \
    "              -1\n"                                                      \
    "            &lt;/upnp:storageUsed&gt;\n"                                 \
    "          &lt;/container&gt;\n"


#define NGX_HTTP_DLNA_BROWSE_ITEM                                             \
    "          &lt;item\n"                                                    \
    "              id=\"%V/%s\"\n"                                            \
    "              parentID=\"%V\"\n"                                         \
    "              restricted=\"false\"&gt;\n"                                \
    "            &lt;dc:title&gt;\n"                                          \
    "              %s\n"                                                      \
    "            &lt;/dc:title&gt;\n"                                         \
    "            &lt;upnp:class&gt;\n"                                        \
    "              object.item.videoItem\n"                                   \
    "            &lt;/upnp:class&gt;\n"                                       \
    "            &lt;dc:date&gt;\n"                                           \
    "              %d-%02d-%02dT%02d:%02d:%02d\n"                             \
    "            &lt;/dc:date&gt;\n"                                          \
    "            &lt;sec:dcmInfo&gt;\n"                                       \
    "                CREATIONDATE=0,"                                         \
                    "FOLDER=ABC,"                                             \
                    "BM=0\n"                                                  \
    "            &lt;/sec:dcmInfo&gt;\n"                                      \
    "            &lt;res\n"                                                   \
    "                size=\"%O\"\n"                                           \
    "                duration=\"0:06:41.832\"\n"                              \
    "                bitrate=\"783441\"\n"                                    \
    "                resolution=\"1280x720\"\n"                               \
    "                protocolInfo=\"http-get:*:video/x-mkv:*\"&gt;"           \
                  "http://%ui.%ui.%ui.%ui:%ui%V%V/%s\n"                       \
                "&lt;/res&gt;\n"                                              \
    "          &lt;/item&gt;\n"


#define NGX_HTTP_DLNA_BROWSE_FOOTER                                           \
    "        &lt;/DIDL-Lite&gt;\n"                                            \
    "      </Result>\n"                                                       \
    "      <NumberReturned>%ui</NumberReturned>\n"                            \
    "      <TotalMatches>%ui</TotalMatches>\n"                                \
    "      <UpdateID>3</UpdateID>\n"                                          \
    "    </u:BrowseResponse>\n"                                               \
    "  </s:Body>\n"                                                           \
    "</s:Envelope>\n"


static void
ngx_http_dlna_browse(ngx_http_request_t *r)
{
    u_char                     type, *filename, *last, *leaf;
    size_t                     root, len, allocated;
    uint32_t                   addr;
    in_port_t                  port;
    ngx_err_t                  err;
    ngx_str_t                  path, root_path, parent_id, object_path,
                               parent_path;
    struct tm                  tm;
    ngx_int_t                  v, rc;
    ngx_dir_t                  dir;
    ngx_uint_t                 n, from, count, nest, returned, nmatches;
    ngx_file_info_t            fi;
    ngx_http_dlna_ctx_t       *ctx;
    ngx_http_dlna_loc_conf_t  *dlcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_dlna_module);

    v = ngx_atoi(ctx->starting_index.data, ctx->starting_index.len);

    if (v == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "bad StartingIndex: \"%V\"", &ctx->starting_index);

        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);

        return;
    }

    from = (ngx_uint_t) v;

    v = ngx_atoi(ctx->requested_count.data, ctx->requested_count.len);

    if (v == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "bad RequestedCount: \"%V\"", &ctx->requested_count);

        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);

        return;
    }

    count = (ngx_uint_t) v;

    if (ctx->browse_flag.len == 14
        && ngx_strncasecmp(ctx->browse_flag.data, (u_char *) "BrowseMetadata",
                           14)
        == 0)
    {
        nest = 0;

    } else if (ctx->browse_flag.len == 20
               && ngx_strncasecmp(ctx->browse_flag.data,
                                  (u_char *) "BrowseDirectChildren", 20)
               == 0)
    {
        nest = 1;

    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "bad BrowseFlag: \"%V\"", &ctx->browse_flag);

        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);

        return;
    }

    type = '0';
    path = ctx->object_id;

    if (path.len && path.data[0] >= (u_char) '0'
        && path.data[0] <= (u_char) '3')
    {
        type = path.data[0];
        path.data++;
        path.len--;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dlna Browse type:%c, path:\"%V\", "
                   "nest:%ui, from:%ui, count:%ui",
                   type, &path, nest, from, count);

    object_path = path;

    ngx_str_null(&root_path);

    last = ngx_http_map_uri_to_path(r, &root_path, &root, path.len);

    if (last == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "error mapping path");

        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);

        return;
    }

    last = ngx_cpymem(last, path.data, path.len);
    path = root_path;

    allocated = path.len;
    path.len = last - path.data;
    /*if (path.len > 1) {
        path.len--;
    }*/
    path.data[path.len] = '\0';

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dlna path: \"%V\"", &path);

    if (ngx_http_dlna_sprintf(r, NGX_HTTP_DLNA_BROWSE_HEADER) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dlna_module);

    port = dlcf->root->port;
    addr = dlcf->root->addr;

    if (nest) {

        returned = 0;
        nmatches = 0;

        if (ngx_open_dir(&path, &dir) == NGX_ERROR) {

            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                          ngx_open_dir_n " \"%V\" failed", &path);

            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);

            return;
        }

        n = 0;

        for ( ;; ) {
            ngx_set_errno(0);

            if (ngx_read_dir(&dir) == NGX_ERROR) {
                err = ngx_errno;

                if (err != NGX_ENOMOREFILES) {
                    ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
                                  ngx_read_dir_n " \"%V\" failed", &path);
                    goto dir_error;
                }

                break;
            }

            len = ngx_de_namelen(&dir);

            if (len && ngx_de_name(&dir)[0] == '.') {
                continue;
            }

            if (n++ < from) {
                continue;
            }

            if (n > from + count) {
                break;
            }
            
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http dlna item n:%ui \"%*s\"",
                           n, len, ngx_de_name(&dir));

            if (!dir.valid_info) {

                if (path.len + 1 + len + 1 > allocated) {
                    allocated = path.len + 1 + len + 1;

                    filename = ngx_pnalloc(r->pool, allocated);
                    if (filename == NULL) {
                        goto dir_error;
                    } 

                    last = ngx_cpystrn(filename, path.data, path.len + 1);
                    *last++ = '/';
                }

                ngx_cpystrn(last, ngx_de_name(&dir), len + 1);

                if (ngx_de_info(filename, &dir) == NGX_FILE_ERROR) {
                    err = ngx_errno;

                    if (err != NGX_ENOENT && err != NGX_ELOOP) {
                        ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
                                      ngx_de_info_n " \"%s\" failed", filename);

                        if (err == NGX_EACCES) {
                            continue;
                        }

                        goto dir_error;
                    }

                    if (ngx_de_link_info(filename, &dir) == NGX_FILE_ERROR) {
                        ngx_log_error(NGX_LOG_CRIT, r->connection->log,
                                      ngx_errno, ngx_de_link_info_n 
                                      " \"%s\" failed", filename);
                        goto dir_error;
                    }
                }
            }

            /*TODO: escape names */

            if (ngx_de_is_dir(&dir)) {
                rc = ngx_http_dlna_sprintf(r, NGX_HTTP_DLNA_BROWSE_CONTAINER,
                                           &ctx->object_id, ngx_de_name(&dir),
                                           &ctx->object_id, ngx_de_name(&dir));
            } else {
                ngx_libc_localtime(ngx_de_mtime(&dir), &tm);

                rc = ngx_http_dlna_sprintf(r, NGX_HTTP_DLNA_BROWSE_ITEM,
                                           &ctx->object_id, ngx_de_name(&dir),
                                           &ctx->object_id, ngx_de_name(&dir),
                                           tm.tm_year + 1900,
                                           tm.tm_mon + 1,
                                           tm.tm_mday,
                                           tm.tm_hour,
                                           tm.tm_min,
                                           tm.tm_sec,
                                           ngx_de_fs_size(&dir),
                                           (ngx_uint_t) (0xff & addr),
                                           (ngx_uint_t) (0xff & (addr >> 8)),
                                           (ngx_uint_t) (0xff & (addr >> 16)),
                                           (ngx_uint_t) (addr >> 24),
                                           (ngx_uint_t) port,
                                           &r->uri,
                                           &object_path, ngx_de_name(&dir));
            }

            if (rc != NGX_OK) {
                goto dir_error;
            }

            returned++;
            nmatches++;
        }

        if (ngx_close_dir(&dir) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                          ngx_close_dir_n " \"%V\" failed", &path);
        }

    } else {

        returned = 1;
        nmatches = 1;

        if (ngx_file_info(path.data, &fi) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                          ngx_file_info_n " \"%V\" failed", &path);

            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);

            return;
        }

        parent_id = ctx->object_id;
        while (parent_id.len > 0 && parent_id.data[parent_id.len] != '/') {
            parent_id.len--;
        }

        leaf = parent_id.data + parent_id.len;

        parent_path = object_path;
        while (parent_path.len > 0 && parent_path.data[parent_path.len] != '/')
        {
            parent_path.len--;
        }

        /*TODO: escape names */

        if (ngx_is_dir(&fi)) {
            rc = ngx_http_dlna_sprintf(r, NGX_HTTP_DLNA_BROWSE_CONTAINER,
                                       &parent_id, leaf, &parent_id, leaf);
        } else {
            ngx_libc_localtime(ngx_de_mtime(&dir), &tm);

            rc = ngx_http_dlna_sprintf(r, NGX_HTTP_DLNA_BROWSE_ITEM,
                                       &parent_id, leaf, &parent_id, leaf,
                                       tm.tm_year + 1900,
                                       tm.tm_mon + 1,
                                       tm.tm_mday,
                                       tm.tm_hour,
                                       tm.tm_min,
                                       tm.tm_sec,
                                       ngx_de_fs_size(&dir),
                                       (ngx_uint_t) (0xff & addr),
                                       (ngx_uint_t) (0xff & (addr >> 8)),
                                       (ngx_uint_t) (0xff & (addr >> 16)),
                                       (ngx_uint_t) (addr >> 24),
                                       (ngx_uint_t) port,
                                       &r->uri, &parent_path, leaf);
        }
    }

    if (ngx_http_dlna_sprintf(r, NGX_HTTP_DLNA_BROWSE_FOOTER, returned,
                              nmatches)
        != NGX_OK)
    {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->last->buf->last_buf = 1;

    r->headers_out.content_length_n = ctx->out_len;
    r->headers_out.status = NGX_HTTP_OK;

    ngx_str_set(&r->headers_out.content_type, "text/xml");

    rc = ngx_http_send_header(r);

    if (rc != NGX_ERROR) {
        rc = ngx_http_output_filter(r, ctx->out);
    }

    ngx_http_finalize_request(r, rc);

    return;

dir_error:

    ngx_close_dir(&dir);

    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
}


static ngx_int_t
ngx_http_dlna_sprintf(ngx_http_request_t *r, const char *fmt, ...)
{
    u_char               *p;
    va_list               args;
    ngx_buf_t            *b;
    ngx_uint_t            ntries;
    ngx_http_dlna_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_dlna_module);

    if (ctx->out == NULL && ngx_http_dlna_new_buf(r) != NGX_OK) {
        return NGX_ERROR;
    }

    for (ntries = 0; ; ntries++) {

        va_start(args, fmt);

        b = ctx->last->buf;
        p = ngx_vslprintf(b->last, b->end, fmt, args);

        va_end(args);

        if (p != b->end) {
            ctx->out_len += (off_t) (p - b->last);
            b->last = p;
            break;
        }

        if (ntries) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "dlna buffer too small");
            return NGX_ERROR;
        }

        if (ngx_http_dlna_new_buf(r) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_dlna_new_buf(ngx_http_request_t *r)
{
    ngx_buf_t            *b;
    ngx_chain_t          *cl;
    ngx_http_dlna_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_dlna_module);

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    b = ngx_create_temp_buf(r->pool, NGX_HTTP_DLNA_BUFSIZE);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    if (ctx->out == NULL) {
        ctx->out = cl;
    }

    if (ctx->last) {
        ctx->last->next = cl;
    }

    ctx->last = cl;

    return NGX_OK;
}


#define NGX_HTTP_DLNA_ROOT                                                    \
"<?xml version=\"1.0\"?>\n"                                                   \
"<root"                                                                       \
   " xmlns=\"urn:schemas-upnp-org:device-1-0\""                               \
   " xmlns:pnpx=\"http://schemas.microsoft.com/windows/pnpx/2005/11\""        \
   " xmlns:df=\"http://schemas.microsoft.com"                                 \
                                     "/windows/2008/09/devicefoundation\">\n" \
"  <specVersion>\n"                                                           \
"    <major>1</major>\n"                                                      \
"    <minor>0</minor>\n"                                                      \
"  </specVersion>\n"                                                          \
"  <device>\n"                                                                \
"    <deviceType>"                                                            \
      "urn:schemas-upnp-org:device:MediaServer:1"                             \
    "</deviceType>\n"                                                         \
"    <pnpx:X_hardwareId>"                                                     \
      "VEN_0000&amp;DEV_0000&amp;REV_01 VEN_0033&amp;DEV_0001&amp;REV_01"     \
    "</pnpx:X_hardwareId>\n"                                                  \
"    <pnpx:X_compatibleId>"                                                   \
      "MS_DigitalMediaDeviceClass_DMS_V001"                                   \
    "</pnpx:X_compatibleId>\n"                                                \
"    <pnpx:X_deviceCategory>"                                                 \
      "MediaDevices"                                                          \
    "</pnpx:X_deviceCategory>\n"                                              \
"    <df:X_deviceCategory>"                                                   \
      "Multimedia.DMS"                                                        \
    "</df:X_deviceCategory>\n"                                                \
"    <friendlyName>"                                                          \
      "%V"                                                                    \
    "</friendlyName>\n"                                                       \
"    <manufacturer>"                                                          \
      "arut"                                                                  \
    "</manufacturer>\n"                                                       \
"    <sec:ProductCap>"                                                        \
      "smi,DCM10,getMediaInfo.sec,getCaptionInfo.sec"                         \
    "</sec:ProductCap>\n"                                                     \
"    <modelDescription>"                                                      \
      "nginxDLNA"                                                             \
    "</modelDescription>\n"                                                   \
"    <modelName>"                                                             \
      "Nginx DLNA service"                                                    \
    "</modelName>\n"                                                          \
"    <modelNumber>"                                                           \
      "1"                                                                     \
    "</modelNumber>\n"                                                        \
"    <sec:X_ProductCap>"                                                      \
      "smi,DCM10,getMediaInfo.sec,getCaptionInfo.sec"                         \
    "</sec:X_ProductCap>\n"                                                   \
"    <UDN>"                                                                   \
      "uuid:57ad7ec9-f4f8-4c33-8028-274b057b4983"                             \
    "</UDN>\n"                                                                \
"    <dlna:X_DLNADOC "                                                        \
        "xmlns:dlna=\"urn:schemas-dlna-org:device-1-0\">"                     \
      "DMS-1.50"                                                              \
"    </dlna:X_DLNADOC>\n"                                                     \
"    <serviceList>\n"                                                         \
"      <service>\n"                                                           \
"        <serviceType>"                                                       \
           "urn:schemas-upnp-org:service:ContentDirectory:1"                  \
         "</serviceType>\n"                                                   \
"        <serviceId>"                                                         \
           "urn:upnp-org:serviceId:ContentDirectory"                          \
        "</serviceId>\n"                                                      \
"        <controlURL>"                                                        \
           "."                                                                \
        "</controlURL>\n"                                                     \
"        <eventSubURL>"                                                       \
        "</eventSubURL>\n"                                                    \
"        <SCPDURL>"                                                           \
          "/.upnp/desc.xml"                                                   \
        "</SCPDURL>\n"                                                        \
"      </service>\n"                                                          \
"    </serviceList>\n"                                                        \
"  </device>\n"                                                               \
"</root>"


static ngx_int_t
ngx_http_dlna_root(ngx_http_request_t *r)
{
    u_char                    *p;
    ngx_str_t                  ct, s;
    ngx_http_complex_value_t   cv;
    ngx_http_dlna_loc_conf_t  *dlcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dlna root");

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dlna_module);

    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));

    s.len = sizeof(NGX_HTTP_DLNA_ROOT) + dlcf->name.len;
    s.data = ngx_palloc(r->pool, s.len);

    if (s.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_snprintf(s.data, s.len, NGX_HTTP_DLNA_ROOT, &dlcf->name);
    s.len = (size_t) (p - s.data);

    cv.value.data = s.data;
    cv.value.len = s.len;

    ngx_str_set(&ct, "text/xml");

    return ngx_http_send_response(r, NGX_HTTP_OK, &ct, &cv);
}


static void
ngx_http_dlna_get_system_update_id(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dlna GetSystemUpdateID");

    ngx_http_dlna_send(r, (u_char*) "", 0);
}


static void
ngx_http_dlna_get_sort_capabilities(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dlna GetSortCapabilities");

    ngx_http_dlna_send(r, (u_char *) "", 0);
}


static void
ngx_http_dlna_get_search_capabilities(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dlna GetSearchCapabilities");

    ngx_http_dlna_send(r, (u_char *) "", 0);
}


#define NGX_HTTP_DLNA_XGETFEATURELIST_RESPONSE                                \
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"                            \
    "<s:Envelope \n"                                                          \
    "     xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"\n"            \
    "     s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n"   \
    "  <s:Body>\n"                                                            \
    "    <u:X_GetFeatureListResponse\n"                                       \
    "         xmlns:u=\"urn:schemas-upnp-org:service:ContentDirectory:1\">\n" \
    "      <FeatureList>\n"                                                   \
                                                                              \
    "        &lt;?xml version=\"1.0\" encoding=\"utf-8\"?&gt;\n"              \
    "        &lt;Features\n"                                                  \
    "            xmlns=\"urn:schemas-upnp-org:av:avs\"\n"                     \
    "            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n"   \
    "            xsi:schemaLocation=\"urn:schemas-upnp-org:av:avs"            \
    " http://www.upnp.org/schemas/av/avs.xsd\"&gt;\n"                         \
    "          &lt;Feature\n"                                                 \
    "              name=\"samsung.com_BASICVIEW\"\n"                          \
    "              version=\"1\"&gt;\n"                                       \
    "            &lt;container\n"                                             \
    "                id=\"1\"\n"                                              \
    "                type=\"object.item.audioItem\"/&gt;\n"                   \
    "            &lt;container\n"                                             \
    "                id=\"2\"\n"                                              \
    "                type=\"object.item.videoItem\"/&gt;\n"                   \
    "            &lt;container\n"                                             \
    "                id=\"3\"\n"                                              \
    "                type=\"object.item.imageItem\"/&gt;\n"                   \
    "          &lt;/Feature&gt;\n"                                            \
    "        &lt;/Features&gt;\n"                                             \
                                                                              \
    "      </FeatureList>\n"                                                  \
    "    </u:X_GetFeatureListResponse>\n"                                     \
    "  </s:Body>\n"                                                           \
    "</s:Envelope>\n"


static void
ngx_http_dlna_x_get_feature_list(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dlna X_GetFeatureList");

    ngx_http_dlna_send(r, (u_char *) NGX_HTTP_DLNA_XGETFEATURELIST_RESPONSE,
                       sizeof(NGX_HTTP_DLNA_XGETFEATURELIST_RESPONSE) - 1);
}


static void
ngx_http_dlna_send(ngx_http_request_t *r, u_char *data, size_t len)
{
    ngx_str_t                 ct;
    ngx_http_complex_value_t  cv;

    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));

    cv.value.data = data;
    cv.value.len = len;

    ngx_str_set(&ct, "text/xml");

    ngx_http_finalize_request(r,
                              ngx_http_send_response(r, NGX_HTTP_OK, &ct, &cv));
}


static char *
ngx_http_dlna(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                  *value;
    ngx_http_dlna_root_t       *root;
    ngx_http_core_srv_conf_t   *cscf;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_dlna_loc_conf_t   *dlcf;
    ngx_http_dlna_main_conf_t  *dmcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_dlna_handler;

    cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);
    dmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_dlna_module);

    root = ngx_array_push(&dmcf->roots);
    if (root == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(root, sizeof(ngx_http_dlna_root_t));

    root->cscf = cscf;
    root->location = clcf->name;

    if (cf->args->nelts == 1) {
        return NGX_CONF_OK;
    }

    dlcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_dlna_module);

    value = cf->args->elts;

    dlcf->name = value[1];
    dlcf->root = root;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_dlna_postconfiguration(ngx_conf_t *cf)
{
    ngx_uint_t                  n, i, j;
    ngx_ssdp_dlna_root_t       *r;
    ngx_http_conf_addr_t       *addr;
    ngx_http_conf_port_t       *port;
    ngx_http_dlna_root_t       *root;
    ngx_ssdp_dlna_conf_t       *sdcf;
    ngx_http_dlna_main_conf_t  *dmcf;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf,  ngx_http_core_module);

    dmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_dlna_module);

    sdcf = (ngx_ssdp_dlna_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
                                                 ngx_ssdp_dlna_module);

    root = dmcf->roots.elts;
    for (j = 0; j < dmcf->roots.nelts; j++) {

        port = cmcf->ports->elts;
        for (n = 0; n < cmcf->ports->nelts; n++) {

            addr = port[n].addrs.elts;
            for (i = 0; i < port[n].addrs.nelts; i++) {

                if (port->family == AF_INET
                    && addr[i].default_server == root[j].cscf)
                {
                    r = ngx_array_push(&sdcf->roots);
                    if (r == NULL) {
                        return NGX_ERROR;
                    }

                    r->location = root->location;
                    r->port = ntohs(port[n].port);
                    r->addr = addr[i].opt.u.sockaddr_in.sin_addr.s_addr;

                    root->port = r->port;
                    root->addr = r->addr;
                }
            }
        }
    }

    return NGX_OK;
}


static void *
ngx_http_dlna_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_dlna_main_conf_t  *dmcf;

    dmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dlna_main_conf_t));
    if (dmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&dmcf->roots, cf->pool, sizeof(ngx_http_dlna_root_t), 1)
        != NGX_OK)
    {
        return NULL;
    }

    return dmcf;
}


static void *
ngx_http_dlna_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_dlna_loc_conf_t  *dlcf;

    dlcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dlna_loc_conf_t));
    if (dlcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     dlcf->name = { 0, NULL };
     */

    return dlcf;
}


static char *
ngx_http_dlna_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_dlna_loc_conf_t  *prev = parent;
    ngx_http_dlna_loc_conf_t  *conf = child;

    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    if (conf->name.data == NULL) {

        if (prev->name.data) {
            conf->name = prev->name;

        } else {
            conf->name = clcf->name;
            if (conf->name.len && conf->name.data[0] == '/') {
                conf->name.len--;
                conf->name.data++;
            }
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_dlna_init_process(ngx_cycle_t *cycle)
{
    return ngx_ssdp_dlna_init();
}
