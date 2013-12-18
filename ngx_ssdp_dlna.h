
/*
 * Copyright (C) Roman Arutyunyan
 */


#ifndef _NGX_SSDP_DLNA_H_INCLUDED_
#define _NGX_SSDP_DLNA_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_SSDP_DLNA_ROOT_URI  "/.upnp-root.xml"


typedef struct {
    uint32_t     addr;
    uint32_t     mask;
} ngx_ssdp_dlna_iface_t;


typedef struct {
    in_port_t    port;
    uint32_t     addr;
    ngx_str_t    location;
} ngx_ssdp_dlna_root_t;


typedef struct {
    ngx_array_t  roots; /* ngx_ssdp_dlna_root_t */
    ngx_array_t  iface; /* ngx_ssdp_dlna_iface_t */
} ngx_ssdp_dlna_conf_t;


ngx_int_t ngx_ssdp_dlna_init();


extern ngx_module_t  ngx_ssdp_dlna_module;


#endif /* _NGX_SSDP_DLNA_H_INCLUDED_ */
