#include "ngx_http_x402_module.h"

/* Configuration commands */
static ngx_command_t ngx_http_x402_commands[] = {
    { ngx_string("x402_enabled"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_x402_enabled,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_x402_conf_t, enabled),
      NULL },

    { ngx_string("x402_public_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_x402_public_key,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_x402_conf_t, public_key),
      NULL },

    { ngx_string("x402_private_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_x402_private_key,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_x402_conf_t, private_key),
      NULL },

    { ngx_string("x402_algorithm"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_x402_algorithm,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_x402_conf_t, algorithm),
      NULL },

    { ngx_string("x402_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_x402_timeout,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_x402_conf_t, timeout),
      NULL },

    { ngx_string("x402_payment_endpoint"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_x402_payment_endpoint,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_x402_conf_t, payment_endpoint),
      NULL },

    { ngx_string("x402_payment"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_http_x402_payment_block,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("scheme"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      0,
      NULL },

    { ngx_string("network"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      0,
      NULL },

    { ngx_string("max_amount_required"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      0,
      NULL },

    { ngx_string("pay_to"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      0,
      NULL },

    { ngx_string("max_timeout_seconds"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      0,
      NULL },

    { ngx_string("asset"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      0,
      NULL },

    { ngx_string("description"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      0,
      NULL },

    { ngx_string("mime_type"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      0,
      NULL },

    { ngx_string("extra"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      0,
      NULL },

    { ngx_string("}"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_http_x402_payment_block_end,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("x402_version"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_x402_conf_t, x402_version),
      NULL },

    ngx_null_command
};

/* Configuration creation */
static void *ngx_http_x402_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_x402_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

/* Request handler */
static ngx_int_t ngx_http_x402_handler(ngx_http_request_t *r);

/* Module */
ngx_module_t ngx_http_x402_module = {
    NGX_MODULE_V1,
    &ngx_http_x402_module_ctx,    /* module context */
    ngx_http_x402_commands,       /* module directives */
    NGX_HTTP_MODULE,              /* module type */
    NULL,                         /* init master */
    NULL,                         /* init module */
    NULL,                         /* init process */
    NULL,                         /* init thread */
    NULL,                         /* exit thread */
    NULL,                         /* exit process */
    NULL,                         /* exit master */
    NGX_MODULE_V1_PADDING
};

/* Module context */
static ngx_http_module_t ngx_http_x402_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */
    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */
    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */
    ngx_http_x402_create_loc_conf, /* create location configuration */
    ngx_http_x402_merge_loc_conf   /* merge location configuration */
};

/* Configuration creation */
static void *
ngx_http_x402_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_x402_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_x402_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /* Set default values */
    conf->enabled = NGX_CONF_UNSET;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->algorithm.data = (u_char *) "secp256k1";
    conf->algorithm.len = sizeof("secp256k1") - 1;
    conf->allowed_currencies = NULL;
    
    /* Payment requirements defaults */
    conf->x402_version = NGX_CONF_UNSET;
    conf->max_timeout_seconds = NGX_CONF_UNSET;

    return conf;
}

/* Configuration merging */
static char *
ngx_http_x402_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_x402_conf_t *prev = parent;
    ngx_http_x402_conf_t *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 30000); /* 30 seconds by default */
    ngx_conf_merge_str_value(conf->algorithm, prev->algorithm, "secp256k1");
    ngx_conf_merge_str_value(conf->public_key, prev->public_key, "");
    ngx_conf_merge_str_value(conf->private_key, prev->private_key, "");
    ngx_conf_merge_str_value(conf->payment_endpoint, prev->payment_endpoint, "");
    
    /* Merge new payment requirements fields */
    ngx_conf_merge_str_value(conf->scheme, prev->scheme, "");
    ngx_conf_merge_str_value(conf->network, prev->network, "");
    ngx_conf_merge_str_value(conf->max_amount_required, prev->max_amount_required, "");
    ngx_conf_merge_str_value(conf->pay_to, prev->pay_to, "");
    ngx_conf_merge_uint_value(conf->max_timeout_seconds, prev->max_timeout_seconds, 0);
    ngx_conf_merge_str_value(conf->asset, prev->asset, "");
    ngx_conf_merge_str_value(conf->description, prev->description, "");
    ngx_conf_merge_str_value(conf->mime_type, prev->mime_type, "");
    ngx_conf_merge_str_value(conf->extra, prev->extra, "");
    ngx_conf_merge_value(conf->x402_version, prev->x402_version, 1);

    return NGX_CONF_OK;
}

/* Request handler */
static ngx_int_t
ngx_http_x402_handler(ngx_http_request_t *r)
{
    ngx_http_x402_conf_t *conf;
    ngx_http_x402_data_t data;
    ngx_int_t rc;

    /* Get configuration */
    conf = ngx_http_get_module_loc_conf(r, ngx_http_x402_module);
    if (conf == NULL || !conf->enabled) {
        return NGX_DECLINED;
    }

    /* Parse x402 header */
    rc = ngx_http_x402_parse_header(r, &data);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "x402: failed to parse header");
        return NGX_HTTP_BAD_REQUEST;
    }

    /* Verify signature */
    rc = ngx_http_x402_verify_signature(r, &data);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "x402: signature verification failed");
        return NGX_HTTP_UNAUTHORIZED;
    }

    /* Verify payment */
    rc = ngx_http_x402_verify_payment(r, &data);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "x402: payment verification failed");
        return NGX_HTTP_PAYMENT_REQUIRED;
    }

    /* Add headers for backend */
    ngx_table_elt_t *h;
    
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    h->hash = 1;
    ngx_str_set(&h->key, "X-X402-Verified");
    ngx_str_set(&h->value, "true");
    h->lowcase_key = (u_char *) "x-x402-verified";

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    h->hash = 1;
    ngx_str_set(&h->key, "X-X402-Network");
    h->value = data.network;
    h->lowcase_key = (u_char *) "x-x402-network";

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    h->hash = 1;
    ngx_str_set(&h->key, "X-X402-Amount");
    h->value = data.amount;
    h->lowcase_key = (u_char *) "x-x402-amount";

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    h->hash = 1;
    ngx_str_set(&h->key, "X-X402-Transaction-Id");
    h->value = data.transaction_id;
    h->lowcase_key = (u_char *) "x-x402-transaction-id";

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "x402: payment verified successfully");

    return NGX_DECLINED; /* Continue request processing */
}

/* Configuration function implementations */
char *
ngx_http_x402_enabled(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;
    ngx_http_x402_conf_t *x402_conf = conf;

    if (ngx_strcmp(value[1].data, "on") == 0) {
        x402_conf->enabled = 1;
    } else if (ngx_strcmp(value[1].data, "off") == 0) {
        x402_conf->enabled = 0;
    } else {
        return "invalid value, must be \"on\" or \"off\"";
    }

    return NGX_CONF_OK;
}

char *
ngx_http_x402_public_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;
    ngx_http_x402_conf_t *x402_conf = conf;

    x402_conf->public_key = value[1];

    return NGX_CONF_OK;
}

char *
ngx_http_x402_private_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;
    ngx_http_x402_conf_t *x402_conf = conf;

    x402_conf->private_key = value[1];

    return NGX_CONF_OK;
}

char *
ngx_http_x402_algorithm(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;
    ngx_http_x402_conf_t *x402_conf = conf;

    x402_conf->algorithm = value[1];

    return NGX_CONF_OK;
}

char *
ngx_http_x402_timeout(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;
    ngx_http_x402_conf_t *x402_conf = conf;
    ngx_msec_t timeout;

    timeout = ngx_parse_time(&value[1], 1);
    if (timeout == (ngx_msec_t) NGX_ERROR) {
        return "invalid timeout value";
    }

    x402_conf->timeout = timeout;

    return NGX_CONF_OK;
}

char *
ngx_http_x402_payment_endpoint(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;
    ngx_http_x402_conf_t *x402_conf = conf;

    x402_conf->payment_endpoint = value[1];

    return NGX_CONF_OK;
}

/* Removed: x402_currency directive
 * Network is now validated through x402_payment blocks
 */
