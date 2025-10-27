#ifndef _NGX_HTTP_X402_MODULE_H_INCLUDED_
#define _NGX_HTTP_X402_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* Maximum public key length */
#define NGX_HTTP_X402_MAX_KEY_LEN 256

/* Maximum signature length */
#define NGX_HTTP_X402_MAX_SIGNATURE_LEN 512

/* Maximum message length for signing */
#define NGX_HTTP_X402_MAX_MESSAGE_LEN 1024

/* Payment requirement configuration */
typedef struct {
    ngx_str_t                     scheme;           /* Payment scheme */
    ngx_str_t                     network;          /* Blockchain network ID */
    ngx_str_t                     max_amount_required; /* Max amount */
    ngx_str_t                     pay_to;           /* Payment address */
    ngx_uint_t                    max_timeout_seconds; /* Timeout in seconds */
    ngx_str_t                     asset;            /* ERC20 contract address */
    ngx_str_t                     description;      /* Description */
    ngx_str_t                     mime_type;        /* MIME type */
    ngx_str_t                     extra;            /* Extra info (JSON) */
} ngx_http_x402_payment_conf_t;

/* Module configuration structure */
typedef struct {
    ngx_flag_t                    enabled;           /* Whether module is enabled */
    ngx_str_t                     public_key;       /* Public key for signature verification */
    ngx_str_t                     private_key;      /* Private key for signature creation */
    ngx_str_t                     algorithm;        /* Signature algorithm (default: secp256k1) */
    ngx_msec_t                    timeout;          /* Timeout for payment verification */
    ngx_str_t                     payment_endpoint; /* Endpoint for payment verification */
    ngx_array_t                  *allowed_currencies; /* Allowed currencies */
    
    /* Multiple payment requirements for X402 specification */
    ngx_array_t                  *payment_requirements; /* Array of ngx_http_x402_payment_conf_t */
    ngx_int_t                     x402_version;     /* Version of x402 protocol */
} ngx_http_x402_conf_t;

/* Structure for storing payment requirements */
typedef struct {
    ngx_str_t                     scheme;           /* Payment scheme (e.g., "exact") */
    ngx_str_t                     network;          /* Blockchain network */
    ngx_str_t                     maxAmountRequired; /* Max amount in atomic units */
    ngx_str_t                     resource;        /* URL of resource to pay for */
    ngx_str_t                     description;      /* Description of the resource */
    ngx_str_t                     mimeType;         /* MIME type of resource response */
    ngx_str_t                     outputSchema;     /* Output schema (optional) */
    ngx_str_t                     payTo;           /* Address to pay value to */
    ngx_uint_t                    maxTimeoutSeconds; /* Max timeout in seconds */
    ngx_str_t                     asset;           /* ERC20 contract address */
    ngx_str_t                     extra;           /* Extra information (optional) */
} ngx_http_x402_payment_requirement_t;

/* Payment Required Response structure */
typedef struct {
    ngx_int_t                     x402Version;     /* Version of x402 protocol */
    ngx_array_t                  *accepts;         /* Array of payment requirements */
    ngx_str_t                     error;           /* Error message */
} ngx_http_x402_payment_required_t;

/* X-PAYMENT header data structure */
typedef struct {
    ngx_int_t                     x402Version;     /* Version of x402 protocol */
    ngx_str_t                     scheme;           /* Payment scheme */
    ngx_str_t                     network;          /* Network ID */
    ngx_str_t                     payload;          /* Scheme-dependent payload */
    ngx_str_t                     signature;        /* Signature (legacy support) */
    ngx_str_t                     public_key;       /* Public key (legacy support) */
    ngx_str_t                     message;          /* Message (legacy support) */
    ngx_str_t                     currency;         /* Payment currency */
    ngx_str_t                     amount;           /* Payment amount */
    ngx_str_t                     transaction_id;   /* Transaction ID */
    time_t                        timestamp;        /* Timestamp */
} ngx_http_x402_data_t;

/* Module functions */
ngx_int_t ngx_http_x402_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_x402_verify_signature(ngx_http_request_t *r, ngx_http_x402_data_t *data);
ngx_int_t ngx_http_x402_verify_payment(ngx_http_request_t *r, ngx_http_x402_data_t *data);
ngx_int_t ngx_http_x402_parse_header(ngx_http_request_t *r, ngx_http_x402_data_t *data);
ngx_int_t ngx_http_x402_create_signature(ngx_str_t *message, ngx_str_t *private_key, ngx_str_t *signature);

/* Payment Required Response functions */
ngx_int_t ngx_http_x402_send_payment_required(ngx_http_request_t *r, 
                                               ngx_http_x402_payment_required_t *payment_req);
ngx_int_t ngx_http_x402_build_payment_required_json(ngx_http_request_t *r,
                                                      ngx_http_x402_payment_required_t *payment_req,
                                                      ngx_str_t *output);

/* X-PAYMENT header parsing (base64 JSON format) */
ngx_int_t ngx_http_x402_parse_x_payment_header(ngx_http_request_t *r, ngx_http_x402_data_t *data);

/* Utility functions */
ngx_int_t ngx_http_x402_hex_decode(ngx_str_t *hex, u_char *binary, size_t *len);
ngx_int_t ngx_http_x402_hex_encode(u_char *binary, size_t len, ngx_str_t *hex);
ngx_int_t ngx_http_x402_verify_timestamp(time_t timestamp, ngx_msec_t timeout);

/* Cryptographic functions */
ngx_int_t ngx_http_x402_verify_ecdsa_signature(u_char *signature, size_t sig_len,
                                               u_char *public_key, size_t pub_key_len,
                                               u_char *message, size_t msg_len);
ngx_int_t ngx_http_x402_create_ecdsa_signature(ngx_str_t *message, ngx_str_t *private_key,
                                                u_char **signature, size_t *sig_len);

/* HTTP functions */
ngx_int_t ngx_http_x402_http_verify_payment(ngx_str_t *endpoint, ngx_http_x402_data_t *data);
static size_t ngx_http_x402_curl_write_callback(void *contents, size_t size, size_t nmemb, void *userp);

/* Configuration directives */
char *ngx_http_x402_enabled(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_http_x402_public_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_http_x402_private_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_http_x402_algorithm(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_http_x402_timeout(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_http_x402_payment_endpoint(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
/* Removed: ngx_http_x402_currency - network validation is done through x402_payment blocks */

/* Configuration commands */
extern ngx_command_t ngx_http_x402_commands[];

/* Module */
extern ngx_module_t ngx_http_x402_module;

#endif /* _NGX_HTTP_X402_MODULE_H_INCLUDED_ */
