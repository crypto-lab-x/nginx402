#include "ngx_http_x402_module.h"
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <curl/curl.h>

/* Helper function to split string by delimiter */
static ngx_int_t
ngx_split_str(ngx_str_t *str, u_char delimiter, ngx_str_t *parts, ngx_int_t max_parts)
{
    u_char *p, *end, *start;
    ngx_int_t count = 0;
    
    p = str->data;
    end = str->data + str->len;
    start = p;
    
    while (p < end && count < max_parts) {
        if (*p == delimiter || p == end - 1) {
            if (p > start || (p == start && *p != delimiter)) {
                parts[count].data = start;
                if (p == end - 1) {
                    parts[count].len = (p - start) + 1;
                    break;
                } else {
                    parts[count].len = p - start;
                }
                count++;
            }
            start = p + 1;
        }
        p++;
    }
    
    return count;
}

/* Base64 decode */
static ngx_int_t
ngx_http_x402_base64_decode(ngx_pool_t *pool, ngx_str_t *b64, ngx_str_t *decoded)
{
    u_char *p, *end, c;
    u_char ch[4];
    ngx_uint_t i, j;

    decoded->len = (b64->len * 3) / 4;
    decoded->data = ngx_pnalloc(pool, decoded->len);
    if (decoded->data == NULL) {
        return NGX_ERROR;
    }

    p = b64->data;
    end = b64->data + b64->len;
    j = 0;

    while (p < end) {
        /* Decode 4 base64 characters to 3 bytes */
        for (i = 0; i < 4 && p < end; i++, p++) {
            c = *p;
            if (c >= 'A' && c <= 'Z') {
                ch[i] = c - 'A';
            } else if (c >= 'a' && c <= 'z') {
                ch[i] = c - 'a' + 26;
            } else if (c >= '0' && c <= '9') {
                ch[i] = c - '0' + 52;
            } else if (c == '+') {
                ch[i] = 62;
            } else if (c == '/') {
                ch[i] = 63;
            } else if (c == '=') {
                break;
            } else {
                return NGX_ERROR;
            }
        }

        while (i < 4) {
            ch[i++] = 0;
        }

        decoded->data[j++] = (ch[0] << 2) | (ch[1] >> 4);
        if (j < decoded->len) {
            decoded->data[j++] = (ch[1] << 4) | (ch[2] >> 2);
        }
        if (j < decoded->len) {
            decoded->data[j++] = (ch[2] << 6) | ch[3];
        }
    }

    decoded->len = j;
    return NGX_OK;
}

/* Parse x402 header (legacy format - semicolon-separated) */
ngx_int_t
ngx_http_x402_parse_header(ngx_http_request_t *r, ngx_http_x402_data_t *data)
{
    ngx_table_elt_t *h;
    ngx_str_t *value;
    ngx_int_t rc;

    /* Initialize data structure */
    ngx_memzero(data, sizeof(ngx_http_x402_data_t));

    /* Find X402 header */
    h = ngx_http_get_header(r, "X402");
    if (h == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "x402: X402 header not found");
        return NGX_ERROR;
    }

    /* Parse header value */
    value = &h->value;
    
    /* Format: signature;public_key;message;currency;amount;transaction_id;timestamp */
    ngx_str_t parts[7];
    ngx_int_t n = ngx_split_str(value, ';', parts, 7);
    
    if (n != 7) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "x402: invalid header format, expected 7 parts, got %i", n);
        return NGX_ERROR;
    }

    /* Fill data structure */
    data->signature = parts[0];
    data->public_key = parts[1];
    data->message = parts[2];
    data->currency = parts[3];
    data->amount = parts[4];
    data->transaction_id = parts[5];

    /* Parse timestamp */
    data->timestamp = ngx_atoi(parts[6].data, parts[6].len);
    if (data->timestamp == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "x402: invalid timestamp");
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* Parse X-PAYMENT header (base64 JSON format) */
ngx_int_t
ngx_http_x402_parse_x_payment_header(ngx_http_request_t *r, ngx_http_x402_data_t *data)
{
    ngx_table_elt_t *h;
    ngx_str_t b64_data, json_data;
    ngx_int_t rc;

    /* Initialize data structure */
    ngx_memzero(data, sizeof(ngx_http_x402_data_t));

    /* Find X-PAYMENT header */
    h = ngx_http_get_header(r, "X-PAYMENT");
    if (h == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "x402: X-PAYMENT header not found");
        return NGX_ERROR;
    }

    /* Decode base64 */
    b64_data = h->value;
    rc = ngx_http_x402_base64_decode(r->pool, &b64_data, &json_data);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "x402: failed to decode base64");
        return NGX_ERROR;
    }

    /* TODO: Parse JSON and extract fields */
    /* For now, we'll extract basic info from JSON */
    /* In a full implementation, you would use a JSON parser library */
    
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "x402: parsed X-PAYMENT header (JSON format)");

    return NGX_OK;
}

/* Verify signature */
ngx_int_t
ngx_http_x402_verify_signature(ngx_http_request_t *r, ngx_http_x402_data_t *data)
{
    ngx_http_x402_conf_t *conf;
    u_char signature_binary[NGX_HTTP_X402_MAX_SIGNATURE_LEN];
    u_char public_key_binary[NGX_HTTP_X402_MAX_KEY_LEN];
    u_char message_binary[NGX_HTTP_X402_MAX_MESSAGE_LEN];
    size_t signature_len, public_key_len, message_len;
    ngx_int_t rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_x402_module);
    if (conf == NULL) {
        return NGX_ERROR;
    }

    /* Decode hex strings */
    rc = ngx_http_x402_hex_decode(&data->signature, signature_binary, &signature_len);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "x402: failed to decode signature");
        return NGX_ERROR;
    }

    rc = ngx_http_x402_hex_decode(&data->public_key, public_key_binary, &public_key_len);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "x402: failed to decode public key");
        return NGX_ERROR;
    }

    rc = ngx_http_x402_hex_decode(&data->message, message_binary, &message_len);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "x402: failed to decode message");
        return NGX_ERROR;
    }

    /* Verify timestamp */
    rc = ngx_http_x402_verify_timestamp(data->timestamp, conf->timeout);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "x402: timestamp verification failed");
        return NGX_ERROR;
    }

    /* ECDSA signature verification */
    rc = ngx_http_x402_verify_ecdsa_signature(signature_binary, signature_len,
                                              public_key_binary, public_key_len,
                                              message_binary, message_len);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "x402: ECDSA signature verification failed");
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "x402: signature verification passed");

    return NGX_OK;
}

/* Verify payment */
ngx_int_t
ngx_http_x402_verify_payment(ngx_http_request_t *r, ngx_http_x402_data_t *data)
{
    ngx_http_x402_conf_t *conf;
    ngx_int_t rc;
    ngx_uint_t i;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_x402_module);
    if (conf == NULL) {
        return NGX_ERROR;
    }

    /* Check if network from header matches any configured payment requirement */
    if (conf->payment_requirements != NULL && conf->payment_requirements->nelts > 0) {
        ngx_http_x402_payment_conf_t *requirements = conf->payment_requirements->elts;
        ngx_int_t found = 0;

        for (i = 0; i < conf->payment_requirements->nelts; i++) {
            if (ngx_strcmp(requirements[i].network.data, data->network.data) == 0) {
                found = 1;
                
                /* Also verify scheme matches */
                if (ngx_strcmp(requirements[i].scheme.data, data->scheme.data) == 0) {
                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                                  "x402: network %V matched requirement", &data->network);
                    break;
                }
            }
        }

        if (!found) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "x402: network %V not allowed", &data->network);
            return NGX_ERROR;
        }
    }

    /* If payment endpoint is specified, make HTTP request */
    if (conf->payment_endpoint.len > 0) {
        rc = ngx_http_x402_verify_payment_remote(r, data, &conf->payment_endpoint);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "x402: remote payment verification failed");
            return NGX_ERROR;
        }
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "x402: payment verification passed for %V on network %V",
                  &data->amount, &data->network);

    return NGX_OK;
}

/* Remote payment verification */
ngx_int_t
ngx_http_x402_verify_payment_remote(ngx_http_request_t *r, ngx_http_x402_data_t *data, ngx_str_t *endpoint)
{
    /* HTTP request to external API for payment status verification */
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "x402: remote payment verification for transaction %V",
                  &data->transaction_id);

    /* Execute HTTP request for payment verification */
    rc = ngx_http_x402_http_verify_payment(endpoint, data);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "x402: remote payment verification failed");
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "x402: remote payment verification successful");
    return NGX_OK;
}

/* Create signature */
ngx_int_t
ngx_http_x402_create_signature(ngx_str_t *message, ngx_str_t *private_key, ngx_str_t *signature)
{
    /* ECDSA cryptographic signature */
    u_char *sig_data;
    size_t sig_len;
    ngx_int_t rc;
    
    rc = ngx_http_x402_create_ecdsa_signature(message, private_key, &sig_data, &sig_len);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }
    
    /* Encode signature to hex */
    rc = ngx_http_x402_hex_encode(sig_data, sig_len, signature);
    if (rc != NGX_OK) {
        ngx_free(sig_data);
        return NGX_ERROR;
    }
    
    ngx_free(sig_data);
    return NGX_OK;
}

/* Decode hex string */
ngx_int_t
ngx_http_x402_hex_decode(ngx_str_t *hex, u_char *binary, size_t *len)
{
    u_char *p, *end;
    u_char c;
    ngx_int_t high, low;
    
    if (hex->len % 2 != 0) {
        return NGX_ERROR;
    }
    
    p = hex->data;
    end = hex->data + hex->len;
    *len = 0;
    
    while (p < end) {
        c = *p++;
        if (c >= '0' && c <= '9') {
            high = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            high = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            high = c - 'A' + 10;
        } else {
            return NGX_ERROR;
        }
        
        c = *p++;
        if (c >= '0' && c <= '9') {
            low = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            low = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            low = c - 'A' + 10;
        } else {
            return NGX_ERROR;
        }
        
        binary[(*len)++] = (high << 4) | low;
    }
    
    return NGX_OK;
}

/* Encode to hex string */
ngx_int_t
ngx_http_x402_hex_encode(u_char *binary, size_t len, ngx_str_t *hex)
{
    u_char *p;
    ngx_uint_t i;
    
    p = ngx_palloc(ngx_cycle->pool, len * 2 + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }
    
    for (i = 0; i < len; i++) {
        ngx_sprintf(p + i * 2, "%02x", binary[i]);
    }
    
    hex->data = p;
    hex->len = len * 2;
    
    return NGX_OK;
}

/* Verify timestamp */
ngx_int_t
ngx_http_x402_verify_timestamp(time_t timestamp, ngx_msec_t timeout)
{
    time_t now = ngx_time();
    time_t diff = now - timestamp;
    
    if (diff < 0 || diff > (timeout / 1000)) {
        return NGX_ERROR;
    }
    
    return NGX_OK;
}

/* Verify ECDSA signature */
ngx_int_t
ngx_http_x402_verify_ecdsa_signature(u_char *signature, size_t sig_len,
                                     u_char *public_key, size_t pub_key_len,
                                     u_char *message, size_t msg_len)
{
    EC_KEY *ec_key = NULL;
    ECDSA_SIG *ecdsa_sig = NULL;
    const EC_GROUP *group;
    BIGNUM *r = NULL, *s = NULL;
    u_char hash[SHA256_DIGEST_LENGTH];
    ngx_int_t rc = NGX_ERROR;
    
    /* Create message hash */
    if (SHA256(message, msg_len, hash) == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "x402: failed to create message hash");
        goto cleanup;
    }
    
    /* Create EC key from public key */
    ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (ec_key == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "x402: failed to create EC key");
        goto cleanup;
    }
    
    /* Decode public key */
    if (EC_KEY_oct2key(ec_key, public_key, pub_key_len, NULL) == 0) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "x402: failed to decode public key");
        goto cleanup;
    }
    
    /* Parse signature */
    if (sig_len < 64) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "x402: signature too short");
        goto cleanup;
    }
    
    /* Create ECDSA_SIG structure */
    ecdsa_sig = ECDSA_SIG_new();
    if (ecdsa_sig == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "x402: failed to create ECDSA_SIG");
        goto cleanup;
    }
    
    /* Parse r and s from signature */
    r = BN_bin2bn(signature, 32, NULL);
    s = BN_bin2bn(signature + 32, 32, NULL);
    
    if (r == NULL || s == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "x402: failed to parse signature components");
        goto cleanup;
    }
    
    if (ECDSA_SIG_set0(ecdsa_sig, r, s) == 0) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "x402: failed to set signature components");
        goto cleanup;
    }
    
    /* Verify signature */
    if (ECDSA_do_verify(hash, SHA256_DIGEST_LENGTH, ecdsa_sig, ec_key) == 1) {
        rc = NGX_OK;
    } else {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "x402: signature verification failed");
    }
    
cleanup:
    if (ecdsa_sig) ECDSA_SIG_free(ecdsa_sig);
    if (ec_key) EC_KEY_free(ec_key);
    
    return rc;
}

/* Create ECDSA signature */
ngx_int_t
ngx_http_x402_create_ecdsa_signature(ngx_str_t *message, ngx_str_t *private_key,
                                     u_char **signature, size_t *sig_len)
{
    EC_KEY *ec_key = NULL;
    ECDSA_SIG *ecdsa_sig = NULL;
    u_char hash[SHA256_DIGEST_LENGTH];
    u_char *sig_data = NULL;
    const BIGNUM *r, *s;
    ngx_int_t rc = NGX_ERROR;
    
    /* Create message hash */
    if (SHA256(message->data, message->len, hash) == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "x402: failed to create message hash");
        goto cleanup;
    }
    
    /* Create EC key from private key */
    ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (ec_key == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "x402: failed to create EC key");
        goto cleanup;
    }
    
    /* Decode private key */
    if (EC_KEY_oct2priv(ec_key, private_key->data, private_key->len) == 0) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "x402: failed to decode private key");
        goto cleanup;
    }
    
    /* Create signature */
    ecdsa_sig = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, ec_key);
    if (ecdsa_sig == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "x402: failed to create signature");
        goto cleanup;
    }
    
    /* Get r and s components */
    ECDSA_SIG_get0(ecdsa_sig, &r, &s);
    
    /* Allocate memory for signature */
    sig_data = ngx_palloc(ngx_cycle->pool, 64);
    if (sig_data == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "x402: failed to allocate memory for signature");
        goto cleanup;
    }
    
    /* Encode r and s to DER format */
    int r_len = BN_num_bytes(r);
    int s_len = BN_num_bytes(s);
    
    if (r_len > 32 || s_len > 32) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "x402: signature components too large");
        goto cleanup;
    }
    
    /* Fill signature */
    ngx_memzero(sig_data, 64);
    BN_bn2bin(r, sig_data + 32 - r_len);
    BN_bn2bin(s, sig_data + 64 - s_len);
    
    *signature = sig_data;
    *sig_len = 64;
    rc = NGX_OK;
    
cleanup:
    if (ecdsa_sig) ECDSA_SIG_free(ecdsa_sig);
    if (ec_key) EC_KEY_free(ec_key);
    
    return rc;
}

/* HTTP request for payment verification */
ngx_int_t
ngx_http_x402_http_verify_payment(ngx_str_t *endpoint, ngx_http_x402_data_t *data)
{
    CURL *curl;
    CURLcode res;
    ngx_str_t url;
    ngx_str_t post_data;
    u_char *response_data = NULL;
    size_t response_len = 0;
    ngx_int_t rc = NGX_ERROR;
    
    /* Initialize curl */
    curl = curl_easy_init();
    if (!curl) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "x402: failed to initialize curl");
        return NGX_ERROR;
    }
    
    /* Form URL */
    url.data = ngx_palloc(ngx_cycle->pool, endpoint->len + 50);
    if (url.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "x402: failed to allocate memory for URL");
        goto cleanup;
    }
    
    ngx_snprintf(url.data, endpoint->len + 50, "%V/verify", endpoint);
    url.len = ngx_strlen(url.data);
    
    /* Form POST data */
    post_data.data = ngx_palloc(ngx_cycle->pool, 512);
    if (post_data.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "x402: failed to allocate memory for POST data");
        goto cleanup;
    }
    
    ngx_snprintf(post_data.data, 512,
                 "transaction_id=%V&currency=%V&amount=%V",
                 &data->transaction_id, &data->currency, &data->amount);
    post_data.len = ngx_strlen(post_data.data);
    
    /* Configure curl */
    curl_easy_setopt(curl, CURLOPT_URL, url.data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data.data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)post_data.len);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ngx_http_x402_curl_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    
    /* Execute request */
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "x402: curl request failed: %s", curl_easy_strerror(res));
        goto cleanup;
    }
    
    /* Check response */
    if (response_data && ngx_strstr(response_data, "verified") != NULL) {
        rc = NGX_OK;
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                      "x402: payment verification successful");
    } else {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "x402: payment verification failed");
    }
    
cleanup:
    if (response_data) ngx_free(response_data);
    curl_easy_cleanup(curl);
    
    return rc;
}

/* Callback function for curl */
static size_t
ngx_http_x402_curl_write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    u_char **response_data = (u_char **)userp;
    
    *response_data = ngx_palloc(ngx_cycle->pool, realsize + 1);
    if (*response_data == NULL) {
        return 0;
    }
    
    ngx_memcpy(*response_data, contents, realsize);
    (*response_data)[realsize] = '\0';
    
    return realsize;
}

/* Build Payment Required JSON response */
ngx_int_t
ngx_http_x402_build_payment_required_json(ngx_http_request_t *r,
                                           ngx_http_x402_payment_required_t *payment_req,
                                           ngx_str_t *output)
{
    u_char *p;
    size_t len = 2048;
    ngx_str_t s;
    ngx_http_x402_payment_requirement_t *req;
    ngx_uint_t i;

    output->data = ngx_pnalloc(r->pool, len);
    if (output->data == NULL) {
        return NGX_ERROR;
    }

    p = output->data;
    output->len = 0;

    /* Start JSON object */
    ngx_sprintf(p, "{");
    p += 1;
    output->len += 1;

    /* x402Version */
    ngx_sprintf(p, "\"x402Version\":%i", payment_req->x402Version);
    p = output->data + output->len + ngx_strlen(output->data + output->len);
    output->len = p - output->data;

    /* accepts array */
    if (payment_req->accepts && payment_req->accepts->nelts > 0) {
        ngx_sprintf(p, ",\"accepts\":[");
        p += 12;
        output->len += 12;

        req = payment_req->accepts->elts;
        for (i = 0; i < payment_req->accepts->nelts; i++) {
            if (i > 0) {
                ngx_sprintf(p, ",");
                p += 1;
                output->len += 1;
            }

            ngx_sprintf(p, "{");
            p += 1;
            output->len += 1;

            /* scheme */
            ngx_sprintf(p, "\"scheme\":\"%V\"", &req[i].scheme);
            p = output->data + output->len + ngx_strlen(output->data + output->len);
            output->len = p - output->data;

            /* network */
            ngx_sprintf(p, ",\"network\":\"%V\"", &req[i].network);
            p = output->data + output->len + ngx_strlen(output->data + output->len);
            output->len = p - output->data;

            /* maxAmountRequired */
            ngx_sprintf(p, ",\"maxAmountRequired\":\"%V\"", &req[i].maxAmountRequired);
            p = output->data + output->len + ngx_strlen(output->data + output->len);
            output->len = p - output->data;

            /* resource */
            ngx_sprintf(p, ",\"resource\":\"%V\"", &req[i].resource);
            p = output->data + output->len + ngx_strlen(output->data + output->len);
            output->len = p - output->data;

            /* description */
            ngx_sprintf(p, ",\"description\":\"%V\"", &req[i].description);
            p = output->data + output->len + ngx_strlen(output->data + output->len);
            output->len = p - output->data;

            /* mimeType */
            ngx_sprintf(p, ",\"mimeType\":\"%V\"", &req[i].mimeType);
            p = output->data + output->len + ngx_strlen(output->data + output->len);
            output->len = p - output->data;

            /* outputSchema (optional) */
            if (req[i].outputSchema.len > 0) {
                ngx_sprintf(p, ",\"outputSchema\":%V", &req[i].outputSchema);
                p = output->data + output->len + ngx_strlen(output->data + output->len);
                output->len = p - output->data;
            }

            /* payTo */
            ngx_sprintf(p, ",\"payTo\":\"%V\"", &req[i].payTo);
            p = output->data + output->len + ngx_strlen(output->data + output->len);
            output->len = p - output->data;

            /* maxTimeoutSeconds */
            ngx_sprintf(p, ",\"maxTimeoutSeconds\":%ui", req[i].maxTimeoutSeconds);
            p = output->data + output->len + ngx_strlen(output->data + output->len);
            output->len = p - output->data;

            /* asset */
            ngx_sprintf(p, ",\"asset\":\"%V\"", &req[i].asset);
            p = output->data + output->len + ngx_strlen(output->data + output->len);
            output->len = p - output->data;

            /* extra (optional) */
            if (req[i].extra.len > 0) {
                ngx_sprintf(p, ",\"extra\":%V", &req[i].extra);
                p = output->data + output->len + ngx_strlen(output->data + output->len);
                output->len = p - output->data;
            }

            ngx_sprintf(p, "}");
            p += 1;
            output->len += 1;
        }

        ngx_sprintf(p, "]");
        p += 1;
        output->len += 1;
    } else {
        ngx_sprintf(p, ",\"accepts\":[]");
        p += 12;
        output->len += 12;
    }

    /* error (optional) */
    if (payment_req->error.len > 0) {
        ngx_sprintf(p, ",\"error\":\"%V\"", &payment_req->error);
        p = output->data + output->len + ngx_strlen(output->data + output->len);
        output->len = p - output->data;
    }

    ngx_sprintf(p, "}");
    p += 1;
    output->len += 1;

    return NGX_OK;
}

/* Send Payment Required response */
ngx_int_t
ngx_http_x402_send_payment_required(ngx_http_request_t *r, 
                                    ngx_http_x402_payment_required_t *payment_req)
{
    ngx_str_t json;
    ngx_int_t rc;
    ngx_buf_t *b;
    ngx_chain_t out;

    /* Build JSON response */
    rc = ngx_http_x402_build_payment_required_json(r, payment_req, &json);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "x402: failed to build payment required JSON");
        return NGX_ERROR;
    }

    /* Set headers */
    r->headers_out.status = NGX_HTTP_PAYMENT_REQUIRED;
    r->headers_out.content_type_len = sizeof("application/json") - 1;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_length_n = json.len;

    /* Allocate buffer */
    b = ngx_create_temp_buf(r->pool, json.len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Copy JSON data */
    ngx_memcpy(b->pos, json.data, json.len);
    b->last = b->pos + json.len;
    b->last_buf = 1;

    /* Send header first */
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }

    /* Send body */
    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}
