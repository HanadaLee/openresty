/* Dynamic-module ABI regression fixture, never installed in release images. */

#include <ngx_config.h>
#include "test_config.h"
#include <ngx_core.h>

#if (RESTY_ABI_TEST_LEGACY)
#undef NGX_MODULE_SIGNATURE
#define NGX_MODULE_SIGNATURE                                               \
    NGX_MODULE_SIGNATURE_0 NGX_MODULE_SIGNATURE_1 NGX_MODULE_SIGNATURE_2    \
    NGX_MODULE_SIGNATURE_3 NGX_MODULE_SIGNATURE_4 NGX_MODULE_SIGNATURE_5    \
    NGX_MODULE_SIGNATURE_6 NGX_MODULE_SIGNATURE_7 NGX_MODULE_SIGNATURE_8    \
    NGX_MODULE_SIGNATURE_9 NGX_MODULE_SIGNATURE_10 NGX_MODULE_SIGNATURE_11  \
    NGX_MODULE_SIGNATURE_12 NGX_MODULE_SIGNATURE_13 NGX_MODULE_SIGNATURE_14 \
    NGX_MODULE_SIGNATURE_15 NGX_MODULE_SIGNATURE_16 NGX_MODULE_SIGNATURE_17 \
    NGX_MODULE_SIGNATURE_18 NGX_MODULE_SIGNATURE_19 NGX_MODULE_SIGNATURE_20 \
    NGX_MODULE_SIGNATURE_21 NGX_MODULE_SIGNATURE_22 NGX_MODULE_SIGNATURE_23 \
    NGX_MODULE_SIGNATURE_24 NGX_MODULE_SIGNATURE_25 NGX_MODULE_SIGNATURE_26 \
    NGX_MODULE_SIGNATURE_27 NGX_MODULE_SIGNATURE_28 NGX_MODULE_SIGNATURE_29 \
    NGX_MODULE_SIGNATURE_30 NGX_MODULE_SIGNATURE_31 NGX_MODULE_SIGNATURE_32 \
    NGX_MODULE_SIGNATURE_33 NGX_MODULE_SIGNATURE_34
#endif

#if (RESTY_ABI_TEST_REVISION)
#undef NGX_RESTY_ABI_VERSION
#define NGX_RESTY_ABI_VERSION  2
#endif

#if (RESTY_ABI_TEST_PRINT)

int
main(void)
{
    puts(NGX_MODULE_SIGNATURE);
    return 0;
}

#else

#include <ngx_http.h>

static ngx_int_t ngx_http_abi_test_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_abi_test_log(ngx_http_request_t *r);

static ngx_http_module_t ngx_http_abi_test_ctx = {
    NULL,
    ngx_http_abi_test_init,
    NULL, NULL,
    NULL, NULL,
    NULL, NULL
};

ngx_module_t ngx_http_abi_test_module = {
    NGX_MODULE_V1,
    &ngx_http_abi_test_ctx,
    NULL,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

ngx_module_t *ngx_modules[] = { &ngx_http_abi_test_module, NULL };
char *ngx_module_names[] = { "ngx_http_abi_test_module", NULL };
char *ngx_module_order[] = { NULL };

static ngx_int_t
ngx_http_abi_test_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                      "abi_test configuration reached");

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_abi_test_log;
    return NGX_OK;
}

static ngx_int_t
ngx_http_abi_test_log(ngx_http_request_t *r)
{
    ngx_http_upstream_state_t  *state;

    if (r->uri.len != sizeof("/probe") - 1
        || ngx_strncmp(r->uri.data, "/probe", r->uri.len) != 0)
    {
        return NGX_OK;
    }

    if (r->upstream_states == NULL || r->upstream_states->nelts != 1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "abi_test missing upstream state");
        return NGX_ERROR;
    }

    state = r->upstream_states->elts;

    /* Read fields beyond the extension's insertions, not just the signature. */
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                  "abi_test uri=%V status=%ui length=%O peer=%V request_length=%O",
                  &r->uri, state->status, state->response_length,
                  state->peer, r->request_length);

    return NGX_OK;
}

#endif
