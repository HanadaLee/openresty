/* Complex-value regression fixture, never installed in release images. */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_http_complex_value_t  *value;
    ngx_msec_t                 reference;
} ngx_http_complex_value_test_loc_conf_t;


static void *ngx_http_complex_value_test_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_complex_value_test_reference(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_complex_value_test_handler(ngx_http_request_t *r);


static ngx_command_t ngx_http_complex_value_test_commands[] = {

    { ngx_string("test_complex_msec"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_complex_value_test_loc_conf_t, value),
      NULL },

    { ngx_string("test_reference_msec"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_complex_value_test_reference,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_complex_value_test_loc_conf_t, reference),
      NULL },

      ngx_null_command
};


static ngx_http_module_t ngx_http_complex_value_test_ctx = {
    NULL, NULL,
    NULL, NULL,
    NULL, NULL,
    ngx_http_complex_value_test_create_loc_conf,
    NULL
};


ngx_module_t ngx_http_complex_value_test_module = {
    NGX_MODULE_V1,
    &ngx_http_complex_value_test_ctx,
    ngx_http_complex_value_test_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

ngx_module_t *ngx_modules[] = { &ngx_http_complex_value_test_module, NULL };
char *ngx_module_names[] = { "ngx_http_complex_value_test_module", NULL };
char *ngx_module_order[] = { NULL };


static void *
ngx_http_complex_value_test_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_complex_value_test_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_complex_value_test_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->reference = NGX_CONF_UNSET_MSEC;

    return conf;
}


static char *
ngx_http_complex_value_test_reference(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char                      *rv;
    ngx_http_core_loc_conf_t   *clcf;

    rv = ngx_conf_set_msec_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_complex_value_test_handler;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_complex_value_test_handler(ngx_http_request_t *r)
{
    ngx_int_t                                rc;
    ngx_buf_t                               *b;
    ngx_chain_t                              out;
    ngx_msec_t                               value;
    ngx_http_complex_value_test_loc_conf_t   *conf;

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_complex_value_test_module);
    value = ngx_http_complex_value_msec(r, conf->value, 17);

    b = ngx_create_temp_buf(r->pool, 2 * NGX_INT64_LEN + 2);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_sprintf(b->pos, "%M %M\n", value, conf->reference);
    b->last_buf = (r == r->main);
    b->last_in_chain = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;
    ngx_str_set(&r->headers_out.content_type, "text/plain");

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}
