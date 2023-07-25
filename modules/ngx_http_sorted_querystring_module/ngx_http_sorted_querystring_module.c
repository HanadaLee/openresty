#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


ngx_int_t    ngx_http_sorted_querystring_pre_config(ngx_conf_t *cf);
void        *ngx_http_sorted_querystring_create_loc_conf(ngx_conf_t *cf);
char        *ngx_http_sorted_querystring_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
char        *ngx_conf_set_parameters_to_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
ngx_int_t    ngx_http_sorted_querystring_args_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
ngx_int_t    ngx_http_sorted_querystring_cmp_parameters(const ngx_queue_t *one, const ngx_queue_t *two);


typedef struct {
    ngx_array_t              *parameters_to_filter;
} ngx_http_sorted_querystring_loc_conf_t;


typedef struct {
    ngx_queue_t               args_queue;
} ngx_http_sorted_querystring_ctx_t;


typedef struct {
    ngx_queue_t               queue;
    ngx_str_t                 key;
    ngx_str_t                 complete;
} ngx_http_sorted_querystring_parameter_t;


static ngx_http_variable_t  ngx_http_sorted_querystring_vars[] = {
    { ngx_string("sorted_querystring_args"),
      NULL,
      ngx_http_sorted_querystring_args_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_command_t ngx_http_sorted_querystring_commands[] = {
    { ngx_string("sorted_querysting_filter_parameter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE,
      ngx_conf_set_parameters_to_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_sorted_querystring_loc_conf_t, parameters_to_filter),
      NULL },

    ngx_null_command
};


static ngx_http_module_t ngx_http_sorted_querystring_module_ctx = {
    ngx_http_sorted_querystring_pre_config,         /* preconfiguration */
    NULL,                                           /* postconfiguration */

    NULL,                                           /* create main configuration */
    NULL,                                           /* init main configuration */

    NULL,                                           /* create server configuration */
    NULL,                                           /* merge server configuration */

    ngx_http_sorted_querystring_create_loc_conf,    /* create location configuration */
    ngx_http_sorted_querystring_merge_loc_conf      /* merge location configuration */
};


ngx_module_t ngx_http_sorted_querystring_module = {
    NGX_MODULE_V1,
    &ngx_http_sorted_querystring_module_ctx,    /* module context */
    ngx_http_sorted_querystring_commands,       /* module directives */
    NGX_HTTP_MODULE,                            /* module type */
    NULL,                                       /* init master */
    NULL,                                       /* init module */
    NULL,                                       /* init process */
    NULL,                                       /* init thread */
    NULL,                                       /* exit thread */
    NULL,                                       /* exit process */
    NULL,                                       /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_int_t
ngx_http_sorted_querystring_pre_config(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_sorted_querystring_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


void *
ngx_http_sorted_querystring_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_sorted_querystring_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sorted_querystring_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->parameters_to_filter = NGX_CONF_UNSET_PTR;

    return conf;
}


char *
ngx_http_sorted_querystring_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_sorted_querystring_loc_conf_t  *prev = parent;
    ngx_http_sorted_querystring_loc_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->parameters_to_filter, prev->parameters_to_filter, NULL);

    return NGX_CONF_OK;
}


char *
ngx_conf_set_parameters_to_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_array_t     **field;
    ngx_str_t        *value, *s;
    ngx_uint_t        i, j;
    ngx_flag_t        exists;

    field = (ngx_array_t **) (p + cmd->offset);

    if (*field != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    *field = ngx_array_create(cf->pool, cf->args->nelts, sizeof(ngx_str_t));
    if (*field == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        exists = 0;
        s = (*field)->elts;
        for (j = 0; j < (*field)->nelts; j++) {
            if ((value[i].len == s[j].len) && ngx_strncasecmp(value[i].data, s[j].data, value[i].len) == 0) {
                exists = 1;
                break;
            }
        }

        if (!exists) {
            s = ngx_array_push(*field);
            if (s == NULL) {
                return NGX_CONF_ERROR;
            }

            *s = value[i];
        }
    }

    return NGX_CONF_OK;
}


ngx_int_t
ngx_http_sorted_querystring_args_variable(ngx_http_request_t *r, ngx_http_variable_value_t *var, uintptr_t data)
{
    ngx_http_sorted_querystring_loc_conf_t      *sqlc = ngx_http_get_module_loc_conf(r, ngx_http_sorted_querystring_module);
    ngx_http_sorted_querystring_ctx_t           *ctx = ngx_http_get_module_ctx(r, ngx_http_sorted_querystring_module);
    ngx_http_sorted_querystring_parameter_t     *param;
    u_char                                      *p, *ampersand, *equal, *last;
    ngx_queue_t                                 *q;
    ngx_flag_t                                   filter;
    ngx_str_t                                   *value;
    ngx_uint_t                                   i;

    if (r->args.len == 0) {
        var->len = 0;
        var->data = (u_char*) "";
        return NGX_OK;
    }

    if (var->len > 0) {
        return NGX_OK;
    }

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_sorted_querystring_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_sorted_querystring_module);

        ngx_queue_init(&ctx->args_queue);

        p = r->args.data;
        last = p + r->args.len;

        for ( /* void */ ; p < last; p++) {
            param = ngx_pcalloc(r->pool, sizeof(ngx_http_sorted_querystring_parameter_t));
            if (param == NULL) {
                return NGX_ERROR;
            }

            ampersand = ngx_strlchr(p, last, '&');
            if (ampersand == NULL) {
                ampersand = last;
            }

            equal = ngx_strlchr(p, last, '=');
            if ((equal == NULL) || (equal > ampersand)) {
                equal = ampersand;
            }

            param->key.data = p;
            param->key.len = equal - p;

            param->complete.data = p;
            param->complete.len = ampersand - p;

            ngx_queue_insert_tail(&ctx->args_queue, &param->queue);

            p = ampersand;
        }

        ngx_queue_sort(&ctx->args_queue, ngx_http_sorted_querystring_cmp_parameters);
    }

    var->data = ngx_pcalloc(r->pool, r->args.len + 2); // 1 char for extra ampersand and 1 for the \0
    if (var->data == NULL) {
        return NGX_ERROR;
    }

    p = var->data;
    for (q = ngx_queue_head(&ctx->args_queue); q != ngx_queue_sentinel(&ctx->args_queue); q = ngx_queue_next(q)) {
        param = ngx_queue_data(q, ngx_http_sorted_querystring_parameter_t, queue);

        filter = 0;
        if (sqlc->parameters_to_filter && (param->key.len > 0)) {
            value = sqlc->parameters_to_filter->elts;
            for (i = 0; i < sqlc->parameters_to_filter->nelts; i++) {
                if ((param->key.len == value[i].len) && ngx_strncasecmp(param->key.data, value[i].data, param->key.len) == 0) {
                    filter = 1;
                    break;
                }
            }

        }

        if (!filter) {
            p = ngx_sprintf(p, "%V&", &param->complete);
        }
    }

    var->len = (p > var->data) ? p - var->data - 1 : 0;

    return NGX_OK;
}


ngx_int_t
ngx_http_sorted_querystring_cmp_parameters(const ngx_queue_t *one, const ngx_queue_t *two)
{
    ngx_http_sorted_querystring_parameter_t   *first, *second;
    ngx_int_t                                  rc;

    first  = ngx_queue_data(one, ngx_http_sorted_querystring_parameter_t, queue);
    second = ngx_queue_data(two, ngx_http_sorted_querystring_parameter_t, queue);

    rc = ngx_strncasecmp(first->key.data, second->key.data, ngx_min(first->key.len, second->key.len));
    if (rc == 0) {
        rc = ngx_strncasecmp(first->complete.data, second->complete.data, ngx_min(first->complete.len, second->complete.len));
        if (rc == 0) {
            rc = -1;
        }
    }

    return rc;
}
