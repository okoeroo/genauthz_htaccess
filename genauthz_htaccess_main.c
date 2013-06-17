#include "genauthz/genauthz_plugin.h"
#include <htaccess/htaccess.h>

int
htaccess_plugin_init(tq_xacml_callout_t *);
void
htaccess_plugin_uninit(tq_xacml_callout_t *);
int
htaccess_plugin_rule_hit(request_mngr_t *, tq_xacml_rule_t *, tq_xacml_callout_t *);

#ifndef GENAUTZ_HTACCESS_TITLE
    #define GENAUTZ_HTACCESS_TITLE "GenAuthZ htaccess"
#endif

int
htaccess_plugin_init(tq_xacml_callout_t *callout) {
    int argc;
    char **argv;
    htaccess_ctx_t *ht_ctx;

    argc = genauthz_callout_get_argc(callout);
    argv = genauthz_callout_get_argv(callout);

    if (argc < 2) {
        printf("%s: Initialization error, expecting 1 argument for the htaccess file\n",
                GENAUTZ_HTACCESS_TITLE);
        return 1;
    }

    ht_ctx = new_htaccess_ctx();
    if (!ht_ctx)
        return 1;

    if (htaccess_parse_file(ht_ctx, argv[1]) != 0) {
        printf("%s: htaccess_parse_file() failed! Error: %s\n",
                GENAUTZ_HTACCESS_TITLE,
                htaccess_get_error(ht_ctx));
    }

    htaccess_print_ctx(ht_ctx);

    genauthz_callout_set_aux(callout, ht_ctx);
    return 0;
}

void
htaccess_plugin_uninit(tq_xacml_callout_t *callout) {
    htaccess_ctx_t *ht_ctx = (htaccess_ctx_t *)genauthz_callout_get_aux(callout);

    free_htaccess_ctx(ht_ctx);
    return;
}

static htaccess_decision_t
run_search_test(htaccess_ctx_t *ht_ctx, const char *dir, const char *file, const char *user) {
    htaccess_decision_t rc;
    rc = htaccess_approve_access(ht_ctx, dir, file, user);
    return rc;

    printf("Using: dir \"%s\" file \"%s\" user \"%s\" ", dir, file, user);
    switch (rc) {
        case HTA_INAPPLICABLE:
            printf("decision: Inapplicable");
            break;
        case HTA_PERMIT:
            printf("decision: Permit");
            break;
        case HTA_DENY:
            printf("decision: Deny");
            break;
        default:
            printf("decision: Unknown!");
    }
    printf("\n");
    return rc;
}

int
htaccess_plugin_rule_hit(request_mngr_t *request_mngr,
                        tq_xacml_rule_t *rule,
                        tq_xacml_callout_t *callout) {
    htaccess_ctx_t *ht_ctx = (htaccess_ctx_t *)genauthz_callout_get_aux(callout);

    if (run_search_test(ht_ctx, "/lat/corpora/archive/1839/imdi/acqui_data/ac-ESF/Info", "esf.html", "corpman") != HTA_PERMIT) {
        printf("Expected PERMIT\n");
    }

    printf("Rule \"%s\" hit! -- %s\n", rule->name, __func__);

    print_normalized_xacml_request(request_mngr->xacml_req);
    print_normalized_xacml_response(request_mngr->xacml_res);
    print_loaded_policy(request_mngr->app->parent->xacml_policy);


    return 0;
}


