#include "genauthz/genauthz_plugin.h"
#include <htaccess/htaccess.h>
#include <genauthz_htaccess.h>

int
htaccess_plugin_init(tq_xacml_callout_t *);
void
htaccess_plugin_uninit(tq_xacml_callout_t *);
int
htaccess_plugin_rule_hit(request_mngr_t *, tq_xacml_rule_t *, tq_xacml_callout_t *);

#ifndef GENAUTZ_HTACCESS_TITLE
    #define GENAUTZ_HTACCESS_TITLE "ga_htaccess:"VERSION
#endif

int
htaccess_plugin_init(tq_xacml_callout_t *callout) {
    int argc;
    char **argv;
    htaccess_ctx_t *ht_ctx;

    argc = genauthz_callout_get_argc(callout);
    argv = genauthz_callout_get_argv(callout);

    if (argc < 2) {
        syslog(LOG_ERR, "[%s][pid:%lu][initerror=expecting 1 argument for the htaccess file]",
                        GENAUTZ_HTACCESS_TITLE, (uint64_t)getpid());
        return 1;
    }

    ht_ctx = new_htaccess_ctx();
    if (!ht_ctx)
        return 1;

    if (htaccess_parse_file(ht_ctx, argv[1]) != 0) {
        syslog(LOG_ERR, "[%s][pid:%lu][initerror=htaccess_parse_file() failed][msg=%s]",
                        GENAUTZ_HTACCESS_TITLE, (uint64_t)getpid(),
                        htaccess_get_error(ht_ctx));
        return 1;
    }

#ifdef DEBUG
    htaccess_print_ctx(ht_ctx);
#endif

    genauthz_callout_set_aux(callout, ht_ctx);
    return 0;
}

void
htaccess_plugin_uninit(tq_xacml_callout_t *callout) {
    htaccess_ctx_t *ht_ctx = (htaccess_ctx_t *)genauthz_callout_get_aux(callout);

    free_htaccess_ctx(ht_ctx);
    return;
}


static char *
htaccess_plugin_search(struct tq_xacml_request_s *xacml_req,
                       enum ga_xacml_category_e cat_type,
                       const char *attribute_id) {
    struct tq_xacml_category_s *req_cat;
    struct tq_xacml_attribute_s *req_attr;
    struct tq_xacml_attribute_value_s *req_value;

    if (attribute_id == NULL) return NULL;

    TAILQ_FOREACH(req_cat, &(xacml_req->categories), next) {
        if (cat_type == GA_XACML_CATEGORY_UNDEFINED ||
            cat_type == req_cat->type) {

            TAILQ_FOREACH(req_attr, &(req_cat->attributes), next) {
                /* Match the Rule->Subject->subjectid with the same
                 * Request->Subject->subjectid */

                if (strcasecmp(attribute_id, (char *)req_attr->id) == 0) {
                    if (TAILQ_EMPTY(&(req_attr->values))) {
                        return NULL;
                    }
                    TAILQ_FOREACH(req_value, &(req_attr->values), next) {
                        /* check if the datatype matches a string */
                        if (GA_XACML_DATATYPE_STRING == req_value->datatype) {
                            /* return the first value */
                            return req_value->data;
                        }
                    }
                }
            }
        }
    }
    return NULL;
}


static void
htaccess_plugin_set_decision(struct tq_xacml_response_s *xacml_res, enum ga_xacml_decision_e decision) {
    xacml_res->decision = decision;
}

int
htaccess_plugin_rule_hit(request_mngr_t *request_mngr,
                        tq_xacml_rule_t *rule,
                        tq_xacml_callout_t *callout) {
    htaccess_ctx_t *ht_ctx = (htaccess_ctx_t *)genauthz_callout_get_aux(callout);
    htaccess_decision_t rc;
    char *username, *access, *directory, *file;

    username    = htaccess_plugin_search(request_mngr->xacml_req,
                                         GA_XACML_CATEGORY_SUBJECT,
                                         "x-urn:nl:mpi:tla:xacml:subject:username");
    access      = htaccess_plugin_search(request_mngr->xacml_req,
                                         GA_XACML_CATEGORY_ACTION,
                                         "x-urn:nl:mpi:tla:xacml:action:access");
    directory   = htaccess_plugin_search(request_mngr->xacml_req,
                                         GA_XACML_CATEGORY_RESOURCE,
                                         "x-urn:nl:mpi:tla:xacml:resource:directory");
    file        = htaccess_plugin_search(request_mngr->xacml_req,
                                         GA_XACML_CATEGORY_RESOURCE,
                                         "x-urn:nl:mpi:tla:xacml:resource:file");

    /* Todo: nice error message on malformed input */

    /* print_normalized_xacml_request(request_mngr->xacml_req); */
    /* print_loaded_policy(request_mngr->app->parent->xacml_policy); */
    /* printf("Using: dir \"%s\" file \"%s\" user \"%s\", access \"%s\" ", directory, file, username, access); */

    /* TODO Check 'access' */
    rc = htaccess_approve_access(ht_ctx, directory, file, username);
    switch (rc) {
        case HTA_INAPPLICABLE:
            /* 128(basic line: name, thr id, etc) + 64 + 768 + 768 + 256 =< 2048(max syslog line) */
            syslog(LOG_NOTICE, "[%s][pid:%lu][threadid:%lu][rule=%.64s][directory=%.768s][file=%.768s][user=%.256s][decision=Inapplicable]",
                                GENAUTZ_HTACCESS_TITLE,
                                (uint64_t)getpid(),
                                pthread_self(),
                                rule->name,
                                directory, file, username);
            htaccess_plugin_set_decision(request_mngr->xacml_res, GA_XACML_DECISION_NOTAPPLICABLE);
            break;
        case HTA_PERMIT:
            syslog(LOG_NOTICE, "[%s][pid:%lu][threadid:%lu][rule=%.64s][directory=%.768s][file=%.768s][user=%.256s][decision=Permit]",
                                GENAUTZ_HTACCESS_TITLE,
                                (uint64_t)getpid(),
                                pthread_self(),
                                rule->name,
                                directory, file, username);
            htaccess_plugin_set_decision(request_mngr->xacml_res, GA_XACML_DECISION_PERMIT);
            break;
        case HTA_DENY:
            syslog(LOG_NOTICE, "[%s][pid:%lu][threadid:%lu][rule=%.64s][directory=%.768s][file=%.768s][user=%.256s][decision=Deny]",
                                GENAUTZ_HTACCESS_TITLE,
                                (uint64_t)getpid(),
                                pthread_self(),
                                rule->name,
                                directory, file, username);
            htaccess_plugin_set_decision(request_mngr->xacml_res, GA_XACML_DECISION_DENY);
            break;
        default:
            syslog(LOG_NOTICE, "[%s][pid:%lu][threadid:%lu][rule=%.64s][directory=%.768s][file=%.768s][user=%.256s][decision=Indeterminate]",
                                GENAUTZ_HTACCESS_TITLE,
                                (uint64_t)getpid(),
                                pthread_self(),
                                rule->name,
                                directory, file, username);
            htaccess_plugin_set_decision(request_mngr->xacml_res, GA_XACML_DECISION_INDETERMINATE);
    }
    /* print_normalized_xacml_response(request_mngr->xacml_res); */
    return 0;
}

