/*
 * Copyright (c) 2021-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include "test.h"
#include "map_cli_subscription.h"

/*#######################################################################
#                   TEST_SUBSCRIPTION                                   #
########################################################################*/
static void subs1_cb(const char *event, const char *payload, void *context)
{
}

static void subs2_cb(const char *event, const char *payload, void *context)
{
}

static void subs3_cb(const char *event, const char *payload, void *context)
{
}

START_TEST(test_subscription)
{
    subscriptions_t         *subscriptions;
    subscription_t          *subscription;
    const char              *e;
    subscription_function_t  f;
    void                    *c;

    /* subscriptions_create */
    fail_unless(!!(subscriptions = subscriptions_create()));

    /* subscriptions_add */
    fail_unless( subscriptions_add(subscriptions, "subs1", NULL,     SUBS_FLAG_MODE_FULL, (void*)1));
    fail_unless( subscriptions_add(subscriptions, NULL,    subs1_cb, SUBS_FLAG_MODE_FULL, (void*)1));
    fail_unless( subscriptions_add(NULL,          "subs1", subs1_cb, SUBS_FLAG_MODE_FULL, (void*)1));
    fail_unless(!subscriptions_add(subscriptions, "subs1", subs1_cb, SUBS_FLAG_MODE_FULL, (void*)1));
    fail_unless( subscriptions_add(subscriptions, "subs1", subs1_cb, SUBS_FLAG_MODE_FULL, (void*)1));
    fail_unless(!subscriptions_add(subscriptions, "subs2", subs2_cb, SUBS_FLAG_MODE_FULL, (void*)2));
    fail_unless(!subscriptions_add(subscriptions, "subs3", subs3_cb, (SUBS_FLAG_MODE_FULL | SUBS_FLAG_MODE_REDUCED), (void*)3));

    /* subscriptions_get */
    fail_unless(!subscriptions_get(subscriptions,  NULL));
    fail_unless(!subscriptions_get(subscriptions, "subs4"));
    fail_unless(!subscriptions_get(subscriptions, "subs4"));
    fail_unless(!!(subscription = subscriptions_get(subscriptions, "subs1")));
    fail_unless(!!(subscription = subscriptions_get(subscriptions, "SUBS1")));

    /* subscription_event */
    fail_unless(!subscription_event(NULL));
    fail_unless(!!(e = subscription_event(subscription)));
    fail_unless(!strcmp(e, "subs1"));

    /* subscription_function */
    fail_unless(!subscription_function(NULL));
    fail_unless(!!(f = subscription_function(subscription)));
    fail_unless(f == subs1_cb);

    /* subscription_context */
    fail_unless(!subscription_context(NULL));
    fail_unless(!!(c = subscription_context(subscription)));
    fail_unless(c == (void*)1);

    /* subscription_flags */
    fail_unless(!!(subscription = subscriptions_get(subscriptions, "subs3")));
    fail_unless(subscription_flags(subscription) & SUBS_FLAG_MODE_FULL);
    fail_unless(subscription_flags(subscription) & SUBS_FLAG_MODE_REDUCED);

    /* subscription_del */
    fail_unless( subscriptions_del(subscriptions, NULL));
    fail_unless( subscriptions_del(NULL,          "subs2"));
    fail_unless(!subscriptions_del(subscriptions, "subs2"));

    fail_unless( !subscriptions_get(subscriptions, "subs2"));
    fail_unless(!!subscriptions_get(subscriptions, "subs1"));
    fail_unless(!!subscriptions_get(subscriptions, "subs3"));

    /* subscriptions_destroy */
    subscriptions_destroy(NULL);
    subscriptions_destroy(subscriptions);

}
END_TEST

const char *test_suite_name = "";
test_case_t test_cases[] = {
    TEST("subscription",   test_subscription  ),
    TEST_CASES_END
};
