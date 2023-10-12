/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "subscription"

#include "map_cli_subscription.h"
#include "map_utils.h"

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
struct subscription_s {
    list_head_t list;
    char *event;
    subscription_function_t function;
    void *context;
    uint32_t flags;
};

struct subscriptions_s {
    list_head_t subscriptions;
    unsigned int count;
};

/*#######################################################################
#                       LOCAL FUNCTIONS                                 #
########################################################################*/
static void subscription_destroy(subscription_t *subscription)
{
    if (subscription == NULL) {
        return;
    }
    if (subscription->event != NULL) {
        free(subscription->event);
    }
    free(subscription);
}

static subscription_t *subscription_create(const char *event, subscription_function_t function, uint32_t flags, void *context)
{
    subscription_t *subscription;
    subscription = NULL;
    if (event == NULL) {
        log_lib_e("event is invalid");
        goto bail;
    }
    if (function == NULL) {
        log_lib_e("function is invalid");
        goto bail;
    }
    subscription = malloc(sizeof(subscription_t));
    if (subscription == NULL) {
        log_lib_e("can not allocate memory");
        goto bail;
    }
    memset(subscription, 0, sizeof(subscription_t));
    subscription->event = strdup(event);
    if (subscription->event == NULL) {
        log_lib_e("can not allocate memory");
        goto bail;
    }
    subscription->function = function;
    subscription->context = context;
    subscription->flags = flags;

    return subscription;

bail:
    if (subscription != NULL) {
        subscription_destroy(subscription);
    }
    return NULL;
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
const char *subscription_event(subscription_t *subscription)
{
    if (subscription == NULL) {
        log_lib_e("subscription is invalid");
        goto bail;
    }
    return subscription->event;

bail:
    return NULL;
}

subscription_function_t subscription_function(subscription_t *subscription)
{
    if (subscription == NULL) {
        log_lib_e("subscription is invalid");
        goto bail;
    }
    return subscription->function;

bail:
    return NULL;
}

void *subscription_context(subscription_t *subscription)
{
    if (subscription == NULL) {
        log_lib_e("subscription is invalid");
        goto bail;
    }
    return subscription->context;

bail:
    return NULL;
}

uint32_t subscription_flags(subscription_t *subscription)
{
    if (subscription == NULL) {
        log_lib_e("subscription is invalid");
        goto bail;
    }
    return subscription->flags;

bail:
    return 0;
}

subscription_t *subscriptions_get(subscriptions_t *subscriptions, const char *event)
{
    subscription_t *subscription;
    if (subscriptions == NULL) {
        log_lib_e("subscriptions is invalid");
        goto bail;
    }
    if (event == NULL) {
        log_lib_e("event is invalid");
        goto bail;
    }
    list_for_each_entry(subscription, &subscriptions->subscriptions, list) {
        if (strcasecmp(event, subscription_event(subscription)) == 0) {
            return subscription;
        }
    }

bail:
    return NULL;
}

int subscriptions_del(subscriptions_t *subscriptions, const char *event)
{
    subscription_t *subscription;
    if (subscriptions == NULL) {
        log_lib_e("subscriptions is invalid");
        goto bail;
    }
    if (event == NULL) {
        log_lib_e("event is invalid");
        goto bail;
    }
    subscription = subscriptions_get(subscriptions, event);
    if (subscription == NULL) {
        goto out;
    }
    list_del(&subscription->list);
    subscriptions->count -= 1;
    subscription_destroy(subscription);

out:
    return 0;

bail:
    return -1;
}

int subscriptions_add(subscriptions_t *subscriptions, const char *event, subscription_function_t function, uint32_t flags, void *context)
{
    subscription_t *subscription;
    if (subscriptions == NULL) {
        log_lib_e("subscriptions is invalid");
        goto bail;
    }
    if (event == NULL) {
        log_lib_e("event is invalid");
        goto bail;
    }
    subscription = subscriptions_get(subscriptions, event);
    if (subscription != NULL) {
        log_lib_e("subscription already exists");
        goto bail;
    }
    subscription = subscription_create(event, function, flags, context);
    if (subscription == NULL) {
        log_lib_e("can not create subscription");
        goto bail;
    }
    list_add_tail(&subscription->list, &subscriptions->subscriptions);
    subscriptions->count += 1;
    return 0;

bail:
    return -1;
}

void subscriptions_destroy(subscriptions_t *subscriptions)
{
    subscription_t *subscription;
    subscription_t *nsubscription;
    if (subscriptions == NULL) {
        return;
    }
    list_for_each_entry_safe(subscription, nsubscription, &subscriptions->subscriptions, list) {
        list_del(&subscription->list);
        subscriptions->count -= 1;
        subscription_destroy(subscription);
    }
    free(subscriptions);
}

subscriptions_t *subscriptions_create(void)
{
    subscriptions_t *subscriptions = calloc(1, sizeof(subscriptions_t));

    if (subscriptions) {
        INIT_LIST_HEAD(&subscriptions->subscriptions);
        subscriptions->count = 0;
    }

    return subscriptions;
}
