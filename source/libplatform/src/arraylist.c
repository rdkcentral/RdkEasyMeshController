/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdlib.h>
#include "arraylist.h"

/*#######################################################################
#                       LOCAL FUNCTIONS                                 #
########################################################################*/
static array_list_node_t* allocate_object(void* obj)
{
    array_list_node_t* node = NULL;
    if (obj) {
        node = calloc(1, sizeof(array_list_node_t));
        if (node) {
            node->obj = obj;
        }
    }
    return node;
}

static array_list_node_t* node_at_index(array_list_t* list, int position)
{
    array_list_node_t * i = NULL;
    if ((list) && ((unsigned int)position < list->count)) {
        i = list->head;
        while (((position-1) >= 0) && i != NULL) {
            i = i->next; position--;
        }
    }
    return i;
}

// Lock should be aquired from the caller of the function
static void remove_node_helper(array_list_t* list, array_list_node_t* node)
{
    if (node == list->head) {
        if (node == list->tail) {
            list->tail = NULL;
        }
        if (node->next) {
            node->next->prev = NULL;
        }
        list->head = node->next;
    } else if (node == list->tail) {
        list->tail = node->prev;
        list->tail->next = NULL;
    } else {
        node->prev->next = node->next;
        node->next->prev = node->prev;
    }
    list->count--;
    free(node);
}

static int is_equal_obj_ptr(void* obj, void* obj_to_find)
{
    return (obj == obj_to_find) ? 1 : 0;
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
array_list_t* new_array_list(void)
{
    return calloc(1, sizeof(array_list_t));
}

void delete_array_list(array_list_t *list)
{
    free(list);
}

//peek the first object (dont remove) O(1)
void* first_object(array_list_t *list)
{
    return list && list->head ? list->head->obj : NULL;
}

//peek the last object (dont remove) O(1)
void* last_object(array_list_t* list)
{
    return list && list->tail ? list->tail->obj : NULL;
}

//stack PUSH operation O(1)
array_list_node_t* push_object_ex(array_list_t *list, void *obj)
{
    array_list_node_t *node;

    if (!list || !obj) {
        return NULL;
    }

    if (!(node = allocate_object(obj))) {
        return NULL;
    }

    if (list->head == NULL) {
        list->head = node;
        list->tail = list->head;
    } else {
        array_list_node_t *old = list->head;   //head = old->next ...
        list->head = node;                     //head=node<->old->next ...
        node->next = old;
        old->prev = node;
    }
    list->count++;

    return node;
}

//stack PUSH operation O(1)
int push_object(array_list_t *list, void *obj)
{
    array_list_node_t *node = push_object_ex(list, obj);

    return node ? 0 : -1;
}

void* pop_object(array_list_t* list)
{
    array_list_node_t *node;
    void *obj;

    if (!list || !list->head) {
        return NULL;
    }

    node = list->head;
    if (node == list->tail) {
        list->tail = NULL;
    }
    if (node->next) {
        node->next->prev = NULL;
    }
    list->head = node->next;
    list->count--;
    obj = node->obj;
    free(node);

    return obj;
}

// use this for random access which is linear time O(n)
// for seq access use iterator
void* object_at_index(array_list_t* list, int position)
{
    array_list_node_t *node = node_at_index(list, position);

    return node ? node->obj : NULL;
}

int insert_last_object(array_list_t* list, void *obj)
{
    array_list_node_t *node;

    if (!obj  || !list) {
        return -1;
    }

    if (!(node = allocate_object(obj))) {
        return -1;
    }

    if (list->head == NULL) {
        list->head = node;
        list->tail = list->head;
    } else {
        node->prev = list->tail;
        list->tail->next = node;
        list->tail = node;
    }
    list->count++;

    return 0;
}

int insert_at_index(array_list_t *list, void * obj, int position)
{
    int ret = -1;

    if (!list || !obj) {
        return -1;
    }

    if (position == 0) {
        ret = push_object(list, obj);
    } else if ((unsigned int)position >= list->count) {
        ret = insert_last_object(list, obj);
    } else {
        array_list_node_t *old = node_at_index(list, position);
        if (old) {
            array_list_node_t *new = allocate_object(obj);
            if (new) {
                new->next = old;
                new->prev = old->prev;
                old->prev->next = new;
                old->prev = new;
                list->count++;
                ret = 0;
            }
        }
    }
    return ret;
}

int compare_and_insert(array_list_t * list, void* obj,
                       int (*is_condition_met)(void* obj, void* object_to_find))
{
    array_list_node_t *new;
    int ret = -1;

    if (!list || !obj || !is_condition_met) {
        return -1;
    }

    if (!(new = allocate_object(obj))) {
        return -1;
    }

    if (list->head == NULL) {
        list->head = new;
        list->tail = list->head;
        list->count++;
        ret = 0;
    } else {
        array_list_node_t *node = list->head;
        while (node) {
            if (is_condition_met(node->obj, obj)) {
                if (node == list->head) {
                    new->prev = NULL;
                    list->head = new;
                } else {
                    new->prev       = node->prev;
                    new->prev->next = new;
                }
                new->next  = node;
                node->prev = new;
                list->count++;
                ret = 0;
                break;
            }
            else if (node == list->tail) {
                node->next = new;
                new->prev  = node;
                new->next  = NULL;
                list->tail = new;
                list->count++;
                ret = 0;
                break;
            }
            node = node->next;
        }
        if (ret != 0) {
            free(new);
        }
    }
    return ret;
}

void* find_object(array_list_t * list, void* object_to_find,
                    int (*is_equal)(void* obj, void* object_to_find))
{
    void *obj = NULL;
    if (list && is_equal && object_to_find) {
        if (list->head != NULL) {
            array_list_node_t *node = list->head;
            while (node) {
                if (is_equal(node->obj , object_to_find)) {
                    obj = node->obj;
                    break;
                }
                node = node->next;
            }
        }
    }
    return obj;
}

void* remove_last_object(array_list_t* list)
{
    void * obj = NULL;
    if (list) {
        if (list->head != NULL) {
            if (list->head == list->tail) {
                obj = list->head->obj;
                free (list->head);
                list->head = list->tail = NULL;
                list->count = 0;
            }
            //else if(list->tail != NULL)
            else {
                array_list_node_t * node2del = list->tail;
                obj = list->tail->obj;
                list->tail = node2del->prev;
                list->tail->next = NULL;
                list->count--;
                free(node2del);
            }
        }
    }
    return obj;
}

void remove_node(array_list_t* list, array_list_node_t* node)
{
    if (list == NULL || node == NULL) {
        return;
    }
    remove_node_helper(list, node);
}

void* remove_object_at_index(array_list_t* list, int position)
{
    void * obj = NULL;
    if (list) {
        array_list_node_t * node = node_at_index(list, position);
        if (node) {
            obj = node->obj;
            remove_node_helper(list, node);
        }
    }
    return obj;
}

void* find_remove_object(array_list_t* list, void* object_to_find,
                    int (*is_equal)(void* obj, void* object_to_find))
{
    void *obj = NULL;
    if (list && is_equal) {
        if (list->head != NULL) {
            array_list_node_t *node = list->head;
            while (node) {
                if (is_equal(node->obj , object_to_find)) {
                    obj = node->obj;
                    break;
                }
                node = node->next;
            }
            if (node) {
                remove_node_helper(list, node);
            }
        }
    }
    return obj;
}

void* remove_object(array_list_t* list, void* obj)
{
    return find_remove_object(list, obj, is_equal_obj_ptr);
}

int list_get_size(array_list_t* list)
{
    int size = 0;
    if (list) {
        size = list->count;
    }
    return size;
}

void bind_list_iterator(list_iterator_t* i, array_list_t* list)
{
    if (i && list) {
        i->list = list;
        i->iter = list->head;
    }
}

list_iterator_t* new_list_iterator(array_list_t* list)
{
    list_iterator_t* i = NULL;
    if (list) {
        i = (list_iterator_t*) calloc(1,sizeof(list_iterator_t));
        if (i) {
            bind_list_iterator(i, list);
        }
    }
    return i;
}

void free_list_iterator(list_iterator_t *i)
{
    free(i);
}

void* get_next_list_object(list_iterator_t* i)
{
    void * obj = NULL;
    if (i && i->iter) {
        obj = i->iter->obj;
        i->iter = i->iter->next;
    }
    return obj;
}

void* get_prev_list_object(list_iterator_t* i)
{
    void * obj = NULL;
    if (i && i->iter && i->iter->prev)  {
        obj = i->iter->prev->obj;
        i->iter = i->iter->prev;
    }
    return obj;
}

void reset_list_iterator(list_iterator_t *i)
{
    if (i && i->list) {
        i->iter = i->list->head;
    }
}
