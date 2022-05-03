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

#ifndef ARRAYLIST_H_
#define ARRAYLIST_H_

#include <stdio.h>
#include <stdint.h>

/* to be removed */
#define eListTypeDefault

typedef struct array_list_node_s array_list_node_t;

struct array_list_node_s {
    array_list_node_t * next;
    array_list_node_t * prev;
    void * obj;
};

typedef struct array_list_s {
    uint32_t count;
    array_list_node_t *head;
    array_list_node_t *tail;
} array_list_t;

typedef struct list_iterator_s {
    array_list_t* list;
    array_list_node_t* iter;
} list_iterator_t;

array_list_t* new_array_list(void);
void delete_array_list(array_list_t* list);
int push_object(array_list_t* list, void * obj);
array_list_node_t* push_object_ex(array_list_t* list, void * obj);
void * pop_object(array_list_t* list);
int insert_at_index(array_list_t * list, void * obj, int position);
int insert_last_object(array_list_t * list, void *obj);
int compare_and_insert(array_list_t * list, void* obj,
                    int (*is_condition_met)(void* obj, void* object_to_find));
void* find_object(array_list_t * list, void* object_to_find,
                    int (*is_equal)(void* obj, void* object_to_find));
void* remove_object(array_list_t* list, void *obj);
void* remove_last_object(array_list_t* list);
void* remove_object_at_index(array_list_t* list, int position);
void* find_remove_object(array_list_t* list, void* object_to_find,
                    int (*is_equal)(void* obj, void* object_to_find)); // O(N)
void* last_object(array_list_t* list);
void* first_object(array_list_t* list);
void* object_at_index(array_list_t* list, int position);
int list_get_size(array_list_t* list);

list_iterator_t* new_list_iterator(array_list_t* list);            //O(1)
void bind_list_iterator(list_iterator_t* i, array_list_t* list);
void* get_next_list_object(list_iterator_t* i);               //O(1)
void* get_prev_list_object(list_iterator_t* i);
void reset_list_iterator(list_iterator_t *i);               //O(1)
void free_list_iterator(list_iterator_t *i);                //O(1)

void remove_node(array_list_t* list, array_list_node_t* node);
#endif /* ARRAYLIST_H_ */
