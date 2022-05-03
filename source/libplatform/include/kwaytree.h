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

#ifndef KWAYTREE_H_
#define KWAYTREE_H_

#include <stdio.h>
#include "arraylist.h"
typedef struct _k_tree_node k_tree_node;

struct _k_tree_node {
    array_list_node_t* self; /* node of the ktree in the parent->children;
                              need for o(1) remove from parent operation*/
    array_list_t * children;
    uint32_t key;
    uint32_t* value;
    k_tree_node* parent;
    int color;
    int height;

};

int ktree_color(k_tree_node* node);
int ktree_set_color(k_tree_node* node, int color);
int ktree_height(k_tree_node* node);
list_iterator_t* ktree_children_iter(k_tree_node* root);
void free_children_iter(list_iterator_t* iter);

k_tree_node* ktree_node(uint32_t key, uint32_t* value);
int ktree_add_node(k_tree_node* parent, k_tree_node* child); //O(1)
void ktree_remove_node(k_tree_node* child); //O(1)
k_tree_node* ktree_predecessor(k_tree_node* child);
int ktree_is_leaf(k_tree_node* node);
array_list_t* ktree_elements_at_depth(k_tree_node* root, int height, int color);
array_list_t* ktree_all_elements_of_node(k_tree_node* root);
int ktree_max_height(k_tree_node* root);
void ktree_free_node(k_tree_node* node);

#endif /* KWAYTREE_H_ */
