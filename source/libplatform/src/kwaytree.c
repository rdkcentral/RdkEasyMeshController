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
#include "kwaytree.h"

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
k_tree_node* ktree_node(uint32_t key, uint32_t* value)
{
    k_tree_node* node = (k_tree_node*) calloc(1, sizeof(k_tree_node));
    if (node != NULL) {
        node->key = key;
        node->value = value;
        node->height = 1;
        node->color = -1;
    }
    return node;
}

array_list_t* ktree_elements_at_depth(k_tree_node* root, int height, int color)
{
    if (root == NULL) {
        return NULL;
    }

    int current_height = 0;
    array_list_t* q = new_array_list(eListTypeDefault);
    array_list_t* list = new_array_list(eListTypeDefault);

    list_iterator_t *it = new_list_iterator(root->children);
    if (it == NULL) {
        // height 1 is the root node. Hence return the list with the root
        if(height == 1) {
            push_object(list, root);
        }
        delete_array_list(q);
        return list;
    }

    push_object(q, root);

    while (list_get_size(q) != 0) {
        int n;

        current_height++;

        if (current_height == height) {
            k_tree_node *tmp_node = NULL;
            while (NULL != (tmp_node = pop_object(q))) {
                if (color == -1 || tmp_node->color == color)
                    push_object(list, tmp_node);
            }

            // Break the loop as we collected all the nodes in that level
            break;
        }

        for (n = list_get_size(q); n > 0; n--) {

            k_tree_node *node = pop_object(q);
            if (node == NULL) {
                continue;
            }

            bind_list_iterator(it, node->children);

            // Insert all the childs to queue
            for (node = get_next_list_object(it); node != NULL; node = get_next_list_object(it)) {
                insert_last_object(q, node);
            }
        }
    }

    free_list_iterator(it);
    delete_array_list(q);

    return list;
}

array_list_t* ktree_all_elements_of_node(k_tree_node* root)
{
    if(root == NULL) {
        return NULL;
    }

    array_list_t* q = new_array_list(eListTypeDefault);
    array_list_t* list = new_array_list(eListTypeDefault);

    list_iterator_t *it = new_list_iterator(root->children);
    if (it == NULL) {
        delete_array_list(q);
        return list;
    }

    push_object(q, root);

    while (list_get_size(q) != 0) {
        int n;
        for (n = list_get_size(q); n > 0; n--) {
            k_tree_node *node = pop_object(q);
            if (node == NULL) {
                continue;
            }

            // Add the node to list; Do not include the parent itself
            if (node != root) {
                push_object(list, node);
            }

            // Insert all the childs to queue
            bind_list_iterator(it, node->children);
            for (node = get_next_list_object(it); node != NULL; node = get_next_list_object(it)) {
                insert_last_object(q, node);
            }
        }
    }

    free_list_iterator(it);
    delete_array_list(q);

    return list;
}


int ktree_max_height(k_tree_node* root)
{
    if(root == NULL) {
        return 0;
    }
    array_list_t* q = new_array_list(eListTypeDefault);

    int depth = 0;
    push_object(q, root);

    list_iterator_t *it = new_list_iterator(root->children);
    if (it == NULL) {
        // Cleanup the resources
        pop_object(q);
        delete_array_list(q);

        // root node has no children. So the level as 1
        return 1;
    }

    while (list_get_size(q) != 0) {
        int n;

        depth++;

        for (n = list_get_size(q); n > 0; n--) {

            k_tree_node *node = pop_object(q);
            if (node == NULL)
                continue;

            bind_list_iterator(it, node->children);

            // Insert all the childs to queue
            for (node = get_next_list_object(it); node != NULL; node = get_next_list_object(it)) {
                insert_last_object(q, node);
            }
        }
    }

    free_list_iterator(it);
    delete_array_list(q);

    return depth;
}

static int ktree_height_helper(k_tree_node* node)
{
    int h = 0;
    while (node != NULL) {
        h++;
        node = node->parent;
    }
    return h;
}

int ktree_height(k_tree_node* node)
{
    int h = 0;
    if (node != NULL) {
        h = node->height;
    }
    return h;
}

int ktree_color(k_tree_node* node)
{
    int color = -1;
    if (node != NULL) {
        color = node->color;
    }
    return color;
}

int ktree_set_color(k_tree_node* node, int color)
{
    int ret = -1;
    if (node != NULL) {
        node->color = color;
        ret = node->color;
    }
    return ret;
}

int ktree_add_node(k_tree_node* parent, k_tree_node* child)
{
    int ret = -1;
    if (parent != NULL && child != NULL) {
        if (parent->children == NULL) {
            /* lazy instance of the children*/
            parent->children = new_array_list();
        }
        child->self = push_object_ex(parent->children, child);
        child->parent = parent;
        child->height = ktree_height_helper(child);
        ret = 0;
    }
    return ret;
}
void ktree_remove_node(k_tree_node* child)
{
    k_tree_node* parent = NULL;
    if (child != NULL && child->parent != NULL) {
        parent = child->parent;
    }
    if (parent && child->self) {
        remove_node(parent->children, child->self);
        child->self = NULL;
        child->parent = NULL;
        child->height = -1;
    }
}

k_tree_node* ktree_predecessor(k_tree_node* child)
{
    k_tree_node* predecessor = NULL;
    if (child != NULL) {
        predecessor = child->parent;
    }
    return predecessor;
}

int ktree_is_leaf(k_tree_node* node)
{
    if (node == NULL) {
        return -1;
    }
    if (node->children == NULL || list_get_size(node->children) == 0) {
        return 1;
    } else {
        return 0;
    }
}

void free_children_iter(list_iterator_t * iter)
{
    free(iter);
}

list_iterator_t* ktree_children_iter(k_tree_node* root)
{
    if(root == NULL) {
        return 0;
    }

    list_iterator_t * it = NULL;
    it = new_list_iterator(root->children);

	return it;
}

void ktree_free_node(k_tree_node* node)
{
    if (node->children) {
        delete_array_list(node->children);
    }
    free(node);
}
