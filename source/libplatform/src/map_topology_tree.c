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
#include <string.h>
#include <syslog.h>
#include <stdlib.h>

#define LOG_TAG "topology_tree"

#include "map_topology_tree.h"
#include "map_utils.h"
#include "1905_platform.h"

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static k_tree_node* g_root_node;
static map_ale_info_t *g_root_ale_node;

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
int32_t map_get_child_count(map_ale_info_t* root_node)
{
    int count = 0;

    if (root_node && root_node->self_tree_node && root_node->self_tree_node->children) {
        count = list_get_size(root_node->self_tree_node->children);
    }

    return count;
}

int8_t init_topology_tree(uint8_t *root_al_mac)
{
    g_root_ale_node = map_dm_create_ale(root_al_mac);

    if (!g_root_ale_node) {
        log_lib_e("root ale node creation failed");
        return -1;
    }

    g_root_node = get_ktree_node(g_root_ale_node);

    if (g_root_node != NULL) {
        g_root_ale_node->self_tree_node = g_root_node;

        g_root_node->parent = NULL;
        g_root_node->children = NULL;

    }

    return 1;
}

int8_t create_topology_tree_node(map_ale_info_t* ale_node, tree_node_type_t type)
{
    static int key = 1;
    k_tree_node* tree_node = NULL;

    tree_node = ktree_node(key,(uint32_t*)ale_node);

    if (tree_node) {
        ale_node->self_tree_node = tree_node;

        tree_node->parent = NULL;
        tree_node->children = NULL;
        ktree_set_color(tree_node,type);
        key++;

        return 1;
    }

    return -1;
}

map_ale_info_t* get_root_ale_node()
{
    return g_root_ale_node;
}

int8_t topology_tree_insert(map_ale_info_t* parent, map_ale_info_t* child)
{
    k_tree_node* child_node;
    k_tree_node* parent_node;

    if (NULL == child || NULL == parent) {
        log_lib_e("cannot insert NULL child or NULL parent node to the tree");
        return -1;
    }

    child_node = get_ktree_node(child);
    parent_node = get_ktree_node(parent);

    if (child_node->parent == NULL) {
        //Add given parent to orphan child
        if (ktree_add_node(parent_node,child_node) < 0) {
            log_lib_e("error in adding new node to the topology tree");
            return -1;
        }

    } else if (child_node->parent != parent_node) {
        /* Update the existing parent to the given new parent
           1. Remove the child from old parent
           2.Change the parent of the child to new parent
	*/
        ktree_remove_node(child_node);

        if (ktree_add_node(parent_node,child_node) < 0) {
            log_lib_e("error in adding new node to the topology tree");
            return -1;
        }

    } else {
        //If existing parent and new parent are the same do nothing
        //parent_node == child_node->parent
        return 1;
    }

    return 1;
}

static char* get_node_type_str(tree_node_type_t type)
{
    switch (type) {
        case AL_ENTITY: return "ALE";
        case STATION:   return "STA";
        default:        return "UNKNOWN";
    }
}

void print_node_info(map_ale_info_t* child, uint32_t height, uint32_t color, map_printf_cb_t print_cb)
{
    mac_addr_str mac_str;
    char *node_type_str = get_node_type_str(color);
    int spaces = height * 8;

    acu_mac_to_string(child->al_mac, mac_str);

    print_cb("%*s|-------------------------------|\n",   spaces, "");
    print_cb("%*s| %s MAC  : %s                   \n",   spaces, "", node_type_str, mac_str);
    print_cb("%*s|-------------------------------|\n\n", spaces, "");
}

void display_topology_tree(k_tree_node* parent_node, map_printf_cb_t print_cb)
{
    map_ale_info_t* parent;
    map_ale_info_t* child;
    k_tree_node* child_node;
    uint32_t height;
    uint32_t color;

    parent = get_ale_from_tree(parent_node);

    if (ktree_is_leaf(parent_node)) {
        return;
    } else {
        foreach_child_in(parent,child) {
            child_node = get_ktree_node(child);
            height = ktree_height(child_node);
            color = ktree_color(child_node);
            print_node_info(child,height,color, print_cb);
            display_topology_tree(child_node, print_cb);
        }
    }
}

void dump_topology_tree(map_printf_cb_t print_cb)
{
    map_ale_info_t* parent;
    uint32_t height = 0;
    uint32_t color = 0;

    print_cb("|----------------------------------------------|\n");
    print_cb("|--------      TOPOLOGY_TREE_DUMP    ----------|\n");
    print_cb("|----------------------------------------------|\n");

    parent = get_root_ale_node();

    height = ktree_height(g_root_node);
    color = ktree_color(g_root_node);

    print_node_info(parent,height,color, print_cb);
    display_topology_tree(g_root_node, print_cb);
}

void dump_topology_tree_by_level(uint32_t level, map_printf_cb_t print_cb)
{
    map_ale_info_t* child;
    uint32_t height;

    height = ktree_max_height(g_root_node);

    if (level < height) {
        height = level;
    }

    array_list_t * l = ktree_elements_at_depth(g_root_node, height, -1);
    print_cb("----------------------------------------------\n");
    print_cb("--------TOPOLOGY_TREE_DUMP AT LEVEL %d--------\n",height);
    print_cb("----------------------------------------------\n");

    while(list_get_size(l)) {
        k_tree_node *e = pop_object(l);
        child = get_ale_from_tree(e);

        if (child) {
            print_cb("----------------------------------------------\n");
            print_cb(" Al ENTITY MAC          : %s\n", child->al_mac_str);
            print_cb(" RECEIVING INTERFACE    : %s\n", child->iface_name);
            print_cb(" NUM OF RADIOS          : %d\n", child->radios_nr);
            print_cb("----------------------------------------------\n");
        }
    }
    //The array list allocated for fetching the ale nodes
    //must be deleted once the list is empty
    delete_array_list(l);
}

map_ale_info_t* fetch_and_free_child_iter(list_iterator_t* iter)
{
    map_ale_info_t* child_node = NULL;

    k_tree_node* tree_node = (k_tree_node*)get_next_list_object(iter);

    if (tree_node) {
        child_node = get_ale_from_tree(tree_node);
    }

    if (!child_node) {
        free_children_iter(iter);
    }

    return child_node;
}

map_ale_info_t* get_parent_ale_node(map_ale_info_t* child_ale)
{
    map_ale_info_t* parent_node = NULL;

    if(child_ale) {
        k_tree_node* tree_node = get_ktree_node(child_ale);
        if (tree_node && tree_node->parent) {
            parent_node = get_ale_from_tree(tree_node->parent);
        }
    }

    return parent_node;
}

void make_all_child_nodes_orphan(k_tree_node* self_node)
{
    k_tree_node* child_node;
    map_ale_info_t* child_ale_node;
    map_ale_info_t* self_ale_node;

    if (ktree_is_leaf(self_node)) {
        return;
    } else {
        list_iterator_t* it;
        for (it = ktree_children_iter(self_node); (NULL != (child_ale_node = fetch_and_free_child_iter(it))); ) {
            child_node = child_ale_node->self_tree_node;
            make_all_child_nodes_orphan(child_node);
            self_ale_node = get_ale_from_tree(child_node);
            log_lib_i("ALE[%s] detached from tree", self_ale_node->al_mac_str);
            /* Since it is now detached, clear information about upstream link */
            map_dm_ale_set_upstream_info(self_ale_node, g_zero_mac, g_zero_mac, g_zero_mac,
                                         true, INTERFACE_TYPE_UNKNOWN);
            ktree_remove_node(child_node);
        }
        delete_array_list(self_node->children);
        self_node->children = NULL;
    }
}

void disassemble_tree(map_ale_info_t* root_node)
{
    k_tree_node* tree_node;

    if (!root_node) {
        return;
    }

    /* Make the ALE orphan first by removing the parent link */
    make_ale_orphaned(root_node);

    /* Since it is now detached, clear information about upstream link */
    map_dm_ale_set_upstream_info(root_node, g_zero_mac, g_zero_mac, g_zero_mac,
                                 true, INTERFACE_TYPE_UNKNOWN);

    tree_node = root_node->self_tree_node;

    /* Remove all children from list and make them orphans now*/
    if (tree_node) {
        make_all_child_nodes_orphan(tree_node);
    }

    return;
}

int8_t is_parent_of(map_ale_info_t* parent, map_ale_info_t* child)
{
    int8_t status = 0;

    if (parent && child) {
        if (parent == get_parent_ale_node(child)) {
            status = 1;
        }
    }

    return status;
}

void remove_topology_tree_node(map_ale_info_t* ale_node)
{
    if (!ale_node) {
        return;
    }

    disassemble_tree(ale_node);

    ktree_free_node(get_ktree_node(ale_node));
}

int32_t map_get_topology_tree_height()
{
    return ktree_max_height(g_root_node);
}

int32_t map_get_height_of(map_ale_info_t* ale_node)
{
    k_tree_node* tree_node = get_ktree_node(ale_node);

    int32_t height = tree_node ? tree_node->height : 0;

    return height;
}
