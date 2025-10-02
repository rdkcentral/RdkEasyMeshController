/*
 * Copyright (c) 2019-2024 AirTies Wireless Networks
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
#include "arraylist.h"

/*#######################################################################
#                   HELP FUNCTIONS                                      #
########################################################################*/
static int test_equal(void* obj, void* object_to_find)
{
    return obj == object_to_find;
}

static int test_before(void* obj, void* object_to_find)
{
    int *a = obj;
    int *b = object_to_find;

    return *a > *b;
}

/*#######################################################################
#                   TEST_ARRAYLIST                                      #
########################################################################*/
/* TODO: test all functions */
START_TEST(test_arraylist)
{
    array_list_t    *list;
    list_iterator_t *iterator;
    int              a = 1;
    int              b = 2;
    int              c = 3;
    int             *p;

    fail_unless(!!(list = new_array_list()));

    /* Add objects in front */
    fail_unless(!push_object(list, &a));
    fail_unless(!push_object(list, &b));
    fail_unless(!!push_object_ex(list, &c));

    /* Check content */
    fail_unless(3 == list_get_size(list));
    fail_unless((p = object_at_index(list, 0)) && *p == 3);
    fail_unless((p = object_at_index(list, 1)) && *p == 2);
    fail_unless((p = object_at_index(list, 2)) && *p == 1);
    fail_unless(!(p = object_at_index(list, 3)));
    fail_unless((p = first_object(list)) && *p == 3);
    fail_unless((p = last_object(list))  && *p == 1);
    fail_unless((p = find_object(list, &c, test_equal)) && *p == 3);


    /* Iterator */
    fail_unless(!!(iterator = new_list_iterator(list)));
    fail_unless((p = get_next_list_object(iterator)) && *p == 3);
    fail_unless((p = get_next_list_object(iterator)) && *p == 2);
    fail_unless((p = get_next_list_object(iterator)) && *p == 1);
    fail_unless(!(p = get_next_list_object(iterator)));
    free_list_iterator(iterator);

    /* Remove */
    fail_unless((p = remove_object_at_index(list, 1)) && *p == 2);
    fail_unless(2 == list_get_size(list));
    fail_unless((p = object_at_index(list, 0)) && *p == 3);
    fail_unless((p = object_at_index(list, 1)) && *p == 1);

    fail_unless((p = pop_object(list)) && *p == 3);
    fail_unless(1 == list_get_size(list));
    fail_unless((p = pop_object(list)) && *p == 1);
    fail_unless(0 == list_get_size(list));


    /* Add tail */
    fail_unless(!insert_last_object(list, &a));
    fail_unless(!insert_last_object(list, &b));
    fail_unless(!insert_last_object(list, &c));

    /* Check content */
    fail_unless(3 == list_get_size(list));
    fail_unless((p = object_at_index(list, 0)) && *p == 1);
    fail_unless((p = object_at_index(list, 1)) && *p == 2);
    fail_unless((p = object_at_index(list, 2)) && *p == 3);

    /* Remove */
    fail_unless((p = remove_last_object(list)) && *p == 3);
    fail_unless((p = remove_object_at_index(list, 1)) && *p == 2);
    fail_unless((p = remove_last_object(list)) && *p == 1);


    /* insert_at_index */
    fail_unless(!push_object(list, &c));
    fail_unless(!push_object(list, &a));
    fail_unless(!insert_at_index(list, &b, 1));

    /* Check and remove */
    fail_unless((p = pop_object(list)) && *p == 1);
    fail_unless((p = pop_object(list)) && *p == 2);
    fail_unless((p = pop_object(list)) && *p == 3);


    /* compare_and_insert */
    fail_unless(!push_object(list, &c));
    fail_unless(!push_object(list, &a));
    compare_and_insert(list, &b, test_before);

    /* Check and remove */
    fail_unless((p = pop_object(list)) && *p == 1);
    fail_unless((p = pop_object(list)) && *p == 2);
    fail_unless((p = pop_object(list)) && *p == 3);

    /* Cleanup */
    delete_array_list(list);
}
END_TEST

/*#######################################################################
#                   TEST_ITERATOR_REMOVE                                #
########################################################################*/
/* Remove object while iterating */
START_TEST(test_iterator_remove)
{
    array_list_t    *list;
    list_iterator_t  iterator = {0};
#define NUM_VALS 5
    int              vals[NUM_VALS] = {0, 1, 2, 3, 4};
    int              i;
    int             *p;

    fail_unless(!!(list = new_array_list()));

    /* Add objects */
    for (i = 0; i < NUM_VALS; i++) {
        insert_last_object(list, &vals[i]);
    }

    bind_list_iterator(&iterator, list);

    /* find all 5 */
    for (i = 0; i < NUM_VALS; i++) {
        fail_unless((p = get_next_list_object(&iterator)) && *p == i);
    }

    reset_list_iterator(&iterator);

    /* Remove third object and check will still get 4 and 5 */
    for (i = 0; i < NUM_VALS; i++) {
        fail_unless((p = get_next_list_object(&iterator)) && *p == i);
        if (i == 2) {
            remove_object(list, p);
            fail_unless(4 == list_get_size(list));
        }
    }

    /* Check if correct 4 elements are left */
    for (i = 0; i < NUM_VALS - 1; i++) {
        fail_unless((p = get_next_list_object(&iterator)) && *p == (i < 2) ? i : i + 1);
    }

    /* Flush list */
    for (i = 0; i < NUM_VALS - 1; i++) {
        fail_unless(!!remove_last_object(list));
    }

    /* Cleanup */
    delete_array_list(list);
}
END_TEST


const char *test_suite_name = "arraylist";
test_case_t test_cases[] = {
    TEST("arraylist",       test_arraylist  ),
    TEST("iterator_remove", test_iterator_remove  ),
    TEST_CASES_END
};
