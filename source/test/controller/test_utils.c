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

#include "map_ctrl_utils.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define Z_1  0
#define Z_2  Z_1,Z_1
#define Z_4  Z_2,Z_2
#define Z_8  Z_4,Z_4
#define Z_16 Z_8,Z_8

#define H08_1  0x08
#define H08_2  H08_1,H08_1
#define H08_4  H08_2,H08_2
#define H08_8  H08_4,H08_4
#define H08_16 H08_8,H08_8

#define H22_1  0x22
#define H22_2  H22_1,H22_1
#define H22_4  H22_2,H22_2
#define H22_8  H22_4,H22_4
#define H22_16 H22_8,H22_8

#define MERGE_OP_CLASS_LIST(m, c, a, b, d, r) do {             \
    log_test_i("---- TEST ----");                              \
    dump_op_class_list(#c, c);                                 \
    dump_op_class_list(#a, a);                                 \
    dump_op_class_list(#b, b);                                 \
    dump_op_class_list(#d, d);                                 \
    fail_unless(!map_merge_pref_op_class_list(m, c, a, b, d)); \
    dump_op_class_list("merged", m);                           \
    dump_op_class_list("expect", r);                           \
    fail_unless(compare_op_class_list(m, r));                  \
    free((m)->op_classes);                                     \
} while(0)

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
/* Cap list contains NOT allowed channels.  Pref list contains allowed channels */
static map_op_class_t g_op_cap[]           = {{.op_class =  81, .channels = {.nr =  2, .channels = {Z_1, 0x30}}},                 /* 12, 13 */
                                              {.op_class = 115, .channels = {.nr =  0, .channels = {0}}},
                                              {.op_class = 116, .channels = {.nr =  0, .channels = {0}}},
                                              {.op_class = 117, .channels = {.nr =  0, .channels = {0}}},
                                              {.op_class = 118, .channels = {.nr =  0, .channels = {0}}},
                                              {.op_class = 119, .channels = {.nr =  0, .channels = {0}}},
                                              {.op_class = 120, .channels = {.nr =  0, .channels = {0}}},
                                              {.op_class = 121, .channels = {.nr =  0, .channels = {0}}},
                                              {.op_class = 122, .channels = {.nr =  0, .channels = {0}}},
                                              {.op_class = 123, .channels = {.nr =  0, .channels = {0}}},
                                              {.op_class = 124, .channels = {.nr =  0, .channels = {0}}},
                                              {.op_class = 125, .channels = {.nr =  2, .channels = {Z_16,Z_4,Z_1,0x20,0x02}}},    /* 173, 177 */
                                              {.op_class = 126, .channels = {.nr =  1, .channels = {Z_16,Z_4,Z_1,0x20}}},         /* 173 */
                                              {.op_class = 127, .channels = {.nr =  1, .channels = {Z_16,Z_4,Z_2,0x02}}},         /* 177 */
                                              {.op_class = 128, .channels = {.nr =  1, .channels = {Z_16,Z_4,Z_1,0x08}}},         /* 171 */
                                              {.op_class = 129, .channels = {.nr =  1, .channels = {Z_16,Z_4,0x08}}},             /* 163 */
                                              {.op_class = 131, .channels = {.nr = 35, .channels = {Z_8,Z_4,H22_16,H22_1,0x02}}}, /* 6G_EU: 97, 101, ..., 233 */
                                              {.op_class = 132, .channels = {.nr = 17, .channels = {Z_8,Z_4,H08_16,H08_1}}},      /* 6G_EU: 99, 107, ..., 227 */
                                              {.op_class = 133, .channels = {.nr =  8, .channels = {Z_8,Z_4,0x80,Z_1,0x80,Z_1,0x80,Z_1,0x80,Z_1,0x80,Z_1,0x80,Z_1,0x80,Z_1,0x80}}}, /* 6G_EU: 103, 119, ..., 215 */
                                              {.op_class = 134, .channels = {.nr =  4, .channels = {Z_8,Z_4,Z_1,0x80,Z_2,Z_1,0x80,Z_2,Z_1,0x80,Z_2,Z_1,0x80}}},                     /* 6G_EU: 111, 143, 175, 207 */
                                              {.op_class = 137, .channels = {.nr =  4, .channels = {Z_8,Z_2,Z_1,0x80,Z_2,Z_1,0x80,Z_2,Z_1,0x80,Z_2,Z_1,0x80}}},                     /* 6G_EU: 95, 127, 159, 191 */
                                             };

static map_op_class_list_t g_opl_cap       = {.op_classes = g_op_cap, .op_classes_nr = ARRAY_SIZE(g_op_cap )};

static map_op_class_list_t g_opl_in_1a     = {.op_classes = NULL, .op_classes_nr = 0};
static map_op_class_list_t g_opl_in_1b     = {.op_classes = NULL, .op_classes_nr = 0};
static map_op_class_list_t g_opl_merged_1  = {.op_classes = NULL, .op_classes_nr = 0};

static map_op_class_t g_op_in_2a[]         = {{.op_class = 115, .pref =  0, .channels = {.nr = 2, .channels = {Z_4,0x10,0x01}}},             /* 36, 40 */
                                              {.op_class = 118, .pref =  0, .channels = {.nr = 4, .channels = {Z_4,Z_2,0x10,0x11,0x01}}},    /* 52, 56, 60, 64 */
                                              {.op_class = 121, .pref =  0, .channels = {.nr = 2, .channels = {Z_16,Z_1,0x10,0x01}}},        /* 140, 144 */
                                              {.op_class = 116, .pref =  0, .channels = {.nr = 2, .channels = {Z_4,0x10,0x10}}},             /* 36, 44 */
                                              {.op_class = 119, .pref =  0, .channels = {.nr = 2, .channels = {Z_4,Z_2,0x10,0x10}}},         /* 52, 60 */
                                              {.op_class = 122, .pref =  0, .channels = {.nr = 1, .channels = {Z_16,Z_1,0x10}}},             /* 140 */
                                              {.op_class = 117, .pref =  0, .channels = {.nr = 2, .channels = {Z_4,Z_1,0x01,0x01}}},         /* 40, 48 */
                                              {.op_class = 120, .pref =  0, .channels = {.nr = 2, .channels = {Z_4,Z_2,Z_1,0x01,0x01}}},     /* 56, 64 */
                                              {.op_class = 123, .pref =  0, .channels = {.nr = 1, .channels = {Z_16,Z_2,0x01}}},             /* 144 */
                                              {.op_class = 128, .pref =  0, .channels = {.nr = 0, .channels = {0}}},
                                              {.op_class = 129, .pref =  0, .channels = {.nr = 1, .channels = {Z_4,Z_2,0x04}}},              /* 50 */
                                              {.op_class = 131, .pref =  0, .channels = {.nr = 2, .channels = {0x22}}},                      /* 6G: 1, 5 */
                                              {.op_class = 132, .pref =  0, .channels = {.nr = 2, .channels = {0x08,0x08}}},                 /* 6G: 3, 11 */
                                              {.op_class = 133, .pref =  0, .channels = {.nr = 2, .channels = {0x80,Z_1,0x80}}},             /* 6G: 7, 23 */
                                              {.op_class = 134, .pref =  0, .channels = {.nr = 2, .channels = {Z_1,0x80,Z_2,Z_1,0x80}}},     /* 6G: 15, 47 */
                                              {.op_class = 137, .pref =  0, .channels = {.nr = 1, .channels = {Z_2,Z_1,0x80}}},              /* 6G: 31 */
                                             };

static map_op_class_t g_op_in_2b[]         = {{.op_class = 118, .pref = 14, .channels = {.nr = 1, .channels = {Z_4,Z_2,0x10}}},                  /* 52 */
                                              {.op_class = 118, .pref = 14, .channels = {.nr = 1, .channels = {Z_4,Z_2,Z_1,0x01}}},              /* 56 */
                                              {.op_class = 118, .pref = 14, .channels = {.nr = 1, .channels = {Z_4,Z_2,Z_1,0x10}}},              /* 60 */
                                              {.op_class = 118, .pref = 14, .channels = {.nr = 1, .channels = {Z_8,0x01}}},                      /* 64 */
                                              {.op_class = 121, .pref = 14, .channels = {.nr = 1, .channels = {Z_8,Z_4,0x10}}},                  /* 100 */
                                              {.op_class = 121, .pref = 14, .channels = {.nr = 1, .channels = {Z_8,Z_4,Z_1,0x01}}},              /* 104 */
                                              {.op_class = 121, .pref = 14, .channels = {.nr = 1, .channels = {Z_8,Z_4,Z_1,0x10}}},              /* 108 */
                                              {.op_class = 121, .pref = 14, .channels = {.nr = 1, .channels = {Z_8,Z_4,Z_2,0x01}}},              /* 112 */
                                              {.op_class = 121, .pref = 14, .channels = {.nr = 1, .channels = {Z_8,Z_4,Z_2,0x10}}},              /* 116 */
                                              {.op_class = 121, .pref = 14, .channels = {.nr = 1, .channels = {Z_16,0x10}}},                     /* 132 */
                                              {.op_class = 121, .pref = 14, .channels = {.nr = 1, .channels = {Z_16,Z_1,0x01}}},                 /* 136 */
                                              {.op_class = 121, .pref = 14, .channels = {.nr = 1, .channels = {Z_16,Z_1,0x10}}},                 /* 140 */
                                              {.op_class = 121, .pref = 14, .channels = {.nr = 1, .channels = {Z_16,Z_2,0x01}}},                 /* 144 */
                                              {.op_class = 119, .pref = 14, .channels = {.nr = 1, .channels = {Z_4,Z_2,0x10}}},                  /* 52 */
                                              {.op_class = 119, .pref = 14, .channels = {.nr = 1, .channels = {Z_4,Z_2,Z_1,0x10}}},              /* 60 */
                                              {.op_class = 122, .pref = 14, .channels = {.nr = 1, .channels = {Z_8,Z_4,0x10}}},                  /* 100 */
                                              {.op_class = 122, .pref = 14, .channels = {.nr = 1, .channels = {Z_8,Z_4,Z_1,0x10}}},              /* 108 */
                                              {.op_class = 122, .pref = 14, .channels = {.nr = 1, .channels = {Z_16,0x10}}},                     /* 132 */
                                              {.op_class = 122, .pref = 14, .channels = {.nr = 1, .channels = {Z_16,Z_1,0x10}}},                 /* 140 */
                                              {.op_class = 120, .pref = 14, .channels = {.nr = 1, .channels = {Z_4,Z_2,Z_1,0x01}}},              /* 56 */
                                              {.op_class = 120, .pref = 14, .channels = {.nr = 1, .channels = {Z_8,0x01}}},                      /* 64 */
                                              {.op_class = 123, .pref = 14, .channels = {.nr = 1, .channels = {Z_8,Z_4,Z_1,0x01}}},              /* 104 */
                                              {.op_class = 123, .pref = 14, .channels = {.nr = 1, .channels = {Z_8,Z_4,Z_2,0x01}}},              /* 112 */
                                              {.op_class = 123, .pref = 14, .channels = {.nr = 1, .channels = {Z_16,Z_1,0x01}}},                 /* 136 */
                                              {.op_class = 123, .pref = 14, .channels = {.nr = 1, .channels = {Z_16,Z_2,0x01}}},                 /* 144 */
                                              {.op_class = 128, .pref = 14, .channels = {.nr = 1, .channels = {Z_8,Z_4,Z_1,0x04}}},              /* 106 */
                                              {.op_class = 128, .pref = 14, .channels = {.nr = 2, .channels = {Z_4,Z_2,Z_1,0x04,Z_8,Z_1,0x04}}}, /* 58, 138 */
                                              {.op_class = 129, .pref = 14, .channels = {.nr = 1, .channels = {Z_4,Z_2,0x04}}},                  /* 50 */
                                              {.op_class = 131, .pref =  0, .channels = {.nr = 2, .channels = {Z_1,0x02}}},                      /* 6G: 9 */
                                              {.op_class = 132, .pref =  0, .channels = {.nr = 1, .channels = {Z_2,0x08}}},                      /* 6G: 19 */
                                              {.op_class = 133, .pref =  0, .channels = {.nr = 1, .channels = {Z_4,0x80}}},                      /* 6G: 39 */
                                              {.op_class = 134, .pref =  0, .channels = {.nr = 1, .channels = {Z_8,Z_1,0x80}}},                  /* 6G: 79 */
                                              {.op_class = 137, .pref =  0, .channels = {.nr = 1, .channels = {Z_2,Z_1,0x80}}},                  /* 6G: 31 */
                                             };

static map_op_class_t g_op_merged_2[]      = {{.op_class = 115, .pref =  0, .channels = {.nr = 2, .channels = {Z_4,0x10,0x01}}},                        /* 36, 40 */
                                              {.op_class = 116, .pref =  0, .channels = {.nr = 0, .channels = {0}}},
                                              {.op_class = 117, .pref =  0, .channels = {.nr = 0, .channels = {0}}},
                                              {.op_class = 118, .pref =  0, .channels = {.nr = 0, .channels = {0}}},
                                              {.op_class = 119, .pref =  0, .channels = {.nr = 0, .channels = {0}}},
                                              {.op_class = 120, .pref =  0, .channels = {.nr = 0, .channels = {0}}},
                                              {.op_class = 121, .pref =  0, .channels = {.nr = 2, .channels = {Z_16,Z_1,0x10,0x01}}},                   /* 140, 144 */
                                              {.op_class = 121, .pref = 14, .channels = {.nr = 7, .channels = {Z_8,Z_4,0x10,0x11,0x11,Z_1,0x10,0x01}}}, /* 100, 104, 108, 112, 116, 132, 136 */
                                              {.op_class = 122, .pref =  0, .channels = {.nr = 1, .channels = {Z_16,Z_1,0x10}}},                        /* 140 */
                                              {.op_class = 122, .pref = 14, .channels = {.nr = 3, .channels = {Z_8,Z_4,0x10,0x10,Z_2,0x10}}},           /* 100, 108, 132 */
                                              {.op_class = 123, .pref =  0, .channels = {.nr = 1, .channels = {Z_16,Z_2,0x01}}}, /* 144 */
                                              {.op_class = 123, .pref = 14, .channels = {.nr = 3, .channels = {Z_8,Z_4,Z_1,0x01,0x01,Z_2,0x01}}},       /* 104, 112, 136 */
                                              {.op_class = 128, .pref =  0, .channels = {.nr = 0, .channels = {0}}},
                                              {.op_class = 129, .pref =  0, .channels = {.nr = 1, .channels = {Z_4,Z_2,0x04}}},                         /* 50 */
                                              {.op_class = 131, .pref =  0, .channels = {.nr = 3, .channels = {0x22,0x02}}},                            /* 6G: 1, 5, 9 */
                                              {.op_class = 132, .pref =  0, .channels = {.nr = 3, .channels = {0x08,0x08,0x08}}},                       /* 6G: 3, 11, 19 */
                                              {.op_class = 133, .pref =  0, .channels = {.nr = 3, .channels = {0x80,Z_1,0x80,Z_1,0x80}}},               /* 6G: 7, 23, 39 */
                                              {.op_class = 134, .pref =  0, .channels = {.nr = 0, .channels = {0}}},                                    /* 6G: 15, 47, 79 -> nothing anymore */
                                              {.op_class = 137, .pref =  0, .channels = {.nr = 1, .channels = {Z_2,Z_1,0x80}}},                         /* 6G: 31 */
                                             };

static map_op_class_list_t g_opl_in_2a     = {.op_classes = g_op_in_2a,    .op_classes_nr = ARRAY_SIZE(g_op_in_2a)};
static map_op_class_list_t g_opl_in_2b     = {.op_classes = g_op_in_2b,    .op_classes_nr = ARRAY_SIZE(g_op_in_2b)};
static map_op_class_list_t g_opl_merged_2  = {.op_classes = g_op_merged_2, .op_classes_nr = ARRAY_SIZE(g_op_merged_2)};

static map_op_class_t g_op_in_3a[]         = {{.op_class =  81, .pref =  0, .channels = {.nr = 3, .channels = {0x0e}}},                  /* 1,2,3 */
                                              {.op_class = 115, .pref =  0, .channels = {.nr = 0, .channels = {0}}},
                                              {.op_class = 121, .pref =  4, .channels = {.nr = 2, .channels = {Z_8,Z_4,Z_1,0x10,0x01}}}, /* 108, 112 */
                                              {.op_class = 121, .pref =  0, .channels = {.nr = 2, .channels = {Z_8,Z_4,0x10,0x01}}},     /* 100, 104 */
                                              {.op_class = 124, .pref =  7, .channels = {.nr = 0, .channels = {0}}},
                                              {.op_class = 125, .pref =  9, .channels = {.nr = 0, .channels = {0}}},
                                              {.op_class = 126, .pref =  8, .channels = {.nr = 0, .channels = {0}}},
                                              {.op_class = 128, .pref = 13, .channels = {.nr = 2, .channels = {Z_4,Z_1,0x04,Z_1,0x04}}}, /* 42, 58 */
                                             };

static map_op_class_t g_op_in_3b[]         = {{.op_class =  81, .pref =  0, .channels = {.nr = 1, .channels = {0x08}}},                            /* 3 */
                                              {.op_class = 115, .pref = 14, .channels = {.nr = 0, .channels = {0}}},
                                              {.op_class = 121, .pref =  6, .channels = {.nr = 6, .channels = {Z_8,Z_4,0x10,0x11,0x11,Z_1,0x10}}}, /* 100, 104, 108, 112, 116, 132 */
                                              {.op_class = 128, .pref = 12, .channels = {.nr = 2, .channels = {Z_4,Z_2,Z_1,0x04,Z_4,Z_1,0x04}}},   /* 58, 106 */
                                              {.op_class = 124, .pref =  8, .channels = {.nr = 0, .channels = {0}}},
                                              {.op_class = 125, .pref =  8, .channels = {.nr = 0, .channels = {0}}},
                                              {.op_class = 126, .pref =  8, .channels = {.nr = 0, .channels = {0}}},
                                              {.op_class = 127, .pref =  8, .channels = {.nr = 0, .channels = {0}}},
                                              {.op_class = 129, .pref = 11, .channels = {.nr = 0, .channels = {0}}}
                                            };


static map_op_class_t g_op_merged_3[]      = {{.op_class =  81, .pref =  0, .channels = {.nr = 3, .channels = {0x0e}}},                          /* 1,2,3 */
                                              {.op_class = 115, .pref =  0, .channels = {.nr = 0, .channels = {0}}},
                                              {.op_class = 121, .pref =  0, .channels = {.nr = 2, .channels = {Z_8,Z_4,0x10,0x01}}},             /* 100, 104 */
                                              {.op_class = 121, .pref =  4, .channels = {.nr = 2, .channels = {Z_8,Z_4,Z_1,0x10,0x01}}},         /* 108, 112 */
                                              {.op_class = 121, .pref =  6, .channels = {.nr = 2, .channels = {Z_8,Z_4,Z_2,0x10,Z_1,0x10}}},     /* 116, 132 */
                                              {.op_class = 124, .pref =  7, .channels = {.nr = 0, .channels = {0}}},
                                              {.op_class = 125, .pref =  8, .channels = {.nr = 0, .channels = {0}}},
                                              {.op_class = 126, .pref =  8, .channels = {.nr = 0, .channels = {0}}},
                                              {.op_class = 127, .pref =  8, .channels = {.nr = 0, .channels = {0}}},
                                              {.op_class = 128, .pref = 12, .channels = {.nr = 2, .channels = {Z_4,Z_2,Z_1,0x04,Z_4,Z_1,0x04}}}, /* 58, 106 */
                                              {.op_class = 128, .pref = 13, .channels = {.nr = 1, .channels = {Z_4,Z_1,0x04}}},                  /* 42  */
                                              {.op_class = 129, .pref = 11, .channels = {.nr = 0, .channels = {0}}}
                                            };

static map_op_class_list_t g_opl_in_3a     = {.op_classes = g_op_in_3a,    .op_classes_nr = ARRAY_SIZE(g_op_in_3a)};
static map_op_class_list_t g_opl_in_3b     = {.op_classes = g_op_in_3b,    .op_classes_nr = ARRAY_SIZE(g_op_in_3b)};
static map_op_class_list_t g_opl_merged_3  = {.op_classes = g_op_merged_3, .op_classes_nr = ARRAY_SIZE(g_op_merged_3)};

static map_op_class_list_t g_opl_in_d      = {.op_classes = NULL, .op_classes_nr = 0};

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
static void test_init(void)
{
    fail_unless(!map_info_init());
}

static void test_fini(void)
{
    map_info_fini();
}

static void dump_op_class_list(char *txt, map_op_class_list_t *opl)
{
    int i;

    log_test_i("op_class list[%s] op_classes[%d]", txt, opl->op_classes_nr);

    for (i = 0; i < opl->op_classes_nr; i++) {
        map_op_class_t *op_class = &opl->op_classes[i];
        char buf[256];

        log_test_i("idx[%d] op_class[%d] pref[%d] channels[%s]", i, op_class->op_class, op_class->pref,
            map_cs_to_string(&op_class->channels, ' ', buf, sizeof(buf)));
    }
    log_test_i("=======================================================");
}

static bool compare_op_class_list(map_op_class_list_t *list1, map_op_class_list_t *list2)
{
    int i;

    if (list1->op_classes_nr != list2->op_classes_nr) {
        return false;
    }

    for (i = 0; i < list1->op_classes_nr; i++) {
        map_op_class_t *op_class1 = &list1->op_classes[i];
        map_op_class_t *op_class2 = &list2->op_classes[i];

        if (memcmp(op_class1, op_class2, sizeof(map_op_class_t))) {
            return false;
        }
    }

    return true;
}

static bool check_channel_set(map_channel_set_t *s, int nr, int *c)
{
    int i;

    if (map_cs_nr(s) != nr) {
        return false;
    }

    for (i = 0; i < nr; i++) {
        if (!map_cs_is_set(s, c[i])) {
            return false;
        }
    }

    return true;
}

static void set_cs(map_channel_set_t *set, int c_nr, int *c)
{
    int i;

    map_cs_unset_all(set);

    for (i = 0; i < c_nr; i++) {
        map_cs_set(set, c[i]);
    }
}

/*#######################################################################
#                       TEST_UPDATE_RADIO_CHANNELS                  #
########################################################################*/
START_TEST(test_update_radio_channels)
{
    map_chan_sel_cfg_t   *cfg              = &map_cfg_get()->controller_cfg.chan_sel;
    map_radio_info_t      radio            = {0};
    map_channel_set_t    *cap_ctl_channels = &radio.cap_ctl_channels;
    map_channel_set_t    *ctl_channels     = &radio.ctl_channels;
    map_channel_bw_set_t *cbw              = &radio.channels_with_bandwidth;
    map_op_class_t        op_classes[13]   = {0};

    test_init();

    radio.supported_freq = IEEE80211_FREQUENCY_BAND_5_GHZ;

    /* Add some op_classes */
    /* 20MHz */
    op_classes[0].op_class = 115;
    op_classes[1].op_class = 118;
    op_classes[2].op_class = 124;
    map_cs_set(&op_classes[2].channels, 161);
    /* 40 MHz */
    op_classes[3].op_class = 116;
    op_classes[4].op_class = 117;
    op_classes[5].op_class = 119;
    op_classes[6].op_class = 120;
    op_classes[7].op_class = 122;
    op_classes[8].op_class = 123;
    op_classes[9].op_class = 126;
    map_cs_set(&op_classes[9].channels, 149);
    map_cs_set(&op_classes[9].channels, 165);
    map_cs_set(&op_classes[9].channels, 173);
    op_classes[10].op_class = 127;
    map_cs_set(&op_classes[10].channels, 161);
    map_cs_set(&op_classes[10].channels, 169);
    map_cs_set(&op_classes[10].channels, 177);
    /* 80 MHz */
    op_classes[11].op_class = 128;
    map_cs_set(&op_classes[11].channels, 171);
    /* 160 MHz */
    op_classes[12].op_class = 129;
    map_cs_set(&op_classes[12].channels, 114);
    map_cs_set(&op_classes[12].channels, 163);
    radio.cap_op_class_list.op_classes_nr = ARRAY_SIZE(op_classes);
    radio.cap_op_class_list.op_classes = op_classes;

    /* Allow all channels */
    cfg->bandlock_5g = MAP_BANDLOCK_5G_DISABLED;
    map_cs_set_all(&cfg->allowed_channel_set_2g);
    map_cs_set_all(&cfg->allowed_channel_set_5g);
    map_cs_set_all(&cfg->allowed_channel_set_6g);

    map_update_radio_channels(&radio);
    fail_unless(check_channel_set(cap_ctl_channels, 11, (int[]){36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157}));
    fail_unless(check_channel_set(ctl_channels, 11, (int[]){36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157}));
    fail_unless(check_channel_set(&cbw->channel_set_20, 11, (int[]){36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157}));
    fail_unless(check_channel_set(&cbw->channel_set_40, 9, (int[]){36, 40, 44, 48, 52, 56, 60, 64, 153}));
    fail_unless(check_channel_set(&cbw->channel_set_80, 8, (int[]){36, 40, 44, 48, 52, 56, 60, 64}));
    fail_unless(check_channel_set(&cbw->channel_set_160, 8, (int[]){36, 40, 44, 48, 52, 56, 60, 64}));

    /* Disallow channel 36 in operating classes */
    map_cs_set(&op_classes[0].channels, 36);
    map_cs_set(&op_classes[3].channels, 36);

    map_update_radio_channels(&radio);

    map_update_radio_channels(&radio);
    fail_unless(check_channel_set(cap_ctl_channels, 10, (int[]){40, 44, 48, 52, 56, 60, 64, 149, 153, 157}));
    fail_unless(check_channel_set(ctl_channels, 10, (int[]){40, 44, 48, 52, 56, 60, 64, 149, 153, 157}));
    fail_unless(check_channel_set(&cbw->channel_set_20, 10, (int[]){40, 44, 48, 52, 56, 60, 64, 149, 153, 157}));
    fail_unless(check_channel_set(&cbw->channel_set_40, 7, (int[]){44, 48, 52, 56, 60, 64, 153}));
    fail_unless(check_channel_set(&cbw->channel_set_80, 4, (int[]){52, 56, 60, 64}));
    fail_unless(check_channel_set(&cbw->channel_set_160, 0, (int[]){}));


    /* Disallow some channels */
    map_cs_unset(&cfg->allowed_channel_set_5g, 52);
    map_cs_unset(&cfg->allowed_channel_set_5g, 56);

    map_update_radio_channels(&radio);
    fail_unless(check_channel_set(cap_ctl_channels, 10, (int[]){40, 44, 48, 52, 56, 60, 64, 149, 153, 157}));
    fail_unless(check_channel_set(ctl_channels, 8, (int[]){40, 44, 48, 60, 64, 153, 149, 157}));
    fail_unless(check_channel_set(&cbw->channel_set_20,  8, (int[]){40, 44, 48, 60, 64, 149, 153, 157}));
    fail_unless(check_channel_set(&cbw->channel_set_40,  5, (int[]){44, 48, 60, 64, 153}));
    fail_unless(check_channel_set(&cbw->channel_set_80,  0, (int[]){}));
    fail_unless(check_channel_set(&cbw->channel_set_160, 0, (int[]){}));

    /* 5G bandlock low (but radio not low_high band) */
    cfg->bandlock_5g = MAP_BANDLOCK_5G_LOW;

    map_update_radio_channels(&radio);
    fail_unless(check_channel_set(cap_ctl_channels, 10, (int[]){40, 44, 48, 52, 56, 60, 64, 149, 153, 157}));
    fail_unless(check_channel_set(ctl_channels, 8, (int[]){40, 44, 48, 60, 64, 149, 153, 157}));
    fail_unless(check_channel_set(&cbw->channel_set_20, 8, (int[]){40, 44, 48, 60, 64, 149, 153, 157}));
    fail_unless(check_channel_set(&cbw->channel_set_40, 5, (int[]){44,48,60,64,153}));
    fail_unless(check_channel_set(&cbw->channel_set_80, 0, (int[]){}));
    fail_unless(check_channel_set(&cbw->channel_set_160, 0, (int[]){}));

    /* 5G bandlock low (and radio low_high band) */
    cfg->bandlock_5g = MAP_BANDLOCK_5G_LOW;
    radio.band_type_5G = MAP_M2_BSS_RADIO5GL | MAP_M2_BSS_RADIO5GU;

    map_update_radio_channels(&radio);

    fail_unless(check_channel_set(cap_ctl_channels, 10, (int[]){40, 44, 48, 52, 56, 60, 64, 149, 153, 157}));
    fail_unless(check_channel_set(ctl_channels, 5, (int[]){40, 44, 48, 60, 64}));
    fail_unless(check_channel_set(&cbw->channel_set_20, 5, (int[]){40, 44, 48, 60, 64}));
    fail_unless(check_channel_set(&cbw->channel_set_40, 4, (int[]){44, 48, 60, 64}));
    fail_unless(check_channel_set(&cbw->channel_set_80, 0, (int[]){}));
    fail_unless(check_channel_set(&cbw->channel_set_160, 0, (int[]){}));

    /* 5G bandlock high */
    cfg->bandlock_5g = MAP_BANDLOCK_5G_HIGH;

    map_update_radio_channels(&radio);

    fail_unless(check_channel_set(cap_ctl_channels, 10, (int[]){40, 44, 48, 52, 56, 60, 64, 149, 153, 157}));
    fail_unless(check_channel_set(ctl_channels, 3, (int[]){149, 153, 157}));
    fail_unless(check_channel_set(&cbw->channel_set_20, 3, (int[]){149, 153, 157}));
    fail_unless(check_channel_set(&cbw->channel_set_40, 1, (int[]){153}));
    fail_unless(check_channel_set(&cbw->channel_set_80, 0, (int[]){}));
    fail_unless(check_channel_set(&cbw->channel_set_160, 0, (int[]){}));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_MERGE_OP_CLASS_LIST                        #
########################################################################*/
START_TEST(test_merge_op_class_list)
{
    map_op_class_list_t merged_list = {0};

    test_init();

    MERGE_OP_CLASS_LIST(&merged_list, &g_opl_cap, &g_opl_in_1a, &g_opl_in_1b, &g_opl_in_d, &g_opl_merged_1);
    MERGE_OP_CLASS_LIST(&merged_list, &g_opl_cap, &g_opl_in_2a, &g_opl_in_2b, &g_opl_in_d, &g_opl_merged_2);
    MERGE_OP_CLASS_LIST(&merged_list, &g_opl_cap, &g_opl_in_3a, &g_opl_in_3b, &g_opl_in_d, &g_opl_merged_3);

    /* Reversed */
    MERGE_OP_CLASS_LIST(&merged_list, &g_opl_cap, &g_opl_in_1b, &g_opl_in_1a, &g_opl_in_d, &g_opl_merged_1);
    MERGE_OP_CLASS_LIST(&merged_list, &g_opl_cap, &g_opl_in_2b, &g_opl_in_2a, &g_opl_in_d, &g_opl_merged_2);
    MERGE_OP_CLASS_LIST(&merged_list, &g_opl_cap, &g_opl_in_3b, &g_opl_in_3a, &g_opl_in_d, &g_opl_merged_3);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_NO_SUBBAND_CHANNEL_SET                     #
########################################################################*/
START_TEST(test_no_subband_channel_set)
{
    map_channel_set_t channels;

    test_init();

    /* subbands of ch[100]/opclass[128] are part of channels list  */
    set_cs(&channels, 4, (int[]){100, 104, 108, 112});
    fail_unless(map_is_no_subband_channel_set(&channels, 128, 100) == false);

    /* subbands of ch[112]/opclass[123] are not part of channels list  */
    set_cs(&channels, 1, (int[]){100});
    fail_unless(map_is_no_subband_channel_set(&channels, 123, 112) == true);

    /* subbands of ch[112]/opclass[128] are part of channels list  */
    set_cs(&channels, 1, (int[]){100});
    fail_unless(map_is_no_subband_channel_set(&channels, 128, 112) == false);

    /* subbands of ch[100]/opclass[128] are not part of channels list  */
    set_cs(&channels, 2, (int[]){36, 40});
    fail_unless(map_is_no_subband_channel_set(&channels, 128, 100) == true);

    /* 6G 320MHz */
    set_cs(&channels, 4, (int[]){9, 13, 29, 193});
    fail_unless(map_is_no_subband_channel_set_6G_320MHz(&channels, 137, false,   5) == false);
    fail_unless(map_is_no_subband_channel_set_6G_320MHz(&channels, 137, false,  33) == false);
    fail_unless(map_is_no_subband_channel_set_6G_320MHz(&channels, 137, false,  65) == true);
    fail_unless(map_is_no_subband_channel_set_6G_320MHz(&channels, 137, false, 189) == true);

    fail_unless(map_is_no_subband_channel_set_6G_320MHz(&channels, 137, true,   33) == true);
    fail_unless(map_is_no_subband_channel_set_6G_320MHz(&channels, 137, true,  189) == false);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_ALL_SUBBAND_CHANNEL_SET                     #
########################################################################*/
START_TEST(test_all_subband_channel_set)
{
    map_channel_set_t channels;

    test_init();

    /* subbands channels of ch[100]/opclass[128] are part of channels list  */
    set_cs(&channels, 4, (int[]){100, 104, 108, 112});
    fail_unless(map_is_all_subband_channel_set(&channels, 128, 100) == true);

    /* subbands channels of ch[100]/opclass[128] are part of channels list  */
    set_cs(&channels, 3, (int[]){100, 104, 108 });
    fail_unless(map_is_all_subband_channel_set(&channels, 128, 100) == false);

    /* subbands channels of ch[112]/opclass[123] are not part of channels list  */
    set_cs(&channels, 1, (int[]){100});
    fail_unless(map_is_all_subband_channel_set(&channels, 123, 112) == false);

    /* subbands channels of ch[112]/opclass[123] are not part of channels list  */
    set_cs(&channels, 2, (int[]){108, 112});
    fail_unless(map_is_all_subband_channel_set(&channels, 123, 112) == true);

    /* subbands channels of ch[112]/opclass[123] are not part of channels list  */
    set_cs(&channels, 1, (int[]){108});
    fail_unless(map_is_all_subband_channel_set(&channels, 123, 112) == false);

    /* subbands channels of ch[112]/opclass[128] are part of channels list  */
    set_cs(&channels, 1, (int[]){100});
    fail_unless(map_is_all_subband_channel_set(&channels, 128, 112) == false);

    /* subbands channels of ch[100]/opclass[128] are not part of channels list  */
    set_cs(&channels, 2, (int[]){36, 40});
    fail_unless(map_is_all_subband_channel_set(&channels, 128, 100) == false);

    /* 6G 320MHz */
    set_cs(&channels, 32, (int[]){  1,   5,   9,  13,  17,  21,  25,  29,  33,  37,  41,  45,  49,  53,  57,  61,
                                  161, 165, 169, 173, 177, 181, 185, 189, 193, 197, 201, 205, 209, 213, 217, 221});
    fail_unless(map_is_all_subband_channel_set_6G_320MHz(&channels, 137, false,  13) == true);
    fail_unless(map_is_all_subband_channel_set_6G_320MHz(&channels, 137, false,  65) == false);
    fail_unless(map_is_all_subband_channel_set_6G_320MHz(&channels, 137, false, 161) == false);
    fail_unless(map_is_all_subband_channel_set_6G_320MHz(&channels, 137, false, 189) == false);

    fail_unless(map_is_all_subband_channel_set_6G_320MHz(&channels, 137, true,  65) == false);
    fail_unless(map_is_all_subband_channel_set_6G_320MHz(&channels, 137, true, 161) == true);
    fail_unless(map_is_all_subband_channel_set_6G_320MHz(&channels, 137, true, 221) == true);

    test_fini();
}
END_TEST

const char *test_suite_name = "utils";
test_case_t test_cases[] = {
    TEST("update_radio_channels",     test_update_radio_channels ),
    TEST("merge_op_class_list",       test_merge_op_class_list  ),
    TEST("no_subband_channel_set",    test_no_subband_channel_set  ),
    TEST("all_subband_channel_set",   test_all_subband_channel_set  ),
    TEST_CASES_END
};
