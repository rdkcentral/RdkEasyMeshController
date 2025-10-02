##########################################################################
# Copyright (c) 2019-2024 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

#
# - Find Check unit test framnework
#
#  CHECK_INCLUDE_DIRS  - Where to find check headers, etc.
#  CHECK_LIBRARIES     - List of libraries when using Check.
#  CHECK_FOUND         - True if Check found.


if(CHECK_INCLUDE_DIRS)
    # Already in cache, be silent
    set(CHECK_FIND_QUIETLY TRUE)
endif(CHECK_INCLUDE_DIRS)

find_path(CHECKC_INCLUDE_DIR check.h)
find_library(CHECK_LIBRARY NAMES check)

# handle the QUIETLY and REQUIRED arguments and set CHECK_FOUND to TRUE if 
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CHECK DEFAULT_MSG CHECK_LIBRARY CHECKC_INCLUDE_DIR)

if(CHECK_FOUND)
  set(CHECK_LIBRARIES ${CHECK_LIBRARY})

  # Check might depend on libsubunit.so
  find_library(SUBUNIT_LIBRARY NAMES subunit)

  if (SUBUNIT_LIBRARY)
    set(CHECK_LIBRARIES ${CHECK_LIBRARIES} ${SUBUNIT_LIBRARY})
  endif(SUBUNIT_LIBRARY)

  set(CHECK_INCLUDE_DIRS ${CHECKC_INCLUDE_DIR})
else(CHECK_FOUND)
  set(CHECK_LIBRARIES)
  set(CHECK_INCLUDE_DIRS)
endif(CHECK_FOUND)

mark_as_advanced(CHECK_INCLUDE_DIRS CHECK_LIBRARIES)
