######################*license start*###################################
#   Copyright (c) 2003-2008 Cavium Inc. (support@cavium.com). All rights
#   reserved.
# 
# 
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
# 
#       * Redistributions of source code must retain the above copyright
#         notice, this list of conditions and the following disclaimer.
# 
#       * Redistributions in binary form must reproduce the above
#         copyright notice, this list of conditions and the following
#         disclaimer in the documentation and/or other materials provided
#         with the distribution.
# 
#       * Neither the name of Cavium Inc. nor the names of
#         its contributors may be used to endorse or promote products
#         derived from this software without specific prior written
#         permission.
# 
#   TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
#   AND WITH ALL FAULTS AND CAVIUM NETWORKS MAKES NO PROMISES, REPRESENTATIONS
#   OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH
#   RESPECT TO THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY
#   REPRESENTATION OR DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT
#   DEFECTS, AND CAVIUM SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES
#   OF TITLE, MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR
#   PURPOSE, LACK OF VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET
#   POSSESSION OR CORRESPONDENCE TO DESCRIPTION.  THE ENTIRE RISK ARISING OUT
#   OF USE OR PERFORMANCE OF THE SOFTWARE LIES WITH YOU.
# 
# 
#   For any questions regarding licensing please contact marketing@cavium.com
# 

#
# File version info: $Id: Makefile 88177 2013-09-11 22:33:14Z cchavva $

# this is the default for our Octeon II 68XX-based system; works great!
OCTEON_TARGET:=cvmx_64
CVMX_USE_1_TO_1_TLB_MAPPINGS:=0

# Built 32-bit binaries instead of 64-bit (don't use!)
##OCTEON_TARGET:=cvmx_n32

# Make cvxm_bootmem_alloc() addresses have identical virtual and
# physical addresses (don't use!)
##CVMX_USE_1_TO_1_TLB_MAPPINGS:=1

ifndef OCTEON_ROOT
OCTEON_ROOT = ../../..
endif

# Default simulation parameters
INTF_TO_USE?="sgmii0"

# default number of cores to use
NUM_PROCESSORS=4

CFLAGS_LOCAL = -g -O2 -W -Wall -Wno-unused-parameter

ifndef OCTEON_SIM_PACKET_TCP_PORT
OCTEON_SIM_PACKET_TCP_PORT=2000
endif

# default target
TARGET=addressing
all: application-target 

# standard common Makefile fragment
include $(OCTEON_ROOT)/common.mk

# include relevant component Makefile fragments
dir := $(OCTEON_ROOT)/executive
include $(dir)/cvmx.mk

# application specification
OBJS = $(OBJ_DIR)/addressing.o
DEPS = $(OBJS:%.o=%.d)
include $(OCTEON_ROOT)/application.mk

clean:
	rm -f $(TARGET) output.log output-*.data
	rm -f $(CLEAN_LIST) $(OBJS) $(DEPS)
	rm -f $(CVMX_CONFIG)

clobber: clean
	rm -rf $(OBJ_DIR)

# run simulation, saving packet output to files
run: $(TARGET)
	oct-packet-io -w 5 -p ${OCTEON_SIM_PACKET_TCP_PORT} -c 1 -o output-%d.data &
	oct-sim $(TARGET) -quiet -noperf -serve=${OCTEON_SIM_PACKET_TCP_PORT} -maxcycles=120000000 -numcores=${NUM_PROCESSORS} ${ADDRESSING_SIM_MODES} ${QLM_LANE_MASK} 

