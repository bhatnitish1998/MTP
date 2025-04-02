# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS   := xdpsock 
USER_TARGETS_OBJS := hashmap.o ./ported-mica/util.o ./ported-mica/table.o ./ported-mica/shm.o ./ported-mica/hash.o ./ported-mica/city.o ./ported-mica/alloc_pool.o ./ported-mica/alloc_malloc.o ./ported-mica/alloc_dynamic.o ./maglev/hashmap.o 
BPF_TARGETS    := xdpsock_kern

LDLIBS += -lpthread -lcrypto
LIB_DIR = ../lib

include $(LIB_DIR)/common.mk
