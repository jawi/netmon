# Makefile for netmon

TARGET_EXEC = netmon

BUILD_DIR = build
SRC_DIRS = src
INC_DIRS = src/inc
TEST_DIRS = test

ifdef TEST
SRCS := $(shell find $(SRC_DIRS) $(TEST_DIRS) -name 'main.c' -prune -o -name '*.c' -print)
TARGET_EXEC = netmon_test
else
SRCS := $(shell find $(SRC_DIRS) -name '*.c')
endif

OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

INC_FLAGS := $(addprefix -I,$(INC_DIRS))

CFLAGS += -Wall -Wstrict-prototypes -Wmissing-prototypes -Wshadow -Wconversion
CPPFLAGS += $(INC_FLAGS) -MMD -MP
LDFLAGS = -lmnl -lmosquitto -lyaml

ifdef TEST
LDFLAGS += -lcunit
endif

all: $(BUILD_DIR)/$(TARGET_EXEC)

$(BUILD_DIR)/$(TARGET_EXEC): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# c source
$(BUILD_DIR)/%.c.o: %.c
	$(MKDIR_P) $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

.PHONY: clean

clean:
	$(RM) -r $(BUILD_DIR)

-include $(DEPS)

MKDIR_P ?= @mkdir -p

###EOF###
