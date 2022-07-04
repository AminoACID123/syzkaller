DEP_SRCS:=$(wildcard common/*.c)

all: btproxy

btproxy: btproxy.c btvirt.c ${DEP_SRCS}
	gcc -g -W -Wshadow main.c btproxy.c btvirt.c controller.c ${DEP_SRCS} -o ${BUILD_DIR}/controller

clean:
	rm btproxy
