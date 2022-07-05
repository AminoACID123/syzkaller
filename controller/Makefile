DEP_SRCS:=$(wildcard common/*.c)

all: controller

controller: btproxy.c btvirt.c ${DEP_SRCS}
	gcc -g -W -Wshadow main.c btproxy.c btvirt.c controller.c ${DEP_SRCS} -o ../bin/controller

clean:
	rm ../bin/controller
