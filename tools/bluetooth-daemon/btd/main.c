#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <alloca.h>
#include <getopt.h>
#include <stdbool.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <termio.h>
#include <netdb.h>
#include <arpa/inet.h>


#define HCI_UART_H4 0
#define BTPROTO_HCI 1
#define ACL_LINK 1
#define SCAN_PAGE 2



#define HCIDEVUP	        _IOW('H', 201, int)
#define HCISETSCAN          _IOW('H', 221, int)

#define HCIUARTSETPROTO     _IOW('U', 200, int)
#define HCIUARTGETPROTO     _IOR('U', 201, int)
#define HCIUARTGETDEVICE    _IOR('U', 202, int)
#define HCIUARTSETFLAGS     _IOW('U', 203, int)
#define HCIUARTGETFLAGS     _IOR('U', 204, int)

#define HCI_UART_RESET_ON_INIT 1
#define HCI_CHANNEL_USER 1
#define HCI_CHANNEL_RAW 0

#define B115200 0010002

unsigned int speed = B115200;
bool flowctrl = true;

#define FATAL(cond, msg)             \
	do {                             \
		if (cond) {                  \
			perror(msg);             \
			exit(1);                 \
		}                            \
	} while (0)

#define CLOFATAL(fd, cond, msg)      \
	do {                             \
		if (cond) {                  \
			perror(msg);             \
			close(fd);               \
			exit(1);                 \
		}                            \
	} while (0)

int open_serial(const char *path)
{
	struct termios ti;
	int fd, ret, saved_ldisc, ldisc = N_HCI;
	fd = open(path, O_RDWR | O_NOCTTY);

	FATAL(fd < 0, "Failed to open serial\n");

    ret = tcflush(fd, TCIFLUSH);
	CLOFATAL(fd, ret < 0, "Failed to flush serial\n");

    ret = ioctl(fd, TIOCGETD, &saved_ldisc);
	CLOFATAL(fd, ret < 0, "Failed to get ldisc\n");

	memset(&ti, 0, sizeof(ti));
	cfmakeraw(&ti);

	ti.c_cflag |= (speed | CLOCAL | CREAD);

	if (flowctrl) {
		ti.c_cflag |= CRTSCTS;
	}

    ret = tcsetattr(fd, TCSANOW, &ti);
	CLOFATAL(fd, ret < 0, "Failed to set serial\n");

    ret = ioctl(fd, TIOCSETD, &ldisc);
	CLOFATAL(fd, ret < 0, "Failed to set ldisc\n");

	printf("Switched line discipline from %d to %d\n", saved_ldisc, ldisc);
	return fd;
}

int create_socket(int index, int channel)
{
    int fd;

    fd = socket(PF_BLUETOOTH, SOCK_RAW | SOCK_NONBLOCK, BTPROTO_HCI);
    FATAL(fd < 0, "Failed to create socket\n");
/*
    memset(&addr, 0, sizeof(addr));
    addr.hci_family = AF_BLUETOOTH;
    addr.hci_dev = index;
    addr.hci_channel = channel;

    ret = bind(fd, (struct sockaddr*)&addr, sizeof(addr));
    CLOFATAL(fd, ret <0, "Failed to bind socket\n");
*/
    return fd;
}

int attach_device(const char *path)
{
	int fd, ret;
	fd = open_serial(path);

    ret = ioctl(fd, HCIUARTSETFLAGS, 1 << HCI_UART_RESET_ON_INIT);
    CLOFATAL(fd, ret < 0, "Failed to set flags\n");

    ret = ioctl(fd, HCIUARTSETPROTO, HCI_UART_H4);
    CLOFATAL(fd, ret < 0, "Failed to set proto\n");

    ret = ioctl(fd, HCIUARTGETDEVICE);
    CLOFATAL(fd, ret < 0, "Failed to get device\n");

    printf("Device %d attached\n", ret);

    return ret;
}

int main(int argc, char **argv)
{
    // FATAL(argc != 2, "Need one argument.\n");
	char* path = getenv("DEV_FILE");
	attach_device(path);


/*
    struct hci_dev_req dr = {
        .dev_id = dev,
        .dev_opt = SCAN_PAGE
    };

    ret = ioctl(sock, HCISETSCAN, &dr);
    FATAL(ret < 0, "Failed to set scan\n");
    close(sock);
*/
    while(1){}

    return 0;

}
