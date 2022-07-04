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
#include <pthread.h>
#include <stdbool.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>

#include <netdb.h>
#include <arpa/inet.h>

#include "common/util.h"
#include "common/mainloop.h"
#include "common/ecc.h"
#include "bt.h"


#define HCI_PRIMARY	0x00
#define HCI_AMP		0x01

#define BTPROTO_HCI	1
struct sockaddr_hci {
	sa_family_t	hci_family;
	unsigned short	hci_dev;
	unsigned short  hci_channel;
};
#define HCI_CHANNEL_USER	1
#define HCI_INDEX_NONE		0xffff


#define BITMASK(bf_off, bf_len) (((1ull << (bf_len)) - 1) << (bf_off))
#define STORE_BY_BITMASK(type, htobe, addr, val, bf_off, bf_len)               \
	*(type *)(addr) = htobe(                                               \
		(htobe(*(type *)(addr)) & ~BITMASK((bf_off), (bf_len))) |      \
		(((type)(val) << (bf_off)) & BITMASK((bf_off), (bf_len))))


extern uint16_t hci_index;
extern bool client_active;
extern bool debug_enabled;
extern bool emulate_ecc;
extern bool skip_first_zero;

struct controller {
	/* Receive commands, ACL, SCO and ISO data */
	int host_fd;
	uint8_t host_buf[4096];
	uint16_t host_len;
	bool host_shutdown;
	bool host_skip_first_zero;

	/* Receive events, ACL, SCO and ISO data */
	int dev_fd;
	uint8_t dev_buf[4096];
	uint16_t dev_len;
	bool dev_shutdown;

	/* ECC emulation */
	uint8_t event_mask[8];
	uint8_t local_sk256[32];
};

typedef struct controller controller;

bool write_packet(int fd, const void *data, size_t size);

void host_write_packet(controller *ctrl, void *buf, uint16_t len);

void dev_write_packet(controller *ctrl, void *buf, uint16_t len);

void send_event(controller* ctrl, uint8_t event, void* data, size_t data_len);

void send_cmd_complete_event(controller *ctrl, uint16_t opcode, void* data, size_t data_len);

void send_cmd_status_event(controller *ctrl, uint8_t status, uint16_t opcode);

void send_le_meta_event(controller *ctrl, uint8_t event, void *data, uint8_t len);

bool setup_proxy(int host_fd);

bool setup_virt(int host_fd);

static inline void hexdump_print(const char *str, void *user_data)
{
	printf("%s%s\n", (char *) user_data,str);
}



