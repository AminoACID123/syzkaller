#include "controller.h"

#define VERSION "0.0.1"

uint16_t hci_index = HCI_INDEX_NONE;
bool client_active = false;
bool debug_enabled = false;
bool emulate_ecc = false;
bool skip_first_zero = false;

void *buf;
size_t buf_size;

static int open_unix(const char *path)
{
	struct sockaddr_un addr;
	size_t len;
	int fd;

	len = strlen(path);
	if (len > sizeof(addr.sun_path) - 1) {
		fprintf(stderr, "Path too long\n");
		return -1;
	}

	unlink(path);

	fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		perror("Failed to open Unix server socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("Failed to bind Unix server socket");
		close(fd);
		return -1;
	}

	if (listen(fd, 1) < 0) {
		perror("Failed to listen Unix server socket");
		close(fd);
		return -1;
	}

	if (chmod(path, 0666) < 0)
		perror("Failed to change mode");

	return fd;
}

static void server_callback(int fd, uint32_t events, void *user_data)
{
	union {
		struct sockaddr common;
		struct sockaddr_un sun;
		struct sockaddr_in sin;
	} addr;
	socklen_t len;
	int host_fd, dev_fd;

	if (events & (EPOLLERR | EPOLLHUP)) {
		mainloop_quit();
		return;
	}

	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);

	if (getsockname(fd, &addr.common, &len) < 0) {
		perror("Failed to get socket name");
		return;
	}

	host_fd = accept(fd, &addr.common, &len);
	if (host_fd < 0) {
		perror("Failed to accept client socket");
		return;
	}

	if (client_active && hci_index != HCI_INDEX_NONE) {
		fprintf(stderr, "Active client already present\n");
		close(host_fd);
		return;
	}

	printf("Setting up controller\n");

	if (hci_index != HCI_INDEX_NONE)
		client_active = setup_proxy(host_fd);
	else
		client_active = setup_virt(host_fd);
}

static void signal_callback(int signum, void *user_data)
{
	switch (signum) {
	case SIGINT:
	case SIGTERM:
		mainloop_quit();
		break;
	}
}

static void usage(void)
{
	printf("btproxy - Bluetooth controller proxy\n"
	       "Usage:\n");
	printf("\tbtproxy [options]\n");
	printf("Options:\n"
	       "\t-i, --index <num>           Use specified controller\n"
	       "\t-a, --amp                   Create AMP controller\n"
	       "\t-e, --ecc                   Emulate ECC support\n"
	       "\t-d, --debug                 Enable debugging output\n"
	       "\t-h, --help                  Show help options\n");
}

static const struct option main_options[] = {
	{ "unix", optional_argument, NULL, 'u' },
	{ "index", required_argument, NULL, 'i' },
	{ "amp", no_argument, NULL, 'a' },
	{ "ecc", no_argument, NULL, 'e' },
	{ "debug", no_argument, NULL, 'd' },
	{ "help", no_argument, NULL, 'h' },
	{}
};

int main(int argc, char *argv[])
{
	const char *connect_address = NULL;
	const char *server_address = NULL;
	const char *unix_path = NULL;
	unsigned short tcp_port = 0xb1ee; /* 45550 */
	bool use_redirect = false;
	uint8_t type = HCI_PRIMARY;
	const char *str;
	unix_path = "/tmp/bt-server-bredr";

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "rc:l::u::p:i:aezdvh",
				  main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'i':
			if (strlen(optarg) > 3 && !strncmp(optarg, "hci", 3))
				str = optarg + 3;
			else
				str = optarg;
			if (!isdigit(*str)) {
				usage();
				return EXIT_FAILURE;
			}
			hci_index = atoi(str);
			break;
		case 'a':
			type = HCI_AMP;
			break;
		case 'e':
			emulate_ecc = true;
			break;
		case 'z':
			skip_first_zero = true;
			break;
		case 'd':
			debug_enabled = true;
			break;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			return EXIT_FAILURE;
		}
	}

	if (argc - optind > 0) {
		fprintf(stderr, "Invalid command line parameters\n");
		return EXIT_FAILURE;
	}

	buf = malloc0(4096);

	mainloop_init();

	int server_fd;

	if (unix_path) {
		printf("Listening on %s\n", unix_path);

		server_fd = open_unix(unix_path);
	}

	if (server_fd < 0)
		return EXIT_FAILURE;

	mainloop_add_fd(server_fd, EPOLLIN, server_callback, NULL, NULL);

	return mainloop_run_with_signal(signal_callback, NULL);
}
