// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2012  Intel Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#include "controller.h"


static void host_emulate_ecc(struct controller *proxy, void *buf, uint16_t len)
{
	uint8_t pkt_type = *((uint8_t *)buf);
	struct bt_hci_cmd_hdr *hdr = buf + 1;
	struct bt_hci_cmd_le_set_event_mask *lsem;
	struct bt_hci_cmd_le_generate_dhkey *lgd;
	struct bt_hci_evt_le_read_local_pk256_complete lrlpkc;
	struct bt_hci_evt_le_generate_dhkey_complete lgdc;

	if (pkt_type != BT_H4_CMD_PKT) {
		host_write_packet(proxy, buf, len);
		return;
	}

	switch (le16_to_cpu(hdr->opcode)) {
	case BT_HCI_CMD_LE_SET_EVENT_MASK:
		lsem = buf + 1 + sizeof(*hdr);
		memcpy(proxy->event_mask, lsem->mask, 8);

		lsem->mask[0] &= ~0x80; /* P-256 Public Key Complete */
		lsem->mask[1] &= ~0x01; /* Generate DHKey Complete */

		host_write_packet(proxy, buf, len);
		break;

	case BT_HCI_CMD_LE_READ_LOCAL_PK256:
		if (!ecc_make_key(lrlpkc.local_pk256, proxy->local_sk256)) {
			send_cmd_status_event(proxy, BT_HCI_ERR_COMMAND_DISALLOWED,
					BT_HCI_CMD_LE_READ_LOCAL_PK256);
			break;
		}
		send_cmd_status_event(proxy, BT_HCI_ERR_SUCCESS,
				BT_HCI_CMD_LE_READ_LOCAL_PK256);

		if (!(proxy->event_mask[0] & 0x80))
			break;

		lrlpkc.status = BT_HCI_ERR_SUCCESS;
		send_le_meta_event(proxy,
				   BT_HCI_EVT_LE_READ_LOCAL_PK256_COMPLETE,
				   &lrlpkc, sizeof(lrlpkc));
		break;

	case BT_HCI_CMD_LE_GENERATE_DHKEY:
		lgd = buf + 1 + sizeof(*hdr);
		if (!ecdh_shared_secret(lgd->remote_pk256, proxy->local_sk256,
					lgdc.dhkey)) {
			send_cmd_status_event(proxy, BT_HCI_ERR_COMMAND_DISALLOWED,
					BT_HCI_CMD_LE_GENERATE_DHKEY);
			break;
		}
		send_cmd_status_event(proxy, BT_HCI_ERR_SUCCESS,
				BT_HCI_CMD_LE_GENERATE_DHKEY);

		if (!(proxy->event_mask[1] & 0x01))
			break;

		lgdc.status = BT_HCI_ERR_SUCCESS;
		send_le_meta_event(proxy, BT_HCI_EVT_LE_GENERATE_DHKEY_COMPLETE,
				   &lgdc, sizeof(lgdc));
		break;

	default:
		host_write_packet(proxy, buf, len);
		break;
	}
}

static void dev_emulate_ecc(struct controller *proxy, void *buf, uint16_t len)
{
	uint8_t pkt_type = *((uint8_t *)buf);
	struct bt_hci_evt_hdr *hdr = buf + 1;
	struct bt_hci_evt_cmd_complete *cc;
	struct bt_hci_rsp_read_local_commands *rlc;

	if (pkt_type != BT_H4_EVT_PKT) {
		dev_write_packet(proxy, buf, len);
		return;
	}

	switch (hdr->evt) {
	case BT_HCI_EVT_CMD_COMPLETE:
		cc = buf + 1 + sizeof(*hdr);

		switch (le16_to_cpu(cc->opcode)) {
		case BT_HCI_CMD_READ_LOCAL_COMMANDS:
			rlc = buf + 1 + sizeof(*hdr) + sizeof(*cc);
			rlc->commands[34] |= 0x02; /* P-256 Public Key */
			rlc->commands[34] |= 0x04; /* Generate DHKey */
			break;
		}

		dev_write_packet(proxy, buf, len);
		break;

	default:
		dev_write_packet(proxy, buf, len);
		break;
	}
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

	if (emulate_ecc)
		host_emulate_ecc(ctrl, ctrl->host_buf, pktlen);
	else
		host_write_packet(ctrl, ctrl->host_buf, pktlen);

	if (ctrl->host_len > pktlen) {
		memmove(ctrl->host_buf, ctrl->host_buf + pktlen,
			ctrl->host_len - pktlen);
		ctrl->host_len -= pktlen;
		goto process_packet;
	}

	ctrl->host_len = 0;
}

static void dev_read_destroy(void *user_data)
{
	struct controller *ctrl = user_data;

	printf("Closing device descriptor\n");

	if (ctrl->dev_shutdown)
		shutdown(ctrl->dev_fd, SHUT_RDWR);

	close(ctrl->dev_fd);
	ctrl->dev_fd = -1;

	if (ctrl->host_fd < 0) {
		client_active = false;
		free(ctrl);
	} else
		mainloop_remove_fd(ctrl->host_fd);
}

static void dev_read_callback(int fd, uint32_t events, void *user_data)
{
	struct controller *proxy = user_data;
	struct bt_hci_evt_hdr *evt_hdr;
	struct bt_hci_acl_hdr *acl_hdr;
	struct bt_hci_sco_hdr *sco_hdr;
	struct bt_hci_iso_hdr *iso_hdr;
	ssize_t len;
	uint16_t pktlen;

	if (events & (EPOLLERR | EPOLLHUP)) {
		fprintf(stderr, "Error from device descriptor\n");
		mainloop_remove_fd(proxy->dev_fd);
		return;
	}

	if (events & EPOLLRDHUP) {
		fprintf(stderr, "Remote hangup of device descriptor\n");
		mainloop_remove_fd(proxy->host_fd);
		return;
	}

	len = read(proxy->dev_fd, proxy->dev_buf + proxy->dev_len,
		   sizeof(proxy->dev_buf) - proxy->dev_len);
	if (len < 0) {
		if (errno == EAGAIN || errno == EINTR)
			return;

		fprintf(stderr, "Read from device descriptor failed\n");
		mainloop_remove_fd(proxy->dev_fd);
		return;
	}

	proxy->dev_len += len;

process_packet:
	if (proxy->dev_len < 1)
		return;

	switch (proxy->dev_buf[0]) {
	case BT_H4_EVT_PKT:
		if (proxy->dev_len < 1 + sizeof(*evt_hdr))
			return;

		evt_hdr = (void *)(proxy->dev_buf + 1);
		pktlen = 1 + sizeof(*evt_hdr) + evt_hdr->plen;
		break;
	case BT_H4_ACL_PKT:
		if (proxy->dev_len < 1 + sizeof(*acl_hdr))
			return;

		acl_hdr = (void *)(proxy->dev_buf + 1);
		pktlen = 1 + sizeof(*acl_hdr) + cpu_to_le16(acl_hdr->dlen);
		break;
	case BT_H4_SCO_PKT:
		if (proxy->dev_len < 1 + sizeof(*sco_hdr))
			return;

		sco_hdr = (void *)(proxy->dev_buf + 1);
		pktlen = 1 + sizeof(*sco_hdr) + sco_hdr->dlen;
		break;
	case BT_H4_ISO_PKT:
		if (proxy->dev_len < 1 + sizeof(*iso_hdr))
			return;

		iso_hdr = (void *)(proxy->dev_buf + 1);
		pktlen = 1 + sizeof(*iso_hdr) + cpu_to_le16(iso_hdr->dlen);
		break;
	default:
		fprintf(stderr, "Received unknown device packet type 0x%02x\n",
			proxy->dev_buf[0]);
		mainloop_remove_fd(proxy->dev_fd);
		return;
	}

	if (proxy->dev_len < pktlen)
		return;

	if (debug_enabled)
		util_hexdump('>', proxy->dev_buf, pktlen, hexdump_print, "D: ");

	if (emulate_ecc)
		dev_emulate_ecc(proxy, proxy->dev_buf, pktlen);
	else
		dev_write_packet(proxy, proxy->dev_buf, pktlen);

	if (proxy->dev_len > pktlen) {
		memmove(proxy->dev_buf, proxy->dev_buf + pktlen,
			proxy->dev_len - pktlen);
		proxy->dev_len -= pktlen;
		goto process_packet;
	}

	proxy->dev_len = 0;
}

static int open_channel(uint16_t index)
{
	struct sockaddr_hci addr;
	int fd, err;

	if (index == HCI_INDEX_NONE)
		index = 0;

	printf("Opening user channel for hci%u\n", index);

	fd = socket(PF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);
	if (fd < 0) {
		perror("Failed to open Bluetooth socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = index;
	addr.hci_channel = HCI_CHANNEL_USER;

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		err = -errno;
		close(fd);

		/* Open next available controller if no specific index was
		 * provided and the error indicates that the controller.
		 */
		if (hci_index == HCI_INDEX_NONE &&
		    (err == -EBUSY || err == -EUSERS))
			return open_channel(++index);

		perror("Failed to bind Bluetooth socket");
		return -1;
	}

	return fd;
}

bool setup_proxy(int host_fd)
{
	printf("Using local controller\n");

	struct controller *ctrl;
	int dev_fd = open_channel(hci_index);
	if (dev_fd < 0) {
		close(host_fd);
		return false;
	}

	printf("New client connected\n");
	ctrl = new0(struct controller, 1);
	if (!ctrl) {
		close(host_fd);
		close(dev_fd);
		return false;
	}

	if (emulate_ecc)
		printf("Enabling ECC emulation\n");

	ctrl->host_fd = host_fd;
	ctrl->host_shutdown = true;
	ctrl->host_skip_first_zero = skip_first_zero;

	ctrl->dev_fd = dev_fd;
	ctrl->dev_shutdown = false;

	mainloop_add_fd(ctrl->host_fd, EPOLLIN | EPOLLRDHUP, host_read_callback,
			ctrl, host_read_destroy);

	mainloop_add_fd(ctrl->dev_fd, EPOLLIN | EPOLLRDHUP, dev_read_callback,
			ctrl, dev_read_destroy);

	return true;
}
