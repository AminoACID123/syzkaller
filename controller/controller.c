#include "controller.h"

void host_write_packet(controller *ctrl, void *buf, uint16_t len)
{
	if (!write_packet(ctrl->dev_fd, buf, len)) {
		fprintf(stderr, "Write to device descriptor failed\n");
		mainloop_remove_fd(ctrl->dev_fd);
	}
}

void dev_write_packet(controller *ctrl, void *buf, uint16_t len)
{
	if (!write_packet(ctrl->host_fd, buf, len)) {
		fprintf(stderr, "Write to host descriptor failed\n");
		mainloop_remove_fd(ctrl->host_fd);
	}
}

void send_event(controller* ctrl, uint8_t event, void* data, size_t data_len)
{
	size_t buf_size = 1 + sizeof(struct bt_hci_evt_hdr) + data_len;
	void* buf = alloca(buf_size);  

	*((uint8_t *) buf) = BT_H4_EVT_PKT;
	struct bt_hci_evt_hdr *hdr = buf + 1;
	hdr->evt = event;
	hdr->plen = data_len;

	if(data_len > 0)
		memcpy(buf+buf_size-data_len, data, data_len);

	dev_write_packet(ctrl, buf, buf_size);
	if (debug_enabled)
		util_hexdump('>', buf, buf_size, hexdump_print, "D: ");
}


void send_cmd_complete_event(controller* ctrl, uint16_t opcode, void* data, size_t data_len)
{
	size_t buf_size = 1 + sizeof(struct bt_hci_evt_hdr) +
				 sizeof(struct bt_hci_evt_cmd_complete) + data_len;
    void* buf = alloca(buf_size);  

	*((uint8_t *) buf) = BT_H4_EVT_PKT;
	struct bt_hci_evt_hdr *hdr = buf + 1;
	struct bt_hci_evt_cmd_complete *cc = buf + 1 + sizeof(*hdr);	

	hdr->evt = BT_HCI_EVT_CMD_COMPLETE;
	hdr->plen = sizeof(struct bt_hci_evt_cmd_complete) + data_len;
	cc->ncmd = 1;
	cc->opcode = opcode;

	if(data_len > 0)
		memcpy(buf+buf_size-data_len, data, data_len);
    
    dev_write_packet(ctrl, buf, buf_size);
	if (debug_enabled)
		util_hexdump('>', buf, buf_size, hexdump_print, "D: ");
}

void send_cmd_status_event(controller* ctrl, uint8_t status, uint16_t opcode)
{
	size_t buf_size = 1 + sizeof(struct bt_hci_evt_hdr) +
					sizeof(struct bt_hci_evt_cmd_status);
    void* buf = alloca(buf_size);

	*((uint8_t *) buf) = BT_H4_EVT_PKT;
	struct bt_hci_evt_hdr *hdr = buf + 1;
	struct bt_hci_evt_cmd_status *cs = buf + 1 + sizeof(*hdr);

	hdr->evt = BT_HCI_EVT_CMD_STATUS;
	hdr->plen = sizeof(*cs);

	cs->status = status;
	cs->ncmd = 0x01;
	cs->opcode = cpu_to_le16(opcode);

    dev_write_packet(ctrl, buf, buf_size);
}

void send_le_meta_event(controller* ctrl, uint8_t event, void *data, uint8_t len)
{
	size_t buf_size = 1 + sizeof(struct bt_hci_evt_hdr) + 1 + len;
    void* buf = alloca(buf_size);

	*((uint8_t *) buf) = BT_H4_EVT_PKT;
	struct bt_hci_evt_hdr *hdr = buf + 1;

	hdr->evt = BT_HCI_EVT_LE_META_EVENT;
	hdr->plen = 1 + len;

	*((uint8_t *) (buf + 1 + sizeof(*hdr))) = event;

	if (len > 0)
		memcpy(buf + 1 + sizeof(*hdr) + 1, data, len);
    
    dev_write_packet(ctrl, buf, buf_size);
}

bool write_packet(int fd, const void *data, size_t size)
{

	struct iovec iv[1];
	iv[0].iov_base = data;
	iv[0].iov_len = size;
	return (writev(fd, iv, 1) >= 0);
	
	while (size > 0) {
		ssize_t written;

		written = write(fd, data, size);
		if (written < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			return false;
		}

		data += written;
		size -= written;
	}

	return true;
}