#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>

#include <libusb20.h>
#include <libusb20_desc.h>
#include <dev/usb/usb_ioctl.h>

#include "flyserv_msg.h"

#define PGMR_VENDOR_ID		0x09fb
#define PGMR_PRODUCT_ID1	0x6810
#define PGMR_PRODUCT_ID2	0x6010

#define DATA_MAX_SIZE 		4096

#define USB_MAX_TRANSFERS	2

#define TR_OUT_IDX		0
#define TR_IN_IDX		1

#define INFLIGHT_SLEEP_USEC	10000

static struct libusb20_device 	*USB_DEVH;
static uint16_t			USB_CUR_PRODUCT_ID;
static volatile int 		OUT_INFLIGHT;
static volatile int 		IN_INFLIGHT;

static const char*
getenv_string(const char* var_name)
{
	const char *var_value = getenv(var_name);
	if (var_value == NULL || strlen(var_value) <= 0)
		errx(1, "Environment variable not set: %s", var_name);
	return var_value;
}


static long
getenv_int(const char* var_name)
{
	const char *var_value = getenv_string(var_name);
	char *int_end;

	errno = 0;
	long num = strtol(var_value, &int_end, 0);
	if (errno != 0 || *int_end != 0)
		err(1, "Invalid value of integer environment variable: %s",
			var_value);
	return num;
}


static int
initialize_server_socket()
{
	int ssfd;
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(getenv_int("FLY_SERVER_PORT"));
	memset(&sa.sin_addr, 0, sizeof(sa.sin_addr));
	sa.sin_addr.s_addr = INADDR_ANY;
	if ( (ssfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		err(1, "Error creating TCP socket");
	if (bind(ssfd, (struct sockaddr *)&sa, sizeof(sa)) != 0)
		err(errno, "Error binding server port");
	if (listen(ssfd, 0) != 0)
		err(errno, "Error call listen on server port");
	return ssfd;
}


static struct libusb20_device*
allocate_usb_device()
{
	struct libusb20_device *pdev, *devh;
	struct libusb20_backend *backend;
	struct libusb20_transfer *txfer;
	int found;

	if ( (backend = libusb20_be_alloc_default()) == 0)
		err(errno, "Error initilazing usb backend");

	found = 0;
	devh = 0;
	while ( (devh = libusb20_be_device_foreach(backend, devh)) != 0) {
		struct usb_device_info info;
		if (libusb20_dev_open(devh, USB_MAX_TRANSFERS) == 0) {
		    if (libusb20_dev_get_info(devh, &info) == 0) {
			if ((info.udi_productNo == PGMR_PRODUCT_ID1 ||
			     info.udi_productNo == PGMR_PRODUCT_ID2) &&
			    info.udi_vendorNo  == PGMR_VENDOR_ID)
			{
			    USB_CUR_PRODUCT_ID = info.udi_productNo;
			    found = 1;
			}
		    }
		    if (found == 0) {
			libusb20_dev_close(devh);
		    } else {
			libusb20_be_dequeue_device(backend, devh);
			break;
		    }
		}
	}

	libusb20_be_free(backend);
	OUT_INFLIGHT = 0;
	IN_INFLIGHT = 0;
	return devh;
}


static void
free_usb_device()
{
	if (USB_DEVH) {
		libusb20_dev_close(USB_DEVH);
		USB_DEVH = 0;
	}
}


static int
write_client_msg(int client_fd, client_msg_t *msg)
{
	if (write(client_fd, msg, sizeof(*msg)) != sizeof(*msg)) {
		warnx("Short write on client socket");
		return -1;
	}
	return 0;
}


static int 
read_socket(int client_fd, void *buf, int buf_size)
{
	int ecode, to_read = buf_size;
	uint8_t *ptr = (uint8_t *)buf;

	while (to_read > 0) {
		ecode = read(client_fd, ptr, to_read);
		if (ecode <= 0)
			return -1;
		ptr += ecode;
		to_read -= ecode;
	}
	return buf_size;
}

STAILQ_HEAD(Transfer_Head, transfer_result) Transfers = 
	SLIST_HEAD_INITIALIZER(Transfers);

struct transfer_result {
	uint64_t	urb_ptr;
	void		*inout_data;
	uint32_t	actual_length;
	int32_t		status;
	int32_t		direction;

	STAILQ_ENTRY(transfer_result)	entries;
};


struct transfer_result*
get_result()
{
	struct transfer_result *result = STAILQ_FIRST(&Transfers);
	if (result) {
		STAILQ_REMOVE_HEAD(&Transfers, entries);
	}
	return result;

}


void
clear_results()
{
	struct transfer_result *result;
	while ( (result = get_result())) {
		free(result->inout_data);
		free(result);	
	}
}


void
transfer_out_cb(struct libusb20_transfer *txfer)
{ 
	uint32_t status = libusb20_tr_get_status(txfer); 

	if (status == LIBUSB20_TRANSFER_START) {
		libusb20_tr_submit(txfer);
	} else {
		struct transfer_result *result = 
			malloc(sizeof(struct transfer_result));
		result->urb_ptr = (uint64_t)libusb20_tr_get_priv_sc0(txfer);
		result->inout_data = libusb20_tr_get_priv_sc1(txfer);
		result->actual_length = libusb20_tr_get_actual_length(txfer);
		result->status = status;
		result->direction = 0;
		libusb20_tr_close(txfer);
		OUT_INFLIGHT = 0;
		STAILQ_INSERT_TAIL(&Transfers, result, entries);
	}
}


void
transfer_in_cb(struct libusb20_transfer *txfer)
{ 
	uint32_t status = libusb20_tr_get_status(txfer); 

	if (status == LIBUSB20_TRANSFER_START) {
		libusb20_tr_submit(txfer);
	} else {
		struct transfer_result *result = 
			malloc(sizeof(struct transfer_result));
		result->urb_ptr = (uint64_t)libusb20_tr_get_priv_sc0(txfer);
		result->inout_data = libusb20_tr_get_priv_sc1(txfer);
		result->actual_length = libusb20_tr_get_actual_length(txfer);
		result->status = 0;
		result->direction = USB_REQTYPE_DIR_IN;
		libusb20_tr_close(txfer);
		IN_INFLIGHT = 0;
		STAILQ_INSERT_TAIL(&Transfers, result, entries);
	}
}


static void
client_loop(int client_fd)
{ 
	uint8_t *data;
	struct libusb20_transfer *txfer;
	struct transfer_result *result;
	struct LIBUSB20_CONTROL_SETUP_DECODED control_req;
	int ecode;

	while (1) {
		client_msg_t msg;
		int len = read_socket(client_fd, &msg, sizeof(msg));
		libusb20_dev_process(USB_DEVH);
		if (len != sizeof(msg)) {
			warnx("Short read on client channel, aborting conn.");
			return;
		}

		switch (msg.msg_type_id) {
		case MSG_GET_PRODUCT_ID:
	            msg.msg_type_id = MSG_OK;
		    msg.usb_iface_nr = 	USB_CUR_PRODUCT_ID;
		    if (write_client_msg(client_fd, &msg) < 0)
			return;
		    break;

		case MSG_CLAIM_INTERFACE:
	            msg.msg_type_id = MSG_OK;
		    if (write_client_msg(client_fd, &msg) < 0)
			return;
		    break;

		case MSG_RELEASE_INTERFACE:
		    msg.msg_type_id = MSG_OK;
		    if (write_client_msg(client_fd, &msg) < 0)
			return;
		    break;

		case MSG_SET_INTERFACE:
		    if (libusb20_dev_set_alt_index(USB_DEVH, 
						msg.usb_iface_nr,
						msg.usb_altsetting_nr) != 0) 
		    {
			warnx("USB Error setting usb alternate setting");
	            	msg.msg_type_id = MSG_FAIL;
		    } else {
	            	msg.msg_type_id = MSG_OK;
		    }
		    if (write_client_msg(client_fd, &msg) < 0)
			return;
		    break;

		case MSG_CLEAR_HALT:
		    /* XXX TODO ??? HOW ?? */
		    msg.msg_type_id = MSG_OK;
		    if (write_client_msg(client_fd, &msg) < 0)
			return;
		    break;

		case MSG_CONTROL:
		    if ((msg.usb_request_type & USB_REQTYPE_DIR_IN) == 0) {
			if (read_socket(client_fd, 
				data, 
				msg.usb_request_length) != 
						msg.usb_request_length) 
			{
			    warnx("Error reading control message data");
			    return;
			}
		    }

		    LIBUSB20_INIT(LIBUSB20_CONTROL_SETUP, &control_req);	
		    control_req.bmRequestType = msg.usb_request_type;
		    control_req.bRequest = msg.usb_request_id;
		    control_req.wValue = msg.usb_request_value;
		    control_req.wIndex = msg.usb_request_index;
		    control_req.wLength = msg.usb_request_length;
		    uint16_t actlen;
		    if (libusb20_dev_request_sync(
					USB_DEVH, 
					&control_req,
					data,
					&actlen,
					msg.usb_request_timeout,
					0) != 0)
		    {
			msg.msg_type_id = MSG_FAIL;
		    } else {
			msg.msg_type_id = MSG_OK;
		    	if (msg.usb_request_type & USB_REQTYPE_DIR_IN) {
				msg.msg_in_data_len = actlen;
			} else {
				msg.msg_out_data_len = actlen;
			}
		    }

		    if (write_client_msg(client_fd, &msg) < 0)
			return;
		    
		    if ((msg.usb_request_type & USB_REQTYPE_DIR_IN) && 
			msg.msg_in_data_len > 0)
		    {
			    if (write(client_fd, data, actlen) != actlen)
			    {
			    	warnx("Error writing control data");
			    	return;
			    }
		    }
		    break;

		case MSG_BULK_TRANSFER_OUT:
		    while (OUT_INFLIGHT) {
			usleep(INFLIGHT_SLEEP_USEC);
			libusb20_dev_process(USB_DEVH);
		    }
		    data = malloc(msg.msg_out_data_len);
		    if (read_socket(client_fd, 
					data,
					msg.msg_out_data_len) != 
						msg.msg_out_data_len)
		    {
			warnx("Error reading bulk-out data");
			return;
		    }
		    
		    if ( (txfer = libusb20_tr_get_pointer(
							USB_DEVH, 
							TR_OUT_IDX)) == 0) 
		    {
			warnx("Error obtaining OUT transfer buffer");
			return;
		    }

		    if (libusb20_tr_open(
				txfer, 8192, 1, msg.usb_endpoint_nr) != 0) {
			warnx("Error opening OUT transfer buffer");
			return;
		    }

		    OUT_INFLIGHT = 1;
		    libusb20_tr_setup_bulk(
				txfer, data, msg.msg_out_data_len, 0);
		    libusb20_tr_set_callback(txfer, transfer_out_cb);
		    libusb20_tr_set_priv_sc0(txfer, (void *)msg.msg_urb_ptr);
		    libusb20_tr_set_priv_sc1(txfer, data); 
		    libusb20_tr_start(txfer);

		    msg.msg_type_id = MSG_OK;
		    msg.msg_in_data_len = 0;

		    if (write_client_msg(client_fd, &msg) < 0)
			return;
		    break;

		case MSG_BULK_TRANSFER_IN:
		    while (IN_INFLIGHT) {
			usleep(INFLIGHT_SLEEP_USEC);
			libusb20_dev_process(USB_DEVH);
		    }
		    data = malloc(msg.msg_in_data_len);

		    if ( (txfer = libusb20_tr_get_pointer(
							USB_DEVH, 
							TR_IN_IDX)) == 0) 
		    {
			warnx("Error obtaining IN transfer buffer");
			return;
		    }
		
		    if (libusb20_tr_open(
				txfer, 8192, 1, msg.usb_endpoint_nr) != 0) {
			warnx("Error opening IN transfer buffer");
			return;
		    }

		    IN_INFLIGHT = 1;
		    libusb20_tr_setup_bulk(txfer, data, msg.msg_in_data_len, 0);
		    libusb20_tr_set_callback(txfer, transfer_in_cb);
		    libusb20_tr_set_priv_sc0(txfer, (void *)msg.msg_urb_ptr);
		    libusb20_tr_set_priv_sc1(txfer, data); 
		    libusb20_tr_start(txfer);

		    msg.msg_type_id = MSG_OK;
		    msg.msg_in_data_len = 0;

		    if (write_client_msg(client_fd, &msg) < 0)
			return;
		    break;

		case MSG_GET_TRANSFER_RESULT:
		    result = get_result();
		    msg.msg_in_data_len = 0;
		    msg.msg_out_data_len = 0;
		    if (result == 0) {
			msg.msg_type_id = MSG_PENDING;
		    } else {
			msg.msg_type_id = MSG_OK;
			msg.msg_urb_ptr = result->urb_ptr;
			msg.msg_urb_status = result->status;
			msg.msg_urb_len = result->actual_length;
			if (result->direction == USB_REQTYPE_DIR_IN) {
				msg.msg_in_data_len = result->actual_length;
			}
		    }

		    ecode = write_client_msg(client_fd, &msg);

		    if(ecode >= 0 && result != 0 && msg.msg_in_data_len > 0) 
		    {
		    	ecode = write(client_fd, 
					result->inout_data, 
					msg.msg_in_data_len);
			if (ecode != msg.msg_in_data_len)
				warnx("Error writing transfer data");
		    }

		    if (result != 0) {
			free(result->inout_data);
			free(result);
		    }

		    if (ecode < 0)
			return;
		    break;

		default:
		    warnx("Unknown client msg: %d", msg.msg_type_id);
		    return;
	    	}
	}
}


static void
service_client(int client_fd)
{
	STAILQ_INIT(&Transfers);
	if ( (USB_DEVH = allocate_usb_device()) != NULL)
	{
		client_loop(client_fd);
	} else {
		warnx("Error opening USB programmer device");
	}
	free_usb_device();
	clear_results();
}


int
main(int argc, char **argv)
{
	int ssfd = initialize_server_socket();
	while (1) {
		struct sockaddr_in addr;
		socklen_t len = sizeof(addr);
		int fd;
		if ( (fd = accept(ssfd, (struct sockaddr *)&addr, &len)) < 0)
			err(errno, "Error accepting client connection");
		service_client(fd);
		close(fd);
	}
}
