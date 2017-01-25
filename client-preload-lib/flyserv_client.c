#include <dlfcn.h>
#include <err.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdarg.h>

#include "/usr/include/asm/ioctl.h"
#include "/usr/include/linux/usbdevice_fs.h"

#include "flyserv_msg.h"

static void
print_urb(const char *fn, struct usbdevfs_urb *urb)
{
		printf("**%s: type: %u, endpoint %u, status %d, "
		       "flags %u, buffer %p, buflen %d, "
		       "actlen %d, start_frame %d, "
		       "errcount %d, signr %u, uctxt %p\n",
		       fn,
		       (unsigned int)urb->type,
		       (unsigned int)urb->endpoint,
		       (int)urb->status,
		       (unsigned int)urb->flags, 
		       urb->buffer,
		       (int)urb->buffer_length,
		       (int)urb->actual_length,
		       (int)urb->start_frame,
		       (int)urb->error_count,
		       (unsigned int)urb->signr,
		       urb->usercontext);
}

static void *LIBC_HANDLE = 0;
static int CLIENT_SOCKET = -1;
static int EMU_FD = 1048576;

typedef int (*fun_open_t)(const char*, int flags, ...);
fun_open_t FUN_OPEN = 0;

typedef int (*fun_ioctl_t)(int fd, unsigned int request, ...);
fun_ioctl_t FUN_IOCTL = 0;


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

static void
initialize_usb_client()
{
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(getenv_int("FLY_SERVER_PORT"));
	memset(&sa.sin_addr, 0, sizeof(sa.sin_addr));
	if (inet_pton(AF_INET, getenv_string("FLY_SERVER_ADDR"),
			&sa.sin_addr) != 1)
		err(1, "Invalid server address");
	if ( (CLIENT_SOCKET = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		err(1, "Error creating TCP socket");
	if (connect(CLIENT_SOCKET, (struct sockaddr *)&sa, sizeof(sa)) != 0)
		err(errno, "Error connecting to server");
}


__attribute__((constructor))
static void
_LIB_CONSTRUCTOR()
{ 
	const char *emsg;

	srand(time(0));

	/* Open handle to libc */
	if ( (LIBC_HANDLE = dlopen("/lib64/libc.so.6", RTLD_LAZY)) == 0)
		err(1, "Error opening libc.so.6");

	dlerror();
	FUN_OPEN = dlsym(LIBC_HANDLE, "open64");
	if ( (emsg = dlerror()) != NULL)
		err(1, "open64: DLSYM error");

	FUN_IOCTL = dlsym(LIBC_HANDLE, "ioctl");
	if ( (emsg = dlerror()) != NULL)
		err(1, "ioctl: DLSYM error");

	/* Open connection to USB server */
	initialize_usb_client();
}


int open64(const char *pathname, int flags, ...)
{
	int mode = 0;	

	if (strcmp(pathname, getenv_string("FLY_USB_DEVICE")) == 0) {
		//printf("**Device Opened\n");
		return EMU_FD;
	}

	if (flags & O_CREAT) {
      		va_list arg;
      		va_start(arg, flags);
      		mode = va_arg(arg, int);
      		va_end(arg);
    	}

	int rv = (*FUN_OPEN)(pathname, flags, mode);
	return rv;
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


static int
do_sync_client_request(
		client_msg_t *cmsg, 
		void *data_out, int data_out_len,
		void *data_in, int data_in_len)
{
	int msgid = cmsg->msg_id;

	if (write(CLIENT_SOCKET, cmsg, sizeof(*cmsg)) != sizeof(*cmsg))
		err(1, "Error transmitting to server: message");

	if (data_out && data_out_len > 0)
	{
   	    if (write(CLIENT_SOCKET, data_out, data_out_len) != data_out_len)
		err(1, "Error transmitting to server: message data out");
	}

	if (read_socket(CLIENT_SOCKET, cmsg, sizeof(*cmsg)) != sizeof(*cmsg))
		err(1, "Error receiving server reply: message");

	if (cmsg->msg_id != msgid)
		err(1, "Protocol failure: invalid reply message id");

	if (cmsg->msg_type_id == MSG_FAIL) {
		warnx("Request Error: %u", cmsg->msg_id);
		return -1;
	}

	if (cmsg->msg_in_data_len > 0) {
		if (!data_in || data_in_len <= 0)
			err(1, "Protocol failure: reply data not handled");

		int read_len = (cmsg->msg_in_data_len > data_in_len ?
					data_in_len :
					cmsg->msg_in_data_len);

		if (read_socket(CLIENT_SOCKET, 
				data_in, 
				read_len) != read_len)
			err(1, "Error receiving server reply: message data in");
	}

	return 0;
}

#define MAX_RESULT_SIZE	4096
char RESULT[MAX_RESULT_SIZE];


int ioctl(
	int fd,
	unsigned int request,
	...)
{
	void *arg;
	struct usbdevfs_setinterface *seti;
	struct usbdevfs_ctrltransfer *cxfer;
	struct usbdevfs_urb *urb;
	struct usbdevfs_urb **urb_result;
	client_msg_t cmsg;

	va_list ap;
	va_start(ap, request);
	arg = va_arg(ap, void *);
	va_end(ap);

	if (fd != EMU_FD)
		return (*FUN_IOCTL)(fd, request, arg);

	int retval = -1;
	memset(&cmsg, 0, sizeof(cmsg));
	cmsg.msg_id = rand();

	//printf("**IOCTL %u\n", request);
	
	switch(request) {
	case USBDEVFS_RESETEP:
		retval = 0;
		break;
	case USBDEVFS_CLEAR_HALT: 
		cmsg.msg_type_id = MSG_CLEAR_HALT;
		cmsg.usb_endpoint_nr = *(unsigned char*)arg;
		retval = do_sync_client_request(&cmsg, 0, 0, 0, 0);
		break;
	case USBDEVFS_CLAIMINTERFACE:
		cmsg.msg_type_id = MSG_CLAIM_INTERFACE;
		cmsg.usb_iface_nr = *(unsigned int*)arg;
		retval = do_sync_client_request(&cmsg, 0, 0, 0, 0);
		break;
	case USBDEVFS_RELEASEINTERFACE:
		cmsg.msg_type_id = MSG_RELEASE_INTERFACE;
		cmsg.usb_iface_nr = *(unsigned int*)arg;
		retval = do_sync_client_request(&cmsg, 0, 0, 0, 0);
		break;
	case USBDEVFS_SETINTERFACE:
		seti = (struct usbdevfs_setinterface*)arg;
		cmsg.msg_type_id = MSG_SET_INTERFACE;
		cmsg.usb_iface_nr = seti->interface;
		cmsg.usb_altsetting_nr = seti->altsetting;
		retval = do_sync_client_request(&cmsg, 0, 0, 0, 0);
		break;
	case USBDEVFS_CONTROL:
		cxfer = (struct usbdevfs_ctrltransfer*)arg;
		/*printf("** CTRL: %u %u %u\n",
			(unsigned int)cxfer->bRequest,
			(unsigned int)cxfer->bRequestType,
			(unsigned int)cxfer->wIndex);*/
		cmsg.msg_type_id = MSG_CONTROL; 
		cmsg.usb_request_type = cxfer->bRequestType;
		cmsg.usb_request_id = cxfer->bRequest;
		cmsg.usb_request_value =  cxfer->wValue;
		cmsg.usb_request_index = cxfer->wIndex;
		cmsg.usb_request_length = cxfer->wLength;
		cmsg.usb_request_timeout = cxfer->timeout;
		if (cmsg.usb_request_type & USB_REQTYPE_DIR_IN) {
			retval = do_sync_client_request(&cmsg, 
						0, 0,
						cxfer->data, 
						cxfer->wLength);
			if (retval == 0)
				retval = cmsg.msg_in_data_len;
		} else {
			retval = do_sync_client_request(&cmsg, 
						cxfer->data, 
						cxfer->wLength, 
						0, 0);
			if (retval == 0)
				retval = cmsg.msg_out_data_len;
		}
		break;


	case USBDEVFS_SUBMITURB:
		urb = (struct usbdevfs_urb*)arg;
		//print_urb("SUBMITURB", urb);
		if (urb->type != 3) {
			errx(1, "Un-handled USB SUBMIT URB (Non Bulk)");
		}

		cmsg.usb_endpoint_nr = urb->endpoint;
		cmsg.msg_urb_ptr= (uint64_t) urb;

		if (urb->endpoint & USB_REQTYPE_DIR_IN) {
			cmsg.msg_type_id = MSG_BULK_TRANSFER_IN; 
			cmsg.msg_in_data_len = urb->buffer_length; 
			retval = do_sync_client_request(&cmsg, 0, 0, 0, 0);
		} else {
			cmsg.msg_type_id = MSG_BULK_TRANSFER_OUT; 
			cmsg.msg_out_data_len = urb->buffer_length; 
			retval = do_sync_client_request(&cmsg, 
							urb->buffer,
							urb->buffer_length,
							0, 0);
		}
		break;

	case USBDEVFS_REAPURBNDELAY:
		urb_result = (struct usbdevfs_urb**)arg;
		cmsg.msg_type_id = MSG_GET_TRANSFER_RESULT;
		retval = do_sync_client_request(&cmsg, 0, 0, 
					RESULT, MAX_RESULT_SIZE);

		if (cmsg.msg_type_id == MSG_OK && cmsg.msg_urb_status == 0) {
			urb = (struct usbdevfs_urb *)cmsg.msg_urb_ptr;
			urb->actual_length = cmsg.msg_urb_len;
			urb->status = cmsg.msg_urb_status;
			if (urb->endpoint & USB_REQTYPE_DIR_IN) {
				memcpy(urb->buffer, RESULT, 
					cmsg.msg_in_data_len);
			}
			*urb_result = urb;
			retval = 0;
			//print_urb("REAPURB", urb);
		} else if (cmsg.msg_type_id == MSG_PENDING) {
			//printf("***PENDING\n");
			errno = EAGAIN;
			retval = -1;
		} else {
			errno = EIO;
			retval = -1;
		}
		break;

	default:
		errx(1, "**IOCTL NOT Implemented: %u", request);
		break;
	}
	usleep(10000);
	return retval;
}

