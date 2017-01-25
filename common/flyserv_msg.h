#ifndef FLYSERV_MSG_H
#define FLYSERV_MSG_H	1

#include <sys/types.h>

typedef struct client_msg {
	uint64_t msg_urb_ptr;
	uint32_t msg_id;	
	uint32_t msg_urb_len;	
	int32_t  msg_urb_status;
	uint32_t msg_in_data_len;	
	uint32_t msg_out_data_len;	
	uint32_t usb_request_timeout;	
	uint16_t msg_type_id;		
	uint16_t usb_iface_nr;		
	uint16_t usb_altsetting_nr;	
	uint16_t usb_request_value;	
	uint16_t usb_request_index;	
	uint16_t usb_request_length;	
	uint8_t usb_request_type;	
	uint8_t usb_request_id;		
	uint8_t usb_endpoint_nr;	
	uint8_t msg_urb_dir;
} __attribute__((packed)) client_msg_t;

#define MSG_OK			0
#define MSG_FAIL		1
#define MSG_PENDING		2

#define MSG_CLAIM_INTERFACE	1
#define MSG_SET_INTERFACE	2
#define MSG_CONTROL		3
#define MSG_RELEASE_INTERFACE	4
#define MSG_CLEAR_HALT		5
#define MSG_BULK_TRANSFER_OUT	6
#define MSG_BULK_TRANSFER_IN	7
#define MSG_GET_TRANSFER_RESULT 8

#define USB_REQTYPE_DIR_IN	0x80

#endif
