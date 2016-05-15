#ifndef __AF_HVSOCK_H__
#define __AF_HVSOCK_H__

#include <linux/kernel.h>
#include <linux/hyperv.h>
#include <net/sock.h>

/* Note: 3-page is the minimal recv ringbuffer size by default:
 *
 * the 1st page is used as the shared read/write index etc, rather than data:
 * see hv_ringbuffer_init();
 *
 * the payload length in the vmbus pipe message received from the host can
 * be 4096 bytes, and considing the header of HVSOCK_HEADER_LEN bytes, we
 * need at least 2 extra pages for ringbuffer data.
 */
#define HVSOCK_RCV_BUF_SZ    PAGE_SIZE
#define DEF_RINGBUFFER_PAGES_HVSOCK_RCV 3

/* As to send, here let's make sure the hvsock_send_buf struct can be held in 1
 * page, and since we want to use 2 pages for the send ringbuffer size (this is
 * the minimal size by default, because the 1st page of the two is used as the
 * shared read/write index etc, rather than data), we only have 1 page for
 * ringbuffer data, this means: the max payload length for hvsock data is
 * PAGE_SIZE - HVSOCK_PKT_LEN(0). And, let's reduce the length by 8-bytes
 * because the ringbuffer can't be 100% full: see hv_ringbuffer_write().
 */
#define HVSOCK_SND_BUF_SZ    (PAGE_SIZE - HVSOCK_PKT_LEN(0) - 8)
#define DEF_RINGBUFFER_PAGES_HVSOCK_SND 2

/* We only send data when the available space is "big enough". This artificial
 * value must be less than HVSOCK_SND_BUF_SZ.
 *
 */
#define HVSOCK_SND_THRESHOLD (PAGE_SIZE / 2)

#define sk_to_hvsock(__sk)   ((struct hvsock_sock *)(__sk))
#define hvsock_to_sk(__hvsk) ((struct sock *)(__hvsk))

struct hvsock_send_buf {
	struct vmpipe_proto_header hdr;
	u8 buf[HVSOCK_SND_BUF_SZ];
};

struct hvsock_recv_buf {
	struct vmpipe_proto_header hdr;
	u8 buf[HVSOCK_RCV_BUF_SZ];

	unsigned int data_len;
	unsigned int data_offset;
};

struct hvsock_sock {
	/* sk must be the first member. */
	struct sock sk;

	struct sockaddr_hv local_addr;
	struct sockaddr_hv remote_addr;

	/* protected by the global hvsock_mutex */
	struct list_head bound_list;
	struct list_head connected_list;

	struct list_head accept_queue;
	/* used by enqueue and dequeue */
	struct mutex accept_queue_mutex;

	struct delayed_work dwork;

	u32 peer_shutdown;

	struct vmbus_channel *channel;

	struct hvsock_send_buf *send;
	struct hvsock_recv_buf *recv;
};

#endif /* __AF_HVSOCK_H__ */
