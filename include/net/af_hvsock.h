#ifndef __AF_HVSOCK_H__
#define __AF_HVSOCK_H__

#include <linux/kernel.h>
#include <linux/hyperv.h>
#include <net/sock.h>

/* The host side's design of the feature requires 5 exact 4KB pages for
 * recv/send rings respectively -- this is suboptimal considering memory
 * consumption, however unluckily we have to live with it, before the
 * host comes up with a better design in the future.
 */
#define PAGE_SIZE_4K		4096
#define RINGBUFFER_HVSOCK_RCV_SIZE (PAGE_SIZE_4K * 5)
#define RINGBUFFER_HVSOCK_SND_SIZE (PAGE_SIZE_4K * 5)

/* The MTU is 16KB per the host side's design.
 * In future, the buffer can be elimiated when we switch to use the coming
 * new VMBus ringbuffer "in-place consumption" APIs, by which we can
 * directly copy data from VMBus ringbuffer into the userspace buffer.
 */
#define HVSOCK_MTU_SIZE		(1024 * 16)
struct hvsock_recv_buf {
	unsigned int data_len;
	unsigned int data_offset;

	struct vmpipe_proto_header hdr;
	u8 buf[HVSOCK_MTU_SIZE];
};

/* In the VM, actually we can send up to HVSOCK_MTU_SIZE bytes of payload,
 * but for now let's use a smaller size to minimize the dynamically-allocated
 * buffer. Note: the buffer can be elimiated in future when we add new VMBus
 * ringbuffer APIs that allow us to directly copy data from userspace buf to
 * VMBus ringbuffer.
 */
#define HVSOCK_MAX_SND_SIZE_BY_VM (1024 * 4)
struct hvsock_send_buf {
	struct vmpipe_proto_header hdr;
	u8 buf[HVSOCK_MAX_SND_SIZE_BY_VM];
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

static inline struct hvsock_sock *sk_to_hvsock(struct sock *sk)
{
	return (struct hvsock_sock *)sk;
}

static inline struct sock *hvsock_to_sk(struct hvsock_sock *hvsk)
{
	return (struct sock *)hvsk;
}

#endif /* __AF_HVSOCK_H__ */
