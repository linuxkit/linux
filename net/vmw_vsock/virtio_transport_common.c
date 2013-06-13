/*
 * common code for virtio vsock
 *
 * Copyright (C) 2013-2015 Red Hat, Inc.
 * Author: Asias He <asias@redhat.com>
 *         Stefan Hajnoczi <stefanha@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */
#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/list.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/virtio_vsock.h>

#include <net/sock.h>
#include <net/af_vsock.h>

#define CREATE_TRACE_POINTS
#include <trace/events/vsock_virtio_transport_common.h>

static const struct virtio_transport *virtio_transport_get_ops(void)
{
	const struct vsock_transport *t = vsock_core_get_transport();

	return container_of(t, struct virtio_transport, transport);
}

static int virtio_transport_send_pkt(struct vsock_sock *vsk,
				     struct virtio_vsock_pkt_info *info)
{
	return virtio_transport_get_ops()->send_pkt(vsk, info);
}

static int virtio_transport_send_pkt_no_sock(struct virtio_vsock_pkt *pkt)
{
	return virtio_transport_get_ops()->send_pkt_no_sock(pkt);
}

struct virtio_vsock_pkt *
virtio_transport_alloc_pkt(struct virtio_vsock_pkt_info *info,
			   size_t len,
			   u32 src_cid,
			   u32 src_port,
			   u32 dst_cid,
			   u32 dst_port)
{
	struct virtio_vsock_pkt *pkt;
	int err;

	pkt = kzalloc(sizeof(*pkt), GFP_KERNEL);
	if (!pkt)
		return NULL;

	pkt->hdr.type		= cpu_to_le16(info->type);
	pkt->hdr.op		= cpu_to_le16(info->op);
	pkt->hdr.src_cid	= cpu_to_le32(src_cid);
	pkt->hdr.src_port	= cpu_to_le32(src_port);
	pkt->hdr.dst_cid	= cpu_to_le32(dst_cid);
	pkt->hdr.dst_port	= cpu_to_le32(dst_port);
	pkt->hdr.flags		= cpu_to_le32(info->flags);
	pkt->len		= len;
	pkt->hdr.len		= cpu_to_le32(len);

	if (info->msg && len > 0) {
		pkt->buf = kmalloc(len, GFP_KERNEL);
		if (!pkt->buf)
			goto out_pkt;
		err = memcpy_from_msg(pkt->buf, info->msg, len);
		if (err)
			goto out;
	}

	trace_virtio_transport_alloc_pkt(src_cid, src_port,
					 dst_cid, dst_port,
					 len,
					 info->type,
					 info->op,
					 info->flags);

	return pkt;

out:
	kfree(pkt->buf);
out_pkt:
	kfree(pkt);
	return NULL;
}
EXPORT_SYMBOL_GPL(virtio_transport_alloc_pkt);

static void virtio_transport_inc_rx_pkt(struct virtio_vsock_sock *vvs,
					struct virtio_vsock_pkt *pkt)
{
	vvs->rx_bytes += pkt->len;
}

static void virtio_transport_dec_rx_pkt(struct virtio_vsock_sock *vvs,
					struct virtio_vsock_pkt *pkt)
{
	vvs->rx_bytes -= pkt->len;
	vvs->fwd_cnt += pkt->len;
}

void virtio_transport_inc_tx_pkt(struct virtio_vsock_sock *vvs, struct virtio_vsock_pkt *pkt)
{
	mutex_lock(&vvs->tx_lock);
	pkt->hdr.fwd_cnt = cpu_to_le32(vvs->fwd_cnt);
	pkt->hdr.buf_alloc = cpu_to_le32(vvs->buf_alloc);
	mutex_unlock(&vvs->tx_lock);
}
EXPORT_SYMBOL_GPL(virtio_transport_inc_tx_pkt);

u32 virtio_transport_get_credit(struct virtio_vsock_sock *vvs, u32 credit)
{
	u32 ret;

	mutex_lock(&vvs->tx_lock);
	ret = vvs->peer_buf_alloc - (vvs->tx_cnt - vvs->peer_fwd_cnt);
	if (ret > credit)
		ret = credit;
	vvs->tx_cnt += ret;
	mutex_unlock(&vvs->tx_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(virtio_transport_get_credit);

void virtio_transport_put_credit(struct virtio_vsock_sock *vvs, u32 credit)
{
	mutex_lock(&vvs->tx_lock);
	vvs->tx_cnt -= credit;
	mutex_unlock(&vvs->tx_lock);
}
EXPORT_SYMBOL_GPL(virtio_transport_put_credit);

static int virtio_transport_send_credit_update(struct vsock_sock *vsk,
					       int type,
					       struct virtio_vsock_hdr *hdr)
{
	struct virtio_vsock_pkt_info info = {
		.op = VIRTIO_VSOCK_OP_CREDIT_UPDATE,
		.type = type,
	};

	return virtio_transport_send_pkt(vsk, &info);
}

static ssize_t
virtio_transport_stream_do_dequeue(struct vsock_sock *vsk,
				   struct msghdr *msg,
				   size_t len)
{
	struct virtio_vsock_sock *vvs = vsk->trans;
	struct virtio_vsock_pkt *pkt;
	size_t bytes, total = 0;
	int err = -EFAULT;

	mutex_lock(&vvs->rx_lock);
	while (total < len &&
	       vvs->rx_bytes > 0 &&
	       !list_empty(&vvs->rx_queue)) {
		pkt = list_first_entry(&vvs->rx_queue,
				       struct virtio_vsock_pkt, list);

		bytes = len - total;
		if (bytes > pkt->len - pkt->off)
			bytes = pkt->len - pkt->off;

		err = memcpy_to_msg(msg, pkt->buf + pkt->off, bytes);
		if (err)
			goto out;
		total += bytes;
		pkt->off += bytes;
		if (pkt->off == pkt->len) {
			virtio_transport_dec_rx_pkt(vvs, pkt);
			list_del(&pkt->list);
			virtio_transport_free_pkt(pkt);
		}
	}
	mutex_unlock(&vvs->rx_lock);

	/* Send a credit pkt to peer */
	virtio_transport_send_credit_update(vsk, VIRTIO_VSOCK_TYPE_STREAM,
					    NULL);

	return total;

out:
	mutex_unlock(&vvs->rx_lock);
	if (total)
		err = total;
	return err;
}

ssize_t
virtio_transport_stream_dequeue(struct vsock_sock *vsk,
				struct msghdr *msg,
				size_t len, int flags)
{
	if (flags & MSG_PEEK)
		return -EOPNOTSUPP;

	return virtio_transport_stream_do_dequeue(vsk, msg, len);
}
EXPORT_SYMBOL_GPL(virtio_transport_stream_dequeue);

int
virtio_transport_dgram_dequeue(struct vsock_sock *vsk,
			       struct msghdr *msg,
			       size_t len, int flags)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL_GPL(virtio_transport_dgram_dequeue);

s64 virtio_transport_stream_has_data(struct vsock_sock *vsk)
{
	struct virtio_vsock_sock *vvs = vsk->trans;
	s64 bytes;

	mutex_lock(&vvs->rx_lock);
	bytes = vvs->rx_bytes;
	mutex_unlock(&vvs->rx_lock);

	return bytes;
}
EXPORT_SYMBOL_GPL(virtio_transport_stream_has_data);

static s64 virtio_transport_has_space(struct vsock_sock *vsk)
{
	struct virtio_vsock_sock *vvs = vsk->trans;
	s64 bytes;

	bytes = vvs->peer_buf_alloc - (vvs->tx_cnt - vvs->peer_fwd_cnt);
	if (bytes < 0)
		bytes = 0;

	return bytes;
}

s64 virtio_transport_stream_has_space(struct vsock_sock *vsk)
{
	struct virtio_vsock_sock *vvs = vsk->trans;
	s64 bytes;

	mutex_lock(&vvs->tx_lock);
	bytes = virtio_transport_has_space(vsk);
	mutex_unlock(&vvs->tx_lock);

	return bytes;
}
EXPORT_SYMBOL_GPL(virtio_transport_stream_has_space);

int virtio_transport_do_socket_init(struct vsock_sock *vsk,
				    struct vsock_sock *psk)
{
	struct virtio_vsock_sock *vvs;

	vvs = kzalloc(sizeof(*vvs), GFP_KERNEL);
	if (!vvs)
		return -ENOMEM;

	vsk->trans = vvs;
	vvs->vsk = vsk;
	if (psk) {
		struct virtio_vsock_sock *ptrans = psk->trans;

		vvs->buf_size	= ptrans->buf_size;
		vvs->buf_size_min = ptrans->buf_size_min;
		vvs->buf_size_max = ptrans->buf_size_max;
		vvs->peer_buf_alloc = ptrans->peer_buf_alloc;
	} else {
		vvs->buf_size = VIRTIO_VSOCK_DEFAULT_BUF_SIZE;
		vvs->buf_size_min = VIRTIO_VSOCK_DEFAULT_MIN_BUF_SIZE;
		vvs->buf_size_max = VIRTIO_VSOCK_DEFAULT_MAX_BUF_SIZE;
	}

	vvs->buf_alloc = vvs->buf_size;

	mutex_init(&vvs->rx_lock);
	mutex_init(&vvs->tx_lock);
	INIT_LIST_HEAD(&vvs->rx_queue);

	return 0;
}
EXPORT_SYMBOL_GPL(virtio_transport_do_socket_init);

u64 virtio_transport_get_buffer_size(struct vsock_sock *vsk)
{
	struct virtio_vsock_sock *vvs = vsk->trans;

	return vvs->buf_size;
}
EXPORT_SYMBOL_GPL(virtio_transport_get_buffer_size);

u64 virtio_transport_get_min_buffer_size(struct vsock_sock *vsk)
{
	struct virtio_vsock_sock *vvs = vsk->trans;

	return vvs->buf_size_min;
}
EXPORT_SYMBOL_GPL(virtio_transport_get_min_buffer_size);

u64 virtio_transport_get_max_buffer_size(struct vsock_sock *vsk)
{
	struct virtio_vsock_sock *vvs = vsk->trans;

	return vvs->buf_size_max;
}
EXPORT_SYMBOL_GPL(virtio_transport_get_max_buffer_size);

void virtio_transport_set_buffer_size(struct vsock_sock *vsk, u64 val)
{
	struct virtio_vsock_sock *vvs = vsk->trans;

	if (val > VIRTIO_VSOCK_MAX_BUF_SIZE)
		val = VIRTIO_VSOCK_MAX_BUF_SIZE;
	if (val < vvs->buf_size_min)
		vvs->buf_size_min = val;
	if (val > vvs->buf_size_max)
		vvs->buf_size_max = val;
	vvs->buf_size = val;
	vvs->buf_alloc = val;
}
EXPORT_SYMBOL_GPL(virtio_transport_set_buffer_size);

void virtio_transport_set_min_buffer_size(struct vsock_sock *vsk, u64 val)
{
	struct virtio_vsock_sock *vvs = vsk->trans;

	if (val > VIRTIO_VSOCK_MAX_BUF_SIZE)
		val = VIRTIO_VSOCK_MAX_BUF_SIZE;
	if (val > vvs->buf_size)
		vvs->buf_size = val;
	vvs->buf_size_min = val;
}
EXPORT_SYMBOL_GPL(virtio_transport_set_min_buffer_size);

void virtio_transport_set_max_buffer_size(struct vsock_sock *vsk, u64 val)
{
	struct virtio_vsock_sock *vvs = vsk->trans;

	if (val > VIRTIO_VSOCK_MAX_BUF_SIZE)
		val = VIRTIO_VSOCK_MAX_BUF_SIZE;
	if (val < vvs->buf_size)
		vvs->buf_size = val;
	vvs->buf_size_max = val;
}
EXPORT_SYMBOL_GPL(virtio_transport_set_max_buffer_size);

int
virtio_transport_notify_poll_in(struct vsock_sock *vsk,
				size_t target,
				bool *data_ready_now)
{
	if (vsock_stream_has_data(vsk))
		*data_ready_now = true;
	else
		*data_ready_now = false;

	return 0;
}
EXPORT_SYMBOL_GPL(virtio_transport_notify_poll_in);

int
virtio_transport_notify_poll_out(struct vsock_sock *vsk,
				 size_t target,
				 bool *space_avail_now)
{
	s64 free_space;

	free_space = vsock_stream_has_space(vsk);
	if (free_space > 0)
		*space_avail_now = true;
	else if (free_space == 0)
		*space_avail_now = false;

	return 0;
}
EXPORT_SYMBOL_GPL(virtio_transport_notify_poll_out);

int virtio_transport_notify_recv_init(struct vsock_sock *vsk,
	size_t target, struct vsock_transport_recv_notify_data *data)
{
	return 0;
}
EXPORT_SYMBOL_GPL(virtio_transport_notify_recv_init);

int virtio_transport_notify_recv_pre_block(struct vsock_sock *vsk,
	size_t target, struct vsock_transport_recv_notify_data *data)
{
	return 0;
}
EXPORT_SYMBOL_GPL(virtio_transport_notify_recv_pre_block);

int virtio_transport_notify_recv_pre_dequeue(struct vsock_sock *vsk,
	size_t target, struct vsock_transport_recv_notify_data *data)
{
	return 0;
}
EXPORT_SYMBOL_GPL(virtio_transport_notify_recv_pre_dequeue);

int virtio_transport_notify_recv_post_dequeue(struct vsock_sock *vsk,
	size_t target, ssize_t copied, bool data_read,
	struct vsock_transport_recv_notify_data *data)
{
	return 0;
}
EXPORT_SYMBOL_GPL(virtio_transport_notify_recv_post_dequeue);

int virtio_transport_notify_send_init(struct vsock_sock *vsk,
	struct vsock_transport_send_notify_data *data)
{
	return 0;
}
EXPORT_SYMBOL_GPL(virtio_transport_notify_send_init);

int virtio_transport_notify_send_pre_block(struct vsock_sock *vsk,
	struct vsock_transport_send_notify_data *data)
{
	return 0;
}
EXPORT_SYMBOL_GPL(virtio_transport_notify_send_pre_block);

int virtio_transport_notify_send_pre_enqueue(struct vsock_sock *vsk,
	struct vsock_transport_send_notify_data *data)
{
	return 0;
}
EXPORT_SYMBOL_GPL(virtio_transport_notify_send_pre_enqueue);

int virtio_transport_notify_send_post_enqueue(struct vsock_sock *vsk,
	ssize_t written, struct vsock_transport_send_notify_data *data)
{
	return 0;
}
EXPORT_SYMBOL_GPL(virtio_transport_notify_send_post_enqueue);

u64 virtio_transport_stream_rcvhiwat(struct vsock_sock *vsk)
{
	struct virtio_vsock_sock *vvs = vsk->trans;

	return vvs->buf_size;
}
EXPORT_SYMBOL_GPL(virtio_transport_stream_rcvhiwat);

bool virtio_transport_stream_is_active(struct vsock_sock *vsk)
{
	return true;
}
EXPORT_SYMBOL_GPL(virtio_transport_stream_is_active);

bool virtio_transport_stream_allow(u32 cid, u32 port)
{
	return true;
}
EXPORT_SYMBOL_GPL(virtio_transport_stream_allow);

int virtio_transport_dgram_bind(struct vsock_sock *vsk,
				struct sockaddr_vm *addr)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL_GPL(virtio_transport_dgram_bind);

bool virtio_transport_dgram_allow(u32 cid, u32 port)
{
	return false;
}
EXPORT_SYMBOL_GPL(virtio_transport_dgram_allow);

int virtio_transport_connect(struct vsock_sock *vsk)
{
	struct virtio_vsock_pkt_info info = {
		.op = VIRTIO_VSOCK_OP_REQUEST,
		.type = VIRTIO_VSOCK_TYPE_STREAM,
	};

	return virtio_transport_send_pkt(vsk, &info);
}
EXPORT_SYMBOL_GPL(virtio_transport_connect);

int virtio_transport_shutdown(struct vsock_sock *vsk, int mode)
{
	struct virtio_vsock_pkt_info info = {
		.op = VIRTIO_VSOCK_OP_SHUTDOWN,
		.type = VIRTIO_VSOCK_TYPE_STREAM,
		.flags = (mode & RCV_SHUTDOWN ?
			  VIRTIO_VSOCK_SHUTDOWN_RCV : 0) |
			 (mode & SEND_SHUTDOWN ?
			  VIRTIO_VSOCK_SHUTDOWN_SEND : 0),
	};

	return virtio_transport_send_pkt(vsk, &info);
}
EXPORT_SYMBOL_GPL(virtio_transport_shutdown);

void virtio_transport_release(struct vsock_sock *vsk)
{
	struct sock *sk = &vsk->sk;

	/* Tell other side to terminate connection */
	if (sk->sk_type == SOCK_STREAM &&
	    vsk->peer_shutdown != SHUTDOWN_MASK &&
	    sk->sk_state == SS_CONNECTED)
		(void)virtio_transport_shutdown(vsk, SHUTDOWN_MASK);
}
EXPORT_SYMBOL_GPL(virtio_transport_release);

int
virtio_transport_dgram_enqueue(struct vsock_sock *vsk,
			       struct sockaddr_vm *remote_addr,
			       struct msghdr *msg,
			       size_t dgram_len)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL_GPL(virtio_transport_dgram_enqueue);

ssize_t
virtio_transport_stream_enqueue(struct vsock_sock *vsk,
				struct msghdr *msg,
				size_t len)
{
	struct virtio_vsock_pkt_info info = {
		.op = VIRTIO_VSOCK_OP_RW,
		.type = VIRTIO_VSOCK_TYPE_STREAM,
		.msg = msg,
		.pkt_len = len,
	};

	return virtio_transport_send_pkt(vsk, &info);
}
EXPORT_SYMBOL_GPL(virtio_transport_stream_enqueue);

void virtio_transport_destruct(struct vsock_sock *vsk)
{
	struct virtio_vsock_sock *vvs = vsk->trans;

	kfree(vvs);
}
EXPORT_SYMBOL_GPL(virtio_transport_destruct);

static int virtio_transport_send_reset(struct vsock_sock *vsk,
				       struct virtio_vsock_pkt *pkt)
{
	struct virtio_vsock_pkt_info info = {
		.op = VIRTIO_VSOCK_OP_RST,
		.type = VIRTIO_VSOCK_TYPE_STREAM,
	};

	/* Send RST only if the original pkt is not a RST pkt */
	if (le16_to_cpu(pkt->hdr.op) == VIRTIO_VSOCK_OP_RST)
		return 0;

	return virtio_transport_send_pkt(vsk, &info);
}

/* Normally packets are associated with a socket.  There may be no socket if an
 * attempt was made to connect to a socket that does not exist.
 */
static int virtio_transport_send_reset_no_sock(struct virtio_vsock_pkt *pkt)
{
	struct virtio_vsock_pkt_info info = {
		.op = VIRTIO_VSOCK_OP_RST,
		.type = le16_to_cpu(pkt->hdr.type),
	};

	/* Send RST only if the original pkt is not a RST pkt */
	if (le16_to_cpu(pkt->hdr.op) == VIRTIO_VSOCK_OP_RST)
		return 0;

	pkt = virtio_transport_alloc_pkt(&info, 0,
					 le32_to_cpu(pkt->hdr.dst_cid),
					 le32_to_cpu(pkt->hdr.dst_port),
					 le32_to_cpu(pkt->hdr.src_cid),
					 le32_to_cpu(pkt->hdr.src_port));
	if (!pkt)
		return -ENOMEM;

	return virtio_transport_send_pkt_no_sock(pkt);
}

static int
virtio_transport_recv_connecting(struct sock *sk,
				 struct virtio_vsock_pkt *pkt)
{
	struct vsock_sock *vsk = vsock_sk(sk);
	int err;
	int skerr;

	switch (le16_to_cpu(pkt->hdr.op)) {
	case VIRTIO_VSOCK_OP_RESPONSE:
		sk->sk_state = SS_CONNECTED;
		sk->sk_socket->state = SS_CONNECTED;
		vsock_insert_connected(vsk);
		sk->sk_state_change(sk);
		break;
	case VIRTIO_VSOCK_OP_INVALID:
		break;
	case VIRTIO_VSOCK_OP_RST:
		skerr = ECONNRESET;
		err = 0;
		goto destroy;
	default:
		skerr = EPROTO;
		err = -EINVAL;
		goto destroy;
	}
	return 0;

destroy:
	virtio_transport_send_reset(vsk, pkt);
	sk->sk_state = SS_UNCONNECTED;
	sk->sk_err = skerr;
	sk->sk_error_report(sk);
	return err;
}

static int
virtio_transport_recv_connected(struct sock *sk,
				struct virtio_vsock_pkt *pkt)
{
	struct vsock_sock *vsk = vsock_sk(sk);
	struct virtio_vsock_sock *vvs = vsk->trans;
	int err = 0;

	switch (le16_to_cpu(pkt->hdr.op)) {
	case VIRTIO_VSOCK_OP_RW:
		pkt->len = le32_to_cpu(pkt->hdr.len);
		pkt->off = 0;

		mutex_lock(&vvs->rx_lock);
		virtio_transport_inc_rx_pkt(vvs, pkt);
		list_add_tail(&pkt->list, &vvs->rx_queue);
		mutex_unlock(&vvs->rx_lock);

		sk->sk_data_ready(sk);
		return err;
	case VIRTIO_VSOCK_OP_CREDIT_UPDATE:
		sk->sk_write_space(sk);
		break;
	case VIRTIO_VSOCK_OP_SHUTDOWN:
		if (le32_to_cpu(pkt->hdr.flags) & VIRTIO_VSOCK_SHUTDOWN_RCV)
			vsk->peer_shutdown |= RCV_SHUTDOWN;
		if (le32_to_cpu(pkt->hdr.flags) & VIRTIO_VSOCK_SHUTDOWN_SEND)
			vsk->peer_shutdown |= SEND_SHUTDOWN;
		if (vsk->peer_shutdown == SHUTDOWN_MASK &&
		    vsock_stream_has_data(vsk) <= 0)
			sk->sk_state = SS_DISCONNECTING;
		if (le32_to_cpu(pkt->hdr.flags))
			sk->sk_state_change(sk);
		break;
	case VIRTIO_VSOCK_OP_RST:
		sock_set_flag(sk, SOCK_DONE);
		vsk->peer_shutdown = SHUTDOWN_MASK;
		if (vsock_stream_has_data(vsk) <= 0)
			sk->sk_state = SS_DISCONNECTING;
		sk->sk_state_change(sk);
		break;
	default:
		err = -EINVAL;
		break;
	}

	virtio_transport_free_pkt(pkt);
	return err;
}

static int
virtio_transport_send_response(struct vsock_sock *vsk,
			       struct virtio_vsock_pkt *pkt)
{
	struct virtio_vsock_pkt_info info = {
		.op = VIRTIO_VSOCK_OP_RESPONSE,
		.type = VIRTIO_VSOCK_TYPE_STREAM,
		.remote_cid = le32_to_cpu(pkt->hdr.src_cid),
		.remote_port = le32_to_cpu(pkt->hdr.src_port),
	};

	return virtio_transport_send_pkt(vsk, &info);
}

/* Handle server socket */
static int
virtio_transport_recv_listen(struct sock *sk, struct virtio_vsock_pkt *pkt)
{
	struct vsock_sock *vsk = vsock_sk(sk);
	struct vsock_sock *vchild;
	struct sock *child;

	if (le16_to_cpu(pkt->hdr.op) != VIRTIO_VSOCK_OP_REQUEST) {
		virtio_transport_send_reset(vsk, pkt);
		return -EINVAL;
	}

	if (sk_acceptq_is_full(sk)) {
		virtio_transport_send_reset(vsk, pkt);
		return -ENOMEM;
	}

	child = __vsock_create(sock_net(sk), NULL, sk, GFP_KERNEL,
			       sk->sk_type, 0);
	if (!child) {
		virtio_transport_send_reset(vsk, pkt);
		return -ENOMEM;
	}

	sk->sk_ack_backlog++;

	lock_sock(child);

	child->sk_state = SS_CONNECTED;

	vchild = vsock_sk(child);
	vsock_addr_init(&vchild->local_addr, le32_to_cpu(pkt->hdr.dst_cid),
			le32_to_cpu(pkt->hdr.dst_port));
	vsock_addr_init(&vchild->remote_addr, le32_to_cpu(pkt->hdr.src_cid),
			le32_to_cpu(pkt->hdr.src_port));

	vsock_insert_connected(vchild);
	vsock_enqueue_accept(sk, child);
	virtio_transport_send_response(vchild, pkt);

	release_sock(child);

	sk->sk_data_ready(sk);
	return 0;
}

static void virtio_transport_space_update(struct sock *sk,
					  struct virtio_vsock_pkt *pkt)
{
	struct vsock_sock *vsk = vsock_sk(sk);
	struct virtio_vsock_sock *vvs = vsk->trans;
	bool space_available;

	/* buf_alloc and fwd_cnt is always included in the hdr */
	mutex_lock(&vvs->tx_lock);
	vvs->peer_buf_alloc = le32_to_cpu(pkt->hdr.buf_alloc);
	vvs->peer_fwd_cnt = le32_to_cpu(pkt->hdr.fwd_cnt);
	space_available = virtio_transport_has_space(vsk);
	mutex_unlock(&vvs->tx_lock);

	if (space_available)
		sk->sk_write_space(sk);
}

/* We are under the virtio-vsock's vsock->rx_lock or vhost-vsock's vq->mutex
 * lock.
 */
void virtio_transport_recv_pkt(struct virtio_vsock_pkt *pkt)
{
	struct sockaddr_vm src, dst;
	struct vsock_sock *vsk;
	struct sock *sk;

	vsock_addr_init(&src, le32_to_cpu(pkt->hdr.src_cid),
			le32_to_cpu(pkt->hdr.src_port));
	vsock_addr_init(&dst, le32_to_cpu(pkt->hdr.dst_cid),
			le32_to_cpu(pkt->hdr.dst_port));

	trace_virtio_transport_recv_pkt(src.svm_cid, src.svm_port,
					dst.svm_cid, dst.svm_port,
					le32_to_cpu(pkt->hdr.len),
					le16_to_cpu(pkt->hdr.type),
					le16_to_cpu(pkt->hdr.op),
					le32_to_cpu(pkt->hdr.flags),
					le32_to_cpu(pkt->hdr.buf_alloc),
					le32_to_cpu(pkt->hdr.fwd_cnt));

	if (le16_to_cpu(pkt->hdr.type) != VIRTIO_VSOCK_TYPE_STREAM) {
		(void)virtio_transport_send_reset_no_sock(pkt);
		goto free_pkt;
	}

	/* The socket must be in connected or bound table
	 * otherwise send reset back
	 */
	sk = vsock_find_connected_socket(&src, &dst);
	if (!sk) {
		sk = vsock_find_bound_socket(&dst);
		if (!sk) {
			(void)virtio_transport_send_reset_no_sock(pkt);
			goto free_pkt;
		}
	}

	vsk = vsock_sk(sk);

	virtio_transport_space_update(sk, pkt);

	lock_sock(sk);

	/* Update CID in case it has changed after a transport reset event */
	vsk->local_addr.svm_cid = dst.svm_cid;

	switch (sk->sk_state) {
	case VSOCK_SS_LISTEN:
		virtio_transport_recv_listen(sk, pkt);
		virtio_transport_free_pkt(pkt);
		break;
	case SS_CONNECTING:
		virtio_transport_recv_connecting(sk, pkt);
		virtio_transport_free_pkt(pkt);
		break;
	case SS_CONNECTED:
		virtio_transport_recv_connected(sk, pkt);
		break;
	default:
		virtio_transport_free_pkt(pkt);
		break;
	}
	release_sock(sk);

	/* Release refcnt obtained when we fetched this socket out of the
	 * bound or connected list.
	 */
	sock_put(sk);
	return;

free_pkt:
	virtio_transport_free_pkt(pkt);
}
EXPORT_SYMBOL_GPL(virtio_transport_recv_pkt);

void virtio_transport_free_pkt(struct virtio_vsock_pkt *pkt)
{
	kfree(pkt->buf);
	kfree(pkt);
}
EXPORT_SYMBOL_GPL(virtio_transport_free_pkt);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Asias He");
MODULE_DESCRIPTION("common code for virtio vsock");
