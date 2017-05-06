/* The program runs in Linux VM. */

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>

int main()
{
	int fd;

	struct sockaddr_vm sa = {
		.svm_family = AF_VSOCK,
		.svm_reserved1 = 0,
		.svm_cid = VMADDR_CID_ANY,
	};

	/* Connecting to the host's 00000808-facb-11e6-bd58-64006a7986d3 */
	sa.svm_port = 0x808;

	fd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
		perror("connect");
		return -1;
	}

	printf("Connected to the host.\n");

	close(fd);
	printf("Closed the connection.\n");

	return 0;
}
