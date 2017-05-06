/* The program runs in Linux VM. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <linux/vm_sockets.h>

int main()
{
	uint32_t port = 0x2017;

	int listen_fd;
	int client_fd;

	struct sockaddr_vm sa_listen = {
		.svm_family = AF_VSOCK,
		.svm_reserved1 = 0,
		.svm_cid = VMADDR_CID_ANY,
	};

	struct sockaddr_vm sa_client;
	socklen_t socklen_client;

	char buf[4096];
	int len;

	/* We'll listen on 00002017-facb-11e6-bd58-64006a7986d3 */
	sa_listen.svm_port = port;

	listen_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		perror("socket()");
		exit(-1);
	}

	if (bind(listen_fd, (struct sockaddr *)&sa_listen,
		 sizeof(sa_listen)) != 0) {
		perror("bind()");
		goto err;
	}

	if (listen(listen_fd, 10) != 0) {
		perror("listen()");
		goto err;
	}

	printf("Listening on port 0x%x...\n", port);

	socklen_client = sizeof(sa_client);
	client_fd = accept(listen_fd, (struct sockaddr*)&sa_client,
			   &socklen_client);
	if (client_fd < 0) {
		perror("accept()");
		goto err;
	}

	printf("Got a connection from the host: cid=0x%x, port=0x%x.\n",
		sa_client.svm_cid, sa_client.svm_port);

	do {
		printf("Reading data from the connection...\n");
		len = read(client_fd, buf, sizeof(buf));
		if (len > 0) {
			printf("Read %d bytes:\n", len);
			fflush(stdout);
			write(STDOUT_FILENO, buf, len);
		}
	} while (len > 0);

	printf("The other end closed the connection.\n");

	close(client_fd);
	close(listen_fd);
	return 0;
err:
	close(listen_fd);
	return -1;
}
