/* The program runs on Windows 10 or Windows Server 2016 host or newer. */

#include <stdio.h>
#include <stdint.h>
#include <winsock2.h>
#include <ws2def.h>
#include <initguid.h>

#pragma comment(lib, "ws2_32.lib")

#ifndef AF_HYPERV
#define AF_HYPERV 34
#define HV_PROTOCOL_RAW 1

typedef struct _SOCKADDR_HV
{
	ADDRESS_FAMILY Family;
	USHORT Reserved;
	GUID VmId;
	GUID ServiceId;
} SOCKADDR_HV, *PSOCKADDR_HV;

DEFINE_GUID(HV_GUID_SELF, 0x00000000, 0x0000, 0x0000,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
#endif /* AF_HYPERV */

#define VMADDR_PORT_ANY 0xFFFFFFFF

/* 00000000-facb-11e6-bd58-64006a7986d3 */
DEFINE_GUID(HVSOCK_LINUX_TEMPLATE, 0x00000000, 0xfacb, 0x11e6,
			0xbd, 0x58, 0x64, 0x00, 0x6a, 0x79, 0x86, 0xd3);

static const GUID VsockServiceIdTemplate = HVSOCK_LINUX_TEMPLATE;

bool TryConvertVsockPortToServiceId(uint32_t port, GUID *serviceId)
{
	if (port == VMADDR_PORT_ANY)
		return false;

	*serviceId = VsockServiceIdTemplate;
	serviceId->Data1 = port;
	return true;
}

bool TryConvertServiceIdToVsockPort(const GUID *serviceId, uint32_t *port)
{
	if (memcmp(&serviceId->Data2, &VsockServiceIdTemplate.Data2,
		sizeof(GUID) - sizeof(uint32_t)) != 0 ||
		serviceId->Data1 == VMADDR_PORT_ANY) {
		return false;
	}

	*port = serviceId->Data1;
	return true;
}

int CreateListenSocket(uint32_t port, SOCKET *result_fd)
{
	SOCKADDR_HV localAddr;
	SOCKET fd;
	int ret;

	fd = socket(AF_HYPERV, SOCK_STREAM, HV_PROTOCOL_RAW);
	if (fd == INVALID_SOCKET) {
		printf("socket() failed: error = %d\n", WSAGetLastError());
		return -1;
	}

	memset(&localAddr, 0, sizeof(SOCKADDR_HV));
	localAddr.Family = AF_HYPERV;
	localAddr.VmId = HV_GUID_SELF;
	TryConvertVsockPortToServiceId(port, &localAddr.ServiceId);

	ret = bind(fd, (SOCKADDR *)&localAddr, sizeof(SOCKADDR_HV));
	if (ret == SOCKET_ERROR) {
		printf("bind() failed: error = %d\n", WSAGetLastError());
		goto err;
	}

	ret = listen(fd, 10);
	if (ret == SOCKET_ERROR) {
		printf("listen() failed: error = %d\n", WSAGetLastError());
		goto err;
	}

	*result_fd = fd;
	printf("Listening on fd = 0x%d, local port = 0x%x\n", fd, port);
	return 0;
err:
	closesocket(fd);
	return -1;
}

int main()
{
	WSADATA wsaData;
	SOCKADDR_HV remoteAddr;
	int remoteAddrLen;
	SOCKET fd;
	SOCKET children[100];
	int i, ret;

	// Initialize Winsock
	ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (ret != NO_ERROR) {
		printf("WSAStartup() failed with error: %d\n", ret);
		return -1;
	}

	// We'll listen on 00000808-facb-11e6-bd58-64006a7986d3
	if (CreateListenSocket(0x808, &fd) < 0) {
		printf("failed to listen!\n");
		ret = -1;
		goto out;
	}

	for (i = 0; i < ARRAYSIZE(children); i++) {
		remoteAddrLen = sizeof(SOCKADDR_HV);
		children[i] = accept(fd, (sockaddr *)&remoteAddr, &remoteAddrLen);
		closesocket(children[i]);
		printf("Got a connection and closed it.\n");
	}

	closesocket(fd);
out:
	WSACleanup();
	return ret;
}
