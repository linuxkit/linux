/* The program runs on Windows 10 or Windows Server 2016 host or newer. */

#include <stdio.h>
#include <stdint.h>
#include <winsock2.h>
#include <ws2def.h>
#include <initguid.h>
#include <rpc.h> /* for UuidFromStringA() */
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "rpcrt4.lib")

#ifndef AF_HYPERV
#define AF_HYPERV 34
#define HV_PROTOCOL_RAW 1

typedef struct _SOCKADDR_HV
{
	ADDRESS_FAMILY Family;
	USHORT Reserved;
	GUID VmId;
	GUID ServiceId;
}SOCKADDR_HV, *PSOCKADDR_HV;

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

int ConnectToVM(const SOCKADDR_HV *remoteAddr, SOCKET *result_fd)
{
	SOCKADDR_HV localAddr;
	SOCKET fd;
	uint32_t port;
	int ret;

	fd = socket(AF_HYPERV, SOCK_STREAM, HV_PROTOCOL_RAW);
	if (fd == INVALID_SOCKET) {
		printf("socket() failed with error: %d\n", WSAGetLastError());
		return -1;
	}

	ret = connect(fd, (SOCKADDR *)remoteAddr, sizeof(SOCKADDR_HV));
	if (ret == SOCKET_ERROR) {
		printf("connect() failed: error = %d\n", WSAGetLastError());
		closesocket(fd);
		return -1;
	}

	*result_fd = fd;
	printf("Connected to the VM: fd = 0x%x\n", fd);
	return 0;
}

int main()
{
	const char *msg = "***Hello! This message is from the host!***\n";
	WSADATA wsaData;
	SOCKADDR_HV remoteAddr;
	SOCKET fd;
	int ret;

	// Initialize Winsock
	ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (ret != NO_ERROR) {
		printf("WSAStartup() failed with error: %d\n", ret);
		return -1;
	}

	memset(&remoteAddr, 0, sizeof(SOCKADDR_HV));
	remoteAddr.Family = AF_HYPERV;

	// The Linux VM is listening in Vsock port 0x2017
	TryConvertVsockPortToServiceId(0x2017, &remoteAddr.ServiceId);

	// This is the "remote" VM's VMID got by the PowerShell command
	// "Get-VM -Name <the_VM_name> | ft id".
	//
	// Change it for your own VM.
	if (UuidFromStringA((RPC_CSTR)"c2624c46-1212-484a-8e28-83dd15fef815",
		&remoteAddr.VmId) != RPC_S_OK) {
		printf("Failed to parse the remote VMID: %d\n", GetLastError());
		ret = -1;
		goto out;
	}

	if (ConnectToVM(&remoteAddr, &fd) < 0) {
		printf("Failed to connect to the VM!\n");
		ret = -1;
		goto out;
	}
	ret = send(fd, msg, strlen(msg), 0);
	printf("Sent a msg to the VM: msg_len = %d.\nExited.\n", ret);

	closesocket(fd);
out:
	WSACleanup();
	return ret;
}
