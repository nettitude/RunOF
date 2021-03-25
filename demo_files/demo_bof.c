#include <windows.h>
#include "beacon.h"

void go(char * args, int alen) {
	DWORD nSize = MAX_COMPUTERNAME_LENGTH + 1;
	char buffer[MAX_COMPUTERNAME_LENGTH+1];

	BeaconPrintf(CALLBACK_OUTPUT, "Hello World");

	BOOL res = GetComputerNameA(buffer, &nSize);

	if (!res) {
		BeaconPrintf(CALLBACK_ERROR, "Unable to run GetComputerNameA");
		return;
	}

	BeaconPrintf(CALLBACK_OUTPUT, "Hostname: %s", buffer);

}
