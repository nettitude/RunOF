#include <windows.h>
#include <stdio.h>
#include "beacon_funcs.h"


void BeaconPrintf(int type, char *fmt, ...) {
        switch (type) {
                // from beacon.h
                case 0x0:
                        MSVCRT$printf("\tCALLBACK_OUTPUT\n");
                        break;
                case 0x1e:
                        MSVCRT$printf("\tCALLBACK_OUTPUT_OEM\n");
                        break;
                case 0x0d:
                        MSVCRT$printf("\tCALLBACK_ERROR\n");
                        break;
                case 0x20:
                        MSVCRT$printf("\tCALLBACK_OUTPUT_UTF8\n");
                        break;
                default:
                        MSVCRT$printf("\tUnknown type...%d\n", type);
                        break;
        }
        va_list argp;
        va_start(argp, fmt);
	MSVCRT$vsnprintf(global_buffer, global_buffer_maxlen, fmt, argp);
        MSVCRT$vprintf(fmt, argp);
        va_end(argp);
	return;
};

void BeaconOutput(int type, char *data, int len) {
	MSVCRT$puts("in BeaconOutput\n");
	
	if (len > global_buffer_maxlen) {
		MSVCRT$memcpy(global_buffer, data, global_buffer_maxlen);
	} else {
		MSVCRT$memcpy(global_buffer, data, len);
	}


}

void BeaconDataParse (datap * parser, char * buffer, int size) {
	MSVCRT$puts("in BeaconDataParse..dunno what to do here\n");
}

char * BeaconDataExtract (datap *parser, int * size) {
	MSVCRT$puts("in BeaconDataExtract..dunno what to do here\n");
	wchar_t *server; 
	server = KERNEL32$VirtualAlloc(0,50, 0x00001000, 0x04);
	MSVCRT$wcscat(server, L"127.0.0.1");
	return (char *)server;

}
