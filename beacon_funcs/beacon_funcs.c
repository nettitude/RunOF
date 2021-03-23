#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <excpt.h>
#include "beacon_funcs.h"


LONG WINAPI VectoredExceptionHandler(struct _EXCEPTION_POINTERS *ExceptionInfo) {
	MSVCRT$printf("\n EXCEPTION \n --------- \n Exception while running object file: %X\n --------- \n\n", ExceptionInfo->ExceptionRecord->ExceptionCode);
	KERNEL32$ExitThread(-1);
}

// we have a wrapper around our go function to change our globals into parameters
// because we can't pass args in a usual way to the new thread
void go_wrapper() {
	KERNEL32$AddVectoredExceptionHandler(0, VectoredExceptionHandler);
	go(argument_buffer, argument_buffer_length);

	//char *ptr = 0;
	//*ptr = 0;
	KERNEL32$ExitThread(0);
	
}

// Output functions

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
	// This needs a lot of work :)
	
	if (len > global_buffer_maxlen) {
		MSVCRT$memcpy(global_buffer, data, global_buffer_maxlen);
	} else {
		MSVCRT$memcpy(global_buffer, data, len);
	}

}

void hexdump(char * buffer, int len) {
	MSVCRT$printf("--\n");
	for (int i =0 ; i< len; i++) {
		MSVCRT$printf("%02x ", buffer[i]);
	}
	MSVCRT$printf("--\n");
}

// Data API
//
// TODO 
//  - handle the length parser element correctly
//  - check we're not running off the end of the buffer..
void BeaconDataParse (datap * parser, char * buffer, int size) {
	MSVCRT$printf("[*] Initialising DataParser...global arg length: %d, local length: %d\n", argument_buffer_length, size);

	// we want to set our parser fields to point to the right stuff...
	parser->original = buffer; // The original buffer
	parser->buffer = buffer; // current pointer into our buffer
	parser->length = size; // remaining length of data
	parser->size = size; // total size of the buffer

	hexdump(buffer, size);
	hexdump(parser->buffer, size);

	MSVCRT$printf("[*] Finished initialising DataParser\n");
}

int BeaconDataLength (datap *parser) {
	return parser->length;
}

char * BeaconDataExtract (datap *parser, int * size) {
	MSVCRT$puts("in BeaconDataExtract...\n");

	// check we have enough space left in our buffer - need at least space for the type and the length
	if (parser->length > 2 * sizeof(uint32_t)) {
		// read a UINT from our current data buffer position to give us the type
		uint32_t arg_type = *(uint32_t *)parser->buffer;
		if (arg_type == BINARY) {
			// we need to increment the buffer pointer only if we're in the right type
			parser->buffer = parser->buffer + sizeof(uint32_t);
			uint32_t arg_len = *(uint32_t *)parser->buffer;
			MSVCRT$printf("[*] Have a binary variable (type %d) of length %d\n", arg_type, arg_len);
			// check have enough space left in our buffer
			if (parser->length + 2*sizeof(uint32_t) <= arg_len) {
				// we have a choice here, we can either return a pointer to the data in the buffer
				// or allocate some more memory, and point back at that. 
				// I'm not too sure what cobalt does tbh!
				parser->buffer = parser->buffer + sizeof(uint32_t);
				if (size != NULL) {
					*size = arg_len;
				}

				char *return_ptr = parser->buffer;
				hexdump(return_ptr, arg_len);
				parser->buffer = parser->buffer + arg_len;
				parser->length = parser->length + arg_len + 2*sizeof(uint32_t);
				return return_ptr;
			}
		}
	}

	MSVCRT$printf("[!] Error extracting binary data - returning empty_string \n");
	return empty_string;
}

int32_t BeaconDataInt(datap *parser) {
	MSVCRT$puts("in BeaconDataInt....\n");

	if (parser->length >= 3 * sizeof(uint32_t)) {

		uint32_t arg_type = *(uint32_t *)parser->buffer;
		if (arg_type == INT_32) {
			// we need to increment the buffer pointer only if we're in the right type
			parser->buffer = parser->buffer + sizeof(uint32_t);
			// check the length
			uint32_t arg_len = *(uint32_t *)parser->buffer;
			parser->buffer = parser->buffer + sizeof(uint32_t);

			if (arg_len != sizeof(uint32_t)) {
				// TODO - rewind the buffer pointer? things have gone badly wrong anyway and we'll probably crash??
				return 0;
			}

			uint32_t arg_data = *(uint32_t *)parser->buffer;
			parser->buffer = parser->buffer + sizeof(uint32_t);
			parser->length = parser->length + 3 * sizeof(uint32_t);
			MSVCRT$printf("Returning %d\n", arg_data);
			return arg_data;
		} else {
			MSVCRT$printf("[!] Asked for 4-byte integer, but have type %d, returning 0\n", arg_type);
			return 0;
		}
	} 

	MSVCRT$printf("[!] Asked for int, but not enough left in our buffer so returning 0\n");

	return 0;
}

int16_t BeaconDataShort(datap *parser) {
	MSVCRT$puts("in BeaconDataShort....\n");

	if (parser->length >= (2*sizeof(uint32_t) + sizeof(uint32_t))) {
		uint32_t arg_type = *(uint32_t *)parser->buffer;
		if (arg_type == INT_16) {
			// we need to increment the buffer pointer only if we're in the right type
			parser->buffer = parser->buffer + sizeof(uint32_t);
			// check the length
			uint32_t arg_len = *(uint32_t *)parser->buffer;
			parser->buffer = parser->buffer + sizeof(uint32_t);

			if (arg_len != sizeof(uint16_t)) {
				// TODO - rewind the buffer pointer? things have gone badly wrong anyway and we'll probably crash??
				return 0;
			}

			uint16_t arg_data = *(uint16_t *)parser->buffer;
			parser->buffer = parser->buffer + sizeof(uint16_t);
			MSVCRT$printf("Returning %d\n", arg_data);
			return arg_data;
		} else {
			MSVCRT$printf("[!] Asked for 2-byte integer, but have type %d, returning 0\n", arg_type);
			return 0;
		}
	}
	MSVCRT$printf("[!] Asked for short, but not enough left in our buffer so returning 0\n");

	return 0;
}

// Format API

void BeaconFormatAlloc(formatp * format, int maxsz) {
	format->original = MSVCRT$calloc(maxsz, 1);
	format->buffer = format->original;
	format->length = 0;
	format->size = maxsz;

}

void BeaconFormatReset(formatp * format) {
	return;
}

void BeaconFormatFree(formatp * format) {
	return;
}

void BeaconFormatAppend(formatp * format, char * text, int len) {
	return;
}

// This could be dangerous?
void BeaconFormatPrintf(formatp * format, char * fmt, ... ) {
	return;
}

char * BeaconFormatToString(formatp *format, int * size) {
}

void BeaconFormatInt(formatp *format, int value) {
	return;
}


// Token Functions
// not sure how to implement these
BOOL BeaconUseToken(HANDLE token) {
	MSVCRT$puts("[!] BeaconUseToken is unimplemented - ignoring request\n");
	return FALSE;
}

void BeaconRevertToken() {
	MSVCRT$puts("[!] BeaconRevertToken is unimplemented - ignoring request\n");
	return;
}

BOOL BeaconIsAdmin() {
	MSVCRT$puts("[!] BeaconIsAdmin is unimplemented - ignoring request\n");
	return FALSE;
}
