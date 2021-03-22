# RunOF

A tool to run object files, mainly beacon object files (BOF), in .Net.

**Current status:** WIP, x86 mostly works (you can't provide arguments), x64 only partially implemented.

## TODO list

Main things to do are:

 - [ ] Passing arguments to BOFs
 - [ ] A testing framework (i.e. run a load of BOFs and check it all works)
 - [ ] Command line & integration into Posh (mirror RunPE)
 - [ ] General tidy up (especially logging)

## Components

### beacon_funcs

This is the "glue" that sits between our unmanaged object file and managed executable.

### RunOF

A .Net application that loads the object file into memory, gets it ready for execution and executes it.

## How it all works

TODO :)
### BOF Arguments

BOF files can accept arguments, that in Cobalt land are "packed" before use with the bof_pack command. Fundamentally, this is a buffer containing data values, which can be unpacked in the BOF by using BeaconDataInt, BeaconDataShort etc.

**Note** This interface has been implemented completely independantly of Cobalt (no reverse engineering), so any assumptions/bugs etc. are ours.


Proposed implementation:

The datap data struct remains the same as that defined in beacon.h:
```
datap struct {
	char * original; // pointer to start ("so we can free it" - but when?)
	char * buffer; // current ptr position
	int length; // remaining length of data
	int size; // todal size of the buffer
	}
```

We will need to implement these functions:

 - BeaconDataParse (initialises a data parser - I think less relevant in our context but it will be called)
 - BeaconDataExtract (return a char* or wchar*)
 - BeaconDataInt (int32)
 - BeaconDataLength (data left to parse)
 - BeaconDataShort (int16)


The bof_pack function outlines five types of data that can be packed with a format specifier:

| Type| Desciption             | Unpack with       |
|-----|------------------------|-------------------|
|  b  | binary data            | BeaconDataExtract |
|  i  |     4-byte int         |                   |
|  s  |     2-byte int         |                   |
|  z  |     zero term string   |                   |
|  Z  | zert-term wchar string |                   |


I think the best way to handle this is for the buffer in datap to contain TLV values:

```

<TYPE><LENGTH><VALUE>

enum data_types {
    BINARY_DATA,
    4BYTE_INT,
    2BYTE_INT,
    STRING,
    WSTRING
} // as a uint32 - so probs need defines really in C

utin32_t length; 

// example (will actually be little endian in practise I guess):


  T:STRING  |    LENGTH   | Value   |
00 00 00 03 | 00 00 00 06 | Hello\0 | 

Multiple TLVs are then stacked together


```

We can treat the buffer like we do the global output buffer at the moment, and pack it with our arguments before the BOF is called. 

The datap struct will exist on the stack of the BOF, so the BeaconDataParse function needs to setup the pointers and values with the globals the C# app has written into place. 

The buffer pointer should be passed to the BOF, along with its length. 

Then each of the BeaconData{Int, Short, Extract} functions need to read the type at the current pointer position, if it matches what we expect then read out the data using the length field and return it. 




Questions: 

 - We need a wrapper to be able to pass the arguments to our _go function in the normal way.
 - What happens if your arguments are packed in the wrong order? (e.g. you put int, int but the BOF calls BeaconDataExtract - can either error, or find the next matching item?)
 - How do we specify the BOF args on the command line. I'm thinking something like b:[base64data] i:1024 etc.
 - 
