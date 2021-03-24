# RunOF

A tool to run object files, mainly beacon object files (BOF), in .Net.

**Current status:** WIP. Most BOF files tested work OK. Not all functions are implemented (mostly the BeaconFormat* functions).

## TODO list

Main things to do are:

 - [x] Passing arguments to BOFs
 - [x] A testing framework (i.e. run a load of BOFs and check it all works)
 - [ ] Test integration into Posh (mirror RunPE)
 - [x] General tidy up (especially logging)

## Usage

```
    -h Show this help text
    -v Show very verbose logs. In debug builds will also pause before starting the OF to allow you to attach a debugger

    One of these is required:
        -f Path to an object file to load
        -a Base64 encoded object file

    Optional arguments:
        These are passed to the object file *in the order they are on the command line*.

        -i:123       A 32 bit integer (e.g. 123 passed to object file)
        -s:12        A 16 bit integer (e.g. 12 passed to object file)
        -z:hello     An ASCII string  (e.g. hello passed to object file)
        -Z:hello     A string that's converted to wchar (e.g. (wchar_t)hello passed to object file)
        -b:aGVsbG8=  A base64 encoded binary blob (decoded binary passed to object file)

        To specify an empty string just leave it blank (e.g. -Z: )
```

Some BOF files take arguments, which would normally be parsed and "packed" by the aggressor script. In RunOF you need to provide these, in the same order that they would be packed in the aggressor script. 

So, for example, if a cna file has the following bof_pack statement:

```
$args = bof_pack($1, "Zs", $targetdir, $subdirs);
```

Then you would specify the command line as:

```
RunOF.exe -f <filename> -Z:targetdir -s:subdirs
```

where targetdir would be a path (like C:\) and -s a 16 bit integer (in this case, 1 to recurse). The ordering and types are important - they must be specified in the same order as in the pack statement for the BOF to read them successfully. 

If you need to specify an empty parameter (e.g. an empty string) then leave it blank (e.g. -Z: ). 

If the BOF file attempts to read an argument that isn't provided then zero is provided for numeric types and an empty string (single null character) for string types. 


### Debugging

To enable copious log messages use the -v command line option. 

If you have a debug build, then if the -v flag is passed it will pause before starting the OF thread to allow you to attach a debugger. You can then set a breakpoint at the thread entry address to debug the loaded object file. 

## TODO list

Main things to do are:

 - [ ] Passing arguments to BOFs
 - [ ] A testing framework (i.e. run a load of BOFs and check it all works)
 - [ ] Command line & integration into Posh (mirror RunPE)
 - [ ] General tidy up (especially logging)

## Components

### beacon_funcs

This is the "glue" that sits between our unmanaged object file and managed executable. It contains:
 - A wrapper function that does some housekeeping and runs the object file entry point
 - An exception handler so if something goes wrong in the OF it can return an error code and message
 - Implementations of the Beacon* functions (e.g. BeaconPrintf) that are normally provided by Cobalt Strike


### RunOF

A .Net application that loads the object file into memory, gets it ready for execution and executes it in a new thread.

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
