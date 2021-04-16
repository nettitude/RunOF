# RunOF

A tool to run object files, mainly beacon object files (BOF), in .Net.

## Usage

```
    -h Show this help text
    -v Show very verbose logs. In debug builds will also pause before starting the OF to allow you to attach a debugger

    One of these is required:
        -f Path to an object file to load
        -a Base64 encoded object file

    Optional arguments:

        -t <timeout> Set thread timeout (in seconds) - default 30 if not specified
	-e <entry> Set entry function name - defaults to go

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

Since these will be called from the BOF, they need to be unmanaged code. Therefore, these are written in C, and compiled into an object file using the provided Makefile. This object file is then loaded into memory in the same way as a "normal" BOF, and the addresses of the various Beacon* functions stored to provide to the BOF later.

### RunOF

A .Net application that loads the object file into memory, gets it ready for execution and executes it in a new thread.

## How it all works

Object files in Windows are defined by the COFF standard. This is not intended to be directly executed, but it is possible to load and execute as follows:

### Find section info

A COFF file consists of a set of sections (text, rodata, bss etc.) that contain the code and data needed to execute.

### Find symbol information 

A COFF file contains a set of symbols which relate to functions and variables that are either defined within the file (e.g. our "go" function) or that need to be imported

### Load into memory

In order to set permissions later, the sections of the COFF file need to loaded into memory on page aligned boundaries (unlike a PE, COFF sections are not page aligned). This is done by allocating a number of pages large enough to contain the section contents and copying into that region. 

For now, memory is set to RW so we can write relocations to it.

### Resolve relocations

Because an object file is designed to be linked together with others in arbitrary order, each section ends with an array of relocation records that define how to update references to other symbols within the section. These must be processed and the address of the symbol written according to the relocation rule. This also allows us to determine if the symbol is "internal" to the object file, or whether it needs to be resolved. There are two types of resolution:

 - Win32 API calls, in the format LIBRARY$Function. These are currently just resolved with LoadLibrary and GetProcAddress.
 - Beacon* functions. These are resolved to the addresses loaded in the beacon_functions object file. 
   
For all imports, a function pointer to the function needs to be returned rather than the function's address. Therefore, the loader also implements a basic "import address table" (IAT) which is simply an array of function pointers. 

### Set permissions

The sections have memory permissions (e.g. RW / R / RX) set as per the header flags.

### Locate entry function

In order to pass arguments to the BOF, we needed to implement a wrapper function that exists in our beacon_funcs object and takes our global argument buffer pointer (which exists in our data section) and supplies it to the BOF's go function as a function argument (e.g. in a register for x64 or on the stack for x86). We need therefore to update our go_wrapper function with a pointer to the target BOF's entry function. 

Usually, a BOF's entry function is called "go", but it is possible to specify an alternative with the -e command line flag.



### Execute!

The code is now executed in a new thread, with a timer set (default 30 seconds, can be changed with the -t flag).

### Retrieve output

The BeaconOutput functions in beacon_funcs write any output the BOF generates into a global_output_buffer, which is allocated on the heap. This buffer can be reallocated to make space for more output, so the .Net assembly must read its new location and size from the BOF's memory before reading the output.

### Cleanup

All memory allocated is zeroed and freed before the application exits.

### BOF Arguments

BOF files can accept arguments, that in Cobalt land are "packed" before use with the bof_pack command. Fundamentally, this is a buffer containing data values, which can be unpacked in the BOF by using BeaconDataInt, BeaconDataShort etc.

**Note** This interface has been implemented completely independantly of Cobalt (no reverse engineering), so any assumptions/bugs etc. are ours.

Implementation:

The datap data struct remains the same as that defined in beacon.h:
```
datap struct {
	char * original; // pointer to start ("so we can free it" - but when?)
	char * buffer; // current ptr position
	int length; // remaining length of data
	int size; // todal size of the buffer
	}
```

We implement these functions:

 - BeaconDataParse (initialises a data parser - I think less relevant in our context but it will be called)
 - BeaconDataExtract (return a char* or wchar*)
 - BeaconDataInt (int32)
 - BeaconDataLength (data left to parse)
 - BeaconDataShort (int16)

The bof_pack function outlines five types of data that can be packed with a format specifier:

| Type | Desciption             | Unpack with       |
|------|------------------------|-------------------|
| b    | binary data            | BeaconDataExtract |
| i    | 4-byte int             | BeaconDataInt     |
| s    | 2-byte int             | BeaconDataShort   |
| z    | zero term string       | BeaconDataExtract |
| Z    | zert-term wchar string | BeaconDataExtract |



The .Net code "serialises" arguments into TLV values, allocates some unmanaged memory and writes its address into a global pointer variable that is in the beacon_functions OF's memory. The TLV encoding is something like this (pseudocode)


```

<TYPE><LENGTH><VALUE>

enum data_types {
    BINARY_DATA,
    4BYTE_INT,
    2BYTE_INT,
    STRING,
    WSTRING
} // as a uint32 - a bit overkill for five values!

utin32_t length; 

// example (will actually be little endian in practise I guess):


  T:STRING  |    LENGTH   | Value   |
00 00 00 03 | 00 00 00 06 | Hello\0 | 
```

Multiple TLVs are stacked together one after the other in the allocated memory region. The BeaconData* functions then extract values from this memory region. There are a number of constraints imposed by this scheme:
 - BOF arguments *must* be provided in the order that the BOF expects to receive them. For example, if the BOF calls BeaconDataInt then BeaconDataShort the arguments must be passed as int then short. If they are passed in the wrong order than BeaconDataInt will fail because the type of the first argument will not match. 
 - Arguments have a maximum length of around 4GB. That should be plenty!


## Useful References

 - https://docs.microsoft.com/en-us/windows/win32/debug/pe-format (especially "Other Contents of the File" section) 
 - https://docs.microsoft.com/en-us/cpp/build/reference/dumpbin-reference?view=msvc-160
