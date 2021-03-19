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

