using RunBOF.Internals;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Text;

namespace RunBOF.Internals
{
    class Coff
    {
        private IMAGE_FILE_HEADER file_header;
        private List<IMAGE_SECTION_HEADER> section_headers;
        private List<IMAGE_SYMBOL> symbols;
        private long string_table;
        private IntPtr base_addr;
        private MemoryStream stream;
        private BinaryReader reader;
        private ARCH MyArch;
        private ARCH BofArch;
        private string ImportPrefix;
        private string HelperPrefix;
        private string EntrySymbol;
        //private IntPtr iat;
        private IAT iat;
        public IntPtr global_buffer { get; private set; }
        public uint global_buffer_size { get; set; } = 1024;
        private string InternalDLLName { get; set; } = "POSHBOF";

        private enum ARCH: int 
        {
            I386 = 0,
            AMD64 = 1
        }

        public Coff(byte[] file_bytes, IAT iat)
        {
            try
            {
                Console.WriteLine($"[*] --- Loading object file from byte array ---");

                if (iat != null)
                {
                    this.iat = iat;
                } else
                {
                    this.iat = new IAT();
                }

                this.MyArch = Environment.Is64BitProcess ? ARCH.AMD64 : ARCH.I386;

                LoadImage(file_bytes);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[x] Unable to load object file - {e}");
                throw (e);
            }

        }

        public Coff(string filename, IAT iat)
        {
            try
            {
                Console.WriteLine($"[*] --- Loading object file {filename} ---");

                if (iat != null)
                {
                    this.iat = iat;
                }
                else
                {
                    this.iat = new IAT();
                }

                this.MyArch = Environment.Is64BitProcess ? ARCH.AMD64 : ARCH.I386;


                byte[] file_bytes = File.ReadAllBytes(filename);

                LoadImage(file_bytes);
                
            } catch (Exception e)
            {
                Console.WriteLine($"[x] Unable to load object file {filename} - {e}");
            }
        }


        private void LoadImage(byte[] file_contents)
        {
            // do some field setup
            this.stream = new MemoryStream(file_contents);
            this.reader = new BinaryReader(this.stream);

            this.section_headers = new List<IMAGE_SECTION_HEADER>();
            this.symbols = new List<IMAGE_SYMBOL>();

            // Allocate some memory, for now just the whole size of the object file. 
            // TODO - could just do the memory for the sections and not the header?
            Console.WriteLine($"[*] Allocating {file_contents.Length} bytes");
            base_addr = NativeDeclarations.VirtualAlloc(IntPtr.Zero, (uint)file_contents.Length, NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_EXECUTE_READWRITE);
            Console.WriteLine($"[*] Mapped image base @ 0x{base_addr.ToInt64():x}");

            // copy across
            Marshal.Copy(file_contents, 0, base_addr, file_contents.Length);

            // setup some objects to help us understand the file
            this.file_header = Deserialize<IMAGE_FILE_HEADER>(file_contents);

            // check the architecture
            Console.WriteLine($"[*] Got file header. Architecture {this.file_header.Machine}");

            if (!ArchitectureCheck())
            {
                Console.WriteLine($"[x] Object file architecture {this.BofArch} does not match process architecture {this.MyArch}");
                throw new NotImplementedException();
            }

            // Compilers use different prefixes to symbols depending on architecture. 
            // There might be other naming conventions for functions imported in different ways, but I'm not sure.
            if (this.BofArch == ARCH.I386)
            {
                this.ImportPrefix = "__imp__";
                this.HelperPrefix = "_"; // This I think means a global function
                this.EntrySymbol = "_go";
            }
            else if (this.BofArch == ARCH.AMD64)
            {
                this.ImportPrefix = "__imp_";
                this.EntrySymbol = "go";
                this.HelperPrefix = String.Empty;
            }

            if (this.file_header.SizeOfOptionalHeader != 0)
            {
                Console.WriteLine($"[x] Bad object file: has an optional header??");
                throw new Exception("Object file had an optional header, not standards-conforming");
            }

            // Setup our section header list.
            Console.WriteLine($"[*] Parsing {this.file_header.NumberOfSections} section headers");
            FindSections();

            Console.WriteLine($"[*] Parsing {this.file_header.NumberOfSymbols} symbols");
            FindSymbols();

            // The string table has specified offset, it's just located directly after the last symbol header - so offset is sym_table_offset + (num_symbols * sizeof(symbol))
            Console.WriteLine($"[*] Setting string table offset to {(this.file_header.NumberOfSymbols * Marshal.SizeOf(typeof(IMAGE_SYMBOL))) + this.file_header.PointerToSymbolTable:X}");
            this.string_table = (this.file_header.NumberOfSymbols * Marshal.SizeOf(typeof(IMAGE_SYMBOL))) + this.file_header.PointerToSymbolTable;

            // Process relocations
            Console.WriteLine("[*] Processing relocations..."); 
            section_headers.ForEach(ProcessRelocs);

        }

        public void ResolveHelpers()
        {
            Console.WriteLine("[*] Looking for beacon helper functions");
            bool global_buffer_found = false;
            bool global_buffer_maxlen_found = false;
            foreach (var symbol in this.symbols) 
            {
                var symbol_name = GetSymbolName(symbol);
                if ((symbol_name.StartsWith(this.HelperPrefix+"Beacon") || symbol_name.StartsWith(this.HelperPrefix + "toWideChar")) && symbol.Type == IMAGE_SYMBOL_TYPE.IMAGE_SYM_TYPE_FUNC)
                {
                    var symbol_addr = new IntPtr(this.base_addr.ToInt64() + symbol.Value + this.section_headers[(int)symbol.SectionNumber - 1].PointerToRawData);

                    //Console.WriteLine($"\t[*] Found helper function {symbol_name} - {symbol.Value}");
                    //Console.WriteLine($"\t[=] Address: {symbol_addr.ToInt64():X}");
                    this.iat.Add(this.InternalDLLName, symbol_name.Replace("_", string.Empty), symbol_addr);
                }
                else if (symbol_name == this.HelperPrefix+"global_buffer")
                {
                    if (this.global_buffer == IntPtr.Zero)
                    {
                        this.global_buffer = NativeDeclarations.VirtualAlloc(IntPtr.Zero, this.global_buffer_size, NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_READWRITE);
                        Console.WriteLine($"[*] Allocated a {this.global_buffer_size} bytes global buffer @ {this.global_buffer.ToInt64():X}");
                    }
                    var symbol_addr = new IntPtr(this.base_addr.ToInt64() + symbol.Value + this.section_headers[(int)symbol.SectionNumber - 1].PointerToRawData);

                  //  Console.WriteLine("Found global buffer");
                  //  Console.WriteLine($"\t[=] Address: {symbol_addr.ToInt64():X}");
                    // write the address of the global buffer we allocated
                    Marshal.WriteIntPtr(symbol_addr, this.global_buffer);
                    global_buffer_found = true;
                   // Console.WriteLine($"Val at addr: {Marshal.ReadInt32(symbol_addr):X}");
                }
                else if (symbol_name == this.HelperPrefix+"global_buffer_maxlen")
                {
                    var symbol_addr = new IntPtr(this.base_addr.ToInt64() + symbol.Value + this.section_headers[(int)symbol.SectionNumber - 1].PointerToRawData);
                    // write the maximum size of the buffer TODO - this shouldn't be hardcoded
                    //Console.WriteLine("Found maxlen");
                    //Console.WriteLine($"\t[=] Address: {symbol_addr.ToInt64():X}");
                    // CAUTION - the sizeo of what you write here MUST match the definition in beacon_funcs.h for global_buffer_maxlen (currently a uint32_t)
                    Marshal.WriteInt32(symbol_addr, 1024);
                    global_buffer_maxlen_found = true;

                }

            }
            if (!global_buffer_found || !global_buffer_maxlen_found) throw new Exception($"Unable to find global_buffer_maxlen or global_buffer symbols in your helper object: global_buffer: {global_buffer_found} global_buffer_maxlen: {global_buffer_maxlen_found}");


        }

        public IntPtr FindEntry()
        {
            IntPtr entry = new IntPtr();
            Console.WriteLine("[*] Finding our entry point (go function)");

            foreach (var symbol in symbols)
            {

                // find the __go symbol address that represents our entry point
                // TODO this isn't v efficient as we keep iterating after having found our symbol!
                if (GetSymbolName(symbol).Equals(this.EntrySymbol))
                {
                    Console.WriteLine("\t[*] Found our _go symbol");
                    // calculate the address
                    // the formula is our base_address + symbol value + section_offset
                    int i = this.symbols.IndexOf(symbol);
                    entry = (IntPtr)(this.base_addr.ToInt64() + symbol.Value + this.section_headers[(int)symbols[i].SectionNumber - 1].PointerToRawData); // TODO not sure about this cast 
                    Console.WriteLine($"\t[*] Found entry address {entry.ToInt64():x}");
                    break;
                }
            }

            if (entry == IntPtr.Zero)
            {
                Console.WriteLine("[x] Unable to find entry point! Does your bof have a _go function?");
                throw new Exception("Unable to find bof entry point");
            }

            return entry;
            
        }
        

        private bool ArchitectureCheck()
        {
            this.BofArch = this.file_header.Machine == IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_AMD64 ? ARCH.AMD64 : ARCH.I386;

            if (this.BofArch == this.MyArch) return true;
            return false;

        }

        private void FindSections()
        {
            this.stream.Seek(Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)), SeekOrigin.Begin); // the first section header is located directly after the IMAGE_FILE_HEADER
            for (int i=0; i < this.file_header.NumberOfSections; i++)
            {
                this.section_headers.Add(Deserialize<IMAGE_SECTION_HEADER>(reader.ReadBytes(Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)))));
            }
        }

        private void FindSymbols()
        {
            this.stream.Seek(this.file_header.PointerToSymbolTable, SeekOrigin.Begin);

            for (int i = 0; i < this.file_header.NumberOfSymbols; i++)
            {
                this.symbols.Add(Deserialize<IMAGE_SYMBOL>(reader.ReadBytes(Marshal.SizeOf(typeof(IMAGE_SYMBOL)))));
            }
            Console.WriteLine($"[*] Created list of {this.symbols.Count} symbols");

        }


        private void ProcessRelocs(IMAGE_SECTION_HEADER section_header)
        {
            if (section_header.NumberOfRelocations > 0)
            {
                Console.WriteLine($"[*] Processing {section_header.NumberOfRelocations} relocations for {Encoding.ASCII.GetString(section_header.Name)} section from offset {section_header.PointerToRelocations:X}");
                this.stream.Seek(section_header.PointerToRelocations, SeekOrigin.Begin);

                for (int i = 0; i < section_header.NumberOfRelocations; i++)
                {
                    var struct_bytes = reader.ReadBytes(Marshal.SizeOf(typeof(IMAGE_RELOCATION)));

                    IMAGE_RELOCATION reloc = Deserialize<IMAGE_RELOCATION>(struct_bytes);
                    Console.WriteLine($"\t[*] Got reloc info: {reloc.VirtualAddress:X} - {reloc.SymbolTableIndex:X} - {reloc.Type} - @ { (this.base_addr + (int)section_header.PointerToRawData + (int)reloc.VirtualAddress).ToInt64():X}");
                    if ((int)reloc.SymbolTableIndex > this.symbols.Count || (int)reloc.SymbolTableIndex < 0)
                    {
                        throw new Exception($"Unable to parse relocation # {i+1} symbol table index - {reloc.SymbolTableIndex}");
                    }
                    IMAGE_SYMBOL reloc_symbol = this.symbols[(int)reloc.SymbolTableIndex];
                    var symbol_name = GetSymbolName(reloc_symbol);
                    Console.WriteLine($"\t[*] Relocation name: {GetSymbolName(reloc_symbol)}");
                    if (reloc_symbol.SectionNumber == IMAGE_SECTION_NUMBER.IMAGE_SYM_UNDEFINED)
                    {

                        IntPtr func_addr;

                        if (symbol_name.StartsWith(this.ImportPrefix + "Beacon") || symbol_name.StartsWith(this.ImportPrefix + "toWideChar"))
                        {
                            Console.WriteLine("\t[*] We need to provide this function");
                            // so we need to have an unmanaged function somewhere and a pointer to that function
                            // We then need to write the address of that pointer to this location
                            var func_name = symbol_name.Replace(this.ImportPrefix, String.Empty);
                            func_addr = this.iat.Resolve(this.InternalDLLName, func_name);

                        } else
                        {
                            // This is a win32 api function
                            Console.WriteLine("Win32API function");

                            string[] symbol_parts = symbol_name.Replace(this.ImportPrefix, "").Split('$');

                            string dll_name;
                            string func_name;
                            try
                            {
                                dll_name = symbol_parts[0];
                                func_name = symbol_parts[1].Split('@')[0]; // some compilers emit the number of bytes in the param list after the fn name
                            } catch (Exception e)
                            {
                                throw new Exception($"Unable to parse function name {symbol_name} while processing relocations - {e}");
                            }

                            func_addr = this.iat.Resolve(dll_name, func_name);

                        }

                        // write our address to the relocation
                        IntPtr reloc_location = this.base_addr + (int)section_header.PointerToRawData + (int)reloc.VirtualAddress;
                        Int64 current_value = Marshal.ReadInt32(reloc_location);
                        Console.WriteLine($"Current value: {current_value:X}");
                        // How we write our relocation depends on the relocation type and architecture
                        switch (reloc.Type)
                        {
#if _I386
                        Marshal.WriteInt32(reloc_location, func_addr.ToInt32()); 
#elif _AMD64
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_REL32:
                                Marshal.WriteInt32(reloc_location, (int)(func_addr.ToInt64() - (reloc_location.ToInt64() + 4))); // subtract the size of the relocation (relative to the end of the reloc)
                                break;
                            default:
                                throw new Exception($"Unable to process function relocation type {reloc.Type}");
#endif
                        }
                        Console.WriteLine($"\t[*] Write relocation to {reloc_location.ToInt64():X}");

                    }
                    else
                    {
                        Console.WriteLine("\t[*] Resolving internal reference");
                        IntPtr reloc_location = this.base_addr + (int)section_header.PointerToRawData + (int)reloc.VirtualAddress;
#if _I386
                        Int32 current_value = Marshal.ReadInt32(reloc_location);
#elif _AMD64
                        Int64 current_value = Marshal.ReadInt64(reloc_location);
                        Int32 current_value_32 = Marshal.ReadInt32(reloc_location);
                        Int64 object_addr;
#endif
                        switch (reloc.Type)
                        {
#if _I386
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_ABSOLUTE:
                                // The relocation is ignored
                                break;
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_DIR16:
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_REL16:
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_SEG12:
                                // The relocation is not supported;
                                break;

                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_DIR32:
                                // The target's 32-bit VA
                                Console.WriteLine("\t\t[*] DIR32");
                                Marshal.WriteInt32(reloc_location, current_value + this.base_addr.ToInt32() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData);

                                break;

                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_REL32:
                                // The target's 32-bit RVA
                                Console.WriteLine("\t\t[*] REL32");
                                // THIS IS NOT RIGHT?
                                Marshal.WriteInt32(reloc_location, current_value + this.base_addr.ToInt32() + (int)this.section_headers[(int)reloc_symbol.SectionNumber-1].PointerToRawData);
                                break;
#elif _AMD64
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_ABSOLUTE:
                                // The relocation is ignored
                                break;
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_ADDR64:
                                // The 64-bit VA of the target
                                Marshal.WriteInt64(reloc_location, current_value + this.base_addr.ToInt64() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData);
                                break;
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_REL32:
                                // relative addressing
                                object_addr = current_value_32 + this.base_addr.ToInt64() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData;
                                Marshal.WriteInt32(reloc_location, (int)((object_addr-4) - (reloc_location.ToInt64())) );

                                break;
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_ADDR32NB:
                                // relative addressing with no base address
                                object_addr = current_value_32 + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData;
                                Marshal.WriteInt32(reloc_location, (int)(object_addr - reloc_location.ToInt64()));
                                break;
#endif

                            default:
                                throw new Exception($"Unhandled relocation type {reloc.Type}");

                        }
                    }   

                }

            }
        }
             
        private string GetSymbolName(IMAGE_SYMBOL symbol)
        {
            if (symbol.Name[0] == 0 && symbol.Name[1] == 0 && symbol.Name[2] == 0 && symbol.Name[3] == 0) 
            {
                // the last four bytes of the Name field contain an offset into the string table.
                uint offset = BitConverter.ToUInt32(symbol.Name, 4);
                long position = this.stream.Position;
                this.stream.Seek(this.string_table + offset, SeekOrigin.Begin);

                // read a C string 
                List<byte> characters = new List<byte>();
                byte c;
                while ((c = reader.ReadByte()) != '\0')
                {
                    characters.Add(c);
                }

                String output = Encoding.ASCII.GetString(characters.ToArray());
                this.stream.Seek(position, SeekOrigin.Begin);
                return output;

            } else
            {
                return Encoding.ASCII.GetString(symbol.Name).Replace("\0", String.Empty);
            } 

        }

        private static T Deserialize<T> (byte[] array) 
            where T:struct
        {
            GCHandle handle = GCHandle.Alloc(array, GCHandleType.Pinned);
            return (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
        }


    }
}
