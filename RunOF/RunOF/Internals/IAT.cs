﻿using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RunBOF.Internals
{
    class IAT
    {
        private readonly IntPtr iat_addr;
        private int iat_count;
        private readonly Dictionary<String, IntPtr> iat_entries;
        public IAT()
        {
            this.iat_addr = NativeDeclarations.VirtualAlloc(IntPtr.Zero, 1024, NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_EXECUTE_READWRITE);
            this.iat_count = 0;
            this.iat_entries = new Dictionary<string, IntPtr>();
        }
        // TODO may need to resize IAT memory location. It's also way too big!
        public IntPtr Resolve(string dll_name, string func_name)
        {
            // do we already have it in our IAT table? It not lookup and add
            if (!this.iat_entries.ContainsKey(dll_name + "$" + func_name))
            {
                Console.WriteLine($"[*] Resolving {func_name} from {dll_name}");

                IntPtr dll_handle = NativeDeclarations.LoadLibrary(dll_name);
                IntPtr func_ptr = NativeDeclarations.GetProcAddress(dll_handle, func_name);
                if (func_ptr == null || func_ptr.ToInt64() == 0)
                {
                    throw new Exception($"Unable to resolve {func_name} from {dll_name}");
                }
                Console.WriteLine($"\t[*] Got function address {func_ptr.ToInt64():X}");
                Add(dll_name, func_name, func_ptr);
            }

            return this.iat_entries[dll_name + "$" + func_name];

        }

        // This can also be called directly for functions where you already know the address (e.g. helper functions)
        public void Add(string dll_name, string func_name, IntPtr func_address)
        {
            Console.WriteLine($"[*] Adding {dll_name+ "$" + func_name} at address {func_address}");
#if _I386
            Marshal.WriteInt32(this.iat_addr + (this.iat_count * 4), func_address.ToInt32());
            this.iat_entries.Add(dll_name + "$" + func_name, this.iat_addr + (this.iat_count * 4));

#elif _AMD64
            Marshal.WriteInt64(this.iat_addr + (this.iat_count * 8), func_address.ToInt64());
            this.iat_entries.Add(dll_name + "$" + func_name, this.iat_addr + (this.iat_count * 8));


#endif

            this.iat_count++;
        }
    }
}