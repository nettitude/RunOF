using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Linq;
using System.Text;
using System.IO;
using System.Threading.Tasks;
using System.Reflection;

namespace RunBOF.Internals
{
    class BofRunner
    {
        private readonly Coff beacon_helper;
        private Coff bof;
        private IntPtr entry_point;
        private readonly IAT iat;
        
        public BofRunner()
        {
            Console.WriteLine("[*] Initialising boff runner");


            // first we need a basic IAT to hold function pointers
            // this needs to be done here so we can share it between our two object files
            this.iat = new IAT();

            // First init our beacon helper object file 
            // This has the code for things like BeaconPrintf, BeaconOutput etc.
            byte[] beacon_funcs;
            string [] resource_names = Assembly.GetExecutingAssembly().GetManifestResourceNames();
            if (resource_names.Contains("RunBOF.beacon_funcs"))
            {
                var ms = new MemoryStream();
                Stream resStream = Assembly.GetExecutingAssembly().GetManifestResourceStream("RunBOF.beacon_funcs");
                resStream.CopyTo(ms);
                beacon_funcs = ms.ToArray();
            } else
            {
                throw new Exception("Unable to load beacon_funcs resource");
            }

            try
            {
                this.beacon_helper = new Coff(beacon_funcs, this.iat);

            } catch (Exception e)
            {
                throw e;
            }

            // Find our helper functions
            this.beacon_helper.ResolveHelpers();
        }

        public void LoadBof(byte[] in_bof)
        {
            Console.WriteLine("[*] Loading bof object...");
            // create new coff to run our bof
            this.bof = new Coff(in_bof, this.iat);
            this.entry_point = this.bof.FindEntry();
        }

        public void LoadBof(string bof_filename)
        {
            Console.WriteLine("[*] Loading boff object...");
            // create new coff
            this.bof = new Coff(bof_filename, this.iat);
            this.entry_point = this.bof.FindEntry();
            Console.WriteLine($"[*] Loaded BOF with entry {this.entry_point.ToInt64():X}");
        }

        public String RunBof(uint timeout)
        {
            Console.WriteLine($"[*] Starting boff in new thread @ {this.entry_point.ToInt64():X}");
            IntPtr hThread = NativeDeclarations.CreateThread(IntPtr.Zero, 0, this.entry_point, IntPtr.Zero, 0, IntPtr.Zero);
            NativeDeclarations.WaitForSingleObject(hThread, timeout * 10);

            // try reading from our shared buffer
            List<byte> output = new List<byte>();

            byte c;
            int i = 0;
            while ((c = Marshal.ReadByte(beacon_helper.global_buffer + i)) != '\0' && i < beacon_helper.global_buffer_size) {
                output.Add(c);
                i++;
            }

            return Encoding.ASCII.GetString(output.ToArray());
            
        }
    }
}
