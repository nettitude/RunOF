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
        public IntPtr entry_point;
        private readonly IAT iat;
        public ParsedArgs parsed_args;
        public BofRunner(ParsedArgs parsed_args)
        {
            Logger.Debug("Initialising boff runner");
            this.parsed_args = parsed_args;

            // first we need a basic IAT to hold function pointers
            // this needs to be done here so we can share it between our two object files
            this.iat = new IAT();

            // First init our beacon helper object file 
            // This has the code for things like BeaconPrintf, BeaconOutput etc.
            // It also has a wrapper for the bof entry point (go_wrapper) that allows us to pass arguments. 
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

            // Serialise the arguments we want to send to our object file
            // Find our helper functions and entry wrapper (go_wrapper)
            this.entry_point = this.beacon_helper.ResolveHelpers(parsed_args.SerialiseArgs(), parsed_args.debug);


        }

        public void LoadBof()
        {

            Logger.Debug("Loading boff object...");
            // create new coff
            this.bof = new Coff(this.parsed_args.file_bytes, this.iat);
            Logger.Debug($"Loaded BOF with entry {this.entry_point.ToInt64():X}");
            // stitch up our go_wrapper and go_functions
            this.bof.StitchEntry();
        }

        public BofRunnerOutput RunBof(uint timeout)
        {
            Logger.Info($"Starting bof in new thread @ {this.entry_point.ToInt64():X}");
            Logger.Debug(" --- MANAGED CODE END --- ");
            IntPtr hThread = NativeDeclarations.CreateThread(IntPtr.Zero, 0, this.entry_point, IntPtr.Zero, 0, IntPtr.Zero);
            NativeDeclarations.WaitForSingleObject(hThread, (uint)(parsed_args.thread_timeout));

            Console.Out.Flush();
            Logger.Debug(" --- MANAGED CODE START --- ");

            int ExitCode;

            NativeDeclarations.GetExitCodeThread(hThread, out ExitCode);

            
            if (ExitCode < 0)
            {
                Logger.Info($"Bof thread exited with code {ExitCode} - see above for exception information. ");

            }


            // try reading from our shared buffer
            List<byte> output = new List<byte>();

            byte c;
            int i = 0;
            while ((c = Marshal.ReadByte(beacon_helper.global_buffer + i)) != '\0' && i < beacon_helper.global_buffer_size) {
                output.Add(c);
                i++;
            }

            BofRunnerOutput Response = new BofRunnerOutput();

            Response.Output = Encoding.ASCII.GetString(output.ToArray());
            Response.ExitCode = ExitCode;

            return Response;
            
        }
    }

    class BofRunnerOutput
    {
        internal string Output;
        internal int ExitCode;
    }
}
