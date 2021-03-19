using RunBOF.Internals;
using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

using System.IO;

namespace RunBOF
{
    class Program
    {
        private const int ERROR_INVALID_COMMAND_LINE = 0x667;

        static void Main(string[] args)
        {
            Console.WriteLine("[*] Starting PoshBOF.");

            if (args.Length != 1)
            {
                Console.WriteLine("[x] Usage: PoshBof.exe <object_file>");
                Environment.Exit(ERROR_INVALID_COMMAND_LINE); 
            }

            var filename = args[0];

            Console.WriteLine($"[*] Loading object file {filename}");

            try
            {
                BofRunner bof_runner = new BofRunner();
                //  bof_runner.LoadBof(filename);

#if _I386
                bof_runner.LoadBof(@"C:\Users\jdsnape\Desktop\SA\ipconfig\ipconfig.x86.o");
#elif _AMD64
                bof_runner.LoadBof(@"C:\Users\jdsnape\Desktop\SA\ipconfig\ipconfig.x64.o");
#endif
                Console.WriteLine("[*] Press enter to start it (✂️ attach debugger here...)");
                Console.ReadLine();

                var output = bof_runner.RunBof(30);

                Console.WriteLine("------- BOF OUTPUT ------");
                Console.WriteLine($"{output}");
                Console.WriteLine("------- BOF OUTPUT FINISHED ------");

                Console.WriteLine("[*] Press enter to continue...");
                Console.ReadLine();
                Console.WriteLine("[*] Thanks for playing!");
            } catch (Exception e)
            {
                Console.WriteLine($"[x] Error! {e}");
                Environment.Exit(-1);
            }





        }
    }
}
