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

            var ParsedArgs = new ParsedArgs(args); 


            Console.WriteLine($"[*] Loading object file {ParsedArgs.filename}");

            try
            {
                BofRunner bof_runner = new BofRunner(ParsedArgs);
                //  bof_runner.LoadBof(filename);

#if _I386
                bof_runner.LoadBof();
#elif _AMD64
                bof_runner.LoadBof(@"C:\Users\jdsnape\Desktop\SA\ipconfig\ipconfig.x64.o");
#endif
                Console.WriteLine($"[*] About to start BOF in new thread at {bof_runner.entry_point.ToInt64():X}");
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
