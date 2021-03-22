using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RunBOF.Internals
{

    class ParsedArgs
    {
        internal string filename;
        internal byte[] file_bytes;
        //        internal OfArgs of_args;
        private const int ERROR_INVALID_COMMAND_LINE = 0x667;
        internal List<OfArg> of_args;

        public ParsedArgs(string[] args)
        {
            Console.WriteLine($"[*] Parsing Arg 2s: {string.Join(" ", args)}");
            of_args = new List<OfArg>();
            // Mandatory arguments are either file (-f) or base 64 encoded bytes(-b)
            if (!args.Contains("-f") && !args.Contains("-a"))
            {
                PrintUsageAndExit();
                Environment.Exit(ERROR_INVALID_COMMAND_LINE);
            }

            if (args.Contains("-f"))
            {
                try
                {
                    filename = ExtractArg(args, "-f");
                    try
                    {
                        file_bytes = File.ReadAllBytes(filename);
                    } catch (Exception e)
                    {
                        Console.WriteLine($"Unable to read file {filename} : {e}");
                        Environment.Exit(-1);
                    }

                }
                catch
                {
                    PrintUsageAndExit();
                }
            } else if (args.Contains("-a"))
            {
                try
                {
                    file_bytes = Convert.FromBase64String(ExtractArg(args, "-a"));
                } catch
                {
                    PrintUsageAndExit();
                }

            }

            // Now read in any optional arguments that get provided to the OF. 

            foreach (var arg in args)
            {
                // binary data, base64
                if (arg.StartsWith("-b:"))
                {
                    try
                    {
                        of_args.Add(new OfArg(Convert.FromBase64String(arg.Substring(3))));

                    } catch (Exception e)
                    {
                        Console.WriteLine($"Unable to parse OF argument -b as a base64 array: {e}");
                    }
                } else if (arg.StartsWith("-i:"))
                {
                    try
                    {
                        of_args.Add(new OfArg(UInt32.Parse(arg.Substring(3))));
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Unable to parse OF argument -i as a uint32: {e}");
                    }

                } else if (arg.StartsWith("-s:"))
                {
                    try
                    {
                        of_args.Add(new OfArg(UInt16.Parse(arg.Substring(3))));
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Unable to parse OF argument -s as a uint16: {e}");
                    }
                }
                else if (arg.StartsWith("-z:"))
                {
                    try
                    {
                        of_args.Add(new OfArg((arg.Substring(3))));

                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Unable to parse OF argument -z as a string: {e}");
                    }
                } else if (arg.StartsWith("-Z:"))
                {
                    try
                    {
                        of_args.Add(new OfArg(arg.Substring(3)));
                        Console.WriteLine("[!] WARNING - wchar strings not tested/supported...carrying on anyway, good luck!");

                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Unable to parse OF argument -Z as a string: {e}");
                    }

                }


            }


        }

        public byte[] SerialiseArgs()
        {
            List<byte> output_bytes = new List<byte>();
            Console.WriteLine($"[*] Serialising {this.of_args.Count} object file arguments ");
            // convert our list of arguments into a byte array
            foreach (var of_arg in this.of_args)
            {
                Console.WriteLine($"\t[*] Serialising arg of type {of_arg.arg_type} [{(UInt32)of_arg.arg_type}:X]");
                // Add the type
                output_bytes.AddRange(BitConverter.GetBytes((UInt32)of_arg.arg_type));
                // Add the length
                output_bytes.AddRange(BitConverter.GetBytes((UInt32)of_arg.arg_data.Count()));
                // Add the data
                output_bytes.AddRange(of_arg.arg_data);
            }
            return output_bytes.ToArray();
            
        }

        private string ExtractArg(string[] args, string key)
        {
            if (!args.Contains(key)) throw new Exception($"Args array does not contains key {key}");
            if (args.Count() > Array.IndexOf(args, key))
            {
                return args[Array.IndexOf(args, key) + 1];
            }
            else
            {
                throw new Exception($"Key {key} does not have a value");
            }

        }

        private void PrintUsageAndExit()
        {
            Console.WriteLine("Stuff here");
            Environment.Exit(ERROR_INVALID_COMMAND_LINE);

        }
    }

    class OfArg
    {

        public enum ArgType: UInt32
        {
            BINARY,
            INT32,
            INT16,
            STR,
            WCHR_STR,

        }

        public byte[] arg_data;

        public ArgType arg_type;
        public OfArg(UInt32 arg_data)
        {
            arg_type = ArgType.INT32;
            this.arg_data = BitConverter.GetBytes(arg_data);
        }

        public OfArg(UInt16 arg_data)
        {
            arg_type = ArgType.INT16;
            this.arg_data = BitConverter.GetBytes(arg_data);

        }

        public OfArg(string arg_data)
        {
            arg_type = ArgType.BINARY;
            this.arg_data = Encoding.ASCII.GetBytes(arg_data+"\0");
        }

        public OfArg(byte[] arg_data)
        { 
            arg_type = ArgType.BINARY;
            this.arg_data = arg_data;
        }
   
    }

}
