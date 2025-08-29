using RncProPackDotNet;
using Serilog;
using Serilog.Extensions.Logging;

namespace RncProPackDotNetConsoleApp
{
    public class Program
    {
        private const uint MAX_BUF_SIZE = 0x1E00000;

        public static void PrintUsage()
        {
            Log.Information("Unpack        : <u> <infile.bin> [outfile.bin] [-i=hex_offset_to_read_from] [-k=hex_key_if_protected]");
            Log.Information("Search        : <s> <infile.bin>");
            Log.Information("Search&Extract: <e> <infile.bin>");
            Log.Information("Pack          : <p> <infile.bin> [outfile.bin] <-m=1|2> [-k=hex_key_to_protect]");
        }

        public static int ParseArgs(string[] args, ref Vars vars)
        {
            if (args.Length < 1)
                return 1;

            if ("puse".IndexOf(args[0][0]) != -1)
            {
                switch (args[0][0])
                {
                    case 'p':
                    case 'u':
                    case 's':
                    case 'e':
                        vars.PuseMode = args[0][0];
                        break;
                }
            }
            else
            {
                return 1;
            }

            int i = 2;
            while (i < args.Length)
            {
                if ((args[i][0] == '-') || (args[i][0] == '/'))
                {
                    char which = args[i][1];
                    string argPtr = args[i].Length > 3 ? args[i].Substring(3) : args[++i];

                    if (string.IsNullOrEmpty(argPtr))
                        return 3;

                    switch (which)
                    {
                        case 'k':
                            if (!ushort.TryParse(argPtr, System.Globalization.NumberStyles.HexNumber, null, out vars.EncKey) || vars.EncKey == 0)
                                return 3;
                            break;
                        case 'd':
                            if (!ushort.TryParse(argPtr, System.Globalization.NumberStyles.HexNumber, null, out vars.DictSize) || vars.DictSize < 0x400)
                                vars.DictSize = 0x400;
                            break;
                        case 'i':
                            if (!int.TryParse(argPtr, System.Globalization.NumberStyles.HexNumber, null, out vars.ReadStartOffset))
                                return 3;
                            break;
                        case 'o':
                            if (!int.TryParse(argPtr, System.Globalization.NumberStyles.HexNumber, null, out vars.WriteStartOffset))
                                return 3;
                            break;
                        case 'm':
                            if (!uint.TryParse(argPtr, out vars.Method) || vars.Method < 1 || vars.Method > 2)
                                return 3;
                            break;
                        default:
                            break;
                    }
                }
                i++;
            }

            return 0;
        }

        public static int Main(string[] args)
        {
            Log.Logger = new LoggerConfiguration()
                .WriteTo.Console()
                .CreateLogger();

            var microsoftLogger = new SerilogLoggerFactory(Log.Logger).CreateLogger("rncProPack");

            var rncProPack = new RncProPack(microsoftLogger);

            Log.Information("-= RNC ProPackED v1.8 [by Lab 313, Coverted by T.Hobbs] (09/06/2024) =-");
            Log.Information("-----------------------------");

            if (args.Length <= 1)
            {
                Log.Information("Compression type: Huffman + LZ77");
                Log.Information("De/Compressor: Dr.MefistO");
                Log.Information("C Version Coding: Dr. MefistO");
                Log.Information("C# Version Coding: T Hobbs");
                Log.Information("Original: Rob Northen Computing");
                Log.Information("Info: De(re)compiled source of the famous RNC ProPack compression tool\n");
                PrintUsage();
                Log.Information("-----------------------------\n");
                return 0;
            }

            var vars = rncProPack.InitVars();
            if (ParseArgs(args, ref vars) != 0)
            {
                Log.Error("Wrong command line specified!");
                return 1;
            }

            if (vars.Method == 1)
            {
                if (vars.DictSize > 0x8000)
                    vars.DictSize = 0x8000;
                vars.MaxMatches = 0x1000;
            }
            else if (vars.Method == 2)
            {
                if (vars.DictSize > 0x1000)
                    vars.DictSize = 0x1000;
                vars.MaxMatches = 0xFF;
            }

            try
            {
                using (FileStream inFile = new FileStream(args[1], FileMode.Open, FileAccess.Read))
                {
                    vars.FileSize = (uint)(inFile.Length - vars.ReadStartOffset);
                    inFile.Seek(vars.ReadStartOffset, SeekOrigin.Begin);
                    vars.Input = new byte[vars.FileSize];
                    inFile.Read(vars.Input, 0, (int)vars.FileSize);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Cannot open input file!");
                return -1;
            }

            vars.Output = new byte[MAX_BUF_SIZE];
            vars.Temp = new byte[MAX_BUF_SIZE];

            int errorCode = 0;
            switch (vars.PuseMode)
            {
                case 'p':
                    errorCode = rncProPack.DoPack(ref vars);
                    break;
                case 'u':
                    errorCode = rncProPack.DoUnpack(ref vars);
                    break;
                case 's':
                case 'e':
                    errorCode = rncProPack.DoSearch(ref vars, vars.FileSize, vars.PuseMode == 'e');
                    break;
            }

            if (errorCode == 0 && vars.PuseMode != 's' && vars.PuseMode != 'e')
            {
                string outFileName;
                if (args.Length <= 3 || (args[3][0] == '-') || (args[3][0] == '/'))
                {
                    outFileName = $"{args[2]}.{vars.ReadStartOffset:X6}.bin";
                }
                else
                {
                    outFileName = args[3];
                }

                try
                {
                    using (FileStream outFile = new FileStream(outFileName, FileMode.Create, FileAccess.Write))
                    {
                        outFile.Write(vars.Output, 0, vars.OutputOffset);
                    }
                    Log.Information($"File successfully {(vars.PuseMode == 'p' ? "packed" : "unpacked")}!");
                    Log.Information($"Original/new size: {(vars.PuseMode == 'u' ? (vars.PackedSize + 18) : vars.FileSize)}/{vars.OutputOffset} bytes");
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "Cannot create output file!");
                    return -1;
                }
            }
            else
            {
                switch (errorCode)
                {
                    case 0: break;
                    case 4: Log.Error("Corrupted input data."); break;
                    case 5: Log.Error("CRC check failed."); break;
                    case 6:
                    case 7: Log.Error("Wrong RNC header."); break;
                    case 10: Log.Error("Decryption key required."); break;
                    case 11: Log.Error("No RNC archives were found."); break;
                    default: Log.Error($"Cannot process file. Error code: {errorCode:X}"); break;
                }
            }

            return errorCode;
        }
    }
}