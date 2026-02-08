using System.CommandLine;
using System.Text.Json;
using System.Text.Json.Serialization;
using doticf;

namespace doticf;

// --- 1. JSON 源码生成器上下文 ---
[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(List<IcfData>))] // 关键：必须包含 List 包装
internal partial class IcfJsonContext : JsonSerializerContext { }

class Program
{
    // 修改为同步入口或确保只有一个入口，解决 CS8892
    static int Main(string[] args)
    {
        var rootCommand = new RootCommand("ICF Reader/Writer CLI");

        // --- Encrypt Command ---
        var encryptCommand = new Command("encrypt", "Fixes some common ICF errors, then encrypt the given ICF");
        var encryptInputArg = new Argument<string>("input", "Input file path");
        var encryptOutputArg = new Argument<string>("output", "Output file path");
        encryptCommand.AddArgument(encryptInputArg);
        encryptCommand.AddArgument(encryptOutputArg);

        encryptCommand.SetHandler((string input, string output) =>
        {
            try
            {
                byte[] icfBuf = File.ReadAllBytes(input);
                Parser.FixupIcf(icfBuf);
                
                var icf = Parser.ParseIcf(icfBuf); 
                foreach (var entry in icf)
                {
                    Console.Write(entry.GetFilename());
                    if (entry.IsPrerelease) Console.Write(" (PRERELEASE)");
                    Console.WriteLine();
                }

                // 假设 Crypto 类已存在
                byte[] encrypted = Crypto.EncryptIcf(icfBuf, Crypto.ICF_KEY, Crypto.ICF_IV);
                File.WriteAllBytes(output, encrypted);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                Environment.Exit(1);
            }
        }, encryptInputArg, encryptOutputArg);

        // --- Decrypt Command ---
        var decryptCommand = new Command("decrypt", "Decrypts the given ICF");
        var decryptInputArg = new Argument<string>("input", "Input file path");
        var decryptOutputArg = new Argument<string>("output", "Output file path");
        decryptCommand.AddArgument(decryptInputArg);
        decryptCommand.AddArgument(decryptOutputArg);

        decryptCommand.SetHandler((string input, string output) =>
        {
            try
            {
                byte[] icfBuf = File.ReadAllBytes(input);
                byte[] decrypted = Crypto.DecryptIcf(icfBuf, Crypto.ICF_KEY, Crypto.ICF_IV);
                File.WriteAllBytes(output, decrypted);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                Environment.Exit(1);
            }
        }, decryptInputArg, decryptOutputArg);

        // --- Decode Command ---
        var decodeCommand = new Command("decode", "Decodes the given ICF (optionally to a JSON file)");
        var decodeIcfArg = new Argument<string>("icf", "Input ICF file path");
        var decodeJsonOutputOption = new Option<string?>("--json-output", "Optional JSON output file path");
        decodeCommand.AddArgument(decodeIcfArg);
        decodeCommand.AddOption(decodeJsonOutputOption);

        decodeCommand.SetHandler((string icfPath, string? jsonOutput) =>
        {
            try
            {
                byte[] icfBuf = File.ReadAllBytes(icfPath);
                var icfData = Parser.DecodeIcf(icfBuf);

                if (jsonOutput != null)
                {
                    // AOT 修复：使用 IcfJsonContext.Default.ListIcfData
                    string json = JsonSerializer.Serialize(icfData, IcfJsonContext.Default.ListIcfData);
                    File.WriteAllText(jsonOutput, json);
                }

                foreach (var entry in icfData)
                {
                    Console.Write(entry.GetFilename());
                    if (entry.IsPrerelease) Console.Write(" (PRERELEASE)");
                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                Environment.Exit(1);
            }
        }, decodeIcfArg, decodeJsonOutputOption);

        // --- Encode Command ---
        var encodeCommand = new Command("encode", "Encodes a JSON file from the decode subcommand to an ICF");
        var encodeJsonInputArg = new Argument<string>("json_input", "Input JSON file path");
        var encodeOutputArg = new Argument<string>("output", "Output file path");
        encodeCommand.AddArgument(encodeJsonInputArg);
        encodeCommand.AddArgument(encodeOutputArg);

        encodeCommand.SetHandler((string jsonInput, string output) =>
        {
            try
            {
                string json = File.ReadAllText(jsonInput);
                
                // AOT 修复：使用 IcfJsonContext.Default.ListIcfData
                var icfData = JsonSerializer.Deserialize(json, IcfJsonContext.Default.ListIcfData);
                
                if (icfData == null) throw new Exception("Failed to deserialize JSON");

                byte[] serialized = Parser.SerializeIcf(icfData);
                byte[] encrypted = Crypto.EncryptIcf(serialized, Crypto.ICF_KEY, Crypto.ICF_IV);
                File.WriteAllBytes(output, encrypted);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                Environment.Exit(1);
            }
        }, encodeJsonInputArg, encodeOutputArg);

        rootCommand.AddCommand(encryptCommand);
        rootCommand.AddCommand(decryptCommand);
        rootCommand.AddCommand(decodeCommand);
        rootCommand.AddCommand(encodeCommand);

        // AOT 建议：Invoke 而非 InvokeAsync (减少 Task 状态机元数据)
        return rootCommand.Invoke(args);
    }
}