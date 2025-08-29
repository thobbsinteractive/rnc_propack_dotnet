namespace RncProPackDotNet.Test;

[TestFixture]
public class UnitTest
{
    [SetUp]
    public void Setup()
    {

    }

    [TestCase(@"Resources/mazetrap_compressed.bin", @"Resources/mazetrap_uncompressed.bin")]
    public void DeCompressionUnitTest(string input, string expected)
    {
        var rncProPack = new RncProPack(null);

        var vars = rncProPack.InitVars();
        vars.Output = new byte[0x1E00000];
        vars.Temp = new byte[0x1E00000];

        vars.Input = File.ReadAllBytes(input);
        vars.FileSize = (uint)(vars.Input.Length - vars.ReadStartOffset);
        vars.DictSize = 0x8000;

        var expectedBytes = File.ReadAllBytes(expected);

        rncProPack.DoUnpack(ref vars);

        using (FileStream outFile = new FileStream(@"Resources/temp_uncompressed.bin", FileMode.Create, FileAccess.Write))
        {
            outFile.Write(vars.Output, 0, vars.OutputOffset);
        }

        var outputBytes = File.ReadAllBytes(@"Resources/temp_uncompressed.bin");

        Assert.That(expectedBytes.Length == outputBytes.Length);

        for (int i = 0; i < expectedBytes.Length; i++)
        {
            Assert.That(expectedBytes[i] == vars.Output[i]);
        }
    }

    [TestCase(@"Resources/mazetrap_uncompressed.bin", @"Resources/mazetrap_compressed.bin")]
    public void CompressionUnitTest(string input, string expected)
    {
        var rncProPack = new RncProPack(null);

        var vars = rncProPack.InitVars();
        vars.Output = new byte[0x1E00000];
        vars.Temp = new byte[0x1E00000];

        vars.Input = File.ReadAllBytes(input);
        vars.FileSize = (uint)(vars.Input.Length - vars.ReadStartOffset);
        vars.DictSize = 0x8000;
        var expectedBytes = File.ReadAllBytes(expected);

        rncProPack.DoPack(ref vars);

        using (FileStream outFile = new FileStream(@"Resources/temp_compressed.bin", FileMode.Create, FileAccess.Write))
        {
            outFile.Write(vars.Output, 0, vars.OutputOffset);
        }

        var outputBytes = File.ReadAllBytes(@"Resources/temp_compressed.bin");

        Assert.That(expectedBytes.Length == outputBytes.Length);

        for (int i = 0; i < expectedBytes.Length; i++)
        {
            Assert.That(expectedBytes[i] == vars.Output[i]);
        }
    }
}