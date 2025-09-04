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
        var rncProPack = new RncProPack();

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
        var rncProPack = new RncProPack();

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

    [TestCase(@"Resources/Levels", @"Resources/PackagedLevels.DAT", @"Resources/PackagedLevels.TAB")]
    public void PackageUnitTest(string inputDir, string expectedDat, string expectedTab)
    {
        var rncProPack = new RncProPack();

        var vars = rncProPack.InitVars();
        vars.Output = new byte[0x1E00000];
        vars.Temp = new byte[0x1E00000];

        var files = Directory.GetFiles(inputDir);

        var expectedDatBytes = File.ReadAllBytes(expectedDat);
        var expectedTabBytes = File.ReadAllBytes(expectedTab);

        rncProPack.DoPackageBullfrogFilesToDatandTab(ref vars, files, 38812, true, @"Resources/package.DAT");

        var outputDatBytes = File.ReadAllBytes(@"Resources/package.DAT");
        var outputTabBytes = File.ReadAllBytes(@"Resources/package.TAB");

        Assert.That(expectedDatBytes.Length == outputDatBytes.Length);

        for (int i = 0; i < expectedDatBytes.Length; i++)
        {
            Assert.That(expectedDatBytes[i] == vars.Output[i]);
        }

        Assert.That(expectedTabBytes.Length == outputTabBytes.Length);

        for (int i = 0; i < expectedTabBytes.Length; i++)
        {
            Assert.That(expectedTabBytes[i] == vars.OutputTab[i]);
        }
    }

    [TestCase(@"Resources/Levels", @"Resources/PackedAndPackagedLevels.DAT", @"Resources/PackedAndPackagedLevels.TAB")]
    public void PackAndPackageUnitTest(string inputDir, string expectedDat, string expectedTab)
    {
        var rncProPack = new RncProPack();

        var vars = rncProPack.InitVars();
        vars.Output = new byte[0x1E00000];
        vars.Temp = new byte[0x1E00000];

        var files = Directory.GetFiles(inputDir);

        var expectedDatBytes = File.ReadAllBytes(expectedDat);
        var expectedTabBytes = File.ReadAllBytes(expectedTab);

        rncProPack.DoPackAndPackageBullfrogFilesToDatandTab(ref vars, files, 38812, true, @"Resources/package_compressed.DAT");

        var outputDatBytes = File.ReadAllBytes(@"Resources/package_compressed.DAT");
        var outputTabBytes = File.ReadAllBytes(@"Resources/package_compressed.TAB");

        Assert.That(expectedDatBytes.Length == outputDatBytes.Length);

        for (int i = 0; i < expectedDatBytes.Length; i++)
        {
            Assert.That(expectedDatBytes[i] == vars.Output[i]);
        }

        Assert.That(expectedTabBytes.Length == outputTabBytes.Length);

        for (int i = 0; i < expectedTabBytes.Length; i++)
        {
            Assert.That(expectedTabBytes[i] == vars.OutputTab[i]);
        }
    }
}