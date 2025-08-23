namespace RncProPackDotNet.Test;

[TestFixture]
public class UnitTest
{
    [SetUp]
    public void Setup()
    {
    }

    [TestCase(@"Resources\mazetrap_compressed.bin", @"Resources\mazetrap_uncompressed.bin")]
    public void DeCompressionUnitTest(string input, string expected)
    {
        var rncProPack = new RncProPack();

        var vars = rncProPack.InitVars();
        vars.Output = new byte[0x1E00000];
        vars.Temp = new byte[0x1E00000];

        vars.Input = File.ReadAllBytes(input);
        vars.FileSize = (uint)(vars.Input.Length - vars.ReadStartOffset);

        var expectedBytes = File.ReadAllBytes(expected);

        rncProPack.DoUnpack(ref vars);
        
        Assert.Equals(expectedBytes.Length, vars.Output.Length);

        for(int i = 0; i < expectedBytes.Length; i++)
        {
            Assert.Equals(expectedBytes[i], vars.Output[i]);
        }
    }
}