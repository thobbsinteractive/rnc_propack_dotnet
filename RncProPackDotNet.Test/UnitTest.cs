namespace RncProPackDotNet.Test
{
    public class UnitTest
    {
        [SetUp]
        public void Setup()
        {
        }

        [TestCase(@"LEVELS.DAT.BK")]
        public void DeCompressionUnitTest(string path)
        {
            var rncProPack = new RncProPack();

            var vars = rncProPack.InitVars();

            vars.PuseMode = 'e';

            vars.Input = File.ReadAllBytes(path);
            vars.InputOffset = 8;
            vars.FileSize = (uint)(vars.InputSize - vars.InputOffset);

            rncProPack.DoSearch(ref vars, vars.FileSize, true);
            
            Assert.Pass();
        }
    }
}