# rnc_propack_dotnet
A .Net Standard 2.0 library of rnc_propack_source (decompiled source of the famous RNC ProPack compression tool see: https://github.com/lab313ru/rnc_propack_source)
## Build Status:

|Branch|Linux|
|------|:---:|
|master|[![.NET](https://github.com/thobbsinteractive/rnc_propack_dotnet/actions/workflows/dotnet.yml/badge.svg?branch=master)](https://github.com/thobbsinteractive/magic-carpet-2-hd/actions/workflows/msbuild.yml)|
|development|[![.NET]([https://github.com/thobbsinteractive/magic-carpet-2-hd/actions/workflows/msbuild.yml/badge.svg)](https://github.com/thobbsinteractive/rnc_propack_dotnet/actions/workflows/dotnet.yml)|

## Calling the Library
You can see how the Library is used in the console application

```c#
uint MAX_BUF_SIZE = 0x1E00000;

var rncProPack = new RncProPackDotNet.RncProPack();
var vars = rncProPack.InitVars();

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

using (FileStream inFile = new FileStream("[InputFilePath]", FileMode.Open, FileAccess.Read))
{
    vars.FileSize = (uint)(inFile.Length - vars.ReadStartOffset);
    inFile.Seek(vars.ReadStartOffset, SeekOrigin.Begin);
    vars.Input = new byte[vars.FileSize];
    inFile.Read(vars.Input, 0, (int)vars.FileSize);
}

vars.Output = new byte[MAX_BUF_SIZE];
vars.Temp = new byte[MAX_BUF_SIZE];

int errorCode = 0;

//Pick one of the following:
//Pack File
errorCode = rncProPack.DoPack(ref vars);

//UnPack File
errorCode = rncProPack.DoUnpack(ref vars);

//DoSearch of File
errorCode = rncProPack.DoSearch(ref vars, vars.FileSize, true, "[OutputDirPath]");

if (errorCode == 0 && vars.PuseMode != 's' && vars.PuseMode != 'e')
{
  using (FileStream outFile = new FileStream("OutputFileName", FileMode.Create, FileAccess.Write))
  {
      outFile.Write(vars.Output, 0, vars.OutputOffset);
  }
}
```
## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.
