namespace RncProPackDotnet
{
    public struct Vars
    {
        public ushort MaxMatches;
        public ushort EncKey;
        public uint PackBlockSize;
        public ushort DictSize;
        public uint Method;
        public uint PuseMode;
        public uint InputSize;
        public uint FileSize;

        // Inner
        public uint BytesLeft;
        public uint PackedSize;
        public uint ProcessedSize;
        public uint V7;
        public uint PackBlockPos;
        public ushort PackToken;
        public ushort BitCount;
        public ushort V11;
        public ushort LastMinOffset;
        public uint V17;
        public uint PackBlockLeftSize;
        public ushort MatchCount;
        public ushort MatchOffset;
        public uint v20;
        public uint v21;
        public uint BitBuffer;

        public uint UnPackedSize;
        public uint RncDataSize;
        public ushort UnpackedCrc;
        public ushort UnpackedCrcReal;
        public ushort PackedCrc;
        public uint Leeway;
        public uint ChunksCount;

        public byte[] Mem1;
        public byte[] PackBlockStart;
        public byte[] PackBlockMax;
        public byte[] PackBlockEnd;
        public ushort[] Mem2;
        public ushort[] Mem3;
        public ushort[] Mem4;
        public ushort[] Mem5;

        public byte[] Decoded;
        public byte[] Window;

        public int ReadStartOffset;
        public int WriteStartOffset;
        public byte[] Input;
        public byte[] Output;
        public byte[] Temp;
        public int InputOffset;
        public int OutputOffset;
        public int TempOffset;

        public byte[] TmpCrcData;
        public Huftable[] RawTable;
        public Huftable[] PosTable;
        public Huftable[] LenTable;
    }
}
