using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace RncProPackDotNet
{
    public class RncProPack
    {
        private const uint RNC_SIGN = 0x524E43; // RNC
        private const byte RNC_HEADER_SIZE = 0x12;
        private const int TAB_FILE_SIZE = 4000;

        private static readonly ushort[] CrcTable = {
            0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
            0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
            0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
            0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
            0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
            0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
            0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
            0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
            0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
            0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
            0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
            0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
            0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
            0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
            0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
            0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
            0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
            0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
            0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
            0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
            0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
            0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
            0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
            0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
            0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
            0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
            0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
            0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
            0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
            0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
            0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
            0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
        };

        private static readonly byte[] MatchCountBitsTable = { 0x00, 0x0E, 0x08, 0x0A, 0x012, 0x013, 0x016 };
        private static readonly byte[] MatchCountBitsCountTable = { 0, 4, 4, 4, 5, 5, 5 };
        private static readonly byte[] MatchOffsetBitsTable = { 0x00, 0x06, 0x08, 0x09, 0x15, 0x17, 0x1D, 0x1F, 0x28, 0x29, 0x2C, 0x2D, 0x38, 0x39, 0x3C, 0x3D };
        private static readonly byte[] MatchOffsetBitsCountTable = { 1, 3, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6 };

        private ILogger Logger { get; }

        public RncProPack(ILogger logger = null)
        {
            Logger = logger;
        }

        protected byte PeekByte(byte[] buf, int offset)
        {
            return buf[offset];
        }

        protected byte ReadByte(byte[] buf, ref int offset)
        {
            return buf[offset++];
        }

        protected void WriteByte(byte[] buf, ref int offset, byte b)
        {
            buf[offset++] = b;
        }

        protected ushort PeekWordBigEndian(byte[] buf, int offset)
        {
            byte b1 = PeekByte(buf, offset + 0);
            byte b2 = PeekByte(buf, offset + 1);

            return (ushort)((b1 << 8) | b2);
        }
        protected ushort ReadWordBigEndian(byte[] buf, ref int offset)
        {
            byte b1 = ReadByte(buf, ref offset);
            byte b2 = ReadByte(buf, ref offset);

            return (ushort)((b1 << 8) | b2);
        }

        protected void WriteWordBigEndian(byte[] buf, ref int offset, ushort val)
        {
            WriteByte(buf, ref offset, (byte)((val >> 8) & 0xFF));
            WriteByte(buf, ref offset, (byte)((val >> 0) & 0xFF));
        }

        protected uint PeekDWordBigEndian(byte[] buf, int offset)
        {
            ushort w1 = PeekWordBigEndian(buf, offset + 0);
            ushort w2 = PeekWordBigEndian(buf, offset + 2);

            return ((uint)w1 << 16) | w2;
        }

        protected uint ReadDWordBigEndian(byte[] buf, ref int offset)
        {
            ushort w1 = ReadWordBigEndian(buf, ref offset);
            ushort w2 = ReadWordBigEndian(buf, ref offset);

            return ((uint)w1 << 16) | w2;
        }

        protected void WriteDWordBigEndian(byte[] buf, ref int offset, uint val)
        {
            WriteWordBigEndian(buf, ref offset, (ushort)(val >> 16));
            WriteWordBigEndian(buf, ref offset, (ushort)(val & 0xFFFF));
        }

        protected void ReadBuffer(byte[] dest, byte[] source, ref int offset, int size)
        {
            Buffer.BlockCopy(source, offset, dest, 0, size);
            offset += size;
        }

        protected void ReadBuffer(byte[] dest, int destOffset, byte[] source, ref int sourceOffset, int size)
        {
            Buffer.BlockCopy(source, sourceOffset, dest, destOffset, size);
            sourceOffset += size;
        }

        protected void WriteBuffer(byte[] dest, ref int offset, byte[] source, int size)
        {
            Buffer.BlockCopy(source, 0, dest, offset, size);
            offset += size;
        }

        protected ushort CrcBlock(byte[] buf, int offset, int size)
        {
            ushort crc = 0;

            while (size-- > 0)
            {
                crc ^= ReadByte(buf, ref offset);
                crc = (ushort)((crc >> 8) ^ CrcTable[crc & 0xFF]);
            }

            return crc;
        }

        protected void RorW(ref ushort x)
        {
            if ((x & 1) != 0)
                x = (ushort)(0x8000 | (x >> 1));
            else
                x >>= 1;
        }

        public Vars InitVars()
        {
            Vars v = new Vars();
            v.EncKey = 0;
            v.MaxMatches = 0x1000;
            v.UnpackedCrcReal = 0;
            v.PackBlockSize = 0x3000;
            v.DictSize = 0xFFFF;
            v.Method = 1;
            v.PuseMode = 'p';

            v.ReadStartOffset = 0;
            v.WriteStartOffset = 0;
            v.InputOffset = 0;
            v.OutputOffset = 0;
            v.TempOffset = 0;

            v.TmpCrcData = new byte[2048];
            v.RawTable = new Huftable[16];
            v.PosTable = new Huftable[16];
            v.LenTable = new Huftable[16];

            return v;
        }

        protected void InitDicts(ref Vars v)
        {
            ushort DictSize = v.DictSize;

            for (int i = 0; i < 0x800; ++i)
            {
                v.Mem2[i * 0x10 + 0x0] = DictSize; v.Mem2[i * 0x10 + 0x1] = DictSize;
                v.Mem2[i * 0x10 + 0x2] = DictSize; v.Mem2[i * 0x10 + 0x3] = DictSize;
                v.Mem2[i * 0x10 + 0x4] = DictSize; v.Mem2[i * 0x10 + 0x5] = DictSize;
                v.Mem2[i * 0x10 + 0x6] = DictSize; v.Mem2[i * 0x10 + 0x7] = DictSize;
                v.Mem2[i * 0x10 + 0x8] = DictSize; v.Mem2[i * 0x10 + 0x9] = DictSize;
                v.Mem2[i * 0x10 + 0xA] = DictSize; v.Mem2[i * 0x10 + 0xB] = DictSize;
                v.Mem2[i * 0x10 + 0xC] = DictSize; v.Mem2[i * 0x10 + 0xD] = DictSize;
                v.Mem2[i * 0x10 + 0xE] = DictSize; v.Mem2[i * 0x10 + 0xF] = DictSize;

                v.Mem3[i * 0x10 + 0x0] = DictSize; v.Mem3[i * 0x10 + 0x1] = DictSize;
                v.Mem3[i * 0x10 + 0x2] = DictSize; v.Mem3[i * 0x10 + 0x3] = DictSize;
                v.Mem3[i * 0x10 + 0x4] = DictSize; v.Mem3[i * 0x10 + 0x5] = DictSize;
                v.Mem3[i * 0x10 + 0x6] = DictSize; v.Mem3[i * 0x10 + 0x7] = DictSize;
                v.Mem3[i * 0x10 + 0x8] = DictSize; v.Mem3[i * 0x10 + 0x9] = DictSize;
                v.Mem3[i * 0x10 + 0xA] = DictSize; v.Mem3[i * 0x10 + 0xB] = DictSize;
                v.Mem3[i * 0x10 + 0xC] = DictSize; v.Mem3[i * 0x10 + 0xD] = DictSize;
                v.Mem3[i * 0x10 + 0xE] = DictSize; v.Mem3[i * 0x10 + 0xF] = DictSize;
            }

            for (int i = 0; i < DictSize; ++i)
            {
                v.Mem5[i & 0x7FFF] = 0;
                v.Mem4[i & 0x7FFF] = (ushort)i;
            }

            v.LastMinOffset = 0;
        }

        protected void UpdatePackedCrc(ref Vars v, byte b)
        {
            ushort crc = v.PackedCrc;
            v.PackedCrc = (ushort)(CrcTable[(crc & 0xFF) ^ b] ^ (crc >> 8));
            v.PackedSize++;
        }

        protected void UpdateUnpackedCrc(ref Vars v, byte b)
        {
            ushort crc = v.UnpackedCrc;
            v.UnpackedCrc = (ushort)(CrcTable[(crc & 0xFF) ^ b] ^ (crc >> 8));
            v.ProcessedSize++;
        }

        protected void WriteToOutput(ref Vars v, byte b)
        {
            if (v.PackedSize >= (v.FileSize - RNC_HEADER_SIZE))
                return;

            WriteByte(v.Output, ref v.OutputOffset, b);
            UpdatePackedCrc(ref v, b);
        }

        protected byte ReadFromInput(ref Vars v)
        {
            byte b = ReadByte(v.Input, ref v.InputOffset);
            UpdateUnpackedCrc(ref v, b);
            return b;
        }

        protected void WriteBitsM2(ref Vars v, ushort value, int count)
        {
            uint mask = (uint)(1 << (count - 1));

            while (count-- > 0)
            {
                v.PackToken <<= 1;

                if ((value & mask) != 0)
                    v.PackToken++;

                mask >>= 1;
                v.BitCount++;

                if (v.BitCount == 8)
                {
                    WriteToOutput(ref v, (byte)(v.PackToken & 0xFF));

                    for (int i = 0; i < v.V11; ++i)
                        WriteToOutput(ref v, v.TmpCrcData[i]);

                    v.V11 = 0;

                    if ((v.ProcessedSize > v.PackedSize) && (v.ProcessedSize - v.PackedSize > v.Leeway))
                        v.Leeway = v.ProcessedSize - v.PackedSize;

                    v.BitCount = 0;
                    v.PackToken = 0;
                }
            }
        }

        protected void WriteBitsM1(ref Vars v, ushort value, int count)
        {
            while (count-- > 0)
            {
                v.PackToken >>= 1;
                v.PackToken |= (value & 1) != 0 ? (ushort)0x8000u : (ushort)0;

                value >>= 1;
                v.BitCount++;

                if (v.BitCount == 16)
                {
                    WriteToOutput(ref v, (byte)(v.PackToken & 0xFF));
                    WriteToOutput(ref v, (byte)((v.PackToken >> 8) & 0xFF));

                    for (int i = 0; i < v.V11; ++i)
                        WriteToOutput(ref v, v.TmpCrcData[i]);

                    v.V11 = 0;

                    if ((v.ProcessedSize > v.PackedSize) && (v.ProcessedSize - v.PackedSize > v.Leeway))
                        v.Leeway = v.ProcessedSize - v.PackedSize;

                    v.BitCount = 0;
                    v.PackToken = 0;
                }
            }
        }

        protected void WriteBits(ref Vars v, ushort bits, int count)
        {
            if (v.Method == 2)
                WriteBitsM2(ref v, bits, count);
            else
                WriteBitsM1(ref v, bits, count);
        }

        protected int FindMatches(ref Vars v)
        {
            v.MatchCount = 1;
            v.MatchOffset = 0;

            int matchOffset = 1;
            while (matchOffset < (v.PackBlockEndIdx - v.PackBlockStartIdx) && (v.PackBlockStart[v.PackBlockStartIdx + matchOffset] == v.PackBlockStart[v.PackBlockStartIdx]))
                matchOffset++;

            ushort firstWord = PeekWordBigEndian(v.PackBlockStart, v.PackBlockStartIdx);
            ushort offset = v.Mem2[firstWord & 0x7FFF];

            while (true)
            {
                if (offset == v.DictSize)
                {
                    if ((v.MatchCount == 2) && (v.MatchOffset > 0x100))
                    {
                        v.MatchCount = 1;
                        v.MatchOffset = 0;
                    }

                    break;
                }

                ushort restore = v.Mem4[offset & 0x7FFF];
                ushort minOffset = v.LastMinOffset;

                if (minOffset <= offset)
                    minOffset += v.DictSize;

                minOffset -= offset;
                if (PeekWordBigEndian(v.PackBlockStart, v.PackBlockStartIdx - minOffset) == PeekWordBigEndian(v.PackBlockStart, v.PackBlockStartIdx))
                {
                    ushort maxCount = v.Mem5[offset & 0x7FFF];

                    if (maxCount <= minOffset)
                    {
                        if (maxCount > matchOffset)
                        {
                            minOffset = (ushort)(minOffset - maxCount + matchOffset);
                            maxCount = (ushort)matchOffset;
                        }

                        int maxSize = v.PackBlockEndIdx - v.PackBlockStartIdx;
                        if (maxCount == matchOffset)
                        {
                            while (maxCount < maxSize && (v.PackBlockStart[v.PackBlockStartIdx + maxCount] == v.PackBlockStart[v.PackBlockStartIdx + maxCount - minOffset]))
                                maxCount++;
                        }
                    }
                    else
                    {
                        minOffset = 1;
                        maxCount = (ushort)matchOffset;
                    }

                    if (maxCount > v.MaxMatches)
                        maxCount = v.MaxMatches;

                    if (maxCount >= v.MatchCount)
                    {
                        v.MatchCount = maxCount;
                        v.MatchOffset = minOffset;
                    }
                }

                offset = restore;
            }

            return 0;
        }

        protected void FindAndCheckMatches(ref Vars v)
        {
            FindMatches(ref v);

            if (v.MatchCount >= 2)
            {
                if (v.PackBlockMaxIdx - v.PackBlockStartIdx >= 3)
                {
                    ushort count = v.MatchCount;
                    ushort offset = v.MatchOffset;
                    ushort minOffset = v.LastMinOffset;

                    v.LastMinOffset = (ushort)((v.LastMinOffset + 1) % v.DictSize);

                    v.PackBlockStartIdx++;
                    FindMatches(ref v);
                    v.PackBlockStartIdx--;

                    v.LastMinOffset = minOffset;

                    if (count < v.MatchCount)
                    {
                        count = 1;
                        offset = 0;
                    }

                    v.MatchCount = count;
                    v.MatchOffset = offset;
                }
            }
        }

        protected int BitsCount(int value)
        {
            int count = 1;
            while ((value >>= 1) != 0)
                count++;

            return count;
        }

        protected void UpdateBitsTable(ref Vars v, Huftable[] data, ushort bits)
        {
            if (bits <= 1)
                data[bits].l1++;
            else
                data[BitsCount(bits)].l1++;

            WriteWordBigEndian(v.Temp, ref v.TempOffset, bits);
        }

        protected void EncodeMatches(ref Vars v, ushort w)
        {
            while (true)
            {
                ushort restore = v.Mem4[v.LastMinOffset & 0x7FFF];
                v.Mem4[v.LastMinOffset & 0x7FFF] = v.DictSize;

                if (restore != v.LastMinOffset)
                {
                    ushort bufferWord = PeekWordBigEndian(v.PackBlockStart, v.PackBlockStartIdx - v.DictSize);
                    v.Mem2[bufferWord & 0x7FFF] = restore;

                    if (v.DictSize == restore)
                        v.Mem3[bufferWord & 0x7FFF] = v.DictSize;
                }

                ushort bufferWord2 = PeekWordBigEndian(v.PackBlockStart, v.PackBlockStartIdx);

                if (v.Mem2[bufferWord2 & 0x7FFF] == v.DictSize)
                    v.Mem2[bufferWord2 & 0x7FFF] = v.LastMinOffset;
                else
                    v.Mem4[v.Mem3[bufferWord2 & 0x7FFF] & 0x7FFF] = v.LastMinOffset;

                v.Mem3[bufferWord2 & 0x7FFF] = v.LastMinOffset;

                int count = 1;

                while (count < (v.PackBlockEndIdx - v.PackBlockStartIdx) && (v.PackBlockStart[v.PackBlockStartIdx + count] == v.PackBlockStart[v.PackBlockStartIdx]))
                    count++;

                v.Mem5[v.LastMinOffset & 0x7FFF] = (ushort)count;

                while (true)
                {
                    v.LastMinOffset = (ushort)((v.LastMinOffset + 1) % v.DictSize);

                    v.PackBlockStartIdx++;

                    if (--w == 0)
                        return;

                    if (--count <= 1)
                        break;

                    v.Mem5[v.LastMinOffset & 0x7FFF] = (ushort)count;

                    if (v.LastMinOffset != v.Mem4[v.LastMinOffset & 0x7FFF])
                    {
                        restore = v.Mem4[v.LastMinOffset & 0x7FFF];
                        v.Mem4[v.LastMinOffset & 0x7FFF] = v.LastMinOffset;

                        ushort bufferWord = PeekWordBigEndian(v.PackBlockStart, v.PackBlockStartIdx - v.DictSize);
                        v.Mem2[bufferWord & 0x7FFF] = restore;

                        if (v.DictSize == restore)
                            v.Mem3[bufferWord & 0x7FFF] = v.DictSize;
                    }
                }
            }
        }

        protected void Proc6(ref Vars v)
        {
            v.V17 = 0;
            v.PackBlockLeftSize = v.PackBlockSize;
            v.InputOffset = (int)(v.ReadStartOffset + v.V7 + v.PackBlockPos);
            v.TempOffset = 0;

            uint dataLength = 0;

            while (v.BytesLeft != 0 || v.PackBlockPos != 0)
            {
                ushort sizeToRead = (ushort)(0xFFFF - v.DictSize - v.PackBlockPos);

                if (v.BytesLeft < sizeToRead)
                    sizeToRead = (ushort)v.BytesLeft;

                v.PackBlockStart = v.Mem1;
                v.PackBlockStartIdx = v.DictSize;
                ReadBuffer(v.PackBlockStart, v.PackBlockStartIdx + (int)v.PackBlockPos, v.Input, ref v.InputOffset, sizeToRead);

                v.BytesLeft -= sizeToRead;
                v.PackBlockPos += sizeToRead;

                v.PackBlockMax = v.PackBlockStart;
                v.PackBlockMaxIdx = v.PackBlockStartIdx + (int)v.PackBlockPos;
                v.PackBlockEnd = v.PackBlockStart;
                v.PackBlockEndIdx = v.PackBlockStartIdx + (int)v.PackBlockPos;

                if (v.PackBlockLeftSize < v.PackBlockPos)
                    v.PackBlockMaxIdx = v.PackBlockStartIdx + (int)v.PackBlockLeftSize;

                while ((v.PackBlockStartIdx < (v.PackBlockMaxIdx) - 1) && v.V17 < 0xFFFE)
                {
                    FindAndCheckMatches(ref v);

                    if (v.MatchCount >= 2)
                    {
                        if (v.PackBlockStartIdx + v.MatchCount <= v.PackBlockMaxIdx)
                        {
                            UpdateBitsTable(ref v, v.RawTable, (ushort)dataLength);
                            UpdateBitsTable(ref v, v.PosTable, (ushort)(v.MatchCount - 2));
                            UpdateBitsTable(ref v, v.LenTable, (ushort)(v.MatchOffset - 1));

                            EncodeMatches(ref v, v.MatchCount);
                            v.V17++;
                            dataLength = 0;
                        }
                        else
                        {
                            if (v.V17 != 0)
                                break;

                            v.MatchCount = (ushort)(v.PackBlockMax.Length - v.PackBlockStart.Length);
                        }
                    }
                    else
                    {
                        EncodeMatches(ref v, 1);
                        dataLength++;
                    }
                }

                v.PackBlockPos = (uint)(v.PackBlockEndIdx - v.PackBlockStartIdx);

                Buffer.BlockCopy(v.PackBlockStart, v.PackBlockStartIdx - v.DictSize, v.Mem1, 0, (int)(v.DictSize + v.PackBlockPos));

                if ((v.PackBlockMaxIdx < v.PackBlockEndIdx) || ((v.PackBlockMaxIdx == v.PackBlockEndIdx) && v.BytesLeft == 0) || v.V17 == 0xFFFE)
                    break;

                v.PackBlockLeftSize -= (uint)(v.PackBlockStartIdx - v.Mem1.Length);
            }

            if (v.PackBlockMaxIdx == v.PackBlockEndIdx && v.BytesLeft == 0 && v.V17 != 0xFFFE)
                dataLength += v.PackBlockPos;

            UpdateBitsTable(ref v, v.RawTable, (ushort)dataLength);
            v.V17++;

            v.TempOffset = 0;
        }

        protected void UpdateTmpCrcData(ref Vars v, byte b)
        {
            if (v.BitCount != 0)
            {
                v.TmpCrcData[v.V11] = b;
                v.V11++;
            }
            else
            {
                WriteToOutput(ref v, b);
            }
        }

        protected void EncodeMatchesCount(ref Vars v, int count)
        {
            while (count > 0)
            {
                if (count >= 12)
                {
                    if ((count & 3) != 0)
                    {
                        WriteBitsM2(ref v, 0, 1);

                        byte b = ReadFromInput(ref v);
                        UpdateTmpCrcData(ref v, (byte)(v.EncKey ^ b));

                        count--;
                    }
                    else
                    {
                        WriteBitsM2(ref v, 0x17, 5);

                        if (count >= 72)
                        {
                            WriteBitsM2(ref v, 0xF, 4);

                            for (int i = 0; i < 72; ++i)
                            {
                                byte b = ReadFromInput(ref v);
                                UpdateTmpCrcData(ref v, (byte)(v.EncKey ^ b));
                            }

                            count -= 72;
                        }
                        else
                        {
                            WriteBitsM2(ref v, (ushort)((count - 12) >> 2), 4);

                            while (count != 0)
                            {
                                byte b = ReadFromInput(ref v);
                                UpdateTmpCrcData(ref v, (byte)(v.EncKey ^ b));
                                count--;
                            }
                        }
                    }

                    RorW(ref v.EncKey);
                }
                else
                {
                    while (count != 0)
                    {
                        WriteBitsM2(ref v, 0, 1);

                        byte b = ReadFromInput(ref v);
                        UpdateTmpCrcData(ref v, (byte)(v.EncKey ^ b));

                        RorW(ref v.EncKey);

                        count--;
                    }
                }
            }
        }

        protected void ClearTable(Huftable[] data, int count)
        {
            for (int i = 0; i < count; ++i)
            {
                data[i].l1 = 0;
                data[i].l2 = 0xFFFF;
                data[i].l3 = 0;
                data[i].BitDepth = 0;
            }
        }

        protected bool Proc17(ref Vars v, Huftable[] data, int count)
        {
            uint d6 = 0xFFFFFFFF;
            uint d5 = 0xFFFFFFFF;

            int i = 0;
            while (i < count)
            {
                if (data[i].l1 != 0)
                {
                    if (data[i].l1 < d5)
                    {
                        d6 = d5;
                        v.V21 = v.V20;
                        d5 = data[i].l1;
                        v.V20 = (uint)i;
                    }
                    else if (data[i].l1 < d6)
                    {
                        d6 = data[i].l1;
                        v.V21 = (uint)i;
                    }
                }

                i++;
            }

            return (d5 != 0xFFFFFFFF && d6 != 0xFFFFFFFF);
        }

        protected uint InverseBits(uint value, int count)
        {
            int i = 0;
            while (count-- != 0)
            {
                i <<= 1;

                if ((value & 1) != 0)
                    i |= 1;

                value >>= 1;
            }

            return (uint)i;
        }

        protected void Proc20(Huftable[] data, int count)
        {
            int val = 0;
            uint div = 0x80000000;
            int bitsCount = 1;

            while (bitsCount <= 16)
            {
                int i = 0;

                while (true)
                {
                    if (i >= count)
                    {
                        bitsCount++;
                        div >>= 1;
                        break;
                    }

                    if (data[i].BitDepth == bitsCount)
                    {
                        data[i].l3 = InverseBits((uint)(val / div), bitsCount);
                        val += (int)div;
                    }

                    i++;
                }
            }
        }

        protected void Proc16(ref Vars v, Huftable[] data, int count)
        {
            int d4 = 0;
            int ve = 0;

            for (int i = 0; i < count; ++i)
            {
                if (data[i].l1 != 0)
                {
                    d4++;
                    ve = i;
                }
            }

            if (d4 == 0)
                return;

            if (d4 == 1)
            {
                data[ve].BitDepth++;
                return;
            }

            while (Proc17(ref v, data, count))
            {
                data[v.V20].l1 += data[v.V21].l1;
                data[v.V21].l1 = 0;
                data[v.V20].BitDepth++;

                while (data[v.V20].l2 != 0xFFFF)
                {
                    v.V20 = data[v.V20].l2;
                    data[v.V20].BitDepth++;
                }

                data[v.V20].l2 = (ushort)v.V21;
                data[v.V21].BitDepth++;

                while (data[v.V21].l2 != 0xFFFF)
                {
                    v.V21 = data[v.V21].l2;
                    data[v.V21].BitDepth++;
                }
            }

            Proc20(data, count);
        }

        protected void Proc18(ref Vars v, Huftable[] data, int count)
        {
            int cnt = count;

            while (cnt != 0 && data[--cnt].BitDepth == 0)
                count--;

            WriteBitsM1(ref v, (ushort)count, 5);

            for (int i = 0; i < count; ++i)
                WriteBitsM1(ref v, data[i].BitDepth, 4);
        }

        protected void Proc19(ref Vars v, Huftable[] data, int count)
        {
            int bits;

            if (count > 1)
                bits = BitsCount(count);
            else
                bits = count;

            WriteBitsM1(ref v, (ushort)data[bits].l3, data[bits].BitDepth);

            if (bits > 1)
                WriteBitsM1(ref v, (ushort)(count - (1 << (bits - 1))), bits - 1);
        }

        protected void CompressData2(ref Vars v)
        {
            int srcOffset = v.ReadStartOffset;

            while (v.V7 < v.UnPackedSize)
            {
                Proc6(ref v);
                v.InputOffset = srcOffset;

                while (v.V17-- > 0)
                {
                    uint dataLength = ReadWordBigEndian(v.Temp, ref v.TempOffset);
                    v.V7 += dataLength;

                    EncodeMatchesCount(ref v, (int)dataLength);

                    if (v.V17 > 0)
                    {
                        v.MatchCount = ReadWordBigEndian(v.Temp, ref v.TempOffset);
                        v.MatchOffset = ReadWordBigEndian(v.Temp, ref v.TempOffset);

                        if (v.MatchCount > 0)
                        {
                            if (v.MatchCount >= 7)
                            {
                                WriteBitsM2(ref v, 0xF, 4);
                                UpdateTmpCrcData(ref v, (byte)((v.MatchCount - 6) & 0xFF)); // Assuming this method is defined elsewhere
                            }
                            else
                                WriteBitsM2(ref v, MatchCountBitsTable[v.MatchCount], MatchCountBitsCountTable[v.MatchCount]);

                            WriteBitsM2(ref v, MatchOffsetBitsTable[v.MatchOffset >> 8], MatchOffsetBitsCountTable[v.MatchOffset >> 8]);
                        }
                        else
                        {
                            WriteBitsM2(ref v, 6, 3);
                        }

                        UpdateTmpCrcData(ref v, (byte)(v.MatchOffset & 0xFF)); // Assuming this method is defined elsewhere

                        v.MatchCount += 2;
                        v.V7 += v.MatchCount;

                        while (v.MatchCount-- > 0)
                            ReadFromInput(ref v);
                    }
                }

                WriteBitsM2(ref v, 0xF, 4);
                UpdateTmpCrcData(ref v, 0); // Assuming this method is defined elsewhere

                if (v.V7 >= v.UnPackedSize)
                    WriteBitsM2(ref v, 0, 1);
                else
                    WriteBitsM2(ref v, 1, 1);

                if (v.BitCount == 0)
                {
                    for (int i = 0; i < v.V11; ++i)
                        WriteToOutput(ref v, v.TmpCrcData[i]);

                    v.V11 = 0;
                }

                v.ChunksCount++;
                srcOffset = v.InputOffset;
            }

            v.PackToken <<= (8 - v.BitCount);

            if (v.BitCount > 0 || v.V11 > 0)
                WriteToOutput(ref v, (byte)(v.PackToken & 0xFF));
        }

        protected void CompressData1(ref Vars v)
        {
            int srcOffset = v.ReadStartOffset;

            while (v.V7 < v.UnPackedSize)
            {
                ClearTable(v.LenTable, v.LenTable.Length);
                ClearTable(v.PosTable, v.PosTable.Length);
                ClearTable(v.RawTable, v.RawTable.Length);

                Proc6(ref v); // Assuming this method is defined elsewhere
                v.InputOffset = srcOffset;

                Proc16(ref v, v.RawTable, v.RawTable.Length);
                Proc16(ref v, v.LenTable, v.LenTable.Length);
                Proc16(ref v, v.PosTable, v.PosTable.Length);

                Proc18(ref v, v.RawTable, v.RawTable.Length);
                Proc18(ref v, v.LenTable, v.LenTable.Length);
                Proc18(ref v, v.PosTable, v.PosTable.Length);

                WriteBitsM1(ref v, (ushort)v.V17, 16);

                while (v.V17-- > 0)
                {
                    uint dataLength = ReadWordBigEndian(v.Temp, ref v.TempOffset);
                    v.V7 += dataLength;

                    Proc19(ref v, v.RawTable, (int)dataLength);

                    if (dataLength > 0)
                    {
                        while (dataLength-- > 0)
                        {
                            byte b = ReadFromInput(ref v);

                            if (v.BitCount == 0)
                                WriteToOutput(ref v, (byte)((v.EncKey ^ b) & 0xFF));
                            else
                            {
                                v.TmpCrcData[v.V11] = (byte)((v.EncKey ^ b) & 0xFF);
                                v.V11++;
                            }
                        }

                        RorW(ref v.EncKey);
                    }

                    if (v.V17 > 0)
                    {
                        v.MatchCount = ReadWordBigEndian(v.Temp, ref v.TempOffset);
                        v.MatchOffset = ReadWordBigEndian(v.Temp, ref v.TempOffset);

                        Proc19(ref v, v.LenTable, v.MatchOffset);
                        Proc19(ref v, v.PosTable, v.MatchCount);

                        v.MatchCount += 2;
                        v.V7 += v.MatchCount;

                        while (v.MatchCount-- > 0)
                            ReadFromInput(ref v);
                    }
                }

                if (v.BitCount == 0)
                {
                    for (int i = 0; i < v.V11; ++i)
                        WriteToOutput(ref v, v.TmpCrcData[i]);

                    v.V11 = 0;
                }

                v.ChunksCount++;
                srcOffset = v.InputOffset;
            }

            v.PackToken >>= (16 - v.BitCount);

            if (v.BitCount > 8 || v.V11 > 0)
                WriteToOutput(ref v, (byte)(v.PackToken & 0xFF));
            if (v.BitCount > 8 || v.V11 > 0)
                WriteToOutput(ref v, (byte)(v.PackToken >> 8));
        }

        protected void DoPackData(ref Vars v)
        {
            v.UnPackedSize = v.FileSize;
            v.PackedSize = v.FileSize;
            v.BytesLeft = v.FileSize;

            if (v.FileSize <= RNC_HEADER_SIZE)
                return;

            v.UnpackedCrc = 0;
            v.PackedCrc = 0;
            v.PackedSize = 0;
            v.ProcessedSize = 0;
            v.V7 = 0;
            v.PackBlockPos = 0;
            v.PackToken = 0;
            v.BitCount = 0;
            v.V11 = 0;
            v.Leeway = 0;
            v.ChunksCount = 0;

            v.Mem1 = new byte[0xFFFF];
            v.Mem2 = new ushort[0x10000/2];
            v.Mem3 = new ushort[0x10000/2];
            v.Mem4 = new ushort[0x10000/2];
            v.Mem5 = new ushort[0x10000/2];

            InitDicts(ref v);

            WriteDWordBigEndian(v.Output, ref v.OutputOffset, (RNC_SIGN << 8) | (v.Method & 0xFF));
            WriteDWordBigEndian(v.Output, ref v.OutputOffset, v.UnPackedSize);
            WriteDWordBigEndian(v.Output, ref v.OutputOffset, 0);
            WriteWordBigEndian(v.Output, ref v.OutputOffset, 0);
            WriteWordBigEndian(v.Output, ref v.OutputOffset, 0);
            WriteWordBigEndian(v.Output, ref v.OutputOffset, 0);

            ushort key = v.EncKey;
            WriteBits(ref v, 0, 1); // no lock
            WriteBits(ref v, (ushort)((v.EncKey != 0) ? 1 : 0), 1);

            switch (v.Method)
            {
                case 1:
                    CompressData1(ref v);
                    break;
                case 2:
                    CompressData2(ref v);
                    break;
            }

            for (int i = 0; i < v.V11; ++i)
                WriteToOutput(ref v, v.TmpCrcData[i]);

            v.V11 = 0;
            v.EncKey = key;

            if (v.Leeway > (v.UnPackedSize - v.PackedSize))
                v.Leeway -= (v.UnPackedSize - v.PackedSize);
            else
                v.Leeway = 0;

            if (v.Method == 2)
                v.Leeway += 2;

            v.PackedSize = (uint)(v.OutputOffset - v.WriteStartOffset);

            v.OutputOffset = v.WriteStartOffset + 8;
            WriteDWordBigEndian(v.Output, ref v.OutputOffset, v.PackedSize - RNC_HEADER_SIZE);
            WriteWordBigEndian(v.Output, ref v.OutputOffset, v.UnpackedCrc);
            WriteWordBigEndian(v.Output, ref v.OutputOffset, v.PackedCrc);
            WriteByte(v.Output, ref v.OutputOffset, (byte)v.Leeway);
            WriteByte(v.Output, ref v.OutputOffset, (byte)v.ChunksCount);

            v.OutputOffset = (int)(v.PackedSize + v.WriteStartOffset);
            v.InputOffset = (int)(v.UnPackedSize + v.ReadStartOffset);
        }

        public int DoPack(ref Vars v)
        {
            if (v.FileSize <= RNC_HEADER_SIZE)
                return 2;

            v.InputOffset = 0;
            v.OutputOffset = 0;

            if ((PeekDWordBigEndian(v.Input, v.InputOffset) >> 8) == RNC_SIGN)
                return 3;

            DoPackData(ref v);
            return 0;
        }

        public int DoPackageBullfrogFilesToDatandTab(ref Vars v, string[] filePaths, int fileSizeBytes, int tabSizeBytes, bool save, bool createTab, string outputPath)
        {
            return DoPackage(ref v, filePaths, fileSizeBytes, tabSizeBytes, save, true, outputPath, new byte[] { 0x42, 0x55, 0x4C, 0x4C, 0x46, 0x52, 0x4F, 0x47 });
        }
        
        public int DoPackage(ref Vars v, string[] filePaths, int fileSizeBytes, int tabSizeBytes, bool save, bool createTab, string outputPath, byte[] header = null)
        {
            var existingFiles = filePaths.Where(f => File.Exists(f));
            var errorCode = 0;

            if (existingFiles is null || !existingFiles.Any())
            {
                throw new ArgumentNullException(nameof(existingFiles));
            }

            if (!Directory.Exists(Path.GetDirectoryName(outputPath)))
            {
                throw new ArgumentNullException(Path.GetDirectoryName(outputPath));
            }

            List<byte[]> packedFiles = new List<byte[]>();

            foreach (var filePath in existingFiles)
            {
                var vars = InitVars();
                vars.Output = new byte[0x1E00000];
                vars.Temp = new byte[0x1E00000];

                if (fileSizeBytes == 0)
                    vars.Input = File.ReadAllBytes(filePath);
                else
                {
                    vars.Input = new byte[fileSizeBytes];
                    Array.Copy(File.ReadAllBytes(filePath), vars.Input, fileSizeBytes);
                }
                vars.FileSize = (uint)(vars.Input.Length - vars.ReadStartOffset);
                vars.DictSize = 0x8000;

                errorCode = DoPack(ref vars);
                if (errorCode != 0)
                    return errorCode;

                var bytes = new byte[vars.OutputOffset];
                Array.Copy(vars.Output, bytes, vars.OutputOffset);
                packedFiles.Add(bytes);
                Logger?.LogInformation($"Added File: {filePath}");
            }

            // Define Header for DAT file
            v.Output = new byte[(packedFiles.Sum(f => f.Length)) + header.Length];

            WriteToArray(header, v.Output, 0); // BULLFROG

            int fileOffsetIndex = header.Length;

            foreach (var fileBytes in packedFiles)
            {
                WriteToArray(fileBytes, v.Output, fileOffsetIndex);
                fileOffsetIndex += fileBytes.Length;
            }

            if (save)
                File.WriteAllBytes(outputPath, v.Output);

            if (createTab)
            {
                fileOffsetIndex = 8;
                int fileIndex = 4;
                v.OutputTab = new byte[tabSizeBytes];
                WriteToArray(new byte[] { 0x08, 0x00, 0x00, 0x00 }, v.OutputTab, 0); // BULLFROG header means first entry is always byte 08

                foreach (var filePath in existingFiles)
                {
                    var file = File.ReadAllBytes(filePath);
                    fileOffsetIndex += file.Length;
                    WriteToArray(BitConverter.GetBytes(fileOffsetIndex), v.OutputTab, fileIndex);
                    fileIndex += 4;
                    Console.WriteLine($"Added File Address: {fileIndex}");
                }

                if (save)
                {
                    var tabFileName = Path.GetFileNameWithoutExtension(outputPath) + ".TAB";
                    File.WriteAllBytes(Path.Combine(Path.GetDirectoryName(outputPath), tabFileName), v.OutputTab);
                }
            }
            return 0;
        }

        protected void WriteToArray(byte[] source, byte[] destination, int startIdx)
        {
            Buffer.BlockCopy(source, 0, destination, startIdx, source.Length);
        }

        protected byte ReadSourceByte(ref Vars v)
        {
            if (v.PackBlockStartIdx == 0xFFFD)
            {
                int leftSize = (int)(v.FileSize - v.InputOffset);

                int sizeToRead = Math.Min(leftSize, 0xFFFD);

                v.PackBlockStartIdx = 0;
                v.PackBlockStart = v.Mem1;

                ReadBuffer(v.PackBlockStart, v.Input, ref v.InputOffset, sizeToRead);

                if (leftSize - sizeToRead > 2)
                {
                    leftSize = 2;
                }
                else
                {
                    leftSize -= sizeToRead;
                }

                ReadBuffer(v.Mem1, sizeToRead, v.Input, ref v.InputOffset, leftSize);
                v.InputOffset -= leftSize;
            }

            return v.PackBlockStart[v.PackBlockStartIdx++];
        }

        protected uint InputBitsM2(Vars v, short count)
        {
            uint bits = 0;

            while (count-- > 0)
            {
                if (v.BitCount == 0)
                {
                    v.BitBuffer = ReadSourceByte(ref v);
                    v.BitCount = 8;
                }

                bits <<= 1;

                if ((v.BitBuffer & 0x80) != 0)
                    bits |= 1;

                v.BitBuffer <<= 1;
                v.BitCount--;
            }

            return bits;
        }

        protected uint InputBitsM1(ref Vars v, short count)
        {
            uint bits = 0;
            uint prevBits = 1;

            while (count-- > 0)
            {
                if (v.BitCount == 0)
                {
                    byte b1 = ReadSourceByte(ref v);
                    byte b2 = ReadSourceByte(ref v);
                    v.BitBuffer = (uint)((v.PackBlockStart[v.PackBlockStartIdx + 1] << 24) | (v.PackBlockStart[v.PackBlockStartIdx] << 16) | (b2 << 8) | b1);

                    v.BitCount = 16;
                }

                if ((v.BitBuffer & 1) != 0)
                    bits |= prevBits;

                v.BitBuffer >>= 1;
                prevBits <<= 1;
                v.BitCount--;
            }

            return bits;
        }

        protected int InputBits(ref Vars v, short count)
        {
            return (int)(v.Method != 2 ? InputBitsM1(ref v, count) : InputBitsM2(v, count));
        }

        protected void DecodeMatchCount(Vars v)
        {
            v.MatchCount = (ushort)(InputBitsM2(v, 1) + 4);

            if (InputBitsM2(v, 1) != 0)
                v.MatchCount = (ushort)(((v.MatchCount - 1) << 1) + (int)InputBitsM2(v, 1));
        }

        protected void DecodeMatchOffset(ref Vars v)
        {
            v.MatchOffset = 0;
            if (InputBitsM2(v, 1) != 0)
            {
                v.MatchOffset = (ushort)InputBitsM2(v, 1);

                if (InputBitsM2(v, 1) != 0)
                {
                    v.MatchOffset = (ushort)(((v.MatchOffset << 1) | (int)InputBitsM2(v, 1)) | 4);

                    if (InputBitsM2(v, 1) == 0)
                        v.MatchOffset = (ushort)((v.MatchOffset << 1) | (int)InputBitsM2(v, 1));
                }
                else if (v.MatchOffset == 0)
                    v.MatchOffset = (ushort)(InputBitsM2(v, 1) + 2);
            }

            v.MatchOffset = (ushort)(((v.MatchOffset << 8) | ReadSourceByte(ref v)) + 1);
        }

        protected void WriteDecodedByte(ref Vars v, byte b)
        {
            if (v.WindowIdx == 0xFFFF)
            {
                WriteBuffer(v.Output, ref v.OutputOffset, v.Decoded.Skip(v.DictSize).ToArray(), 0xFFFF - v.DictSize);
                Array.Copy(v.Decoded.Skip(v.WindowIdx -v.DictSize).ToArray(), 0, v.Decoded, 0, v.DictSize);
                v.WindowIdx = v.DictSize;
            }

            v.Decoded[v.WindowIdx] = b;
            v.WindowIdx++;
            v.UnpackedCrcReal = (ushort)(CrcTable[(v.UnpackedCrcReal ^ b) & 0xFF] ^ (v.UnpackedCrcReal >> 8));
        }

        protected int UnpackDataM2(ref Vars v)
        {
            while (v.ProcessedSize < v.InputSize)
            {
                while (true)
                {
                    if (InputBitsM2(v, 1) == 0)
                    {
                        WriteDecodedByte(ref v, (byte)((v.EncKey ^ ReadSourceByte(ref v)) & 0xFF));
                        RorW(ref v.EncKey);
                        v.ProcessedSize++;
                    }
                    else
                    {
                        if (InputBitsM2(v, 1) != 0)
                        {
                            if (InputBitsM2(v, 1) != 0)
                            {
                                if (InputBitsM2(v, 1) != 0)
                                {
                                    v.MatchCount = (ushort)(ReadSourceByte(ref v) + 8);

                                    if (v.MatchCount == 8)
                                    {
                                        InputBitsM2(v, 1);
                                        break;
                                    }
                                }
                                else
                                    v.MatchCount = 3;

                                DecodeMatchOffset(ref v);
                            }
                            else
                            {
                                v.MatchCount = 2;
                                v.MatchOffset = (ushort)(ReadSourceByte(ref v) + 1);
                            }

                            v.ProcessedSize += v.MatchCount;

                            while (v.MatchCount-- > 0)
                                WriteDecodedByte(ref v, v.Decoded[v.WindowIdx + v.DictSize - v.MatchOffset]);
                        }
                        else
                        {
                            DecodeMatchCount(v);

                            if (v.MatchCount != 9)
                            {
                                DecodeMatchOffset(ref v);
                                v.ProcessedSize += v.MatchCount;

                                while (v.MatchCount-- > 0)
                                    WriteDecodedByte(ref v, v.Decoded[v.WindowIdx + v.DictSize - v.MatchOffset]);
                            }
                            else
                            {
                                uint dataLength = (InputBitsM2(v, 4) << 2) + 12;
                                v.ProcessedSize += dataLength;

                                while (dataLength-- > 0)
                                    WriteDecodedByte(ref v, (byte)((v.EncKey ^ ReadSourceByte(ref v)) & 0xFF));

                                RorW(ref v.EncKey);
                            }
                        }
                    }
                }
            }

            Array.Copy(v.Decoded, v.DictSize, v.Output, v.OutputOffset, v.WindowIdx - v.DictSize);
            return 0;
        }

        protected void MakeHuffTable(ref Vars v, Huftable[] data, int count)
        {
            ClearTable(data, count);

            int leafNodes = (int)InputBitsM1(ref v, 5);

            if (leafNodes > 0)
            {
                if (leafNodes > 16)
                    leafNodes = 16;

                for (int i = 0; i < leafNodes; ++i)
                    data[i].BitDepth = (ushort)InputBitsM1(ref v, 4);

                Proc20(data, leafNodes);
            }
        }

        protected uint DecodeTableData(ref Vars v, Huftable[] data)
        {
            int i = 0;

            while (true)
            {
                if (data[i].BitDepth != 0 && data[i].l3 == (v.BitBuffer & ((1 << data[i].BitDepth) - 1)))
                {
                    InputBitsM1(ref v, (short)data[i].BitDepth);

                    if (i < 2)
                        return (uint)i;

                    return InputBitsM1(ref v, (short)(i - 1)) | (uint)(1 << (i - 1));
                }

                i++;
            }
        }

        protected int UnpackDataM1(ref Vars v)
        {
            while (v.ProcessedSize < v.InputSize)
            {
                MakeHuffTable(ref v, v.RawTable, v.RawTable.Length);
                MakeHuffTable(ref v, v.LenTable, v.LenTable.Length);
                MakeHuffTable(ref v, v.PosTable, v.PosTable.Length);

                int subchunks = (int)InputBitsM1(ref v, 16);

                while (subchunks-- > 0)
                {
                    uint dataLength = DecodeTableData(ref v, v.RawTable);
                    v.ProcessedSize += dataLength;

                    if (dataLength != 0)
                    {
                        while (dataLength-- > 0)
                            WriteDecodedByte(ref v, (byte)((v.EncKey ^ ReadSourceByte(ref v)) & 0xFF));

                        RorW(ref v.EncKey);

                        v.BitBuffer = (uint)((((v.PackBlockStart[v.PackBlockStartIdx + 2] << 16) | (v.PackBlockStart[v.PackBlockStartIdx + 1] << 8) | v.PackBlockStart[v.PackBlockStartIdx]) << v.BitCount) | (v.BitBuffer & ((1 << v.BitCount) - 1)));
                    }

                    if (subchunks > 0)
                    {
                        v.MatchOffset = (ushort)(DecodeTableData(ref v, v.LenTable) + 1);
                        v.MatchCount = (ushort)(DecodeTableData(ref v, v.PosTable) + 2);
                        v.ProcessedSize += v.MatchCount;

                        while (v.MatchCount-- > 0)
                            WriteDecodedByte(ref v, v.Decoded[v.WindowIdx - v.MatchOffset]);
                    }
                }
            }

            WriteBuffer(v.Output, ref v.OutputOffset, v.Decoded.Skip(v.DictSize).ToArray(), v.WindowIdx - v.DictSize);
            return 0;
        }

        public int DoUnpackData(ref Vars v)
        {
            int start_pos = v.InputOffset;

            uint sign = ReadDWordBigEndian(v.Input, ref v.InputOffset);
            if ((sign >> 8) != RNC_SIGN)
                return 6;

            v.Method = sign & 3;
            v.InputSize = ReadDWordBigEndian(v.Input, ref v.InputOffset);
            v.PackedSize = ReadDWordBigEndian(v.Input, ref v.InputOffset);
            if (v.FileSize < v.PackedSize)
                return 7;
            v.UnpackedCrc = ReadWordBigEndian(v.Input, ref v.InputOffset);
            v.PackedCrc = ReadWordBigEndian(v.Input, ref v.InputOffset);

            ReadByte(v.Input, ref v.InputOffset);
            ReadByte(v.Input, ref v.InputOffset);

            if (CrcBlock(v.Input, v.InputOffset, (int)v.PackedSize) != v.PackedCrc)
                return 4;

            v.Mem1 = new byte[0xFFFF];
            v.Decoded = new byte[0xFFFF];
            v.PackBlockStart = v.Mem1;
            v.PackBlockStartIdx = 0xFFFD;
            v.WindowIdx = v.DictSize;

            v.UnpackedCrcReal = 0;
            v.BitCount = 0;
            v.BitBuffer = 0;
            v.ProcessedSize = 0;

            ushort specified_key = v.EncKey;

            int error_code = 0;
            if (InputBits(ref v, 1) != 0 && v.PuseMode == 'p')
                error_code = 9;

            if (error_code == 0)
            {
                if (InputBits(ref v, 1) != 0 && v.EncKey == 0) // key is needed, but not specified as argument
                    error_code = 10;
            }

            if (error_code == 0)
            {
                switch (v.Method)
                {
                    case 1: error_code = UnpackDataM1(ref v); break;
                    case 2: error_code = UnpackDataM2(ref v); break;
                }
            }

            v.EncKey = specified_key;

            v.Mem1 = null;
            v.Decoded = null;

            v.InputOffset = (int)(start_pos + v.PackedSize + RNC_HEADER_SIZE);

            if (error_code != 0)
                return error_code;

            if (v.UnpackedCrc != v.UnpackedCrcReal)
                return 5;

            return 0;
        }

        public int DoUnpack(ref Vars v)
        {
            v.PackedSize = v.FileSize;

            if (v.FileSize < RNC_HEADER_SIZE)
                return 6;

            return DoUnpackData(ref v); // data
        }

        public int DoSearch(ref Vars v, uint input_size, bool save, string outDir = "extracted")
        {
            int error_code = 11;
            bool has_rncs = false;

            for (uint i = 0; i < input_size - RNC_HEADER_SIZE;)
            {
                v.ReadStartOffset = (int)i;
                v.FileSize = input_size - i;
                v.InputOffset = 0;
                v.OutputOffset = 0;

                byte[] input_ptr = v.Input;
                v.Input = new byte[v.FileSize];
                Array.Copy(input_ptr, i, v.Input, 0, v.FileSize);

                if ((error_code = DoUnpack(ref v)) == 0)
                {
                    Logger?.LogInformation($"RNC archive found: 0x{i:X6} ({v.PackedSize + RNC_HEADER_SIZE}/{v.OutputOffset}/{input_size} bytes)");
                    i += v.PackedSize + RNC_HEADER_SIZE;
                    error_code = 0;
                    has_rncs = true;

                    if (save)
                    {
                        Directory.CreateDirectory(outDir);

                        string outName = $"{outDir}/data_{v.ReadStartOffset:X6}.bin";

                        using (FileStream outFile = new FileStream(outName, FileMode.Create, FileAccess.Write))
                        {
                            outFile.Write(v.Output, 0, v.OutputOffset);
                        }
                    }
                }
                else
                {
                    switch (error_code)
                    {
                        case 4: Logger?.LogError($"Position 0x{i:X6}: Packed CRC is wrong!"); break;
                        case 5: Logger?.LogError($"Position 0x{i:X6}: Unpacked CRC is wrong!"); break;
                        case 9: Logger?.LogError($"Position 0x{i:X6}: File already packed!"); break;
                        case 10: Logger?.LogError($"Position 0x{i:X6}: Decryption key required!"); break;
                    }

                    i++;
                }

                v.Input = input_ptr;
            }

            return has_rncs ? 0 : ((error_code == 6) ? 11 : error_code);
        }
    }
}
