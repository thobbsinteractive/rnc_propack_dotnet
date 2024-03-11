using System;

namespace rnc_propack_dotnet
{
    public class RncProPack
    {
        public byte PeekByte(byte[] buf, int offset)
        {
            return buf[offset];
        }

        public byte ReadByte(byte[] buf, ref int offset)
        {
            return buf[offset++];
        }

        public void WriteByte(byte[] buf, ref int offset, byte b)
        {
            buf[offset++] = b;
        }

        public ushort PeekWordBigEndian(byte[] buf, int offset)
        {
            byte b1 = PeekByte(buf, offset + 0);
            byte b2 = PeekByte(buf, offset + 1);

            return (ushort)((b1 << 8) | b2);
        }
        public ushort ReadWordBigEndian(byte[] buf, ref int offset)
        {
            byte b1 = ReadByte(buf, ref offset);
            byte b2 = ReadByte(buf, ref offset);

            return (ushort)((b1 << 8) | b2);
        }

        public void WriteWordBigEndian(byte[] buf, ref int offset, ushort val)
        {
            WriteByte(buf, ref offset, (byte)((val >> 8) & 0xFF));
            WriteByte(buf, ref offset, (byte)((val >> 0) & 0xFF));
        }

        public uint PeekDWordBigEndian(byte[] buf, int offset)
        {
            ushort w1 = PeekWordBigEndian(buf, offset + 0);
            ushort w2 = PeekWordBigEndian(buf, offset + 2);

            return ((uint)w1 << 16) | w2;
        }

        public uint ReadDWordBigEndian(byte[] buf, ref int offset)
        {
            ushort w1 = ReadWordBigEndian(buf, ref offset);
            ushort w2 = ReadWordBigEndian(buf, ref offset);

            return ((uint)w1 << 16) | w2;
        }

        public void WriteDWordBigEndian(byte[] buf, ref int offset, uint val)
        {
            WriteWordBigEndian(buf, ref offset, (ushort)(val >> 16));
            WriteWordBigEndian(buf, ref offset, (ushort)(val & 0xFFFF));
        }

        public void ReadBuffer(byte[] dest, byte[] source, ref int offset, int size)
        {
            Buffer.BlockCopy(source, offset, dest, 0, size);
            offset += size;
        }

        public void WriteBuffer(byte[] dest, ref int offset, byte[] source, int size)
        {
            Buffer.BlockCopy(source, 0, dest, offset, size);
            offset += size;
        }
    }
}
