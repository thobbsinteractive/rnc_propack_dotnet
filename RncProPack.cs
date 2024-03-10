namespace rnc_propack_dotnet
{
    public class RncProPack
    {
        public byte PeekByte(byte[] buf, ulong offset)
        {
            return buf[offset];
        }

        public byte ReadByte(byte[] buf, ref ulong offset)
        {
            return buf[offset++];
        }

        public void WriteByte(byte[] buf, ref ulong offset, byte b)
        {
            buf[offset++] = b;
        }

        public ushort PeekWordBigEndian(byte[] buf, ulong offset)
        {
            byte b1 = PeekByte(buf, offset + 0);
            byte b2 = PeekByte(buf, offset + 1);

            return (ushort)((b1 << 8) | b2);
        }
    }
}
