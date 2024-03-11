using RncProPackDotnet;
using System;

namespace rnc_propack_dotnet
{
    public class RncProPack
    {
        private const uint RNC_SIGN = 0x524E43; // RNC
        private const byte RNC_HEADER_SIZE = 0x12;
        private const uint MAX_BUF_SIZE = 0x1E00000;

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

        private static readonly byte[] match_count_bits_table = { 0x00, 0x0E, 0x08, 0x0A, 0x012, 0x013, 0x016 };
        private static readonly byte[] match_count_bits_count_table = { 0, 4, 4, 4, 5, 5, 5 };
        private static readonly byte[] match_offset_bits_table = { 0x00, 0x06, 0x08, 0x09, 0x15, 0x17, 0x1D, 0x1F, 0x28, 0x29, 0x2C, 0x2D, 0x38, 0x39, 0x3C, 0x3D };
        private static readonly byte[] match_offset_bits_count_table = { 1, 3, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6 };

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

        public ushort CrcBlock(byte[] buf, ref int offset, int size)
        {
            ushort crc = 0;

            while (size-- > 0)
            {
                crc ^= ReadByte(buf, ref offset);
                crc = (ushort)((crc >> 8) ^ CrcTable[crc & 0xFF]);
            }

            return crc;
        }

        public void RorW(ref ushort x)
        {
            if ((x & 1) != 0)
                x = (ushort)(0x8000 | (x >> 1));
            else
                x >>= 1;
        }

        public Vars InitVars()
        {
            Vars v = new Vars();
            v.enc_key = 0;
            v.max_matches = 0x1000;
            v.unpacked_crc_real = 0;
            v.pack_block_size = 0x3000;
            v.dict_size = 0xFFFF;
            v.method = 1;
            v.puse_mode = 'p';

            v.read_start_offset = 0;
            v.write_start_offset = 0;
            v.input_offset = 0;
            v.output_offset = 0;
            v.temp_offset = 0;

            Array.Clear(v.tmp_crc_data, 0, v.tmp_crc_data.Length);
            Array.Clear(v.raw_table, 0, v.raw_table.Length);
            Array.Clear(v.pos_table, 0, v.pos_table.Length);
            Array.Clear(v.len_table, 0, v.len_table.Length);

            return v;
        }

        public void InitDicts(ref Vars v)
        {
            ushort dict_size = v.dict_size;

            for (int i = 0; i < 0x800; ++i)
            {
                v.mem2[i * 0x10 + 0x0] = dict_size; v.mem2[i * 0x10 + 0x1] = dict_size;
                v.mem2[i * 0x10 + 0x2] = dict_size; v.mem2[i * 0x10 + 0x3] = dict_size;
                v.mem2[i * 0x10 + 0x4] = dict_size; v.mem2[i * 0x10 + 0x5] = dict_size;
                v.mem2[i * 0x10 + 0x6] = dict_size; v.mem2[i * 0x10 + 0x7] = dict_size;
                v.mem2[i * 0x10 + 0x8] = dict_size; v.mem2[i * 0x10 + 0x9] = dict_size;
                v.mem2[i * 0x10 + 0xA] = dict_size; v.mem2[i * 0x10 + 0xB] = dict_size;
                v.mem2[i * 0x10 + 0xC] = dict_size; v.mem2[i * 0x10 + 0xD] = dict_size;
                v.mem2[i * 0x10 + 0xE] = dict_size; v.mem2[i * 0x10 + 0xF] = dict_size;

                v.mem3[i * 0x10 + 0x0] = dict_size; v.mem3[i * 0x10 + 0x1] = dict_size;
                v.mem3[i * 0x10 + 0x2] = dict_size; v.mem3[i * 0x10 + 0x3] = dict_size;
                v.mem3[i * 0x10 + 0x4] = dict_size; v.mem3[i * 0x10 + 0x5] = dict_size;
                v.mem3[i * 0x10 + 0x6] = dict_size; v.mem3[i * 0x10 + 0x7] = dict_size;
                v.mem3[i * 0x10 + 0x8] = dict_size; v.mem3[i * 0x10 + 0x9] = dict_size;
                v.mem3[i * 0x10 + 0xA] = dict_size; v.mem3[i * 0x10 + 0xB] = dict_size;
                v.mem3[i * 0x10 + 0xC] = dict_size; v.mem3[i * 0x10 + 0xD] = dict_size;
                v.mem3[i * 0x10 + 0xE] = dict_size; v.mem3[i * 0x10 + 0xF] = dict_size;
            }

            for (int i = 0; i < dict_size; ++i)
            {
                v.mem5[i & 0x7FFF] = 0;
                v.mem4[i & 0x7FFF] = (ushort)i;
            }

            v.last_min_offset = 0;
        }

        public void UpdatePackedCrc(ref Vars v, byte b)
        {
            ushort crc = v.packed_crc;
            v.packed_crc = (ushort)(CrcTable[(crc & 0xFF) ^ b] ^ (crc >> 8));
            v.packed_size++;
        }

        public void UpdateUnpackedCrc(ref Vars v, byte b)
        {
            ushort crc = v.unpacked_crc;
            v.unpacked_crc = (ushort)(CrcTable[(crc & 0xFF) ^ b] ^ (crc >> 8));
            v.processed_size++;
        }

        public void WriteToOutput(ref Vars v, byte b)
        {
            if (v.packed_size >= (v.file_size - RNC_HEADER_SIZE))
                return;

            WriteByte(v.output, ref v.output_offset, b);
            UpdatePackedCrc(ref v, b);
        }

        public byte ReadFromInput(ref Vars v)
        {
            byte b = ReadByte(v.input, ref v.input_offset);
            UpdateUnpackedCrc(ref v, b);
            return b;
        }
    }
}
