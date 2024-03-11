namespace RncProPackDotnet
{
    public struct Vars
    {
        public ushort max_matches;
        public ushort enc_key;
        public uint pack_block_size;
        public ushort dict_size;
        public uint method;
        public uint puse_mode;
        public uint input_size;
        public uint file_size;

        // Inner
        public uint bytes_left;
        public uint packed_size;
        public uint processed_size;
        public uint v7;
        public uint pack_block_pos;
        public ushort pack_token;
        public ushort bit_count;
        public ushort v11;
        public ushort last_min_offset;
        public uint v17;
        public uint pack_block_left_size;
        public ushort match_count;
        public ushort match_offset;
        public uint v20;
        public uint v21;
        public uint bit_buffer;

        public uint unpacked_size;
        public uint rnc_data_size;
        public ushort unpacked_crc;
        public ushort unpacked_crc_real;
        public ushort packed_crc;
        public uint leeway;
        public uint chunks_count;

        public byte[] mem1;
        public byte[] pack_block_start;
        public byte[] pack_block_max;
        public byte[] pack_block_end;
        public ushort[] mem2;
        public ushort[] mem3;
        public ushort[] mem4;
        public ushort[] mem5;

        public byte[] decoded;
        public byte[] window;

        public int read_start_offset;
        public int write_start_offset;
        public byte[] input;
        public byte[] output;
        public byte[] temp;
        public int input_offset;
        public int output_offset;
        public int temp_offset;

        public byte[] tmp_crc_data;
        public Huftable[] raw_table;
        public Huftable[] pos_table;
        public Huftable[] len_table;
    }
}
