#Get Nvram.ini
#AiMiLiYa
import idautils
import ida_segment
import ida_bytes
import idaapi
import os

class NvramExtractPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL  
    comment = "Extract key-value pairs from .data section"
    help = "Extracts NVRAM key-value pairs and saves to nvram.ini"
    wanted_name = "NVRAM Extractor" 
    wanted_hotkey = "Ctrl-Alt-N"  

    def init(self):
        idaapi.msg("NVRAM Extractor plugin initialized\n")
        return idaapi.PLUGIN_OK 

    def run(self, arg):
        idaapi.msg("Running NVRAM Extractor plugin\n")
        self.extract_key_value_pairs(output_file="nvram.ini")
        return

    def term(self):
        idaapi.msg("NVRAM Extractor plugin terminated\n")

    def is_null_separator(self, ea, min_null_bytes=4):
        for i in range(min_null_bytes):
            if ida_bytes.get_byte(ea + i) != 0:
                return False
        return True

    def extract_key_value_pairs(self, output_file="nvram.ini"):
        pairs_found = []
        
        data_seg = None
        for seg in idautils.Segments():
            seg_name = ida_segment.get_segm_name(ida_segment.getseg(seg))
            if seg_name.lower() == ".data":
                data_seg = ida_segment.getseg(seg)
                break
        
        if not data_seg:
            idaapi.msg("Not Find .data section\n")
            return
        
        seg_start = data_seg.start_ea
        seg_end = data_seg.end_ea
        idaapi.msg(f"Find .data section: 0x{seg_start:x} - 0x{seg_end:x}\n")
        
        current_ea = seg_start
        while current_ea + 8 <= seg_end:  
            key_addr = ida_bytes.get_dword(current_ea)
            value_addr = ida_bytes.get_dword(current_ea + 4) 
            key_str = None
            value_str = None
            if key_addr and ida_bytes.is_mapped(key_addr):
                key_data = ida_bytes.get_strlit_contents(key_addr, -1, 0)  
                if key_data:
                    try:
                        key_str = key_data.decode('utf-8')
                    except UnicodeDecodeError:
                        idaapi.msg(f"Skip 0x{current_ea:x}: Get key string failed\n")
            if value_addr and ida_bytes.is_mapped(value_addr):
                value_data = ida_bytes.get_strlit_contents(value_addr, -1, 0)  
                if value_data:
                    try:
                        value_str = value_data.decode('utf-8')
                    except UnicodeDecodeError:
                        idaapi.msg(f"Skip 0x{current_ea:x}: Get Value string failed\n")
            if key_str and value_str:
                pairs_found.append((current_ea, key_addr, key_str, value_addr, value_str))
                idaapi.msg(f"Find: 0x{current_ea:x} -> Key 0x{key_addr:x} ({key_str}), Value 0x{value_addr:x} ({value_str})\n")
                current_ea += 8  
            else:
                current_ea += 4  
            if current_ea + 4 <= seg_end and not self.is_null_separator(current_ea, min_null_bytes=4):
                current_ea += 4  
            else:
                current_ea += 4  
        
        if pairs_found:
            idaapi.msg("\nFound key-value pairs in .data section:\n")
            for ea, key_addr, key_str, value_addr, value_str in pairs_found:
                idaapi.msg(f"0x{ea:x}: Key 0x{key_addr:x} ({key_str}), Value 0x{value_addr:x} ({value_str})\n")
        else:
            idaapi.msg("Failed to find valid key-value pairs in the .data section\n")
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("[config]\n")
                for _, _, key_str, _, value_str in pairs_found:
                    if ' ' in value_str:
                        f.write(f"{key_str}=\"{value_str}\"\n")
                    else:
                        f.write(f"{key_str}={value_str}\n")
            idaapi.msg(f"\nSuccess Save: {output_file}\n")
        except Exception as e:
            idaapi.msg(f"Save file failed: {str(e)}\n")
        
        return pairs_found

def PLUGIN_ENTRY():
    return NvramExtractPlugin()

