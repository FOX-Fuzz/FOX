from elftools.elf.elffile import ELFFile
import sys
import pickle

def get_begin_sancov_addr(elf_file_path):
    with open(elf_file_path, 'rb') as f:
        elffile = ELFFile(f)
        for section in elffile.iter_sections():
            if section.name == "__sancov_guards":
                return section['sh_addr']
    return None

# bc dummy to sancov mapping is one to one mapping, but sancov to dummy mapping is not
def get_dummy_to_sancov_mapping(sancov_begin_addr, elf_file_path):
    dummy_2_sancov = {}
    # read from .log_section
    with open(elf_file_path, 'rb') as f:
        elffile = ELFFile(f)
        for section in elffile.iter_sections():
            if section.name == ".log_section":
                for i in range(0, section.data_size, 16):
                    sancov_addr = int.from_bytes(section.data()[i:i+8], byteorder='little')
                    dummy_id = int.from_bytes(section.data()[i+8:i+12], byteorder='little')
                    dummy_2_sancov[dummy_id] = (sancov_addr-sancov_begin_addr)//4
    return dummy_2_sancov

def get_sancov_cfg(elf_file_path, sancov_begin_addr):
    cfg_dict_list = dict()
    
    # read from .cfg_log_section
    with open(elf_file_path, 'rb') as f:
        elffile = ELFFile(f)
        for section in elffile.iter_sections():
            if section.name == ".cfg_log_section":
                for i in range(0, section.data_size, 16):
                    sancov_addr = int.from_bytes(section.data()[i:i+8], byteorder='little')
                    pred_index = (sancov_addr-sancov_begin_addr)//4
                    succ_sancov_addr = int.from_bytes(section.data()[i+8:i+16], byteorder='little')
                    succ_index = (succ_sancov_addr-sancov_begin_addr)//4
                    if pred_index not in cfg_dict_list:
                        cfg_dict_list[pred_index] = []
                    cfg_dict_list[pred_index].append(succ_index)
    return cfg_dict_list

if __name__ == "__main__":
    # first arg is the path to the elf file
    elf_path = sys.argv[1]
    sancov_addr = get_begin_sancov_addr(elf_path)
    if not sancov_addr:
        print("No sancov section found")
        sys.exit(1)
    # from .log_section get sancov_addr(8 bytes) and corresponding dummy id (8 bytes)
    dummy_2_sancov = get_dummy_to_sancov_mapping(sancov_addr, elf_path)
    # from .cfg_log_section get sancov_addr(8 bytes) and corresponding succ's sancov_addr (8 bytes)
    cfg_dict_list = get_sancov_cfg(elf_path, sancov_addr)
    # store dummy_2_sancov and cfg_list in a file using pickle
    with open("dummy_2_sancov.pkl", "wb") as f:
        pickle.dump(dummy_2_sancov, f)
    with open("cfg_dict_list.pkl", "wb") as f:
        pickle.dump(cfg_dict_list, f)