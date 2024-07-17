import sys
from collections import defaultdict
import pickle
from elftools.elf.elffile import ELFFile

sw_border_edge_2_br_dist = {}
id_2_cmp_type = {} # connect dummy log_br id to compare type

cmp_typ_dic = {'NA': 0, 'ugt': 1, 'sgt': 2, 'eq': 3, 'uge': 4, 'sge': 5, 'ult': 6, 'slt': 7, 'ne': 8, 'ule': 9, 'sle': 10, 'strcmp': 11,  'strncmp':12, 'memcmp':13, 'strstr':14, 'switch': 15}
# only for normal sancov instrument
# for example:
# getelementptr inbounds ([12 x i32], [12 x i32]* @__sancov_gen_.5, i32 0, i32 0)
# inttoptr (i64 add (i64 ptrtoint ([12 x i32]* @__sancov_gen_.5 to i64), i64 20) to i32*)
def parse_local_edge_from_normal_sancov_instrument(instrument):
    if "inttoptr" not in instrument:
        local_edge = 0
    else:
        local_edge = instrument.split()[15][:-1]
    return local_edge

isStrcmp = {"strcmp", "xmlStrcmp", "xmlStrEqual", "g_strcmp0", "curl_strequal", "strcsequal", "strcasecmp", "stricmp", "ap_cstr_casecmp", "OPENSSL_strcasecmp", "xmlStrcasecmp", "g_strcasecmp", "g_ascii_strcasecmp", "Curl_strcasecompare", "Curl_safe_strcasecompare", "cmsstrcasecmp"}
isMemcmp = {"memcmp", "bcmp", "CRYPTO_memcmp", "OPENSSL_memcmp", "memcmp_const_time", "memcmpct"}
isStrncmp = {"strncmp", "xmlStrncmp", "curl_strnequal", "strncasecmp", "strnicmp", "ap_cstr_casecmpn", "OPENSSL_strncasecmp", "xmlStrncasecmp", "g_ascii_strncasecmp", "Curl_strncasecompare", "g_strncasecmp"}
isStrstr = {"strstr", "g_strstr_len", "ap_strcasestr", "xmlStrstr", "xmlStrcasestr", "g_str_has_prefix", "g_str_has_suffix"}
def recognize_strcmp_subtype(instruction):
    for func in isStrcmp:
        if func in instruction:
            return 'strcmp'

    for func in isMemcmp:
        if func in instruction:
            return 'memcmp'

    for func in isStrncmp:
        if func in instruction:
            return 'strncmp'

    for func in isStrstr:
        if func in instruction:
            return 'strstr'

    return 'error'


def get_begin_sancov_addr(elf_file_path):
    with open(elf_file_path, 'rb') as f:
        elffile = ELFFile(f)
        for section in elffile.iter_sections():
            if section.name == "__sancov_guards":
                return section['sh_addr']
    return None

# bc dummy to sancov mapping is one to one mapping, but sancov to dummy mapping is not
def get_dummy_to_sancov_mapping(sancov_begin_addr, elf_file_path, gap):
    dummy_2_sancov = {}
    # read from .log_section
    with open(elf_file_path, 'rb') as f:
        elffile = ELFFile(f)
        for section in elffile.iter_sections():
            if section.name == ".log_section":
                for i in range(0, section.data_size, 2 * gap):
                    sancov_addr = int.from_bytes(section.data()[i:i+8], byteorder='little')
                    dummy_id = int.from_bytes(section.data()[i+gap:i+gap+4], byteorder='little')
                    dummy_2_sancov[dummy_id] = (sancov_addr-sancov_begin_addr)//4
    return dummy_2_sancov

def get_sancov_cfg(elf_file_path, sancov_begin_addr, gap):
    cfg_dict_list = dict()
    
    # read from .cfg_log_section
    with open(elf_file_path, 'rb') as f:
        elffile = ELFFile(f)
        for section in elffile.iter_sections():
            if section.name == ".cfg_log_section":
                for i in range(0, section.data_size, 2 * gap):
                    sancov_addr = int.from_bytes(section.data()[i:i+8], byteorder='little')
                    pred_index = (sancov_addr-sancov_begin_addr)//4
                    succ_sancov_addr = int.from_bytes(section.data()[i+gap:i+gap+8], byteorder='little')
                    succ_index = (succ_sancov_addr-sancov_begin_addr)//4
                    if pred_index not in cfg_dict_list:
                        cfg_dict_list[pred_index] = []
                    cfg_dict_list[pred_index].append(succ_index)
    return cfg_dict_list

def get_gap(elf_file_path):
    with open(elf_file_path, 'rb') as f:
        elffile = ELFFile(f)
        for section in elffile.iter_sections():
            if section.name == ".log_section":
                for i in range(8, section.data_size):
                    # first 8 bytes must be a sancov_addr
                    if section.data()[i] != 0:
                        # i should be divisible by 8
                        log_gap = i//8 * 8
                        break
            if section.name == ".cfg_log_section":
                for i in range(8, section.data_size):
                    # first 8 bytes must be a sancov_addr
                    if section.data()[i] != 0:
                        cfg_gap = i//8 * 8
                        break
        if log_gap != cfg_gap:
            print("BUG: log_gap != cfg_gap")
            sys.exit(1)
    return log_gap
            
                    
if __name__ == '__main__': 
    sancov_add_number = int(sys.argv[3]) # __afl_final_loc + 1
    border_edge_add_number = int(sys.argv[4]) # max_border_edge
    elf_path = sys.argv[1]
    sancov_addr = get_begin_sancov_addr(elf_path)
    if not sancov_addr:
        print("No sancov section found")
        sys.exit(1)
    # get gap between two number
    # gap = get_gap(elf_path)
    # we use struct, no need to get gap 
    gap = 8
    # from .log_section get sancov_addr(8 bytes) and corresponding dummy id (8 bytes)
    dummy_2_sancov = get_dummy_to_sancov_mapping(sancov_addr, elf_path, gap)
    # from .cfg_log_section get sancov_addr(8 bytes) and corresponding succ's sancov_addr (8 bytes)
    cfg = get_sancov_cfg(elf_path, sancov_addr, gap)
    
    border_edges = []
    with open(sys.argv[2], 'r') as f:
        for line in f.readlines():
            tokens = line.split('|')
            dummy_id = int(tokens[1])
            if dummy_id not in dummy_2_sancov:
                continue
            # not switch and select
            if tokens[0] != '4' and tokens[0] != '3':
                str_len = int(tokens[6])
                sancov_id = dummy_2_sancov[dummy_id]

                if tokens[0] == '1':
                    cmp_inst = tokens[3]
                    cmp_type = cmp_inst.split()[3]
                elif tokens[0] == '2':
                    cmp_inst = tokens[3]
                    cmp_type = recognize_strcmp_subtype(cmp_inst)
                    if cmp_type == 'error':
                        print("BUG: error strcmp type")

                id_2_cmp_type[sancov_id] = (cmp_typ_dic[cmp_type], dummy_id, str_len)

            # for switch case
            elif tokens[0] == '3':
                cmp_type = 'switch'
                str_len = int(tokens[6])
                sancov_src_instrument = tokens[2]
                sancov_src_id = dummy_2_sancov[dummy_id]

                sancov_dst_instrument = tokens[5]
                local_src_edge = int(parse_local_edge_from_normal_sancov_instrument(sancov_src_instrument))
                local_dst_edge = int(sancov_dst_instrument.split()[16][:-1])
                sancov_dst_id = (local_dst_edge - local_src_edge) // 4 + sancov_src_id
                id_2_cmp_type[sancov_src_id] = (cmp_typ_dic[cmp_type], -1, str_len)
                sw_border_edge_2_br_dist[(sancov_src_id, sancov_dst_id)] = dummy_id

    
    
    # cmp_type[node_id] = cmp_type
    # sancov node_id, cmp_type
    with open("br_node_id_2_cmp_type_"+str(sancov_add_number), "w") as f:
        for node in sorted(cfg.keys()):
            children = cfg[node]
            children.sort()
            if len(children) > 1:
                # branch_NO_instrumentation_info
                if node not in id_2_cmp_type:
                    f.write(str(node+sancov_add_number) + " " + str(0) + "\n")
                else:
                    cmp_type = id_2_cmp_type[node][0]
                    f.write(str(node+sancov_add_number) + " " + str(cmp_type) + "\n")

    # build border edge array
    for node in sorted(cfg.keys()):
        children = cfg[node]
        children.sort()
        if len(children) > 1:
            for c in children:
                # no instrumentation info
                if node not in id_2_cmp_type:
                    #border_edges.append((node, c, -1, 0, 0, 0))
                    border_edges.append((node, c, -1, 0))
                else:
                    cmp_type = id_2_cmp_type[node][0]
                    dummy_id = id_2_cmp_type[node][1]
                    str_len = id_2_cmp_type[node][2]
                    # switch
                    if cmp_type == 15:
                        border_edges.append((node, c, sw_border_edge_2_br_dist[(node, c)], str_len))
                    # strcmp
                    elif 11<=cmp_type <= 14:
                        border_edges.append((node, c, dummy_id, str_len))
                    # other normal binary br
                    else:
                        border_edges.append((node, c, dummy_id, str_len))

    # border_edge_parent sancov id, boder_edge_child sancov id, border_edge_br_dist_id(i.e., dummy id), str_len
    # DO NOT FORGET to add offset to the node_id!!!!
    with open("border_edges_"+str(sancov_add_number), "w") as f:
        for parent, child, dummy_id, str_len in border_edges:
            f.write(str(parent+sancov_add_number) + " " + str(child+sancov_add_number) + " " + str(dummy_id) + " " + str(str_len) + "\n")

    with open("max_border_edge_id_"+str(sancov_add_number), "w") as f:
        f.write(str(len(border_edges)+border_edge_add_number))

    with open("max_br_dist_edge_id_"+str(sancov_add_number), "w") as f:
        f.write(str(max(dummy_id + str_len for _, _, dummy_id, str_len in border_edges if dummy_id != -1)))

    parent_node_id_map = defaultdict(list)
    for key, val in enumerate(border_edges):
        parent_node_id_map[val[0]].append(key)

    # border_edge_parent, first_border_edge_idx, num_of_border_edges_starting_from_this_parent
    with open("border_edges_cache_"+str(sancov_add_number), "w") as f:
        for parent, id_list in parent_node_id_map.items():
            f.write(str(parent+sancov_add_number) + " " + str(id_list[0]+border_edge_add_number) + " " + str(id_list[-1] - id_list[0] + 1) + "\n")
            if (id_list[-1] - id_list[0] + 1) <= 1:
                print("BUG: bug in 'border_edges_cache'")
