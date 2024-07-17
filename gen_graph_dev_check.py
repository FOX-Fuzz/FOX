#python ./gen_graph_dev_check.py LLVM_IR_FILE CFG_OUT_DIR BINARY_PATH
#
import hashlib
import ipdb
import sys
import glob
import time
import re
import os
import pickle
import dill
import pprint
import sys
from os import path
import subprocess
import networkit as nk
from collections import defaultdict

dot_id_2_llvm_id_list = []
local_table_2_fun_name = {}
covered_node = []
node_2_callee, func_name_2_root_exit_dict = {}, {}
id_map = {}
global_reverse_graph = defaultdict(list)
global_graph = defaultdict(list)
global_graph_weighted = defaultdict(dict)
global_back_edge = list()
debug_sw = set()
global_select_node = defaultdict(list)
strcmp_node = []
sw_node = []
int_cmp_node = []
eq_cmp_node = []

select_edge_2_cmp_type = {}
sw_border_edge_2_br_dist = {}
debug_tmp_cnt = 0
debug_tmp_cnt2 = 0
missing_cnt = [0]
id_2_fun = {}

ordered_key = []
id_2_cmp_type = {} # connect dummy log_br id to compare type

# Holds the mapping of sancov id of handled branch nodes from the branch sancov
# ID's to their corresponding children sancov ID's. This information is used to
# infer which branches were hit or flipped.
sancov_mapping = defaultdict(list)
sancov_br_list = [] # Holds the (sancov ID's, branch type, br_dist_id)  for handled branches

inline_table= {}
cmp_typ_dic = {'NA': 0, 'ugt': 1, 'sgt': 2, 'eq': 3, 'uge': 4, 'sge': 5, 'ult': 6, 'slt': 7, 'ne': 8, 'ule': 9, 'sle': 10, 'strcmp': 11,  'strncmp':12, 'memcmp':13, 'strstr':14, 'switch': 15}
cond_typ_dic = {'and': 0, 'or': 1, 'xor': 2}
# ipdb.set_trace()
nm_ret = subprocess.check_output('llvm-nm ' + sys.argv[3], shell=True, encoding='utf-8').splitlines()
internal_func_list = set()
for ele in nm_ret:
    fun_name = ele.split()[-1]
    if len(fun_name) > 200:
        fun_name = fun_name[:20] + hashlib.md5(fun_name.encode()).hexdigest() + fun_name[-20:]
    internal_func_list.add(fun_name)

def inline_counter_table_init(filename, bin_name):

    bin_text = ''
    with open(filename, "r") as f:
        bin_text = f.read()

    line = subprocess.check_output('grep "llvm.compiler.used" ' + filename, shell=True, encoding='utf-8')[:-1]
    data = [ele for ele in line.split(', i8*') if ' i32]* @__sancov_gen_' in ele]
    data[0] = data[0].split(' [i8*')[1] # data looks like this: bitcast ([N1 x i32]* @__sancov_gen_.N2.N3 to i8*)

    # handle dummy counter which are not used by any functions.
    new_data = []
    for ele in data:
        new_data.append(ele)
    data = new_data

    ans = {}

    for ele in data:
        ans[ele.split()[4]] = int(ele.split()[1][2:]) # ans[ @__sancov_gen_.N2.N3] = N1
        ordered_key.append(ele.split()[4])

    tmp_sum = 0
    for key in ordered_key:
        inline_table[key] = tmp_sum
        tmp_sum += ans[key]
        # print(key, tmp_sum)

    tokens = subprocess.check_output('llvm-nm ' + bin_name + ' |grep sancov_guards', shell=True, encoding='utf-8').split()
    if tmp_sum != ((int('0x'+ tokens[3], 0) - int('0x' + tokens[0], 0))/4):
        print("BUGG: inline table wrong, try to fix...")

    return inline_table

def inline_counter_table_final(filename, bin_name):

    bin_text = ''
    with open(filename, "r") as f:
        bin_text = f.read()

    line = subprocess.check_output('grep "llvm.compiler.used" ' + filename, shell=True, encoding='utf-8')[:-1]
    data = [ele for ele in line.split(', i8*') if ' i32]* @__sancov_gen_' in ele]
    data[0] = data[0].split(' [i8*')[1] # data looks like this: bitcast ([N1 x i32]* @__sancov_gen_.N2.N3 to i8*)

    # handle dummy counter which are not used by any functions.
    new_data = []
    for ele in data:
        new_data.append(ele)
    data = new_data

    ans = {}
    ordered_key.clear()
    for ele in data:
        if ele.split()[4] not in local_table_2_fun_name:
            continue
        ans[ele.split()[4]] = int(ele.split()[1][2:]) # ans[ @__sancov_gen_.N2.N3] = N1
        ordered_key.append(ele.split()[4])

    tmp_sum = 0
    for key in ordered_key:
        inline_table[key] = tmp_sum
        tmp_sum += ans[key]
        # print(key, tmp_sum)

    tokens = subprocess.check_output('llvm-nm ' + bin_name + ' |grep sancov_guards', shell=True, encoding='utf-8').split()
    if tmp_sum != ((int('0x'+ tokens[3], 0) - int('0x' + tokens[0], 0))/4):
        print("BUGG: inline table wrong, please manual checking sancov mapping")
        sys.exit("ERR")

    return inline_table

def get_fun_to_local_table (dot_file, inline_table, fun_list, node_2_callee, func_name_2_root_exit_dict):

    lines = open(dot_file, 'r').readlines()
    graph, reverse_graph = {}, {}

    my_func_name = dot_file.split('/')[-1].split('.')[0]
    if my_func_name not in internal_func_list:
        # print("######## skip a dead function " + my_func_name)
        return

    global debug_tmp_cnt
    global debug_tmp_cnt2
    dot_id_2_llvm_id = {}
    dot_id_2_llvm_id_list.append(dot_id_2_llvm_id)
    local_id_map = {}
    local_log_r = {} # llvm brach id : dummy id of log funcion
    last_global_edge = -1
    select_case = [0, None, None] # flag, global edge, node_id
    sancov_dot_node_id = None

    non_sancov_nodes = []
    sw_caseval_2_dummy_id = {}
    sw_bb_2_dummy_id = {}
    sw_case_bb = []
    total_node = 0
    local_select_node = []

    func_str = open(dot_file, 'r').read()
    if " @__sancov_gen_" not in func_str: return

    for i in range(len(lines)):
        line = lines[i]
        if line.startswith('\t'):
            if '[' in line:
                split_idx = line.index('[')
                dot_node_id = line[:split_idx].strip()
                code = line.split('label=')[1].strip()[1:-3]
                # check instrumention basic block only
                loc = code.find(' @__sancov_gen_')

                # convert dot node id to llvm node id
                if loc != -1:

                    code = code.replace("\l...", '')
                    insts = code.split('\\l  ')
                    found_select = 0
                    found_the_first_node = 0
                    found_the_second_node = 0
                    first_node = None
                    second_node = None
                    non_first_second_node_select = 0
                    select_node = []
                    for inst in insts:
                        if "__sancov_gen_" in inst:
                            if "getelementptr" in inst:
                                found_the_first_node = 1
                                first_node = inst
                            elif ' = select i1 ' not in inst:
                                found_the_second_node = 1
                                second_node = inst
                            else:
                                found_select = 1
                                select_node.append(inst)

                    local_table, local_edge = None, None

                    if found_the_first_node:
                        local_table = first_node.split('(')[1].split(')')[0].split()[6][:-1]
                        local_edge = 0
                    elif found_the_second_node:
                        local_table = second_node.split()[13]
                        local_edge = second_node.split()[17][:-1]
                    else:
                        non_first_second_node_select = 1

                    if found_the_first_node or found_the_second_node:
                        if local_table not in local_table_2_fun_name:
                            local_table_2_fun_name[local_table] = my_func_name
                            break

def construct_graph_init(dot_file, inline_table, fun_list, node_2_callee, func_name_2_root_exit_dict):

    lines = open(dot_file, 'r').readlines()
    graph, reverse_graph = {}, {}

    my_func_name = dot_file.split('/')[-1].split('.')[0]
    if my_func_name not in internal_func_list:
        # print("######## skip a dead function")
        return

    global debug_tmp_cnt
    global debug_tmp_cnt2
    dot_id_2_llvm_id = {}
    local_id_map = {}
    local_log_r = {} # llvm brach id : dummy id of log funcion
    last_global_edge = -1
    select_case = [0, None, None] # flag, global edge, node_id
    sancov_dot_node_id = None

    non_sancov_nodes = []
    sw_caseval_2_dummy_id = {}
    sw_bb_2_dummy_id = {}
    sw_case_bb = []
    total_node = 0
    local_select_node = []

    func_str = open(dot_file, 'r').read()
    if " @__sancov_gen_" not in func_str: return

    for i in range(len(lines)):
        line = lines[i]
        if line.startswith('\t'):
            if '[' in line:
                split_idx = line.index('[')
                dot_node_id = line[:split_idx].strip()
                code = line.split('label=')[1].strip()[1:-3]
                # check instrumention basic block only
                loc = code.find(' @__sancov_gen_')

                # convert dot node id to llvm node id
                if loc != -1:

                    code = code.replace("\l...", '')
                    insts = code.split('\\l  ')
                    found_select = 0
                    found_the_first_node = 0
                    found_the_second_node = 0
                    first_node = None
                    second_node = None
                    non_first_second_node_select = 0
                    select_node = []
                    for inst in insts:
                        if "__sancov_gen_" in inst:
                            if "getelementptr" in inst:
                                found_the_first_node = 1
                                first_node = inst
                            elif ' = select i1 ' not in inst:
                                found_the_second_node = 1
                                second_node = inst
                            else:
                                found_select = 1
                                select_node.append(inst)

                    local_table, local_edge = None, None
                    # three cases for first/second node checking:
                    # 1. bb with first_node
                    # 2. bb with second_node
                    # 3. bb without first_node and second_node

                    # two cases for select node checking
                    # 3. bb with single/multiple select_node
                    # 4. bb without any select_node
                    if found_the_first_node:
                        local_table = first_node.split('(')[1].split(')')[0].split()[6][:-1]
                        local_edge = 0
                    elif found_the_second_node:
                        local_table = second_node.split()[13]
                        local_edge = second_node.split()[17][:-1]
                    else:
                        non_first_second_node_select = 1

                    if found_the_first_node or found_the_second_node:
                        if local_table not in local_table_2_fun_name:
                            local_table_2_fun_name[local_table] = my_func_name
                        global_edge = int(int(local_edge)/4) + inline_table[local_table] # "global edge" is our custom edge id

                        last_global_edge = global_edge
                        sancov_dot_node_id = dot_node_id
                        dot_id_2_llvm_id[dot_node_id] = global_edge # is "node_id" the actual id that should be mapped to global edge?

                    # handle select case
                    if found_select:
                        if non_first_second_node_select:
                            non_sancov_nodes.append(dot_node_id)
                        for inst in select_node:
                            # TODO: check if there is a instrumentation site hooked with this select-instr ID
                            select_node_local_table, select_node_local_edge = None, None
                            new_loc = inst.find(" @__sancov_gen_")
                            if ',' not in inst[new_loc:].split(')')[0]:
                                select_node_local_table = inst[new_loc:].split(')')[0].split()[0]
                                select_node_local_edge = inst[new_loc:].split(')')[1].split()[-1]
                            else:
                                print("BUG: parse select error")
                            select_node_global_edge = int(int(select_node_local_edge)/4) + inline_table[select_node_local_table] # "global edge" is our custom edge id
                            local_select_node.append((last_global_edge, select_node_global_edge))
                            global_select_node[last_global_edge].append(select_node_global_edge)

                            # parse the next select node
                            sub_code = inst[new_loc+14:]
                            new_loc = sub_code.find(' @__sancov_gen_')
                            if ',' not in sub_code[new_loc:].split(')')[0]:
                                select_node_local_table = sub_code[new_loc:].split(')')[0].split()[0]
                                select_node_local_edge = sub_code[new_loc:].split(')')[1].split()[-1]
                            else:
                                print("BUG: parse select error")
                            select_node_global_edge = int(int(select_node_local_edge)/4) + inline_table[select_node_local_table] # "global edge" is our custom edge id
                            local_select_node.append((last_global_edge, select_node_global_edge))
                            global_select_node[last_global_edge].append(select_node_global_edge)

                # handle non-id BBs 1) skip asan node; 2) hook instrumentation site with a corresponding llvm id
                else:
                    non_sancov_nodes.append(dot_node_id)
                    code = code.replace("\l...", '')
                    insts = code.split('\\l  ')

                    for inst_idx, inst in enumerate(insts):
                        if ('call ' in inst or 'invoke ' in inst) and '@' in inst:
                            fun_name = inst[inst.find('@')+1:inst.find('(')]
                            # normal cmp condition (log_br)
                            if fun_name in ['log_br8', 'log_br16', 'log_br32', 'log_br64',
                                    'log_br8_unsign', 'log_br16_unsign', 'log_br32_unsign', 'log_br64_unsign', 'eq_log_br8', 'eq_log_br16', 'eq_log_br32', 'eq_log_br64']:
                                if (last_global_edge == -1):
                                    print("BUG: global edge not updated error{}".format(i))
                                dummy_id = int(inst.split()[3][:-1])
                                #local_id_map[dummy_id] = [last_global_edge, 0, 0]
                                cmp_br_id = re.search(r'%\d+', insts[inst_idx+1]).group()
                                try:
                                    cmp_code = lines[i+2].split('label=')[1].strip()[1:-3]
                                    cmp_code = cmp_code.replace("\l...", '')
                                    cmp_insts = cmp_code.split('\\l')
                                    if cmp_br_id == cmp_insts[0][1:-1]:
                                        found_cmp = 0
                                        for cmp_inst in cmp_insts:
                                            if 'icmp' in cmp_inst:
                                                cmp_type = cmp_inst.split()[3]
                                                if last_global_edge in id_2_cmp_type:
                                                    print("DEBUG: double parsing instrumented node")
                                                    ipdb.set_trace()
                                                strlen = 0
                                                if "br8" in fun_name:
                                                    strlen = 1
                                                elif "br16" in fun_name:
                                                    strlen = 2
                                                elif "br32" in fun_name:
                                                    strlen = 4
                                                elif "br64" in fun_name:
                                                    strlen = 8
                                                id_2_cmp_type[last_global_edge] = (cmp_typ_dic[cmp_type], dummy_id, strlen)
                                                id_2_fun[last_global_edge] = (dot_node_id, my_func_name)
                                                sancov_br_list.append((last_global_edge, cmp_typ_dic[cmp_type], dummy_id))
                                                if 'eq_' in fun_name:
                                                    eq_cmp_node.append((last_global_edge, 1, dummy_id))
                                                else:
                                                    int_cmp_node.append((last_global_edge, 1, dummy_id))
                                                found_cmp = 1
                                                break
                                        if not found_cmp:
                                            print("BUG: preciding line is not icmp type")
                                            ipdb.set_trace()
                                    else:
                                        print("BUG: preciding line is not icmp type")
                                        ipdb.set_trace()
                                except:
                                    print("BUG: normal cmp condition parsing error {}".format(i))
                                    ipdb.set_trace()

                            # nested condition (log_br*_r)
                            # TODO: log left over log_br*_r
                            elif fun_name in ['log_br8_r', 'log_br16_r', 'log_br32_r', 'log_br64_r',
                                    'log_br8_unsign_r', 'log_br16_unsign_r', 'log_br32_unsign_r', 'log_br64_unsign_r']:
                                if (last_global_edge == -1):
                                    print("BUG1: global edge not updated error{}".format(i))
                                dummy_id = int(inst.split()[3][:-1])
                                cmp_br_id = re.search(r'%\d+', insts[inst_idx+1]).group()

                                found_cmp = 0
                                found_sel = 0
                                cmp_ret = None
                                cmp_type = None
                                for new_line in lines[i+1:]:
                                    if 'label=' in new_line:
                                        cmp_code = new_line.split('label=')[1].strip()[1:-3]
                                        cmp_code = cmp_code.replace("\l...", '')
                                        cmp_insts = cmp_code.split('\\l')
                                        # check if cmp corresponds to the log_br_r()
                                        if cmp_br_id == cmp_insts[0][1:-1]:
                                            for cmp_inst in cmp_insts:
                                                if 'icmp' in cmp_inst:
                                                    cmp_type = cmp_inst.split()[3]
                                                    cmp_ret = cmp_inst.split()[0]
                                                    found_cmp = 1
                                                    break
                                            if found_cmp:
                                                break
                                if not found_cmp:
                                    print("BUG: fail to find cmp")
                                    ipdb.set_trace()
                                for new_line in lines[i+1:]:
                                    if 'label=' in new_line:
                                        cmp_code = new_line.split('label=')[1].strip()[1:-3]
                                        cmp_code = cmp_code.replace("\l...", '')
                                        cmp_insts = cmp_code.split('\\l')
                                        for cmp_inst in cmp_insts:
                                            if 'select i1 ' + cmp_ret in cmp_inst and '@__sancov_gen_' in cmp_inst:
                                                tokens = cmp_inst[:cmp_inst.rfind(')')].split()
                                                local_table = tokens[14]
                                                local_edge1 = tokens[18][:-1]
                                                local_edge2 = tokens[34][:-1]
                                                select1 = int(int(local_edge1)/4) + inline_table[local_table]
                                                select2 = int(int(local_edge2)/4) + inline_table[local_table]
                                                select_edge_2_cmp_type[(last_global_edge, select1)] = (cmp_typ_dic[cmp_type], dummy_id, 0)
                                                select_edge_2_cmp_type[(last_global_edge, select2)] = (cmp_typ_dic[cmp_type], dummy_id, 0)
                                                # sancov_br_list.append((last_global_edge, cmp_typ_dic['cmp_type'], dummy_id))
                                                found_sel = 1
                                                break
                                        if found_sel:
                                            break
                                if not found_sel:
                                    print("BUG: fail to find cmp")
                                    ipdb.set_trace()

                            # strcmp condition (strcmp_log) need test
                            elif fun_name == 'strcmp_log':
                                dummy_id = int(inst.split()[3][:-1])
                                str_len = int(inst[inst.find('('):inst.rindex(')')].split()[-1])
                                if last_global_edge in id_2_cmp_type:
                                    print("DEBUG: double parsing instrumented node")
                                    ipdb.set_trace()
                                id_2_cmp_type[last_global_edge] = (cmp_typ_dic['strcmp'], dummy_id, str_len)
                                sancov_br_list.append((last_global_edge, cmp_typ_dic['strcmp'], dummy_id))
                                strcmp_node.append((last_global_edge, 1, dummy_id))

                            elif fun_name == 'strncmp_log':
                                dummy_id = int(inst.split()[3][:-1])
                                str_len = int(inst[inst.find('('):inst.rindex(')')].split()[-1])
                                if last_global_edge in id_2_cmp_type:
                                    print("DEBUG: double parsing instrumented node")
                                    ipdb.set_trace()
                                id_2_cmp_type[last_global_edge] = (cmp_typ_dic['strncmp'], dummy_id, str_len)
                                sancov_br_list.append((last_global_edge, cmp_typ_dic['strncmp'], dummy_id))
                                strcmp_node.append((last_global_edge, 2, dummy_id))

                            elif fun_name == 'memcmp_log':
                                dummy_id = int(inst.split()[3][:-1])
                                str_len = int(inst[inst.find('('):inst.rindex(')')].split()[-1])
                                if last_global_edge in id_2_cmp_type:
                                    print("DEBUG: double parsing instrumented node")
                                    ipdb.set_trace()
                                id_2_cmp_type[last_global_edge] = (cmp_typ_dic['memcmp'], dummy_id, str_len)
                                sancov_br_list.append((last_global_edge, cmp_typ_dic['memcmp'], dummy_id))
                                strcmp_node.append((last_global_edge, 3, dummy_id))

                            elif fun_name == 'strstr_log':
                                dummy_id = int(inst.split()[3][:-1])
                                str_len = int(inst[inst.find('('):inst.rindex(')')].split()[-1])
                                if last_global_edge in id_2_cmp_type:
                                    print("DEBUG: double parsing instrumented node")
                                    ipdb.set_trace()
                                id_2_cmp_type[last_global_edge] = (cmp_typ_dic['strstr'], dummy_id, str_len)
                                sancov_br_list.append((last_global_edge, cmp_typ_dic['strstr'], dummy_id))
                                strcmp_node.append((last_global_edge, 4, dummy_id))
                            # the sancov Edge id is resolved later, cannot use last_global_edge
                            elif fun_name in ['sw_log_br8', 'sw_log_br16', 'sw_log_br32', 'sw_log_br64',
                                    'sw_log_br8_unsign', 'sw_log_br16_unsign', 'sw_log_br32_unsign', 'sw_log_br64_unsign']:
                                sub_inst = inst[inst.find('('):inst.rindex(')')].split()
                                dummy_id = int(sub_inst[1][:-1])
                                case_value = int(sub_inst[-1])
                                strlen = 0
                                if "br8" in fun_name:
                                    strlen = 1
                                elif "br16" in fun_name:
                                    strlen = 2
                                elif "br32" in fun_name:
                                    strlen = 4
                                elif "br64" in fun_name:
                                    strlen = 8
                                sw_caseval_2_dummy_id[case_value] = dummy_id
                                id_2_cmp_type[last_global_edge] = (cmp_typ_dic['switch'], -1, strlen)
                                if ((last_global_edge, 5, dummy_id)) not in sw_node:
                                    sw_node.append((last_global_edge, 5, dummy_id))


                        # switch condition (sw_log_br) need more test
                        if (inst.startswith('switch ')):
                            if inst.split()[1] not in ['i8', 'i32', 'i16', 'i64']:
                                continue
                            #if last_global_edge in id_2_cmp_type:
                            #    print("DEBUG: double parsing instrumented node")
                            #    ipdb.set_trace()
                            #id_2_cmp_type[last_global_edge] = (cmp_typ_dic['switch'], -1, 0)
                            sancov_br_list.append((last_global_edge, cmp_typ_dic['switch'], dummy_id))
                            sw_case = 0
                            for local_i, local_j in enumerate(insts[inst_idx:]):
                                if local_j.startswith("]"):
                                    sw_case = local_i
                                    break

                            #if len(sw_case_bb) != 0:
                            #    print("BUG: sw_case_bb not initilized")
                            default_bb = inst.split()[-2]
                            sw_case_bb.append(default_bb)
                            caseval_list = []
                            for case_inst in insts[inst_idx+1:inst_idx + sw_case]:
                                case_target_bb = case_inst.split()[-1]
                                case_val = int(case_inst.split()[1][:-1])
                                sw_case_bb.append(case_target_bb)
                                dummy_id = sw_caseval_2_dummy_id[case_val]
                                sw_bb_2_dummy_id[case_target_bb] = [dummy_id, last_global_edge]
                                caseval_list.append(case_val)
                            default_caseval_list = list(set(sw_caseval_2_dummy_id.keys()) - set(caseval_list))
                            default_caseval = default_caseval_list[0]
                            if len(default_caseval_list) != 1:
                                print("BUG: wrong switch cases")
                            sw_bb_2_dummy_id[default_bb] = [sw_caseval_2_dummy_id[default_caseval], last_global_edge]

                            sw_caseval_2_dummy_id.clear()

                graph[dot_node_id] = []
                if dot_node_id not in reverse_graph:
                    reverse_graph[dot_node_id] = []

            # construct a graph with dot node id
            elif '->' in line:
                # ignore the last character ';'
                tokens = line.split('->')
                src_node = tokens[0].strip().split(':')[0]
                dst_node = tokens[1].strip()[:-1]
                if dst_node not in graph[src_node]:
                    graph[src_node].append(dst_node)
                if dst_node not in reverse_graph:
                    reverse_graph[dst_node] = [src_node]
                else:
                    if src_node not in reverse_graph[dst_node]:
                        reverse_graph[dst_node].append(src_node)

    # check if current BB is a switch_jump_target, resolve instrumentaiton site ID to llvm id
    for i in range(len(lines)):
        line = lines[i]
        if line.startswith('\t'):
            if '[' in line:
                split_idx = line.index('[')
                dot_node_id = line[:split_idx].strip()
                code = line.split('label=')[1].strip()[1:-3]
                # check instrumention basic block only
                loc = code.find(' @__sancov_gen_')

                # convert dot node id to llvm node id
                if loc != -1:

                    code = code.replace("\l...", '')
                    insts = code.split('\\l  ')
                    found_select = 0
                    found_the_first_node = 0
                    found_the_second_node = 0
                    first_node = None
                    second_node = None
                    select_node = []
                    for inst in insts:
                        if "__sancov_gen_" in inst:
                            if "getelementptr" in inst:
                                found_the_first_node = 1
                                first_node = inst
                                total_node = int(inst.split('(')[1].split(')')[0].split()[0][1:])
                            elif ' = select i1 ' not in inst:
                                found_the_second_node = 1
                                second_node = inst
                            else:
                                found_select = 1
                                select_node.append(inst)

                    local_table, local_edge = None, None
                    # three cases for first/second node checking:
                    # 1. bb with first_node
                    # 2. bb with second_node
                    # 3. bb without first_node and second_node

                    # two cases for select node checking
                    # 3. bb with single/multiple select_node
                    # 4. bb without any select_node
                    if found_the_first_node:
                        local_table = first_node.split('(')[1].split(')')[0].split()[6][:-1]
                        local_edge = 0
                    elif found_the_second_node:
                        local_table = second_node.split()[13]
                        local_edge = second_node.split()[17][:-1]

                    if found_the_first_node or found_the_second_node:
                        if local_table not in local_table_2_fun_name:
                            local_table_2_fun_name[local_table] = my_func_name
                        global_edge = int(int(local_edge)/4) + inline_table[local_table] # "global edge" is our custom edge id

                        last_global_edge = global_edge

                    # check if current BB is a switch_jump_target, resolve instrumentaiton site ID to llvm id
                    if sw_case_bb:
                        bb_name = insts[0][1:].split(':')[0]
                        if bb_name[0] != "%":
                            bb_name = "%" + bb_name
                        if bb_name in sw_case_bb:
                            dummy_id, parent_node_id = sw_bb_2_dummy_id[bb_name]
                            sw_border_edge_2_br_dist[(parent_node_id, global_edge)] = dummy_id
                            sw_case_bb.remove(bb_name)

    if sw_case_bb:
        print("unhandled sw_case BB")
    # TODO: group sancov node (delete ASAN-nodes as well) DONE
    for node in non_sancov_nodes:
        children, parents = graph[node], reverse_graph[node]
        for child in children:
            for parent in parents:
                #if child == -1 or parent == -1:
                #    continue
                if child not in graph[parent]:
                    graph[parent].append(child)
                if parent not in reverse_graph[child]:
                    reverse_graph[child].append(parent)

        del graph[node]
        del reverse_graph[node]
        for parent in parents:
            if parent in graph:
                if node in graph[parent]:
                    graph[parent].remove(node)
        for child in children:
            if child in reverse_graph:
                if node in reverse_graph[child]:
                    reverse_graph[child].remove(node)

    new_graph, new_reverse_graph = {}, {}
    for node, neis in graph.items():
        if dot_id_2_llvm_id[node] not in new_graph:
            new_graph[dot_id_2_llvm_id[node]] = []
        for nei in neis:
            new_graph[dot_id_2_llvm_id[node]].append(dot_id_2_llvm_id[nei])

    for node, neis in reverse_graph.items():
        if dot_id_2_llvm_id[node] not in new_reverse_graph:
            new_reverse_graph[dot_id_2_llvm_id[node]] = []
        for nei in neis:
            new_reverse_graph[dot_id_2_llvm_id[node]].append(dot_id_2_llvm_id[nei])

    # add select edge
    for select_1, select_2 in local_select_node:
        if select_2 not in new_graph:
            new_graph[select_2] = []
        if select_2 not in new_reverse_graph:
            new_reverse_graph[select_2] = []
        # find all edges in (select_1, child)
        # 1. delete (select_1, child)
        # 2. add (select_1, select_2) and (select_2, child)
        # find all edges in (child, selelct_1)
        # 1. delete (child, select_1)
        # 2. add (child, select_1) and (select_1, select_2)
        '''
        tmp_child_list = new_graph[select_1].copy()
        for child in tmp_child_list:
            new_graph[select_1].remove(child)
            new_reverse_graph[child].remove(select_1)
            new_graph[select_1].append(select_2)
            new_reverse_graph[select_2].append(select_1)
            new_graph[select_2].append(child)
            new_reverse_graph[child].append(select_2)
        '''
        #new_graph[select_1].append(select_2)
        #new_reverse_graph[select_2].append(select_1)


    # convert node id from dot_id to llvm_instrumented_id, add to global graph
    for node, neis in new_graph.items():
        if not neis:
            global_graph[node] = []
            global_graph_weighted[node] = {}
        for nei in neis:
            global_graph[node].append(nei)
            global_graph_weighted[node][nei] = 1

    for node, neis in reverse_graph.items():
        if not neis:
            global_reverse_graph[node] = []
        for nei in neis:
            global_reverse_graph[node].append(nei)

    debug_tmp_cnt += total_node
    debug_tmp_cnt2 += len(new_graph)
    # print(my_func_name, total_node, debug_tmp_cnt, debug_tmp_cnt2, len(global_graph))
    if total_node != len(new_graph):
        missing_cnt[0] += 1
        #print("!!!BUG", my_func_name, total_node, len(new_graph), missing_cnt[0])

    return

def cmp_to_str_type(cmp_id):
    '''
    Given a cmp_id, returns it natural language description
    Type descriptions: switch, strcmp, unhandled
    '''
    if (cmp_id == 15):
        return "switch"
    elif (cmp_id == 13):
        return "memcmp"
    elif (cmp_id == 11 or cmp_id == 12 or cmp_id == 14):
        return "strcmp"
    elif (cmp_id >= 1 and cmp_id < 11):
        return "intcmp"
    elif (cmp_id == 0):
        return "NA"
    else:
        raise ValueError("Unknown cmp ID encountered here")

def classify_edges(global_graph):
    # id_2_cmp_type[sancov_id] = {cmp_type, dummy_id, str_len}
    branch_type_freq = defaultdict(int)
    branch_type_ids = defaultdict(list)
    for node in sorted(global_graph.keys()):
        # Check if it is a branch node with > 1 children
        if len(global_graph[node]) > 1:
            if node in id_2_cmp_type:
                cmp_type = id_2_cmp_type[node][0]
                cmp_type_str = cmp_to_str_type(cmp_type)
                branch_type_freq[cmp_type_str] += 1
                branch_type_ids[cmp_type_str].append(node + 1)
            # XXX: Currently the select instrumentation is disabled so all select comparisons
            # will be mapped to NA and can be treated as being unhandled
            # elif node in global_select_node:
            #     for select_node in global_select_node[node]:
            #         if (node, select_node) in select_edge_2_cmp_type:
            #             cmp_type = select_edge_2_cmp_type[(node, select_node)][0]
            #         else:n
            #             cmp_type = 0
            #         cmp_type_str = cmp_to_str_type(cmp_type)
            #         branch_type_ids[cmp_type_str].append(node)
            #         branch_type_freq[cmp_type_str] += 1
            else:
                branch_type_freq["unhandled"] += 1
                branch_type_ids["unhandled"].append(node + 1)
    pprint.pprint(branch_type_freq)
    return branch_type_ids

def collect_children(sancov_br_list, global_graph):
    '''
    Given a list of branch sancov ID's creates a list of it's children keyed at
    the branch types as listed in cmp_to_str_type
    '''
    for item in sancov_br_list:
        sancov_id, cmp_type_id, dummy_id = item[0], item[1], item[2]
        tmp_list = [sancov_id + 1]
        cmp_type_str = cmp_to_str_type(cmp_type_id)
        child_nodes = global_graph[sancov_id]
        assert len(child_nodes) >= 2, "Non-branch node was selected for stat collection, please check"
        tmp_list.extend([int(child) + 1 for child in child_nodes])
        sancov_mapping[cmp_type_str].append(tmp_list)
    return sancov_mapping

if __name__ == '__main__':
    inline_table = inline_counter_table_init(sys.argv[1], sys.argv[3])
    fun_list = [dot_file.split('/')[-1].split('.')[0] for dot_file in glob.glob("./" + sys.argv[2] + "/*")]
    for dot_file in glob.glob("./" + sys.argv[2] +"/*"):
        get_fun_to_local_table(dot_file, inline_table, fun_list, node_2_callee, func_name_2_root_exit_dict)

    inline_table = inline_counter_table_final(sys.argv[1], sys.argv[3])
    for dot_file in glob.glob("./" + sys.argv[2] +"/*"):
        construct_graph_init(dot_file, inline_table, fun_list, node_2_callee, func_name_2_root_exit_dict)

    # Perform branch categorization and print the corresponding stats along with returning the actual sancov ids
    # corresponding to each branch as well
    branch_type_ids = classify_edges(global_graph)
    pickle.dump(branch_type_ids, open("branch_type_ids", "wb"))

    # Create pickled structure containing all the handled branches and their corresponding sancov IDs
    br_nodes_2_children = collect_children(sancov_br_list, global_graph)
    # pprint.pprint(br_nodes_2_children)
    pickle.dump(br_nodes_2_children, open("br_nodes_2_children", "wb"))

    # ipdb.set_trace()
    #for key in ordered_key:
    #    tmp_sum = inline_table[key]
    #    print(key, local_table_2_fun_name[key], hex(tmp_sum*4 + 0x0afda88))

    strcmp_node_2_children = {}
    for node, cmp_type, dummy_id in strcmp_node:
        strcmp_node_2_children[node] = (global_graph[node].copy(), cmp_type, dummy_id)

    # add offset 1 to align node id to fuzzer sancov id
    new_strcmp_node_2_children = {}
    for key, value in strcmp_node_2_children.items():
        new_strcmp_node_2_children[key+1] = ([int(ele)+1 for ele in value[0]], value[1], value[2])
    import pickle
    pickle.dump(new_strcmp_node_2_children, open("strcmp_node_2_children", "wb"))

    sw_node_2_children = {}
    for node, cmp_type, dummy_id in sw_node:
        sw_node_2_children[node] = (global_graph[node].copy(), cmp_type, dummy_id)

    # add offset 1 to align node id to fuzzer sancov id
    new_sw_node_2_children = {}
    for key, value in sw_node_2_children.items():
        new_sw_node_2_children[key+1] = ([int(ele)+1 for ele in value[0]], value[1], value[2])
    pickle.dump(new_sw_node_2_children, open("sw_node_2_children", "wb"))

    int_cmp_node_2_children = {}
    for node, cmp_type, dummy_id in int_cmp_node:
        int_cmp_node_2_children[node] = (global_graph[node].copy(), cmp_type, dummy_id)

    # add offset 1 to align node id to fuzzer sancov id
    new_int_cmp_node_2_children = {}
    for key, value in int_cmp_node_2_children.items():
        new_int_cmp_node_2_children[key+1] = ([int(ele)+1 for ele in value[0]], value[1], value[2])
    pickle.dump(new_int_cmp_node_2_children, open("int_cmp_node_2_children", "wb"))

    eq_cmp_node_2_children = {}
    for node, cmp_type, dummy_id in eq_cmp_node:
        eq_cmp_node_2_children[node] = (global_graph[node].copy(), cmp_type, dummy_id)

    # add offset 1 to align node id to fuzzer sancov id
    new_eq_cmp_node_2_children = {}
    for key, value in eq_cmp_node_2_children.items():
        new_eq_cmp_node_2_children[key+1] = ([int(ele)+1 for ele in value[0]], value[1], value[2])
    pickle.dump(new_eq_cmp_node_2_children, open("eq_cmp_node_2_children", "wb"))

    br_sancov = defaultdict(lambda: None)
    border_edges = []
    select_border_edges = []
    # cmp_type[node_id] = cmp_type
    # node_id, cmp_type
    with open("br_node_id_2_cmp_type", "w") as f:
        for node in sorted(global_graph.keys()):
            children = global_graph[node]
            children.sort()
            if len(children) > 1:
                # branch_NO_instrumentation_info
                if node not in id_2_cmp_type:
                    f.write(str(node+1) + " " + str(0) + "\n")
                else:
                    cmp_type = id_2_cmp_type[node][0]
                    f.write(str(node+1) + " " + str(cmp_type) + "\n")

    # cmp_type[select_node_id] = cmp_type
    # select_node_id, cmp_type
    with open("select_node_id_2_cmp_type", "w") as f:
        for node in sorted(global_graph.keys()):
            children = global_graph[node]
            children.sort()
            if node in global_select_node:
                for select_node in global_select_node[node]:
                    if (node, select_node) in select_edge_2_cmp_type:
                        cmp_type = select_edge_2_cmp_type[(node, select_node)][0]
                        f.write(str(node+1) + " " + str(cmp_type) + "\n")
                    else:
                        f.write(str(node+1) + " " + str(0) + "\n")

    for node in sorted(global_graph.keys()):
        children = global_graph[node]
        children.sort()
        if len(children) > 1:
            #if len(children) >2:
            #   if id_2_cmp_type[node][0] != 15:
            #        print("BUG", node, children, len(children))
            #        ipdb.set_trace()
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
                    if dummy_id != -1:
                        if (br_sancov[dummy_id] == None):
                            br_sancov[dummy_id] = (node + 1, [c + 1])
                        else:
                            br_sancov[dummy_id][1].append(c + 1)

        if node in global_select_node:
            for select_node in global_select_node[node]:
                if (node, select_node) in select_edge_2_cmp_type:
                    dummy_id = select_edge_2_cmp_type[(node, select_node)][1]
                    select_border_edges.append((node, select_node, dummy_id,  0 ))
                else:
                    select_border_edges.append((node, select_node, -1, 0))

    # border_edge_parent, boder_edge_child, border_edge_br_dist_id(i.e., dummy id), str_len
    # DO NOT FORGET to add 1 to the node_id!!!!
    with open("border_edges", "w") as f:
        for parent, child, dummy_id, str_len in border_edges:
            f.write(str(parent + 1) + " " + str(child + 1) + " " + str(dummy_id) + " " + str(str_len) + "\n")

    dill.dump(br_sancov, open("br_sancov_map", "wb"))

    parent_node_id_map = defaultdict(list)
    for key, val in enumerate(border_edges):
        parent_node_id_map[val[0]].append(key)

    # border_edge_parent, first_border_edge_idx, num_of_border_edges_starting_from_this_parent
    with open("border_edges_cache", "w") as f:
        for parent, id_list in parent_node_id_map.items():
            f.write(str(parent+1) + " " + str(id_list[0]) + " " + str(id_list[-1] - id_list[0] + 1) + "\n")
            if (id_list[-1] - id_list[0] + 1) <= 1:
                print("BUG: bug in 'border_edges_cache'")


    # border_edge_parent, boder_edge_child, border_edge_br_dist_id(i.e., dummy id), str_len
    #
    with open("select_border_edges", "w") as f:
        for parent, child, dummy_id, str_len in select_border_edges:
            f.write(str(parent + 1) + " " + str(child + 1) + " " + str(dummy_id) + " " + str(str_len) + "\n")

    select_parent_node_id_map = defaultdict(list)
    for key, val in enumerate(select_border_edges):
        select_parent_node_id_map[val[0]].append(key)

    # border_edge_parent, first_border_edge_idx, num_of_border_edges_starting_from_this_parent
    with open("select_border_edges_cache", "w") as f:
        for parent, id_list in select_parent_node_id_map.items():
            f.write(str(parent+1) + " " + str(id_list[0]) + " " + str(id_list[-1] - id_list[0] + 1) + "\n")
            if (id_list[-1] - id_list[0] + 1) <= 1:
                print("BUG: bug in 'select_border_edges_cache'")

    # save global graph for debugging
    with open("global_graph", "wb") as f:
        pickle.dump(global_graph, f)

    with open("id_2_fun", "wb") as f:
        pickle.dump(id_2_fun, f)

    global_dot_id_2_llvm_id = {}
    for dot_id_2_llvm_id in dot_id_2_llvm_id_list:
        for dot_id, llvm_id in dot_id_2_llvm_id.items():
            if dot_id in global_dot_id_2_llvm_id and global_dot_id_2_llvm_id[dot_id] != llvm_id:
                print("BUG: dot_id maps to multiple llvm_ids")
            global_dot_id_2_llvm_id[dot_id] = llvm_id

    with open("dot_id_2_llvm_id", "wb") as f:
        pickle.dump(global_dot_id_2_llvm_id, f)
