#python ./gen_graph_dev_refactor.py LLVM_IR_FILE CFG_OUT_DIR BINARY_PATH META_FILE
#
import hashlib
import sys
import glob
import sys
import subprocess
from collections import defaultdict

dummy_id_2_local_table = {}
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
binary_log_funcs = ['log_br8', 'log_br16', 'log_br32', 'log_br64','log_br8_unsign', 'log_br16_unsign', 'log_br32_unsign', 'log_br64_unsign', 'eq_log_br8', 'eq_log_br16', 'eq_log_br32', 'eq_log_br64']
switch_log_funcs = ['sw_log_br8', 'sw_log_br16', 'sw_log_br32', 'sw_log_br64','sw_log_br8_unsign', 'sw_log_br16_unsign', 'sw_log_br32_unsign', 'sw_log_br64_unsign']
select_log_funcs = ['log_br8_r', 'log_br16_r', 'log_br32_r', 'log_br64_r', 'log_br8_unsign_r', 'log_br16_unsign_r', 'log_br32_unsign_r', 'log_br64_unsign_r']
strcmp_log_funcs = ['strcmp_log']
strncmp_log_funcs = ['strncmp_log']
memcmp_log_funcs = ['memcmp_log']
strstr_log_funcs = ['strstr_log']
sancov_set = set()
sancov_2_func = {}
nm_ret = subprocess.check_output('llvm-nm ' + sys.argv[3], shell=True, encoding='utf-8').splitlines()
internal_func_list = set()
for ele in nm_ret:
    fun_name = ele.split()[-1]
    if len(fun_name) > 200:
        fun_name = fun_name[:20] + hashlib.md5(fun_name.encode()).hexdigest() + fun_name[-20:]
    internal_func_list.add(fun_name)

# ir file + bin file
def inline_counter_table_init(filename, bin_name):
    output = subprocess.check_output('grep "section \\\"__sancov_guards\\\"" ' + filename, shell=True, encoding='utf-8')[:-1]
    lines = [line for line in output.split('\n')]
    ans = {}
    for line in lines:
        data = [ele for ele in line.split(',') if '@__sancov_gen_' in ele][0]
        if data.split()[0] in sancov_set:
            ans[data.split()[0]] = int(data.split()[4][1:])
            ordered_key.append(data.split()[0])

    tmp_sum = 0
    for key in ordered_key:
        inline_table[key] = tmp_sum
#        print(sancov_2_func[key], tmp_sum)
        tmp_sum += ans[key]

    tokens = subprocess.check_output('llvm-nm ' + bin_name + ' |grep sancov_guards', shell=True, encoding='utf-8').split()
    if tmp_sum != ((int('0x'+ tokens[3], 0) - int('0x' + tokens[0], 0))/4):
        print("BUGG: inline table wrong, try to fix...")

    return inline_table

def build_sancov_set(dot_file):
    func_str = open(dot_file, 'r').read()
    if " @__sancov_gen_" not in func_str: return
    my_func_name = dot_file.split('/')[-1].split('.')[0]
    lines = open(dot_file, 'r').readlines()
    for line in lines:
        if line.startswith('\t'):
            if '[' in line:
                code = line.split('label=')[1].strip()[1:-3]
                # check instrumention basic block only
                loc = code.find(' @__sancov_gen_')

                # convert dot node id to llvm node id
                if loc != -1:
                    code = code.replace("\l...", '')
                    insts = code.split('\\l  ')
                    for inst in insts:
                        if "__sancov_gen_" in inst:
                            for subinst in inst.split():
                                if "__sancov_gen_" in subinst:
                                    if "," not in subinst:
                                        sancov_set.add(subinst)
                                        sancov_2_func[subinst] = my_func_name
                                    elif subinst.endswith(","):
                                        sancov_set.add(subinst[:-1])
                                        sancov_2_func[subinst[:-1]] = my_func_name
                                    return

def construct_graph_init(dot_file, inline_table):
    lines = open(dot_file, 'r').readlines()
    graph, reverse_graph = {}, {}

    my_func_name = dot_file.split('/')[-1].split('.')[0]
    if my_func_name not in internal_func_list:
        # print("######## skip a dead function")
        return

    global debug_tmp_cnt
    global debug_tmp_cnt2
    dot_id_2_llvm_id = {}
    last_global_edge = -1

    non_sancov_nodes = []
    total_node = 0
    local_select_node = []
    local_table = None

    func_str = open(dot_file, 'r').read()
    if " @__sancov_gen_" not in func_str: return

    # 1. parse node(sancov instrumentation site with sancov ID) and edge("->" in dot graph) from the dot graph
    # 2. parse our instrumentation function (log_br() with br_dist_edge_id), hook sancov ID with br_dist_edge_id. Switch is a special case since our instrumentation function occurs before sancov instrumentation, so we need to scan the function for a second time.
    # 3. parse select instructions as additional nodes and their br_dist_edge_id
    # algorithm: linear scan each line of instructions, then identify instruction with "__sancov_node_id" as nodes

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
                            # There are three types of instruction with "__sancov_gen"
                            # case1: first sancov node in a function
                            # load i32, i32* getelementptr inbounds ... @__sancov_gen_
                            if "load" in inst and "inttoptr" not in inst:
                                found_the_first_node = 1
                                first_node = inst
                            # case2 : second and the following sancov node in a function
                            # load i32, i32* inttoptr ... @__sancov_gen_
                            elif ' = select' not in inst:
                                found_the_second_node = 1
                                second_node = inst
                            # case3: select instruction with sancov node
                            # select i1 ... @__sancov_gen_
                            else:
                                found_select = 1
                                select_node.append(inst)

                    local_edge = None
                    # three cases for first/second node checking:
                    # 1. bb with first_node
                    # 2. bb with second_node
                    # 3. bb without first_node and second_node

                    # two cases for select node checking
                    # 3. bb with single/multiple select_node
                    # 4. bb without any select_node
                    if found_the_first_node:
                        if not local_table:
                            local_table = first_node.split()[5][:-1]
                        local_edge = 0
                    elif found_the_second_node:
                        if not local_table:
                            local_table = second_node.split()[11]
                        local_edge = second_node.split()[15][:-1]
                    else:
                        non_first_second_node_select = 1

                    if found_the_first_node or found_the_second_node:
                        global_edge = int(int(local_edge)/4) + inline_table[local_table] # "global edge" is the final sancov node id used in AFL++ to trace edge coverage

                        last_global_edge = global_edge
                        dot_id_2_llvm_id[dot_node_id] = global_edge # dot_node_id is the node ID in the raw dot graph

                    # handle select case
                    if found_select:
                        if non_first_second_node_select:
                            non_sancov_nodes.append(dot_node_id)
                        for inst in select_node:
                            select_node_local_edge = None
                            new_loc = inst.find(" @__sancov_gen_")
                            if ',' not in inst[new_loc:].split(')')[0]:
                                if not local_table:
                                    local_table = inst[new_loc:].split(')')[0].split()[0]
                                select_node_local_edge = inst[new_loc:].split(')')[1].split()[-1]
                            else:
                                print("BUG: parse select error")
                            select_node_global_edge = int(int(select_node_local_edge)/4) + inline_table[local_table] # "global edge" is sancov node id
                            local_select_node.append((last_global_edge, select_node_global_edge))
                            global_select_node[last_global_edge].append(select_node_global_edge)

                            # parse the next select node
                            sub_code = inst[new_loc+14:]
                            new_loc = sub_code.find(' @__sancov_gen_')
                            if ',' not in sub_code[new_loc:].split(')')[0]:
                                if not local_table:
                                    local_table = sub_code[new_loc:].split(')')[0].split()[0]
                                select_node_local_edge = sub_code[new_loc:].split(')')[1].split()[-1]
                            else:
                                print("BUG: parse select error")
                            select_node_global_edge = int(int(select_node_local_edge)/4) + inline_table[local_table] # "global edge" is sancov node id
                            local_select_node.append((last_global_edge, select_node_global_edge))
                            global_select_node[last_global_edge].append(select_node_global_edge)

                # handle inject log function
                # map dummy id to local table
                else:
                    non_sancov_nodes.append(dot_node_id)
                    code = code.replace("\l...", '')
                    insts = code.split('\\l  ')

                    for _, inst in enumerate(insts):
                        if ('call ' in inst or 'invoke ' in inst) and '@' in inst:
                            fun_name = inst[inst.find('@')+1:inst.find('(')]
                            # normal cmp condition (log_br)
                            if fun_name in (switch_log_funcs + binary_log_funcs + select_log_funcs + memcmp_log_funcs + strcmp_log_funcs + strncmp_log_funcs + strstr_log_funcs):
                                dummy_id = int(inst.split()[3][:-1])
                                if not local_table:
                                    print("BUG: parse local table error!")
                                else:
                                    dummy_id_2_local_table[dummy_id] = local_table


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

def cal_sancov_id_from_local_edge_and_dummy_id(local_edge, dummy_id):
    return int(int(local_edge)/4) + inline_table[dummy_id_2_local_table[dummy_id]]

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


if __name__ == '__main__':
    for dot_file in glob.glob("./" + sys.argv[2] +"/*"):
        build_sancov_set(dot_file)
    # check if there is discrepency between llvm IR symbol table and binary's symbol table
    inline_table = inline_counter_table_init(sys.argv[1], sys.argv[3])
    fun_list = [dot_file.split('/')[-1].split('.')[0] for dot_file in glob.glob("./" + sys.argv[2] + "/*")]
    for dot_file in glob.glob("./" + sys.argv[2] +"/*"):
        construct_graph_init(dot_file, inline_table)

    border_edges = []
    select_border_edges = []
    # 0x00 build a map from br_dist_edge_id to local_edge_table(base number)
    # dummy_id_2_local_table
    # read local index from instrument_meta_data, use local_edge_table from last step to compute sancov ID
    # given instrument_meta_data, parse 1) sancov_id to cmp type; 2) [sancov1, sancov2] to cmp type for select;
    # build id_2_cmp_type and select_edge_2_cmp_type
    # id_2_cmp_type: id_2_cmp_type[sancov_id] = (cmp_type, dummy_id, str_len)
    # select_edge_2_cmp_type: select_edge_2_cmp_type[(src_sancov_id, dst_sancov_id)] = (cmp_type, dummy_id, str_len)
    with open(sys.argv[4], 'r') as f:
        for line in f.readlines():
            tokens = line.split('|')
            dummy_id = int(tokens[1])
            if dummy_id not in dummy_id_2_local_table:
                continue
            # not switch and select
            if tokens[0] != '4' and tokens[0] != '3':
                str_len = int(tokens[6])
                sancov_instrument = tokens[2]
                local_edge = parse_local_edge_from_normal_sancov_instrument(sancov_instrument)
                sancov_id = cal_sancov_id_from_local_edge_and_dummy_id(local_edge, dummy_id)

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
                local_src_edge = parse_local_edge_from_normal_sancov_instrument(sancov_src_instrument)
                sancov_src_id = cal_sancov_id_from_local_edge_and_dummy_id(local_src_edge, dummy_id)

                sancov_dst_instrument = tokens[5]
                local_dst_edge = sancov_dst_instrument.split()[16][:-1]
                sancov_dst_id = cal_sancov_id_from_local_edge_and_dummy_id(local_dst_edge, dummy_id)
                id_2_cmp_type[sancov_src_id] = (cmp_typ_dic[cmp_type], -1, str_len)
                sw_border_edge_2_br_dist[(sancov_src_id, sancov_dst_id)] = dummy_id

            # for select:2 edges
            # (src sancov id, 1st element of select instruction sancov id)
            elif tokens[0] == '4':
                cmp_inst = tokens[3]
                cmp_type = cmp_inst.split()[3]
                str_len = int(tokens[6])
                sancov_src_instrument = tokens[2]
                local_src_edge = parse_local_edge_from_normal_sancov_instrument(sancov_src_instrument)
                sancov_src_id = cal_sancov_id_from_local_edge_and_dummy_id(local_src_edge, dummy_id)

                sancov_dst_instrument = tokens[4]
                # we choose the fist element
                local_dst_edge = sancov_dst_instrument.split()[16][:-1]
                sancov_dst_id = cal_sancov_id_from_local_edge_and_dummy_id(local_dst_edge, dummy_id)

                select_edge_2_cmp_type[(sancov_src_id, sancov_dst_id)] = (cmp_typ_dic[cmp_type], dummy_id, str_len)

                # then choose the second element
                second_sancov_dst_id = sancov_dst_id + 1
                select_edge_2_cmp_type[(sancov_src_id, second_sancov_dst_id)] = (cmp_typ_dic[cmp_type], dummy_id, str_len)


    # cmp_type[node_id] = cmp_type
    # sancov node_id, cmp_type
    with open("br_node_id_2_cmp_type", "w") as f:
        for node in sorted(global_graph.keys()):
            children = global_graph[node]
            children.sort()
            if len(children) > 1:
                # branch_NO_instrumentation_info
                if node not in id_2_cmp_type:
                    f.write(str(node+6) + " " + str(0) + "\n")
                else:
                    cmp_type = id_2_cmp_type[node][0]
                    f.write(str(node+6) + " " + str(cmp_type) + "\n")

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
                        f.write(str(node+6) + " " + str(cmp_type) + "\n")
                    else:
                        f.write(str(node+6) + " " + str(0) + "\n")

    # build border edge array
    for node in sorted(global_graph.keys()):
        children = global_graph[node]
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

        if node in global_select_node:
            for select_node in global_select_node[node]:
                if (node, select_node) in select_edge_2_cmp_type:
                    dummy_id = select_edge_2_cmp_type[(node, select_node)][1]
                    str_len = select_edge_2_cmp_type[(node, select_node)][2]
                    select_border_edges.append((node, select_node, dummy_id,  str_len))
                else:
                    select_border_edges.append((node, select_node, -1, 0))


    # border_edge_parent sancov id, boder_edge_child sancov id, border_edge_br_dist_id(i.e., dummy id), str_len
    # DO NOT FORGET to add 1 to the node_id!!!!
    with open("border_edges", "w") as f:
        for parent, child, dummy_id, str_len in border_edges:
            f.write(str(parent+6) + " " + str(child+6) + " " + str(dummy_id) + " " + str(str_len) + "\n")

    parent_node_id_map = defaultdict(list)
    for key, val in enumerate(border_edges):
        parent_node_id_map[val[0]].append(key)

    # border_edge_parent, first_border_edge_idx, num_of_border_edges_starting_from_this_parent
    with open("border_edges_cache", "w") as f:
        for parent, id_list in parent_node_id_map.items():
            f.write(str(parent+6) + " " + str(id_list[0]) + " " + str(id_list[-1] - id_list[0] + 1) + "\n")
            if (id_list[-1] - id_list[0] + 1) <= 1:
                print("BUG: bug in 'border_edges_cache'")

    # border_edge_parent, boder_edge_child, border_edge_br_dist_id(i.e., dummy id), str_len
    #
    with open("select_border_edges", "w") as f:
        for parent, child, dummy_id, str_len in select_border_edges:
            f.write(str(parent+6) + " " + str(child+6) + " " + str(dummy_id) + " " + str(str_len) + "\n")

    select_parent_node_id_map = defaultdict(list)
    for key, val in enumerate(select_border_edges):
        select_parent_node_id_map[val[0]].append(key)

    # border_edge_parent, first_border_edge_idx, num_of_border_edges_starting_from_this_parent
    with open("select_border_edges_cache", "w") as f:
        for parent, id_list in select_parent_node_id_map.items():
            f.write(str(parent+6) + " " + str(id_list[0]) + " " + str(id_list[-1] - id_list[0] + 1) + "\n")
            if (id_list[-1] - id_list[0] + 1) <= 1:
                print("BUG: bug in 'select_border_edges_cache'")

