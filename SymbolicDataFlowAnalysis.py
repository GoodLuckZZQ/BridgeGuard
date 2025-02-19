from calendar import c
from collections import namedtuple
import time
from turtle import back
from z3 import * 
import traceback
import os
import errno
import signal
import tokenize
from tokenize import NUMBER, NAME, NEWLINE
import six
import json
import copy
import gc 

from global_utils import *
import global_controller
import global_controller
from basicblock import BasicBlock
from global_utils import *
from TaintSymbolicGen import *
from detect import *
from executionState import *

CONSTANT_ONES_159 = BitVecVal((1 << 160) - 1, 256)
secondMode = False

# Analyze only needs disasm_file, source_map and source_file.
def audit(disasm_file = None, bytecode = None, source_map = None, source_file = None):
    global g_disasm_file

    global g_bytecode
    
    global real_instruction_length


    g_disasm_file = disasm_file
    g_bytecode = bytecode

    global report_file

    if global_controller.REPORT_MODE:
        report_file = open(g_disasm_file + '.report', 'w')

    global results
    results = {
        "evm_code_coverage": 0,
        "time_cost": 0,
        "bytecode_length": 0,
        "vulnerabilities": {
            "unchecked_return_value": [],
            "reentrancy": [],
            "Crosschain_Function_Call": [],
            "Unprotected_Data_Injection": [],
        }
    }

    results["bytecode_length"] = len(g_bytecode)/2
    real_instruction_length = len(g_bytecode)/2

    begin = time.time()
    print('[BridgeGuard]  \033[96m\t Check if a contract is vulnerable ... ...\033[0m')
    
    print('[BridgeGuard]  \t Contract File      : %s' % g_disasm_file)
    
    print('[BridgeGuard]  \t Contract bytecode  : %s...' % g_bytecode[:50])
    
    print('[BridgeGuard]  \t Bytecode length    : %d' % results["bytecode_length"] )
    
    def timeout_cb():
        if global_controller.DEBUG_MODE:
            traceback.print_exc()
    
    run_build_cfg_and_analyze(timeout_cb = timeout_cb)
    
    results = detect_vulnerabilities()

    print("[BridgeGuard]  \t\033[92m ============ Analysis Completed =============\033[0m")
    
    stop = time.time()
    print("[BridgeGuard]  \t\033[96m Time Cost: %s s\033[0m"% (stop-begin))

    results["time_cost"] = stop - begin

    if global_controller.REPORT_MODE:
        report_file.write("\n===================================================\n")
        report_file.write("This Audit Cost: ")
        
        report_file.write(str(stop - begin)+"\n")
        report_file.write(str(results))
        
        report_file.close()
        
    return results 

########################################################################
# Build CFG and do symbolic data flow analysis.
########################################################################
# 1st, initialize global variables
# 2nd, build CFG and do symbolic data flow analysis.
class TimeoutError(Exception):
    pass
# Raise timeout error.
class Timeout:
    """Timeout class using ALARM signal."""

    def __init__(self, sec = 10, error_mesage = os.strerror(errno.ETIME)):
        self.sec = sec
        self.error_mesage = error_mesage

    def __enter__(self):
        signal.signal(signal.SIGALRM, self._handle_timeout)
        signal.alarm(self.sec)

    def __exit__(self, *args):
        signal.alarm(0)

    def _handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_mesage)

def do_nothing():
    pass

def run_build_cfg_and_analyze(timeout_cb = do_nothing):
    global g_disasm_file
    global g_bytecode
    global real_instruction_length
    
    global solver
    solver = Solver()
    solver.set("timeout", 2)

    global g_timeout
    g_timeout = False
   
    global end_ins_dict
    end_ins_dict = {}

    global instructions
    instructions = {}

    global jump_type
    jump_type = {}

    global basic_block
    basic_block = {}

    global edges
    edges = {}
    
    global gen
    gen = VarGenerator()

    global RETURNDATASIZE
    RETURNDATASIZE = BitVecVal(0, 256)

    global visited_pcs
    visited_pcs = set()  

    global total_no_of_paths
    total_no_of_paths = 0

    global funcs_of_paths
    funcs_of_paths = {} 

    global all_paths
    all_paths = {}

    global valided_paths
    valided_paths = {}

    global forcibly_terminated_paths
    forcibly_terminated_paths = {}

    global path_conditions_of_all_paths
    path_conditions_of_all_paths = {}

    global maybe_crosschain_function_call_paths
    maybe_crosschain_function_call_paths={}

    global maybe_unprotected_data_injection_paths
    maybe_unprotected_data_injection_paths = {}

    global reentrancy_all_paths
    reentrancy_all_paths = {}

    global maybe_unchecked_external_call_paths
    maybe_unchecked_external_call_paths = {}

    global sstore_storage_ALL_paths
    sstore_storage_ALL_paths = {}

    global sload_storage_ALL_paths
    sload_storage_ALL_paths = {}
    
    try:
        with Timeout(sec = global_controller.GLOBAL_SYMBOLIC_TIMEOUT):
            build_cfg_and_analyze() 

        print("[BridgeGuard]  \t\033[96m Symbolic Data Flow Analysis:\033[0m\t\t\t\033[92m Done\033[0m")

    except TimeoutError:
        print("[BridgeGuard]  \t\033[91m SYMBOLIC Timeout \033[0m")

        g_timeout = True
        with open("AuditTimeout.txt", "a") as f:
            f.write("%s\n" % g_disasm_file)

        timeout_cb()    

# Build CFG and analyze.
def build_cfg_and_analyze():
    change_format()
   
    with open(g_disasm_file, 'r') as disasm_file:
        disasm_file.readline()
        
        tokens = tokenize.generate_tokens(disasm_file.readline)
        collect_basic_block(tokens) 
        
        construct_basic_block() 
        
        construct_static_edges() 
        
        run_symbolic_execution()
 
# Change format of disasm file and rewrite it.
def change_format():
    with open(g_disasm_file) as disasm_file:
        disasm_file_contents = disasm_file.readlines()
        i = 0
        firstLine = disasm_file_contents[0].strip('\n')

        for line in disasm_file_contents:
            line = line.replace('Missing opcode 0xfd', 'REVERT')
            line = line.replace('Missing opcode 0xfe', 'ASSERTFAIL')
            line = line.replace('Missing opcode', 'INVALID')
            line = line.replace(':', '')

            lineParts = line.split(' ')
            
            try:
                lineParts[0] = str(int(lineParts[0], 16))
            except:
                lineParts[0] = lineParts[0]   
            
            lineParts[-1] = lineParts[-1].strip('\n')
            
            try:
                lastInt = lineParts[-1]

                if (int(lastInt, 16) or int(lastInt, 16)==0) and len(lineParts)>2:
                    lineParts[-1] = "=>"
                    lineParts.append(lastInt)

            except:
                pass

            disasm_file_contents[i] = ' '.join(lineParts)
            i = i + 1 
        
        disasm_file_contents[0] = firstLine 
        disasm_file_contents[-1] += '\n'
    
    with open(g_disasm_file, 'w') as disasm_file:
        disasm_file.write("\n".join(disasm_file_contents))


########################################################################
# Build basic block and static edges.
########################################################################
# 1. Parse the disassembled file.
# 2. Then identify start pc and end pc of each basic block.
# 3. Store them in end_ins_dict and jump_type.
def collect_basic_block(tokens):
    global end_ins_dict 
    global instructions
    global jump_type

    current_instr_pc = 0 
    last_instr_pc = 0
    is_new_line = True
    current_block = 0
    current_line_content = ""
    wait_for_push = False
    is_new_block = False

    for token_type, token_string, (start_row, start_col), _, line_content in tokens:
        if wait_for_push is True:
            push_val = ""
            
            for ptok_type, ptok_string, _, _, _ in tokens:
                if ptok_type == NEWLINE:
                    is_new_line = True
                    current_line_content += push_val + " "
                    instructions[current_instr_pc] = current_line_content
                    idx = None
                    current_line_content = ""
                    wait_for_push = False
                    break

                try:
                    int(ptok_string, 16)
                    push_val += ptok_string
                except ValueError:
                    pass

            continue

        elif is_new_line is True and token_type == NUMBER:
            last_instr_pc = current_instr_pc
            try:
                current_instr_pc = int(token_string)
            except ValueError:
                print("Error when paring row: %d col: %d"% (start_row, start_col))
                quit()
            
            is_new_line = False
            
            if is_new_block:
                current_block = current_instr_pc
                is_new_block = False
            continue
        
        elif token_type == NEWLINE:
            is_new_line = True
            instructions[current_instr_pc] = current_line_content
            idx = None
            current_line_content = ""
            continue
        elif token_type == NAME:
            if token_string == "JUMPDEST": 
                if last_instr_pc not in end_ins_dict:
                    end_ins_dict[current_block] = last_instr_pc
                current_block = current_instr_pc
                is_new_block = False
            
            elif token_string in ("STOP", "RETURN", "SUICIDE", "SELFDESTRUCT", "REVERT", "INVALID"): 
                jump_type[current_block] = "terminal"
                end_ins_dict[current_block] = current_instr_pc
                is_new_block = True
            
            elif token_string == "JUMP": 
                jump_type[current_block] = "direct"
                end_ins_dict[current_block] = current_instr_pc
                is_new_block = True
            
            elif token_string == "JUMPI": 
                jump_type[current_block] = "conditional"
                end_ins_dict[current_block] = current_instr_pc
                is_new_block = True
            
            elif token_string.startswith("PUSH", 0):
                wait_for_push = True
            
            is_new_line = False
        
        if token_string != "=" and token_string != ">": 
            current_line_content += token_string + " "
    
    if current_block not in end_ins_dict:
        if global_controller.VERBOSE:
            print("[BridgeGuard]:\t current block: %d"% current_block)
            print("[BridgeGuard]:\t last line: %d"% current_instr_pc)

        end_ins_dict[current_block] = current_instr_pc
     
    if current_block not in jump_type:
        jump_type[current_block] = "terminal"

    for key in end_ins_dict:
        if key not in jump_type:
            jump_type[key] = "falls_to"

# Write in basic_block which is dictionaty where keys is start pc of basic_block, and value is BasicBlock objective.
def construct_basic_block():
    global basic_block
    global edges

    sorted_pcs = sorted(instructions.keys())
    size = len(sorted_pcs)

    for key in end_ins_dict:
        end_pc = end_ins_dict[key]
        block = BasicBlock(key, end_pc)

        if key not in instructions:
            continue
        block.add_instruction(str(key) + " " + instructions[key])
        i = sorted_pcs.index(key) + 1

        while i < size and sorted_pcs[i] <= end_pc:
            block.add_instruction(str(sorted_pcs[i]) +  " " + instructions[sorted_pcs[i]])
            i += 1

        block.set_block_type(jump_type[key])
        basic_block[key] = block
        edges[key] = []

# When jump_type is conditional (JUMPI), there are two branch, one is falls_to, the other is jump to location of JUMPDEST.
# Find falls_to branch.
def construct_static_edges():
    add_falls_to()

# Set attribute of falls_to in the BasicBlock. Then write edge.
def add_falls_to():
    global basic_block
    global edges
    key_list = sorted(jump_type.keys())
    length = len(key_list)

    for i, key in enumerate(key_list):
        if jump_type[key] != "terminal" and jump_type[key] != "direct" and i+1 < length:
            target = key_list[i+1]
            edges[key].append(target)
            basic_block[key].set_falls_to(target)


########################################################################
# Run symbolic data flow analysis.
########################################################################
def run_symbolic_execution():
    path_conditions_and_vars = {"path_condition": []} 
    
    world_state = init_world_state(path_conditions_and_vars) 

    analysis = init_alalysis() 
    
    executionstate = ExecutionState(path_conditions_and_vars = path_conditions_and_vars, world_state = world_state, analysis = analysis)
    
    print("[BridgeGuard]  \t\033[96m Begin Symbolic Data Flow Analysis ...\033[0m")
    
    symbolic_execution_block(executionstate, 0, 0, 0)

def symbolic_execution_block(executionstate, block, pre_block, depth):
    global solver
    global visited_edges
    global total_no_of_paths

    visited = executionstate.visited  
    visited_edges = executionstate.visited_edges
    analysis = executionstate.analysis
    sig_of_func = executionstate.sig_of_func
    path_conditions_and_vars = executionstate.path_conditions_and_vars

    Edge = namedtuple("Edge", ["v1", "v2"])
    if block < 0:
        print("[BridgeGuard]  \033[91m UNKNOWN JUMP ADDRESS. TERMINATING THIS PATH\033[0m")
        if global_controller.VERBOSE:
            print("[BridgeGuard]:\t \033[91m UNKNOWN JUMP ADDRESS. TERMINATING THIS PATH\033[0m")
        return ["ERROR"]
    
    if global_controller.VERBOSE:
        print("[BridgeGuard]:\t \033[96m############################### Path-%s: From %d Reach block address %d: \033[0m"% (total_no_of_paths+1, pre_block, block))

    current_edge = Edge(pre_block, block)

    if current_edge in visited_edges:
        updated_count_number = visited_edges[current_edge] + 1
        visited_edges.update({current_edge: updated_count_number})
    else:
        visited_edges.update({current_edge: 1})

    try:
        block_instructions = basic_block[block].get_instructions()
    except:
        print("[BridgeGuard]  \033[91mThis block %s results in an exception (cannot get block_instructions), possibly an invalid jump address\033[0m"% block)
        if global_controller.VERBOSE:
            print("[BridgeGuard]:\t \033[91mThis block %s results in an exception (cannot get block_instructions), possibly an invalid jump address\033[0m"% block)
        return ["ERROR"]

    for i, instr in enumerate(block_instructions):
        instr_parts = str.split(instr, " ") 
        opcode = instr_parts[1]
        
        if opcode in ("PUSH3","PUSH4"):
            pushed_value = instr_parts[2]

            if jump_type[block] == "conditional":
                second_instr_part = []
                third_instr_part = []

                if (i+1) < len(list(block_instructions)):
                    second_instr_part = str.split(block_instructions[i+1], " ")

                if (i+2) < len(list(block_instructions)):
                    third_instr_part = str.split(block_instructions[i+2], " ")

                if str(second_instr_part) != "[]" and str(third_instr_part) != "[]":
                    if second_instr_part[1] in ("EQ", "GT", "LT") and  "PUSH" in third_instr_part[1]:
                        sig_of_func.append(pushed_value)

        symbolic_execution_instruction(executionstate, block, instr, sig_of_func)

    if sig_of_func:
        if sig_of_func[-1] == global_controller.SAME_OVERLOOP_FUNC:
            if global_controller.SAME_OVRRLOOP_NUM == global_controller.SAME_OVERLOOP_NUM_LIMIT:
                return
            
        if sig_of_func[-1] == global_controller.SAME_OVERLONG_FUNC:
            if global_controller.SAME_OVERLONG_NUM == global_controller.SAME_OVERLONG_NUM_LIMIT:
                return
            
        if sig_of_func[-1] == global_controller.SAME_VALID_FUNC:
            if global_controller.SAME_VALID_NUM == global_controller.SAME_VALID_NUM_LIMIT:
                return
            
        if sig_of_func[-1] == global_controller.SAME_REVERT_FUNC:
            if global_controller.SAME_REVERT_NUM == global_controller.SAME_REVERT_NUM_LIMIT:
                return
            
    else:
        if str(sig_of_func) == global_controller.SAME_OVERLOOP_FUNC:
            if global_controller.SAME_OVRRLOOP_NUM == global_controller.SAME_OVERLOOP_NUM_LIMIT:
                return
            
        if str(sig_of_func) == global_controller.SAME_OVERLONG_FUNC:
            if global_controller.SAME_OVERLONG_NUM == global_controller.SAME_OVERLONG_NUM_LIMIT:
                return
            
        if str(sig_of_func) == global_controller.SAME_VALID_FUNC:
            if global_controller.SAME_VALID_NUM == global_controller.SAME_VALID_NUM_LIMIT:
                return
            
        if str(sig_of_func) == global_controller.SAME_REVERT_FUNC:
            if global_controller.SAME_REVERT_NUM == global_controller.SAME_REVERT_NUM_LIMIT:
                return
            
    visited.append(block) 
    depth += 1 

    if jump_type[block] == "terminal" or depth > global_controller.DEPTH_LIMIT or visited_edges[current_edge] >= global_controller.LOOP_LIMIT:

        total_no_of_paths += 1

        all_paths[total_no_of_paths] = visited

        path_conditions_of_all_paths[total_no_of_paths] = copy.deepcopy(path_conditions_and_vars["path_condition"])
        
        if sig_of_func:
            funcs_of_paths[total_no_of_paths] = sig_of_func[-1]
        else:
            funcs_of_paths[total_no_of_paths] = sig_of_func

        last_instr = basic_block[block].get_instructions()[-1]
        opcode = str.split(last_instr, " ")[1]

        if opcode in ("RETURN","STOP","SUICIDE","SELFDESTRUCT") or depth > global_controller.DEPTH_LIMIT or visited_edges[current_edge] >= global_controller.LOOP_LIMIT:
            if analysis["reentrancy_call_pcs"]:
                reentrancy_all_paths[total_no_of_paths] = analysis["reentrancy_call_pcs"]
            
            if analysis["CALL_pcs"]:
                maybe_unchecked_external_call_paths[total_no_of_paths]= analysis["CALL_pcs"]
                
                maybe_unprotected_data_injection_paths[total_no_of_paths]= analysis["CALL_pcs"]
                
                maybe_crosschain_function_call_paths[total_no_of_paths]= analysis["CALL_pcs"]
            
            if analysis["DELEGATECALL_pcs"]:
                maybe_unchecked_external_call_paths[total_no_of_paths]= analysis["DELEGATECALL_pcs"]
            
            if analysis["STATICCALL_pcs"]:
                maybe_unchecked_external_call_paths[total_no_of_paths]= analysis["STATICCALL_pcs"]
            
            if analysis["SSTORE_info"]:
                sstore_storage_ALL_paths[total_no_of_paths] = analysis["SSTORE_info"]
            
            if analysis["SLOAD_info"]:
                sload_storage_ALL_paths[total_no_of_paths] = analysis["SLOAD_info"]

            if opcode in ("RETURN","STOP","SUICIDE","SELFDESTRUCT"):
                valided_paths[total_no_of_paths] = visited
                
                if sig_of_func:
                    if str(sig_of_func[-1]) != global_controller.SAME_VALID_FUNC:
                        global_controller.SAME_VALID_FUNC = str(sig_of_func[-1])
                        global_controller.SAME_VALID_NUM = 1
                    else:
                        global_controller.SAME_VALID_NUM += 1
                else:
                    if str(sig_of_func) != global_controller.SAME_VALID_FUNC:
                        global_controller.SAME_VALID_FUNC = str(sig_of_func)
                        global_controller.SAME_VALID_NUM = 1
                    else:
                        global_controller.SAME_VALID_NUM += 1


            if depth > global_controller.DEPTH_LIMIT:
                forcibly_terminated_paths[total_no_of_paths] = visited
                if sig_of_func:
                    print("[BridgeGuard]  \033[91m\t This path %s is too long:\033[0m, \033[91m possibly an exception %s\033[0m"% (str(total_no_of_paths),str(sig_of_func[-1])))
                    
                    if global_controller.VERBOSE:
                        print("[BridgeGuard]:\t \033[91m\t This path %s is too long:\033[0m, \033[91m possibly an exception %s\033[0m"% (str(total_no_of_paths),str(sig_of_func[-1])))
                    
                    if str(sig_of_func[-1]) != global_controller.SAME_OVERLONG_FUNC:
                        global_controller.SAME_OVERLONG_FUNC = str(sig_of_func[-1])
                        global_controller.SAME_OVERLONG_NUM = 1
                    else:
                        global_controller.SAME_OVERLONG_NUM += 1
                else:
                    print("[BridgeGuard]  \033[91m\t This path %s is too long:\033[0m, \033[91m possibly an exception %s\033[0m"% (str(total_no_of_paths),str(sig_of_func)))
                    
                    if global_controller.VERBOSE:
                        print("[BridgeGuard]:\t \033[91m\t This path %s is too long:\033[0m, \033[91m possibly an exception\033[0m"% str(total_no_of_paths))
                    
                    if str(sig_of_func) != global_controller.SAME_OVERLONG_FUNC:
                        global_controller.SAME_OVERLONG_FUNC = str(sig_of_func)
                        global_controller.SAME_OVERLONG_NUM = 1
                    else:
                        global_controller.SAME_OVERLONG_NUM += 1
                return 

            if visited_edges[current_edge] >= global_controller.LOOP_LIMIT: 
                forcibly_terminated_paths[total_no_of_paths] = visited
                
                if sig_of_func:
                    print("[BridgeGuard]  \033[91m\t Overcome a number of loop limit. Terminating path %s ... %s\033[0m"% (str(total_no_of_paths), str(sig_of_func[-1])))
                    
                    if global_controller.VERBOSE:
                        print("[BridgeGuard]:\t \033[91m\t Overcome a number of loop limit. Terminating path %s ... %s\033[0m"% (str(total_no_of_paths), str(sig_of_func[-1])))
                    if str(sig_of_func[-1]) != global_controller.SAME_OVERLOOP_FUNC:
                        global_controller.SAME_OVERLOOP_FUNC = str(sig_of_func[-1])
                        global_controller.SAME_OVRRLOOP_NUM = 1
                    else:
                        global_controller.SAME_OVRRLOOP_NUM += 1
                else:
                    print("[BridgeGuard]  \033[91m\t Overcome a number of loop limit. Terminating path %s ... %s\033[0m"% (str(total_no_of_paths), str(sig_of_func)))
                    
                    if global_controller.VERBOSE:
                        print("[BridgeGuard]:\t \033[91m\t Overcome a number of loop limit. Terminating path %s ...\033[0m"% str(total_no_of_paths)) 
                    
                    if str(sig_of_func) != global_controller.SAME_OVERLOOP_FUNC:
                        global_controller.SAME_OVERLOOP_FUNC = str(sig_of_func)
                        global_controller.SAME_OVRRLOOP_NUM = 1
                    else:
                        global_controller.SAME_OVRRLOOP_NUM += 1      
                return
        
        if opcode in ("REVERT"):
            if sig_of_func:
                if str(sig_of_func[-1]) != global_controller.SAME_REVERT_FUNC:
                    global_controller.SAME_REVERT_FUNC = str(sig_of_func[-1])
                    global_controller.SAME_REVERT_NUM = 1
                else:
                    global_controller.SAME_REVERT_NUM += 1
            else:
                if str(sig_of_func) != global_controller.SAME_REVERT_FUNC:
                    global_controller.SAME_REVERT_FUNC = str(sig_of_func)
                    global_controller.SAME_REVERT_NUM = 1
                else:
                    global_controller.SAME_REVERT_NUM += 1
        
        if global_controller.VERBOSE:
            print("[BridgeGuard]:\t \033[92mTERMINATING A PATH .....\033[0m")

    elif jump_type[block] == "direct": 
        successor = basic_block[block].get_jump_target()
        new_executionstate = executionstate.copy()
        new_executionstate.world_state["pc"] = successor
        symbolic_execution_block(new_executionstate, successor, block, depth)
    
    elif jump_type[block] == "falls_to": 
        successor = basic_block[block].get_falls_to()
        new_executionstate = executionstate.copy()
        new_executionstate.world_state["pc"] = successor
        symbolic_execution_block(new_executionstate, successor, block, depth)
    
    elif jump_type[block] == "conditional": 
        if not global_controller.SECONDMODE:
            branch_expression = copy.deepcopy(basic_block[block].get_branch_expression())
            negated_branch_expression = Not(copy.deepcopy(basic_block[block].get_branch_expression()))
            left_cond = copy.deepcopy(path_conditions_and_vars["path_condition"])
            left_cond.append(branch_expression)
            right_cond = copy.deepcopy(path_conditions_and_vars["path_condition"])
            right_cond.append(negated_branch_expression)
        
            if global_controller.VERBOSE:
                print("[BridgeGuard]:\t Branch expression: " + str(branch_expression))
            try:
                if solver_check(left_cond) == unsat:
                    if global_controller.VERBOSE:
                        print("[BridgeGuard]:\t \033[91mINFEASIBLE PATH DETECTED\033[0m")
                else:
                    left_branch = basic_block[block].get_jump_target()
                    new_executionstate = executionstate.copy()
                    new_executionstate.world_state["pc"] = left_branch
                    new_executionstate.path_conditions_and_vars["path_condition"].append(basic_block[block].get_branch_expression())
                    symbolic_execution_block(new_executionstate, left_branch, block, depth)
            
            except TimeoutError:
                print("[BridgeGuard]  \033[91m Branch expression is timeout %s \033[0m" % basic_block[block].get_jump_target())
                raise
            
            except Exception as e:
                print("[BridgeGuard]  \033[91m Branch expression is error %s\033[0m" % basic_block[block].get_jump_target())
                raise

            if global_controller.VERBOSE:
                print("[BridgeGuard]:\t Negated branch expression: " + str(negated_branch_expression))
            
            try:
                if solver_check(right_cond) == unsat:
                    if global_controller.VERBOSE:
                        print("[BridgeGuard]:\t \033[91mINFEASIBLE PATH DETECTED\033[0m")
                else: 
                    right_branch = basic_block[block].get_falls_to()
                    new_executionstate = executionstate.copy()
                    new_executionstate.world_state["pc"] = right_branch
                    new_executionstate.path_conditions_and_vars["path_condition"].append(Not(basic_block[block].get_branch_expression()))
                    symbolic_execution_block(new_executionstate, right_branch, block, depth)
            
            except TimeoutError:
                print("[BridgeGuard]  \033[91mNegated Branch expression is timeout %s\033[0m" % basic_block[block].get_falls_to())
                raise
            
            except Exception as e:
                print("[BridgeGuard]  \033[91mNegated Branch expression is error %s\033[0m" % basic_block[block].get_falls_to())
                raise

        if global_controller.SECONDMODE:
            branch_expression = copy.deepcopy(basic_block[block].get_branch_expression())
            negated_branch_expression = Not(copy.deepcopy(basic_block[block].get_branch_expression()))

            left_cond = copy.deepcopy(path_conditions_and_vars["path_condition"])
            left_cond.append(branch_expression)

            right_cond = copy.deepcopy(path_conditions_and_vars["path_condition"])
            right_cond.append(negated_branch_expression)

            if global_controller.VERBOSE:
                print("[BridgeGuard]:\t Branch expression: " + str(branch_expression))
            
            left_branch = basic_block[block].get_jump_target()

            new_executionstate = executionstate.copy()
            new_executionstate.world_state["pc"] = left_branch
            new_executionstate.path_conditions_and_vars["path_condition"].append(basic_block[block].get_branch_expression())
            
            symbolic_execution_block(new_executionstate, left_branch, block, depth)

            if global_controller.VERBOSE:
                print("[BridgeGuard]:\t Negated branch expression: " + str(negated_branch_expression))
            
            right_branch = basic_block[block].get_falls_to()
            
            new_executionstate = executionstate.copy()
            new_executionstate.world_state["pc"] = right_branch
            new_executionstate.path_conditions_and_vars["path_condition"].append(Not(basic_block[block].get_branch_expression()))
            
            symbolic_execution_block(new_executionstate, right_branch, block, depth)

    else:
        raise Exception('\033[91mUnknown Jump-Type\033[0m')

def symbolic_execution_instruction(executionstate, block, instruction, sig_of_func):
    global visited_pcs
    global solver
    global basic_block
    global edges
    global g_source_map

    g_source_map = None

    global g_bytecode
    global RETURNDATASIZE
    global real_instruction_length

    stack = executionstate.stack  
    mem = executionstate.mem  
    world_state = executionstate.world_state
    analysis = executionstate.analysis
    sha3_list = executionstate.sha3_list
    path_conditions_and_vars = executionstate.path_conditions_and_vars

    visited_pcs.add(world_state["pc"]) 
    instruction_parts = str.split(instruction, " ") 
    opcode = instruction_parts[1]

    if opcode == "INVALID": 
        return

    if len(sig_of_func) >= 1:
        func = sig_of_func[-1]
    else:
        func = "[]"
    
    if global_controller.VERBOSE:
        print("[BridgeGuard]:\t ===============================--%s" % func)
        print("[BridgeGuard]:\t Stack: " + str(stack))
        print("[BridgeGuard]:\t  Mem: " + str(mem))
        print("[BridgeGuard]:\t EXECUTING: " + str(instruction))

    update_analysis(analysis, opcode, stack, world_state, path_conditions_and_vars, g_disasm_file)

    if opcode == "STOP": 
        pass

    elif opcode == "ADD": 
        if len(stack) > 1:
            world_state["pc"] += 1
            first = stack.pop(0)
            second = stack.pop(0)
            
            computed = binary(first, second, world_state["pc"]-1, opcode)
            stack.insert(0, computed)  
        else:
            raise ValueError('STACK underflow')
        
    elif opcode == "MUL": 
        if len(stack) > 1:
            world_state["pc"] += 1
            first = stack.pop(0)
            second = stack.pop(0)

            computed = binary(first, second, world_state["pc"] - 1, opcode)
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "SUB": 
        if len(stack) > 1:
            world_state["pc"] += 1
            first = stack.pop(0)
            second = stack.pop(0)

            computed = binary(first, second, world_state["pc"]-1, opcode)
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "DIV": 
        if len(stack) > 1:
            world_state["pc"] += 1
            first = stack.pop(0)
            second = stack.pop(0)
    
            computed = binary(first, second, world_state["pc"]-1, opcode)
            stack.insert(0, computed)
        else: 
            raise ValueError("STACK underflow")
        
    elif opcode == "SDIV":  
        if len(stack) > 1:
            world_state["pc"] += 1
            first = stack.pop(0)
            second = stack.pop(0)
  
            computed = binary(first, second, world_state["pc"]-1, opcode)
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "MOD":
        if len(stack) > 1:
            world_state["pc"] += 1
            first = stack.pop(0)
            second = stack.pop(0)
    
            computed = binary(first, second, world_state["pc"]-1, opcode)
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "SMOD":  
        if len(stack) > 1:
            world_state["pc"] += 1
            first = stack.pop(0)
            second = stack.pop(0)
 
            computed = binary(first, second, world_state["pc"]-1, opcode)
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "ADDMOD":
        if len(stack) > 2:
            world_state["pc"] += 1
            first = stack.pop(0)
            second = stack.pop(0)
            third = stack.pop(0)
       
            computed = ternary(first, second, third, world_state["pc"]-1, opcode)
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "MULMOD": 
        if len(stack) > 2:
            world_state["pc"] += 1
            first = stack.pop(0)
            second = stack.pop(0)
            third = stack.pop(0)
        
            computed = ternary(first, second, third, world_state["pc"]-1, opcode)
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "EXP": 
        if len(stack) > 1:
            world_state["pc"] += 1
            base = stack.pop(0)
            exponent = stack.pop(0)
    
            computed = binary(base, exponent, world_state["pc"]-1, opcode)
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "SIGNEXTEND": 
        if len(stack) > 1:
            world_state["pc"] += 1
            first = stack.pop(0)
            second = stack.pop(0)
            first = simplify(first)
            second = simplify(second)

            if not is_bv_value(first) or not is_bv_value(second):
               
                new_var_name = gen.gen_signextend_var()
                stack.insert(0, BitVec(new_var_name, 256))
                
            else:
                first = get_value(first)
                second = get_value(second)
                o = second
                t = 256 - 8 * (first + 1 )
                tbit = (o >> t) & 1
                n = 0
                for i in range(256):
                    n ^= (tbit if i <= t else ((o>>i) & 1)) << i
                stack.insert(0, BitVecVal(n, 256))
        else:
            raise ValueError("STACK underflow")
    
   
    elif opcode == "LT": 
        if len(stack) > 1:
            world_state["pc"] += 1
            first = stack.pop(0)
            second = stack.pop(0)

            computed = binary(first, second, world_state["pc"]-1, opcode)
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "GT": 
        if len(stack) > 1:
            world_state["pc"] = world_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)

            computed = binary(first, second, world_state["pc"]-1, opcode)
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
        
    elif opcode == "SLT": 
        if len(stack) > 1:
            world_state["pc"] = world_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
 
            computed = binary(first, second, world_state["pc"]-1, opcode)
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
        
    elif opcode == "SGT": 
        if len(stack) > 1:
            world_state["pc"] = world_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)

            computed = binary(first, second, world_state["pc"]-1, opcode)
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
        
    elif opcode == "EQ": 
        if len(stack) > 1:
            world_state["pc"] = world_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)

            computed = binary(first, second, world_state["pc"]-1, opcode)
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
        
    elif opcode == "ISZERO": 
        
        if len(stack) > 0:
            world_state["pc"] = world_state["pc"] + 1
            first = stack.pop(0)

            computed = unary(first, world_state["pc"]-1, opcode)
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
        
    elif opcode == "AND": 
        if len(stack) > 1:
            world_state["pc"] += 1
            first = stack.pop(0)
            second = stack.pop(0)

            computed = binary(first, second, world_state["pc"]-1, opcode)
            stack.insert(0, computed)
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "OR": 
        if len(stack) > 1:
            world_state["pc"] = world_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
 
            computed = binary(first, second, world_state["pc"]-1, opcode)
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
        
    elif opcode == "XOR": 
        if len(stack) > 1:
            world_state["pc"] = world_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)

            computed = binary(first, second, world_state["pc"]-1, opcode)
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
        
    elif opcode == "NOT": 
        if len(stack) > 0:
            world_state["pc"] = world_state["pc"] + 1
            first = stack.pop(0)

            computed = unary(first, world_state["pc"]-1, opcode)
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
        
    elif opcode == "BYTE": 
        if len(stack) > 1:
            world_state["pc"] += 1
            byte_index = stack.pop(0)
            word = stack.pop(0)

            result = (simplify(word) >> (8 * (31 - simplify(byte_index)))) & 0xff
            
            stack.insert(0, simplify(result))  
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "SHL": 
        if len(stack) > 1:
            world_state["pc"] += 1
            shift_bit = stack.pop(0)
            value = stack.pop(0)

            result = simplify(value) << simplify(shift_bit)
            
            stack.insert(0, simplify(result))               
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "SHR": 
        if len(stack) > 1:
            world_state["pc"] += 1
            shift_bit = stack.pop(0)
            value = stack.pop(0)

            result = LShR(value, shift_bit)
            stack.insert(0, simplify(result))
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "SAR": 
        if len(stack) > 1:
            world_state["pc"] += 1
            shift_bit = stack.pop(0)
            value = stack.pop(0)

            result = simplify(value) >> simplify(shift_bit)
            stack.insert(0, simplify(result))
        else:
            raise ValueError("STACK underflow")

     
    elif opcode in ("SHA3", "KECCAK256"): 
        if len(stack) > 1:
            world_state["pc"] += 1
            address = stack.pop(0)
            offset = stack.pop(0)
   
            address = simplify(address)
            offset = simplify(offset)

            if is_bv_value(address) and is_bv_value(offset):
                exact_address = get_value(address)
                exact_offset  = get_value(offset)
                sha3_content = "["
                
                for i in range(exact_address + exact_offset):
                    if exact_address + i in mem:
                        sha3_content += str(mem[exact_address+i])

                sha3_content += "]"

                if sha3_content not in sha3_list:
                    new_var_name = gen.gen_sha3_var(sha3_content)
                    new_var = BitVec(new_var_name, 256)
                    path_conditions_and_vars[new_var_name] = new_var
                    sha3_list[sha3_content] = new_var
                    stack.insert(0, new_var)
                else:
                    res = sha3_list[sha3_content]
                    stack.insert(0, res)

            else:
                if is_bv_value(address):
                    address = get_value(address)
                else:
                    address = str(address)
                sha3_content = ""
                if address in mem:
                    sha3_content = '[' + str(mem[address]) + ']'
                else:
                    sha3_content = '[' + str(address) + "+" + str(offset) + ']'

                if sha3_content not in sha3_list:
                    new_var_name = gen.gen_sha3_var(sha3_content)
                    new_var = BitVec(new_var_name, 256)
                    path_conditions_and_vars[new_var_name] = new_var
                    sha3_list[sha3_content] = new_var
                    stack.insert(0, new_var)
                else:
                    res = sha3_list[sha3_content]
                    stack.insert(0, res)
        else:
            raise ValueError("STACK underflow")
   
    
    elif opcode == "ADDRESS": 
        world_state["pc"] += 1
        stack.insert(0, world_state["receiver_address"])
    elif opcode == "BALANCE": 
        if len(stack) > 0:
            world_state["pc"] += 1
            address = stack.pop(0)
 
            address = simplify(address) 
            if is_bv_value(address):
                address = hex(get_value(address))
                hashed_address = str(address)
                new_var_name = gen.gen_balance_var(hashed_address)
                new_var = BitVec(new_var_name, 256)
                world_state["balance"][hashed_address] = new_var
                stack.insert(0, new_var)
            else:
                hashed_address = str(address)
                new_var_name = gen.gen_balance_var(hashed_address)
                new_var = BitVec(new_var_name, 256)
                world_state["balance"][hashed_address] = new_var
                stack.insert(0, new_var)
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "CALLER": 
        world_state["pc"] += 1
        stack.insert(0, world_state["sender_address"])

    elif opcode == "ORIGIN": 
        world_state["pc"] += 1
        stack.insert(0, world_state["origin"])

    elif opcode == "CALLVALUE": 
        world_state["pc"] += 1
        stack.insert(0, world_state["callvalue"])

    elif opcode == "CALLDATALOAD": 
        if len(stack) > 0:
            world_state["pc"] += 1
            position = stack.pop(0) 
            
            position = simplify(position)

            new_var_name = gen.get_Taint_Offchain_data_var(position)
            new_var = BitVec(new_var_name, 256)
            stack.insert(0, new_var)
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "CALLDATASIZE": 
        world_state["pc"] += 1
        new_var_name = "Taint_calldata_size"
        new_var = BitVec(new_var_name, 256)
        stack.insert(0, new_var)

    elif opcode == "CALLDATACOPY": 
        if len(stack) > 2:
            world_state["pc"] += 1
            memory_address = stack.pop(0)
            calldata_address = stack.pop(0)
            length = stack.pop(0)

            memory_address = simplify(memory_address)
            calldata_address = simplify(calldata_address)
            length = simplify(length)
            
            calldata_name = "Taint_Calldata_" + "[" + str(calldata_address) + "]+" + str(length)
            new_var = BitVec(calldata_name, 256)
            if is_bv_value(memory_address):
                if is_bv_value(length):
                    i=0
                    memory_address = get_value(memory_address)
                    while i<get_value(length):
                        mem[memory_address+i] = new_var
                        i += 32
                else:
                    memory_address = get_value(memory_address)
                    mem[memory_address] = new_var
            else:                
                mem[str(memory_address)] = new_var
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "CODESIZE": 
        world_state["pc"] += 1
        code_size = len(g_bytecode) / 2
        stack.insert(0, BitVecVal(code_size, 256))

    elif opcode == "CODECOPY":
        if len(stack) > 2:
            world_state["pc"] += 1
            memory_location = stack.pop(0)
            code_start = stack.pop(0)
            number_bytes_of_code = stack.pop(0)

            memory_location = simplify(memory_location)
            code_start = simplify(code_start)
            number_bytes_of_code = simplify(number_bytes_of_code)

           

            if is_bv_value(code_start):
                length = get_value(code_start)
                if length < real_instruction_length:
                    real_instruction_length = length 

            new_var_name = gen.gen_code_var("Ia", code_start, number_bytes_of_code)
            new_var = BitVec(new_var_name, 256)      
            if is_bv_value(memory_location):
                if is_bv_value(number_bytes_of_code):
                    i=0
                    memory_location = get_value(memory_location)
                    while i<get_value(number_bytes_of_code):
                        mem[memory_location+i] = new_var
                        i += 32
                else:
                    memory_location = get_value(memory_location)
                    mem[memory_location] = new_var
            else:
                mem[str(memory_location)] = new_var
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "GASPRICE": 
        world_state["pc"] += 1
        stack.insert(0, world_state["gas_price"]) 

    elif opcode == "EXTCODESIZE": 
        if len(stack) > 0:
            world_state["pc"] += 1
            address = stack.pop(0)

            address = simplify(address)
            if is_bv_value(address):
                address = hex(get_value(address))
                new_var_name = gen.gen_extcode_size_var(address)
                new_var = BitVec(new_var_name, 256)
                stack.insert(0, new_var)
            else:
                new_var_name = gen.gen_extcode_size_var(str(address))
                new_var = BitVec(new_var_name, 256)
                stack.insert(0, new_var)
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "EXTCODECOPY": 
        if len(stack) > 3:
            world_state["pc"] += 1
            address = stack.pop(0)
            memory_location = stack.pop(0)
            code_start = stack.pop(0)
            number_bytes_of_code = stack.pop(0)

            address = simplify(address)
            memory_location = simplify(memory_location)
            code_start = simplify(code_start)
            number_bytes_of_code = simplify(number_bytes_of_code)

            new_var_name = gen.gen_extcode_var(address, code_start, number_bytes_of_code)
            new_var = BitVec(new_var_name, 256)

            if is_bv_value(memory_location):
                memory_location = get_value(memory_location)
                if is_bv_value(number_bytes_of_code):
                    i=0
                    memory_location = get_value(memory_location)
                    while i<get_value(number_bytes_of_code):
                        mem[memory_location+i] = new_var
                        i += 32
                else:
                    memory_location = get_value(memory_location)
                    mem[memory_location] = new_var
            else:
                memory_location = str(memory_location)
                mem[memory_location] = new_var 

        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "RETURNDATASIZE":  
        world_state["pc"] += 1
        if is_bv_value(RETURNDATASIZE):
            stack.insert(0, RETURNDATASIZE)
        else:
            new_var = BitVec(str(RETURNDATASIZE), 256)
            stack.insert(0, new_var)     

    elif opcode == "RETURNDATACOPY":
        if len(stack) > 2:
            world_state["pc"] += 1
            memory_address = stack.pop(0)
            return_address = stack.pop(0)
            byte_length = stack.pop(0)

            memory_address = simplify(memory_address)
            return_address = simplify(return_address)
            byte_length = simplify(byte_length)

            new_var_name = gen.gen_returndata_var(return_address, byte_length)
            new_var = BitVec(new_var_name, 256)

            if is_bv_value(memory_address):
                if is_bv_value(byte_length):
                    memory_address = get_value(memory_address)
                    i=0
                    while i < get_value(byte_length):
                        mem[memory_address+i] = new_var
                        i += 32
                else:    
                    memory_address = get_value(memory_address)
                    mem[memory_address] = new_var
            else:
                memory_address = str(memory_address)
                mem[memory_address] = new_var
            
            
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "EXTCODEHASH": 
        if len(stack) > 1:
            world_state["pc"] += 1
            address = stack.pop(0)

            address = simplify(address)

            if is_bv_value(address):
                address = hex(get_value(address))

            new_var_name = gen.gen_extcodehash_var(address)
            new_var = BitVec(new_var_name, 256)
            stack.insert(0, new_var)
        else:
            raise ValueError("STACK underflow")

    elif opcode == "BLOCKHASH": 
        if len(stack) > 0:
            world_state["pc"] += 1
            stack.pop(0)
            new_var_name = "BLOCK_IH_blockhash"
            new_var = BitVec(new_var_name, 256)
            stack.insert(0, new_var)
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "COINBASE": 
        world_state["pc"] += 1
        stack.insert(0, world_state["currentCoinbase"])

    elif opcode == "TIMESTAMP":  
        world_state["pc"] = world_state["pc"] + 1
        stack.insert(0, world_state["currentTimestamp"])

    elif opcode == "NUMBER":  
        world_state["pc"] = world_state["pc"] + 1
        stack.insert(0, world_state["currentNumber"])

    elif opcode == "DIFFICULTY":  
        world_state["pc"] = world_state["pc"] + 1
        stack.insert(0, world_state["currentDifficulty"])

    elif opcode == "GASLIMIT":  
        world_state["pc"] = world_state["pc"] + 1
        stack.insert(0, world_state["currentGasLimit"])

    elif opcode == "CHAINID":  
        world_state["pc"] = world_state["pc"] + 1
        new_var_name = "BLOCK_IH_chainid"
        new_var = BitVec(new_var_name, 256)
        stack.insert(0, new_var)

    elif opcode == "SELFBALANCE":  
        world_state["pc"] = world_state["pc"] + 1
        stack.insert(0, world_state["balance"]["Ia"])

    elif opcode == "BASEFEE":  
        world_state["pc"] = world_state["pc"] + 1
        new_var_name = "Basefee"
        new_var = BitVec(new_var_name, 256)
        stack.insert(0, new_var)
    
    
    elif opcode == "POP": 
        if len(stack) > 0:
            world_state["pc"] += 1
            stack.pop(0)
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "MLOAD": 
        if len(stack) > 0:
            world_state["pc"] += 1
            mem_address = stack.pop(0)

            mem_address = simplify(mem_address)
            lpc = -1
            rpc = -1
            if is_bv_value(mem_address):
                mem_address = get_value(mem_address)
                if mem_address not in mem:
                    for i in list(mem.keys()):
                        if isinstance(i, int) and i < mem_address and mem_address - i <32 :
                            if lpc < 0 :
                                lpc = i
                            elif lpc >=0 and (mem_address - i) < (mem_address - lpc) : 
                                lpc = i
                        elif isinstance(i, int) and i > mem_address and i - mem_address <32 :
                            if rpc < 0 :
                                rpc = i
                            elif rpc >=0 and (i - mem_address) < (rpc - mem_address) : 
                                rpc = i 
            else:
                mem_address = str(mem_address)

            if mem_address in mem:
                stack.insert(0, mem[mem_address])
            else:
                if lpc >= 0 and rpc >= 0:
                    strAnd = str(mem[lpc])+ '&' + str(mem[rpc])
                    stack.insert(0, BitVec(strAnd, 256))
                    mem[mem_address] = BitVec(strAnd, 256)
                elif lpc >= 0 and rpc < 0:
                    stack.insert(0, mem[lpc])
                    new_var_name = str(mem[lpc])
                    mem[mem_address] = BitVec(new_var_name, 256)
                elif lpc < 0 and rpc >= 0:
                    stack.insert(0, mem[rpc])
                    new_var_name = str(mem[rpc])
                    mem[mem_address] = BitVec(new_var_name, 256)
                else:
                    new_var_name = gen.gen_mem_var(mem_address)
                    new_var = BitVec(new_var_name, 256)
                    mem[mem_address] = new_var
                    stack.insert(0, new_var)
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "MSTORE": 
        if len(stack) > 1:
            world_state["pc"] += 1
            stored_address = stack.pop(0)
            stored_value = stack.pop(0)

            if is_bv(stored_address):
                stored_address = simplify(stored_address)
            if is_bv(stored_value):
                stored_value = simplify(stored_value)

            if is_bv_value(stored_address):
                stored_address = get_value(stored_address)
            else:
                stored_address = str(stored_address)
            mem[stored_address] = copy.deepcopy(stored_value)            
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "MSTORE8": 
        if len(stack) > 1:
            world_state["pc"] += 1
            stored_address = stack.pop(0)
            stored_value = stack.pop(0)
            
            stored_address = simplify(stored_address)
            stored_value = simplify(stored_value)

            if is_bv_value(stored_address):
                stored_address = get_value(stored_address)
            else:
                stored_address = str(stored_address)
            
            if is_bv_value(stored_value):
                stored_value = get_value(stored_value) % 256   
                stored_value = BitVecVal(stored_value, 256) 
            else:
                stored_value = URem(stored_value, BitVecVal(256, 256))  
            
            mem[stored_address] = stored_value
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "SLOAD": 
        if len(stack) > 0:
            world_state["pc"] += 1
            storage_pos = stack.pop(0)
            
            storage_pos = simplify(storage_pos)
            
            if is_bv_value(storage_pos):
                storage_pos = get_value(storage_pos)
            else:
                storage_pos = str(storage_pos)

            if storage_pos in world_state["Ia_Storage"]:
                value = world_state["Ia_Storage"][storage_pos]
                stack.insert(0, value)   
                analysis["SLOAD_info"][world_state["pc"]-1] = {storage_pos: value}
            else:
                new_var_name = gen.gen_owner_store_var(storage_pos)
                new_var = BitVec(new_var_name, 256)
                stack.insert(0, new_var)    
                world_state["Ia_Storage"][storage_pos] = new_var  
                analysis["SLOAD_info"][world_state["pc"]-1] = {storage_pos: new_var} 
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "SSTORE": 
        if len(stack) > 1:
            world_state["pc"] += 1
            stored_address = stack.pop(0)
            stored_value = stack.pop(0)
    
            stored_address = simplify(stored_address)
            stored_value = simplify(stored_value)
            
            analysis["SSTORE_pcs"].append((world_state["pc"]-1, path_conditions_and_vars["path_condition"])) 
            if is_bv_value(stored_address):
                stored_address = get_value(stored_address)
                world_state["Ia_Storage"][stored_address] = stored_value
                analysis["SSTORE_info"][world_state["pc"]-1] = {stored_address: stored_value}
            else:
                world_state["Ia_Storage"][str(stored_address)] = stored_value
                analysis["SSTORE_info"][world_state["pc"]-1] = {str(stored_address): stored_value}
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "JUMP": 
        if len(stack) > 0:
            target_address = stack.pop(0)

            target_address = simplify(target_address)

            if is_bv_value(target_address):
                target_address = get_value(target_address)
            else:
                print("[BridgeGuard]  \033[93m\t The address of JUMP on %s must be an integer \033[0m"% (world_state["pc"] - 1))
           
            basic_block[block].set_jump_target(target_address)
            if target_address not in edges[block]:
                edges[block].append(target_address)
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "JUMPI": 
        if len(stack) > 1:
            target_address = stack.pop(0)
            flag = stack.pop(0)
            
            target_address = simplify(target_address)
            flag = simplify(flag)
           
            if is_bv_value(target_address):
                target_address = get_value(target_address)
            else:
                print("[BridgeGuard]  \033[93m\t The address of JUMPI on %x must be an integer \033[0m"% world_state["pc"] - 1)
            
            basic_block[block].set_jump_target(target_address)
            branch_expression = (BitVecVal(0, 1) == BitVecVal(1, 1))
            if is_bv_value(flag):
                flag = get_value(flag)
                if flag != 0:
                    branch_expression = True   
                else:
                    branch_expression = False
            else:
                branch_expression = (flag != 0)
            
            basic_block[block].set_branch_expression(branch_expression)
            if target_address not in edges[block]:
                edges[block].append(target_address)
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "PC": 
        stack.insert(0, BitVecVal(world_state["pc"], 256))
        world_state["pc"] += 1 

    elif opcode == "MSIZE": 
        world_state["pc"] += 1
        msize = len(mem) * 32
        stack.insert(0, BitVecVal(msize, 256))

    elif opcode == "GAS": 
        world_state["pc"] += 1
        remaining_gas = 4000000 
        stack.insert(0, BitVecVal(remaining_gas, 256))

    elif opcode == "JUMPDEST": 
        world_state["pc"] += 1
    
    elif opcode.startswith("PUSH", 0): 
        position = int(opcode[4:], 10) 
        world_state["pc"] = world_state["pc"] + 1 + position
        pushed_value = int(instruction_parts[2], 16)
        stack.insert(0, BitVecVal(pushed_value, 256))

    elif opcode.startswith("DUP", 0): 
        world_state["pc"] += 1 
        position = int(opcode[3:], 10) - 1
        if len(stack) > position:
            duplicate = copy.deepcopy(stack[position])
            stack.insert(0, duplicate)
        else:
            raise ValueError("STACK underflow")
    
    
    elif opcode.startswith("SWAP", 0): 
        world_state["pc"] += 1
        position = int(opcode[4:], 10)
        if len(stack) > position:
            temp = copy.deepcopy(stack[position])
            stack[position] = copy.deepcopy(stack[0])
            stack[0] = temp
        else:
            raise ValueError("STACK underflow")
    
    
    elif opcode in ("LOG0", "LOG1", "LOG2", "LOG3", "LOG4"): 
        
        world_state["pc"] += 1
        num_of_pops = 2 + int(opcode[3:])
        while num_of_pops > 0:
            stack.pop(0)
            num_of_pops -= 1
        
   
    elif opcode == "CREATE":  
        if len(stack) > 2:
            world_state["pc"] += 1
            transfer_amount = stack.pop(0)
            memory_address = stack.pop(0)
            length = stack.pop(0)

            transfer_amount = simplify(transfer_amount)
            memory_address = simplify(memory_address)
            length = simplify(length)
            
            if is_bv_value(memory_address):
                memory_address = get_value(memory_address)
            else:
                memory_address = str(memory_address)

            new_var_name = gen.gen_create_address()
            new_var = BitVec(new_var_name, 256)
            stack.insert(0, new_var)

            if memory_address in mem:
                analysis["CREATE_pcs"].append((world_state["pc"]-1, mem[memory_address])) 


            if is_bv_value(transfer_amount) and get_value(transfer_amount) == 0: 
                return
            else:
                analysis["money_flow"].append(("Ia", str(new_var), str(transfer_amount)))

        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "CALL": 
        if len(stack) > 6:
            world_state["pc"] += 1

            outgas = stack.pop(0)
            recipient = stack.pop(0)
            transfer_amount = stack.pop(0)
            memory_input_address = stack.pop(0)
            input_length = stack.pop(0)
            memory_return_address = stack.pop(0)
            return_length = stack.pop(0)
            outgas = simplify(outgas)
            recipient = simplify(recipient)
            transfer_amount = simplify(transfer_amount)
            memory_return_address = simplify(memory_return_address)
            return_length = simplify(return_length)
            RETURNDATASIZE = return_length
            
            if is_bv_value(memory_input_address):
                memory_input_address = get_value(memory_input_address)
            else:
                memory_input_address = str(memory_input_address)

            if memory_input_address in mem:
                if isinstance(memory_input_address, int):
                    if is_bv_value(input_length):
                        mem_input = ""
                        input_length = get_value(input_length)
                        
                        for i in list(mem.keys()):
                            if isinstance(i, int) and i >= memory_input_address and i < (memory_input_address + input_length):
                                mem_input = mem_input + '#' + str(mem[i])
                        
                        analysis["CALL_pcs"].append((world_state["pc"]-1, recipient, path_conditions_and_vars["path_condition"],mem_input,transfer_amount))
                    
                    else:
                        analysis["CALL_pcs"].append((world_state["pc"]-1, recipient, path_conditions_and_vars["path_condition"],mem[memory_input_address],transfer_amount))
                
                else:
                    analysis["CALL_pcs"].append((world_state["pc"]-1, recipient, path_conditions_and_vars["path_condition"],mem[memory_input_address],transfer_amount))

            else:
                analysis["CALL_pcs"].append((world_state["pc"]-1, recipient, path_conditions_and_vars["path_condition"],"Mem",transfer_amount)) 

            if is_bv_value(memory_return_address):
                memory_return_address = get_value(memory_return_address)
            else:
                memory_return_address = str(memory_return_address)
            
            if is_bv_value(return_length):
                return_length = get_value(return_length)
                if return_length == 0:
                    return_data = BitVecVal(0, 256)
                    mem[memory_return_address] = return_data
                else:
                    return_data_name = gen.gen_returndata_var(memory_return_address, return_length)
                    return_data = BitVec(return_data_name, 256)
                    
                    if isinstance(memory_return_address,int):
                        i=0
                        while i < return_length:
                            mem[memory_return_address+i] = return_data
                            i += 32
                    else:
                        mem[memory_return_address] = return_data
            else:
                return_data_name = gen.gen_returndata_var(memory_return_address, return_length)
                return_data = BitVec(return_data_name, 256)
                mem[memory_return_address] = return_data

            stack.insert(0, BitVec("call_return", 256))
           
            if is_bv_value(transfer_amount) and get_value(transfer_amount) == 0: 
                return

            balance_ia = world_state["balance"]["Ia"]
            new_balance_ia = (balance_ia - transfer_amount)
            world_state["balance"]["Ia"] = new_balance_ia
            analysis["money_flow"].append(("Ia", str(recipient), str(transfer_amount)))
 
        else:
            raise ValueError("STACK underflow")
    elif opcode == "CALLCODE": 
        if len(stack) > 6:
            world_state["pc"] += 1
            outgas = stack.pop(0)
            recipient = stack.pop(0)
            transfer_amount = stack.pop(0)
            memory_input_address = stack.pop(0)
            input_length = stack.pop(0)
            memory_return_address = stack.pop(0)
            return_length = stack.pop(0)

            outgas = simplify(outgas)
            recipient = simplify(recipient)
            transfer_amount = simplify(transfer_amount)
            memory_return_address = simplify(memory_return_address)
            return_length = simplify(return_length)

            analysis["CALLCODE_pcs"].append((world_state["pc"]-1, recipient, path_conditions_and_vars["path_condition"])) 
            
            RETURNDATASIZE = return_length

            if is_bv_value(memory_return_address):
                memory_return_address = get_value(memory_return_address)
            else:
                memory_return_address = str(memory_return_address)

            if is_bv_value(return_length):
                return_length = get_value(return_length)
                
                if return_length == 0:
                    return_data = BitVecVal(0, 256)
                    mem[memory_return_address] = return_data
                else:
                    return_data_name = gen.gen_returndata_var(memory_return_address, return_length)
                    return_data = BitVec(return_data_name, 256)
                    
                    if isinstance(memory_return_address,int):
                        i=0
                        while i < return_length:
                            mem[memory_return_address+i] = return_data
                            i += 32
                    else:
                        mem[memory_return_address] = return_data
            
            else:
                return_data_name = gen.gen_returndata_var(memory_return_address, return_length)
                return_data = BitVec(return_data_name, 256)
                mem[memory_return_address] = return_data

            stack.insert(0, BitVec("call_return", 256))

            if is_bv_value(transfer_amount) and get_value(transfer_amount) == 0:
                return

            balance_ia = world_state["balance"]["Ia"]
            new_balance_ia = (balance_ia - transfer_amount)
            world_state["balance"]["Ia"] = new_balance_ia
            analysis["money_flow"].append(("Ia", str(recipient), str(transfer_amount))) 
        else:
            raise ValueError("STACK underflow")
        
    elif opcode == "DELEGATECALL":
        if len(stack) > 5:
            world_state["pc"] += 1

            outgas = stack.pop(0)
            recipient = stack.pop(0)
            memory_input_address = stack.pop(0)
            input_length = stack.pop(0)
            memory_return_address = stack.pop(0)
            return_length = stack.pop(0)

            outgas = simplify(outgas)
            recipient = simplify(recipient)
            memory_return_address = simplify(memory_return_address)
            return_length = simplify(return_length)

            if is_bv_value(memory_input_address):
                memory_input_address = get_value(memory_input_address)
            else:
                memory_input_address = str(memory_input_address)
            
            if memory_input_address in mem:
                if isinstance(memory_input_address, int):
                    if is_bv_value(input_length):
                        mem_input = ""
                        input_length = get_value(input_length)
                        
                        for i in list(mem.keys()):
                            if isinstance(i, int) and i >= memory_input_address and i < (memory_input_address + input_length):
                                mem_input = mem_input + '#' + str(mem[i])
                        analysis["DELEGATECALL_pcs"].append((world_state["pc"]-1, recipient, path_conditions_and_vars["path_condition"],mem_input,block))
                    else:
                        analysis["DELEGATECALL_pcs"].append((world_state["pc"]-1, recipient, path_conditions_and_vars["path_condition"],mem[memory_input_address],block))
                
                else:
                    analysis["DELEGATECALL_pcs"].append((world_state["pc"]-1, recipient, path_conditions_and_vars["path_condition"],mem[memory_input_address],block))

            else:
                analysis["DELEGATECALL_pcs"].append((world_state["pc"]-1, recipient, path_conditions_and_vars["path_condition"],"Mem",block)) 

            RETURNDATASIZE = return_length
            
            if is_bv_value(memory_return_address):
                memory_return_address = get_value(memory_return_address)
            else:
                memory_return_address = str(memory_return_address)

            if is_bv_value(return_length):
                return_length = get_value(return_length)
                
                if return_length == 0:
                    return_data = BitVecVal(0, 256)
                    mem[memory_return_address] = return_data
                else:
                    return_data_name = gen.gen_returndata_var(memory_return_address, return_length)
                    return_data = BitVec(return_data_name, 256)
                    
                    if isinstance(memory_return_address,int):
                        i=0
                        while i < return_length:
                            mem[memory_return_address+i] = return_data
                            i += 32
                    else:
                        mem[memory_return_address] = return_data
            
            else:
                return_data_name = gen.gen_returndata_var(memory_return_address, return_length)
                return_data = BitVec(return_data_name, 256)
                mem[memory_return_address] = return_data

            stack.insert(0, BitVec("call_return", 256))
        
        else:
            raise ValueError('STACK underflow')
        
    elif opcode in ("STATICCALL"): 
        if len(stack) > 5:
            world_state["pc"] += 1

            outgas = stack.pop(0)
            recipient = stack.pop(0)
            memory_input_address = stack.pop(0)
            input_length = stack.pop(0)
            memory_return_address = stack.pop(0)
            return_length = stack.pop(0)

            outgas = simplify(outgas)
            recipient = simplify(recipient)
            memory_return_address = simplify(memory_return_address)
            return_length = simplify(return_length)
            
            analysis["STATICCALL_pcs"].append((world_state["pc"]-1, recipient)) 

            RETURNDATASIZE = return_length

            if is_bv_value(memory_return_address):
                memory_return_address = get_value(memory_return_address)
            else:
                memory_return_address = str(memory_return_address)
            if is_bv_value(return_length):
                return_length = get_value(return_length)
                if return_length == 0:
                    return_data = BitVecVal(0, 256)
                    mem[memory_return_address] = return_data
                else:
                    return_data_name = gen.gen_returndata_var(memory_return_address, return_length)
                    return_data = BitVec(return_data_name, 256)
                    if isinstance(memory_return_address,int):
                        i=0
                        while i < return_length:
                            mem[memory_return_address+i] = return_data
                            i += 32
                    else:
                        mem[memory_return_address] = return_data
            else:
                return_data_name = gen.gen_returndata_var(memory_return_address, return_length)
                return_data = BitVec(return_data_name, 256)
                mem[memory_return_address] = return_data

            stack.insert(0, BitVec("call_return", 256))
        else:
            raise ValueError('STACK underflow')
        
    elif opcode == "CREATE2": 
        if len(stack) > 3:
            world_state["pc"] += 1
            transfer_amount = stack.pop(0)
            memory_address = stack.pop(0)
            length = stack.pop(0)
            salt = stack.pop(0)

            transfer_amount = simplify(transfer_amount)
            memory_address = simplify(memory_address)
            length = simplify(length)
            salt = simplify(salt)
            
            if is_bv_value(memory_address):
                memory_address = get_value(memory_address)
            else:
                memory_address = str(memory_address)

            new_var_name = gen.gen_create_address()
            new_var = BitVec(new_var_name, 256)
            stack.insert(0, new_var)
            
            if memory_address in mem:
                analysis["CREATE2_pcs"].append((world_state["pc"]-1, mem[memory_address])) 
            
            if is_bv_value(transfer_amount) and get_value(transfer_amount) == 0:
                return
            else:
                analysis["money_flow"].append(("Ia", str(new_var), str(transfer_amount)))

        else:
            raise ValueError("STACK underflow")
        
    elif opcode in ("RETURN", "REVERT"): 
        if len(stack) > 1:
            stack.pop(0)
            stack.pop(0)
            pass
        else:
            raise ValueError('STACK underflow')
        
    elif opcode in ("SUICIDE", "SELFDESTRUCT"):
        world_state["pc"] += 1
        recipient = stack.pop(0)

        recipient = simplify(recipient)
        
        analysis["SUICIDE_pcs"].append((world_state["pc"]-1, recipient)) 
        transfer_amount = world_state["balance"]["Ia"]
        world_state["balance"]["Ia"] = 0
        analysis["money_flow"].append(("Ia", str(recipient), "all_remaining"))
        path_conditions_and_vars["path_condition"].append(BitVec("account_code", 256) == 0)
        return
    
    else:
        if global_controller.VERBOSE:
            print("[BridgeGuard]:\t \033[91mUNKNOWN INSTRUCTION: %s \033[0m" % opcode)

        raise Exception('\033[91mUNKNOWN INSTRUCTION: %s \033[0m' % opcode)


########################################################################
# Detect vulnerabilities and Print Results.
########################################################################
def detect_vulnerabilities():
    global visited_pcs
    global results
    global g_source_map
    g_source_map = None
    global real_instruction_length

    if instructions:
        real_length = len(instructions)

        if real_instruction_length != len(g_bytecode)/2:
            i = 0
            for pc in range(real_instruction_length):
                if pc in instructions:
                    i +=1
            real_length = i
        else:
            real_length = returnRealLength(instructions)
        
        evm_code_coverage = float(len(visited_pcs)) / real_length * 100

        if evm_code_coverage > 75:
            print("[BridgeGuard]  \t \033[92mCode Coverage: \t %s%%\033[0m" % round(evm_code_coverage, 1))
        else:
            print("[BridgeGuard]  \t \033[91mCode Coverage: \t %s%%\033[0m" % round(evm_code_coverage, 1))

        results["evm_code_coverage"] = round(evm_code_coverage, 1)
        
        print('[BridgeGuard]  \033[96m\t Detect Vulnerability ... ...\033[0m')
        print("[BridgeGuard]  \t\033[92m ===================Results===================\033[0m")
        
        if global_controller.HASHES_FILE:
            hashes_filename = str.split(g_disasm_file, ".bin-runtime")[0] + ".signatures"

            hashes_to_funcnames = {}
            
            with open(hashes_filename, 'r') as hashes_file:
                hashes = hashes_file.readlines()
                
                for hash in hashes: 
                    if ": " in hash:
                        hash_parts = hash.split(": ")
                        if len(hash_parts[0]) <= 8:
                            hashes_to_funcnames[hash_parts[0]] = hash_parts[1].strip("\n")
                            
            hashes_file.close()

            for path in funcs_of_paths:
                for hash in hashes_to_funcnames:
                    if str(funcs_of_paths[path][2:]) in hash:
                        funcs_of_paths[path] = [str(hash), hashes_to_funcnames[hash]]

        if global_controller.REPORT_MODE:    
            report_file.write("\nAll paths:\n")
            for path in all_paths:
                report_file.write(str(path)+ ": " +str(funcs_of_paths[path]) + "-" + str(len(all_paths[path]))+"-" + str(all_paths[path]) +"\n")

            report_file.write("\nValided paths:\n")
            for path in valided_paths:
                report_file.write(str(path)+ ": " +str(funcs_of_paths[path]) + "-" + str(len(valided_paths[path]))+"-" + str(valided_paths[path]) +"\n")

            
        # ================================================================= 
        # Detect_Uncheched-external-call   
        detect_unchecked_external_call(maybe_unchecked_external_call_paths, path_conditions_of_all_paths, funcs_of_paths, results)
        
        # # ================================================================= 
        # Detect_reentrancy_bug       
        detect_reentrancy(reentrancy_all_paths, funcs_of_paths, results)

        # ================================================================= 
        # Detect_Cross-chain_Function_Call CFC
        detect_Crosschain_Function_Call(maybe_crosschain_function_call_paths, sstore_storage_ALL_paths, funcs_of_paths, results)

        # ================================================================= 
        # Detect Bypassing Signature Verification
        detect_Unprotected_Data_Injection(maybe_unprotected_data_injection_paths, path_conditions_of_all_paths, funcs_of_paths, results)

       

    else:
        print("[BridgeGuard]  \t  EVM code coverage: \t 0/0")

        results["evm_code_coverage"] = 0

    return results
