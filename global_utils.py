import shlex
import subprocess
import os

from z3 import *
from z3.z3util import get_vars
from func_timeout import func_set_timeout

import func_timeout

from multiprocessing import Process, Queue, JoinableQueue

import global_controller
from TaintSymbolicGen import *

# Start a sudprocess to run the command in the terminal and return the result.
def run_command(cmd):
    FNULL = open(os.devnull, 'w')
    solc_p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=FNULL)
    return solc_p.communicate()[0].decode('utf-8', 'strict')

# Copy dictionary.
def custom_deepcopy(input):
    output = {}
    
    for key in input:
        if isinstance(input[key], list):
            output[key] = list(input[key])
        
        elif isinstance(input[key], dict):
            output[key] = custom_deepcopy(input[key])
        
        else:
            output[key] = input[key]

    return output


# Get value of is_bv_value-type.
def get_value(Z3express):
    return simplify(Z3express).as_long()

# Compute y^x mod n.
def power(y, x, n):
    if x == 0: 
        return 1
    elif (x % 2 == 0): 
        return power((y*y)%n, x//2, n) % n
    else: 
        return (y*power((y*y)%n, x//2, n)) % n

# Deal with some opcodes which need one argument.
def unary(arg, pc, opcode = 'NONE'):
    a1 = simplify(arg)
    
    if opcode == 'NOT': 
        a3 = ~a1
    
    elif opcode == 'ISZERO': 
        a3 = If(a1 == 0, BitVecVal(1, 256), BitVecVal(0, 256))
    
    else:
        print('did not process unary operation: %s' % pc)
        print(arg)
    
    return simplify(a3)

# Deal with some opcodes which need two argument.
def binary(arg1, arg2, pc, opcode = "NONE"):
    if is_bv_value(arg1):
        val = get_value(arg1)
        
        if opcode in ['MUL','AND','DIV','SDIV'] and val == 0:
            return BitVecVal(0, 256) 
        
        if opcode in ['XOR','ADD'] and val == 0: 
            return arg2

    if is_bv_value(arg2):
        val = get_value(arg2)
        
        if opcode in ['MUL','AND','DIV','SDIV'] and val == 0:
            return BitVecVal(0, 256) 
        
        if opcode in ['XOR','ADD'] and val == 0: 
            return arg1
    
    a1 = simplify(arg1)
    a2 = simplify(arg2)

    if opcode == 'AND' :  a3 = a1 & a2
    
    elif opcode == 'OR'  : a3 = a1 | a2
    
    elif opcode == 'XOR' : a3 = a1 ^ a2
    
    elif opcode == 'ADD' : a3 = a1 + a2
    
    elif opcode == 'SUB' : a3 = a1 - a2 
    
    elif opcode == 'EXP' : 
        if is_bv_value(a1) and is_bv_value(a2):
            a3 = BitVecVal(power(a1.as_long(), a2.as_long(), 2 ** 256), 256)
        else: 
            new_name = str(a1) + "-exp-" + str(a2)
            a3 = BitVec(new_name, 256)

    elif opcode == 'DIV' : a3 = UDiv(a1, a2)
    
    elif opcode == 'SDIV': a3 = a1/a2 
    
    elif opcode == 'MOD' : a3 = URem(a1, a2)
    
    elif opcode == 'SMOD': a3 = SRem(a1, a2)
    
    elif opcode == 'MUL' : a3 = a1 * a2 
    
    elif opcode == 'GT'  : a3 = If(UGT(a1, a2), BitVecVal(1, 256), BitVecVal(0, 256))
    
    elif opcode == 'SGT' : a3 = If(a1 > a2, BitVecVal(1, 256), BitVecVal(0, 256))
    
    elif opcode == 'LT'  : a3 = If(ULT(a1, a2), BitVecVal(1, 256), BitVecVal(0, 256))
    
    elif opcode == 'SLT' : a3 = If(a1 < a2, BitVecVal(1, 256), BitVecVal(0, 256))
    
    elif opcode == 'EQ'  : a3 = If(a1 == a2, BitVecVal(1, 256), BitVecVal(0, 256))
    
    else:
        print('did not process binary operation: %s' % pc)
        print(arg1)
        print(arg2)

    return simplify(a3)    

# Deal with some opcodes which need three argument.
def ternary(arg1, arg2, arg3, pc, opcode = "NONE"):
    if is_bv_value(arg3) and get_value(arg3) == 0:
        return BitVecVal(0, 256)

    a1 = simplify(arg1)
    a2 = simplify(arg2)
    a3 = simplify(arg3)

    if opcode == 'ADDMOD': 
        a4 = (a1 + a2) % a3 
    
    elif opcode == 'MULMOD': 
        a4 = (a1 * a2) % a3
    
    else:
        print('did not process ternary operation: %s ' % pc)
        print(a1)
        print(a2)
        print(a3)
    
    return simplify(a4)


# Copy permanent storage of Ia.
def copy_world_state_Ia(world_state):
    return world_state["Ia_Storage"]

# Return all vars in a list of expressions.
def get_all_vars(exprs):
    ret_vars = []
    
    for expr in exprs:
        if is_expr(expr):
            ret_vars += get_vars(expr)

    return ret_vars

# Determine if it is a Ia_storage variable.
def is_storage_var(var):
    if is_bv(var):
        var = var.decl().name()

    return var.startswith("Ia_store")

# Get postion of Ia_storage according to var.
def get_storage_position(var):
    if is_bv(var):
        var = var.decl().name() 
    
    pos = var.split('-')[1]
    
    try:
        return int(pos)
    except:
        return pos

# Check a path_condition has storage element to determine the path is protected.
def path_condition_has_storage(path_condition):
    has_storage = False

    for var in get_all_vars(list(path_condition)):

        if is_storage_var(var):
            has_storage = True
            break
        
        else:
            has_storage = False

    return has_storage

def path_is_unprotected(path_condition):
    is_unprotected = False
    
    if "Ia_store" in str(path_condition) or "Is" in str(path_condition) or "balance" in str(path_condition):
        is_unprotected = False
    
    else:
        is_unprotected = True
    
    return is_unprotected

# Determine two paths are related   
def front_and_back_is_related(front_strorage, back_path, back_storage = None):
    is_related = False
    
    back_path = list(back_path)
    
    for var in get_all_vars(back_path):
        if is_storage_var(var):
            pos = get_storage_position(var)
            
            if pos in front_strorage:
                is_related = True

    return is_related

# Determine two psths have a same condition which includes storage.
def front_and_back_is_same_condition(front_path, back_path):
    is_same = False
    front_path = list(front_path)
    back_path = list(back_path)
    
    for front_cond in front_path:
        if is_expr(front_cond):
            front_cond_vars = get_vars(front_cond)
            for front_cond_var in front_cond_vars:
                if is_storage_var(front_cond_var):
                    for back_cond in back_path:
                        if is_expr(back_cond):
                            back_cond_vars = get_vars(back_cond)
                            for back_cond_var in back_cond_vars:
                                if is_storage_var(back_cond_var):
                                    if front_cond == back_cond: 
                                        is_same = True

    return is_same

# Rename variables to distinguish variables in two different paths.
# e.g. Ia_store_0 in path i becomes Ia_store_0_old if Ia_store_0 is modified
# else we must keep Ia_store_0 if its not modified
def rename_vars(path_cond, money_flow_storage):
    ret_constraints = []
    vars_mapping = {}

    for constraint in path_cond:
        if is_expr(constraint):
            list_vars = get_vars(constraint)
            
            for var in list_vars:
                if var in vars_mapping:
                    constraint = substitute(constraint, (var, vars_mapping[var]))
                    continue
                
                var_name = var.decl().name()
                
                if is_storage_var(var):
                    pos = get_storage_position(var)
                    if pos not in money_flow_storage:
                        continue
                
                new_var_name = var_name + '_old'
                new_var = BitVec(new_var_name, 256)
                vars_mapping[var] = new_var
                constraint = substitute(constraint, (var, vars_mapping[var]))

        ret_constraints.append(constraint)

    ret_ws_Ia = {}

    for storage_addr in money_flow_storage:
        storage_val = money_flow_storage[storage_addr]
        
        if is_expr(storage_val):
            list_vars = get_vars(storage_val)
            
            for var in list_vars:
                if var in vars_mapping:
                    storage_val = substitute(storage_val, (var, vars_mapping[var]))
                    continue
                
                var_name = var.decl().name()
                
                if var_name.startswith("Ia_store_"):
                    position = int(var_name.split('_')[len(var_name.split('_')) - 1])
                    if position not in money_flow_storage:
                        continue
                
                new_var_name = var_name + '_old'
                new_var = BitVec(new_var_name, 256)
                vars_mapping[var] = new_var
                storage_val = substitute(storage_val, (var, vars_mapping[var]))
        
        ret_ws_Ia[storage_addr] = storage_val

    return ret_constraints, ret_ws_Ia

# Check if it is possible to execute a path after a previous path
# Previous path has prev_path (previous path condition) and set world state variables as in wstate (only storage values)
# Current path has curr_path
def is_independent_and_feasible(prev_path, prev_storage, curr_path):
    is_independent = True
    is_feasible = True
    curr_path = list(curr_path)

    new_path = []
    
    for var in get_all_vars(curr_path):
        if is_storage_var(var):
            pos = get_storage_position(var)
            if pos in prev_storage:
                is_independent = False
                new_path.append(var == prev_storage[pos])

    curr_path += new_path
    curr_path += prev_path

    solver = Solver()
    solver.set("timeout", 20)
    solver.push()
    solver.add(curr_path)

    if solver.check() == unsat:
        solver.pop()
        is_feasible = False
    else:
        solver.pop()
        is_feasible = True

    return is_independent, is_feasible

def solver_check(constrains):
    solver = Solver()
    solver.set("timeout", 2)
    solver.push()
    solver.add(constrains)

    res = solver.check()
    solver.pop()

    return res

def changeResultstoList(contractName,results):
    res = []
    res.append(contractName)

    for item in results:
        if item != "vulnerabilities":
            res.append(results[item])
        else:
            for vul in results[item]:
                res.append(results[item][vul])

    return res

def returnRealLength(instructions):
    reallength = len(instructions)
    pcList = list(instructions)

    for i in range(1, len(instructions)):
        instr_parts = str.split(instructions[pcList[-i]], " ") 

        opcode1 = instr_parts[0]
        opcode2 = ""
        
        instr_parts = str.split(instructions[pcList[-(i+1)]], " ")
        opcode2 = instr_parts[0]
        
       
        if (opcode1 == "INVALID" and opcode2 == "JUMP") or (opcode1 == "STOP" and opcode2 == "JUMP"):
            reallength = reallength - i
            break

    return reallength

def isAuthentication(cond):
    if "Is" in cond:
        return True
    else:
        return False

def isNotTaint(cond):
    if "Taint_Calldata" not in cond:
        return True
    else:
        return False