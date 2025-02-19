import six
import logging
import re
from z3 import *
from z3.z3util import *


from global_utils import *
import global_controller

# Store intermediate information of every paths.
class ExecutionState:
    def __init__(self, **kwargs):
        attr_defaults = {
            "world_state": {}, 
            "visited_edges": {}, 
            "visited": [], 
            "stack": [], 
            "mem": {}, 
            "sha3_list": {},
            "analysis": {}, 
            "sig_of_func": [], 
            "path_conditions_and_vars": {} 
        }
        
        for (attr, default) in six.iteritems(attr_defaults):
            setattr(self, attr, kwargs.get(attr, default))
    
    def copy(self):
        _kwargs = custom_deepcopy(self.__dict__)
        return ExecutionState(**_kwargs)

# Init world_state in which vars use symbolic. We can use special public blockchain information to speed symbolic execution. 
def init_world_state(path_conditions_and_vars):
    world_state = {"balance": {}, "pc": 0}
    
    balance_Is = None  
    balance_Ia = None  
    
    deposited_value = None 
    
    sender_address = None 
    receiver_address = None
    
    gas_price = None  
    
    origin = None  
    
    currentCoinbase = None  
    currentNumber = None  
    currentDifficulty = None  
    currentGasLimit = None 
    currentTimestamp = None 

    sender_address = BitVec("Is", 256)
    receiver_address = BitVec("IA", 256)
    deposited_value = BitVec("Iv", 256)
    balance_Is = BitVec("balance_Is", 256)
    balance_Ia = BitVec("balance_Ia", 256)

    constraint = (deposited_value >= BitVecVal(0, 256))
    path_conditions_and_vars["path_condition"].append(constraint)
    world_state["balance"]["Is"] = (balance_Is)
    world_state["balance"]["Ia"] = (balance_Ia)

    if not gas_price:
        gas_price = BitVec("Ip", 256)

    if not origin:
        origin = BitVec("Io_origin", 256)

    if not currentCoinbase:
        currentCoinbase = BitVec("BLOCK_IH_c", 256)

    if not currentNumber:
        currentNumber = BitVec("BLOCK_IH_i", 256)

    if not currentDifficulty:
        currentDifficulty = BitVec("BLOCK_IH_d", 256)

    if not currentGasLimit:
        currentGasLimit = BitVec("BLOCK_IH_l", 256)

    if not currentTimestamp:
        currentTimestamp = BitVec("BLOCK_IH_s", 256)

    if "Ia_Storage" not in world_state:
        world_state["Ia_Storage"] = {}

    world_state["receiver_address"] = receiver_address
    world_state["sender_address"] = sender_address
    
    world_state["origin"] = origin
    
    world_state["callvalue"] = deposited_value  
    world_state["gas_price"] = gas_price
    
    world_state["currentCoinbase"] = currentCoinbase
    world_state["currentNumber"] = currentNumber
    world_state["currentDifficulty"] = currentDifficulty
    world_state["currentGasLimit"] = currentGasLimit
    world_state["currentTimestamp"] = currentTimestamp

    return world_state

# Return dictionary which store state in the process of opcode execution.
def init_alalysis():
    analysis = {
        "money_flow": [("Is", "Ia", "Iv")],
        "BLOCKSTATE_pcs": [],
        "need_checked_blockstate_dependency": [], 
        "CREATE_pcs": [],
        "CREATE2_pcs": [],
        "CALL_pcs": [], 
        "reentrancy_call_pcs": [],
        "CALLCODE_pcs": [], 
        "DELEGATECALL_pcs": [], 
        "STATICCALL_pcs": [],
        "SUICIDE_pcs": [],
        "SSTORE_info": {},
        "SLOAD_info": {},
        "ORIGIN_info": [],
        "overflow_pcs": [],
        "underflow_pcs": [],
        "LOG_pcs": [],
        "CALLINPUT_pcs":[],
        "SSTORE_pcs":[],
    }
    return analysis

# Update analysis which includes state in the process of opcode execution. TODO: should add SSTORE.
def update_analysis(analysis, opcode, stack, world_state, path_conditions_and_vars, g_disasm_file):
    if opcode in ("CALL"):   
        recipient = stack[1]
        
        transfer_value = stack[2]
        
        if is_bv_value(transfer_value) and get_value(transfer_value) == 0:
            return
        
        recipient = simplify(recipient)
        
        reentrancy_result = check_reentrancy_bug(analysis, path_conditions_and_vars, stack, world_state) 
        
        if reentrancy_result:
            analysis["reentrancy_call_pcs"].append(world_state["pc"])

# May this can be optimized.
# Check if this call has the Reentrancy bug. There are three steps:
# 1. Check if path_condition and new_path_condition are satisfied;
# 2. Check if outgas > 2300 is satisfied.
# 3. Check if transfer_amount > deposit_value is satisfied.
# If one of three aboves are dissatisfied, we can determine that there is not reentrancy_bug.
# Return true if it does, false otherwise.
def check_reentrancy_bug(analysis, path_conditions_and_vars, stack, world_state):
    path_condition = copy.deepcopy(path_conditions_and_vars["path_condition"])
    new_path_condition = []

    if "Extract(159, 0, Is) ==" in str(path_condition) or "== Extract(159, 0, Is)" in str(path_condition):
        return False

    for expression in path_condition:
        if not is_expr(expression):
            continue
        
        list_vars = get_vars(expression)
        
        for var in list_vars:
            if is_storage_var(var):
                pathpos = get_storage_position(var)
                
                for pc in analysis["SSTORE_info"]:
                    for pos in analysis["SSTORE_info"][pc]:
                        if str(pathpos) == str(pos):
                            new_path_condition.append(var == analysis["SSTORE_info"][pc][pos])
    
    constrain1 = (False)
    constrain2 = (False)
    constrain3 = (False)
    constrain4 = (False)
    transfer_amount = stack[2]

    for pc in analysis["SSTORE_info"]:
        for pos in analysis["SSTORE_info"][pc]:
            old_storage = "Ia_store-" + str(pos)
            constrain1 = (BitVec(old_storage, 256) != (transfer_amount + analysis["SSTORE_info"][pc][pos]))

    if is_expr(transfer_amount):
        list_vars = get_vars(transfer_amount)
        
        for var in list_vars:
            if is_storage_var(var):
                transferpos = get_storage_position(var)
                for pc in analysis["SSTORE_info"]:
                    for pos in analysis["SSTORE_info"][pc]:
                        if str(transferpos) == str(pos):
                            new_path_condition.append(analysis["SSTORE_info"][pc][pos] + transfer_amount != var)
               
    for expression in path_condition:
        if not is_expr(expression):
            continue
        
        list_vars = get_vars(expression)
        
        for var in list_vars:
            if is_storage_var(var):
                pos = get_storage_position(var)
                
                if pos in world_state["Ia_Storage"]:
                    constrain3 = (var == world_state["Ia_Storage"][pos])
    
    if len(analysis["SSTORE_info"]) == 0:
        constrain4 = (True)

    new_path_condition.append(Or(constrain1, constrain2, constrain3, constrain4))

    solver = Solver()
    
    solver.set("timeout", 50)
    
    solver.push()
    
    solver.add(path_condition)
    
    solver.add(new_path_condition)
    
    solver.add(stack[0] > 2300)
    
    solver.add(stack[2] > BitVec('Iv', 256))
    
    ret_val = False
    
    if solver.check() == sat:
        ret_val = True
    
    solver.pop()

    return ret_val

