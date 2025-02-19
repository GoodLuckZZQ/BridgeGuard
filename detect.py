from z3 import * 
from global_utils import *


# Detect unchecked_external_call: do not check return value of external call.
def detect_unchecked_external_call(maybe_unchecked_external_call_paths, path_conditions_of_all_paths, funcs_of_paths, results):
    unchecked_paths = set()
    
    for path in maybe_unchecked_external_call_paths:
        exited = False

        for item in unchecked_paths:
            if str(funcs_of_paths[item]) == str(funcs_of_paths[path]):
                exited = True
                break

        if exited:
            continue
        
        if ("call_return == 0" in str(path_conditions_of_all_paths[path])) or ("call_return != 0" in str(path_conditions_of_all_paths[path])):
            pass
        else:
            unchecked_paths.add(path)


    if len(unchecked_paths) != 0:
        results["vulnerabilities"]["unchecked_return_value"] = True
        
        print("[BridgeGuard] \t \033[91mUnchecked External Call: \t\t\t %s\033[0m"% True)  
        
        for path in unchecked_paths:
            print("[BridgeGuard] \t \033[93mWarning: BUG_FUNC--%s\033[0m"% funcs_of_paths[path]) 
    else:
        results["vulnerabilities"]["unchecked_return_value"] = False

        print("[BridgeGuard] \t Unchecked External Call: \t\t\t \033[92m%s\033[0m"% False)  
        
# Detect reentrancy_bug, BUG_Opcode: CALL-type.
# check if it is possible to re_execute the call.
def detect_reentrancy(reentrancy_all_paths, funcs_of_paths, results):
    reentrancy_paths = set()
    for path in reentrancy_all_paths:
        exited = False
       
        for item in reentrancy_paths:
            if str(funcs_of_paths[item]) == str(funcs_of_paths[path]):
                exited = True
                break
        
        if exited:
            continue

        reentrancy_paths.add(path)


    if len(reentrancy_paths) != 0:
        results["vulnerabilities"]["reentrancy"] = True
        
        print("[BridgeGuard] \t \033[91mRe-Entrancy Vulnerability: \t\t\t %s\033[0m"% True)
        
        for path in reentrancy_paths:
            print("[BridgeGuard] \t \033[93mWarning: BUG_FUNC--%s\033[0m"% funcs_of_paths[path]) 
    else:
        results["vulnerabilities"]["reentrancy"] = False
        
        print("[BridgeGuard] \t Re-Entrancy Vulnerability: \t\t\t \033[92m%s\033[0m"% False)  

# Detect_Cross-chain_Function_Call CFC
def detect_Crosschain_Function_Call(maybe_crosschain_function_call_paths, sstore_storage_ALL_paths, funcs_of_paths, results):
    crosschain_function_call_path = set()
    for path in maybe_crosschain_function_call_paths:
        exited = False
        
        for item in crosschain_function_call_path:
            if str(funcs_of_paths[item]) == str(funcs_of_paths[path]):
                exited = True
                break
        
        if exited:
            continue
        
        for item in maybe_crosschain_function_call_paths[path]:
            if "Ia_store" in str(item[1]):
                if "Is" in str(item[3]) or "IA" in str(item[3]) or "Ia_store" in str(item[3]):
                    continue
                inputlist = str(item[3]).split("#")
                
                if inputlist[0] == '':    
                    inputlist.pop(0)
                
                judge = True
                
                if len(inputlist) == 1:
                    if isNotTaint(inputlist[0]):
                        judge = False
                elif len(inputlist) > 1:
                    if isNotTaint(inputlist[0]):
                        judge = False
                    else:
                        for i in inputlist[1:]:
                            if not isNotTaint(i):
                                judge = True
                                break
                else:
                    judge = False

                if judge:
                    if not isAuthentication(str(item[2])):
                        crosschain_function_call_path.add(path)
                
            

    if len(crosschain_function_call_path) != 0:
        results["vulnerabilities"]["Crosschain_Function_Call"] = True
        
        print("[BridgeGuard] \t \033[91mCross-chain Function Call: \t\t\t %s\033[0m"% True)
        
        for path in crosschain_function_call_path:
            print("[BridgeGuard] \t \033[93mWarning: BUG_FUNC--%s\033[0m"% funcs_of_paths[path]) 
    else:
        results["vulnerabilities"]["Crosschain_Function_Call"] = False
       
        print("[BridgeGuard] \t Cross-chain Function Call: \t\t\t \033[92m%s\033[0m"% False)


# Detect Unprotected Data Injection UDI
def detect_Unprotected_Data_Injection(maybe_unprotected_data_injection_paths, path_conditions_of_all_paths, funcs_of_paths, results):
    unprotected_data_injection_paths = set()

    for path in maybe_unprotected_data_injection_paths:
        exited = False
        
        for item in unprotected_data_injection_paths:
            if str(funcs_of_paths[item]) == str(funcs_of_paths[path]):
                exited = True
                break
        
        if exited:
            continue

        for item in maybe_unprotected_data_injection_paths[path]:
            if "Is" in str(item[3]) or "IA" in str(item[3]) or "Ia_store" in str(item[3]):
                continue

            inputlist = str(item[3]).split("#")
            
            if inputlist[0] == '':  
                inputlist.pop(0)
            
            if "Taint_Calldata" in str(item[1]):
                if not isAuthentication(str(item[2])):
                    unprotected_data_injection_paths.add(path)
                    break
                
    if len(unprotected_data_injection_paths) != 0:
        results["vulnerabilities"]["Unprotected_Data_Injection"] = True
        
        print("[BridgeGuard] \t \033[91mUnprotected Data Injection: \t\t\t %s\033[0m"% True)
        
        for path in unprotected_data_injection_paths:
            print("[BridgeGuard] \t \033[93mWarning: BUG_FUNC--%s\033[0m"% funcs_of_paths[path]) 
    else:
        results["vulnerabilities"]["Unprotected_Data_Injection"] = False
        
        print("[BridgeGuard] \t Unprotected Data Injection: \t\t\t \033[92m%s\033[0m"% False)
