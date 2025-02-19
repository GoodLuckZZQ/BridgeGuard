import argparse
import shutil
import json
import csv
import os
from sys import stdin
import multiprocessing


import global_controller
from compile import *
import SymbolicDataFlowAnalysis

# Analyze bytecode.
def analyze_bytecode(bytecode_source):
    input_generator = InputGenerator(InputGenerator.BYTECODE, source = bytecode_source)
    
    inputs = input_generator.get_inputs()
    
    results = SymbolicDataFlowAnalysis.audit(disasm_file = inputs[0]["disasm_file"], bytecode = inputs[1]["bytecode"])
    
    input_generator.rm_tmp_files()

    return results

# Analyze solidity source.
def analyze_solidity(solidity_source):
    
    try:
        compile_solidity(solidity_source)
    except:
        dir_path = ""
        pathList= str.split(solidity_source, "/")

        for i in range(len(pathList) -1):
            dir_path += pathList[i] + "/"

        shutil.move(dir_path, "test-cannot-compile")

        return "compile error!"
    
    results = {}
    compile_file_path = solidity_source[0:-4]
    main_file_path = ""
    main_file_lenth = 0

    for root, dirs, files in os.walk(compile_file_path):
        for file in files:
            if ".bin-runtime" == file[-12:]:
                path = os.path.join(root,file) 

                if "Log" in file:
                    os.remove(path)
                    continue

                with open(path, 'r') as f:
                    bytecode = f.readline()

                    if len(bytecode) > main_file_lenth:
                        main_file_lenth = len(bytecode)
                        main_file_path = path
    
    for root, dirs, files in os.walk(compile_file_path):
        for file in files:
            main_file_path_signature = main_file_path.split(".bin-runtime")[0] + ".signatures"
            
            path = os.path.join(root,file)   

            if str(path) != main_file_path and str(path) != main_file_path_signature:
                os.remove(path)


    results =  analyze_bytecode(str(main_file_path))

    if global_controller.SECONDDOOR and results["evm_code_coverage"] < global_controller.SECONDMODEPERCENT and results["evm_code_coverage"] > 0:
        global_controller.SECONDMODE = True
        global_controller.SAME_VALID_NUM_LIMIT = 90
        global_controller.SAME_OVERLOOP_NUM_LIMIT = 90
        secondResults =  analyze_bytecode(str(main_file_path))

        if secondResults["evm_code_coverage"] > results["evm_code_coverage"]:
            results = secondResults

    if global_controller.SAVE_RESULTS:
        result_file = solidity_source.split('.sol')[0] + '.json'

        with open(result_file, 'w') as of:
            of.write(json.dumps(results, indent = 3))

        print("[BridgeGuard]\t\033[96m Wrote results to: \033[0m%s" % result_file)             

    return results

# Analyze json solidity source.
def analyze_json_solidity(json_dirs):

    try:
        audit_bin_path = compile_json_dirs(str(json_dirs))
    except:
        shutil.move(json_dirs, "test-cannot-compile")
        return "compile error!"

    results =  analyze_bytecode(str(audit_bin_path))

    if global_controller.SECONDDOOR and results["evm_code_coverage"] < global_controller.SECONDMODEPERCENT and results["evm_code_coverage"] > 0:
        global_controller.SECONDMODE = True
        global_controller.SAME_VALID_NUM_LIMIT = 90
        global_controller.SAME_OVERLOOP_NUM_LIMIT = 90

        secondResults =  analyze_bytecode(str(audit_bin_path))

        if secondResults["evm_code_coverage"] > results["evm_code_coverage"]:
            results = secondResults

    if global_controller.SAVE_RESULTS:
        result_file = json_dirs + 'results.json'

        with open(result_file, 'w') as of:
            of.write(json.dumps(results, indent = 3))

        print("[BridgeGuard]\t\033[96m Wrote results to: \033[0m%s" % result_file)             

    return results
    

def main():
    global args
    # The Argumentparser object contains all the information needed to parse the command line into Python data types.
    parser = argparse.ArgumentParser() 
    # Ensuring that only one parameter in the mutex group is available on the command line. 
    # The required parameter indicates that at least one parameter in the mutually exclusive group is required:
    # group = parser.add_mutually_exclusive_group(required = True) 
    # # In the command line, we must give complete route.
    parser.add_argument("-sol", "--solidity", type=str, help="Check solidity contract by specifying: 1) solidity file, 2) Main contract name", action='store', nargs =1)
    
    parser.add_argument("-bs","--bytecode_source", type=str, help="Check source bytecode contract by specifying contract file", action='store')
    
    parser.add_argument("-js","--json_source", type=str, help="Check source bytecode contract by specifying contract file", action='store')
    
    parser.add_argument("-v", "--version", action="version", version="BridgeGuard 1.0")
    
    parser.add_argument("-vb", "--verbose", action="store_true", help="Verbose output, print everything.")

    parser.add_argument("-test","--empirical_test", type=str, help="Empirical test", action='store')

    args = parser.parse_args()


    if args.verbose:
        global_controller.VERBOSE = 1

    if args.json_source:
        analyze_json_solidity(args.json_source)

    if args.solidity:    
        analyze_solidity(args.solidity[0])      

    if args.bytecode_source:
        global_controller.HASHES_FILE = 0
        analyze_bytecode(args.bytecode_source)

    if args.empirical_test:

        CSV_header = ['contractName', 'evm_code_coverage', 'time_cost', 'bytecode_length',
                        'UER', 'REE', 'CFC', 'UDI']

        if(os.path.exists("testResults.csv") == True):
            print("[BridgeGuard]\t\033[96m testResults.csv is existed.\033[0m")
            print('[BridgeGuard]\t\033[96m Remove old testResults.csv? Enter Y to Do.\033[0m')
            
            input_string = str(stdin.readline())
            
            if((input_string[0] == 'Y') | (input_string[0] == 'y')):
                os.remove("testResults.csv")
                with open('testResults.csv', 'a') as file:
                    writer = csv.writer(file)
                    writer.writerow(CSV_header)
                file.close()

                for dir in os.listdir("test-cannot"):
                    shutil.rmtree("test-cannot"+"/"+dir)

                for dir in os.listdir("test-cannot-compile"):
                    shutil.rmtree("test-cannot-compile"+"/"+dir)

                for dir in os.listdir("test-completed"):
                    shutil.rmtree("test-completed"+"/"+dir)

                for dir in os.listdir("test-lowcoverage"):
                    shutil.rmtree("test-lowcoverage"+"/"+dir)

        if (os.path.exists("total-results.json") == True):
            print("[BridgeGuard]\t\033[96m total-results.json is existed.\033[0m")
            print('[BridgeGuard]\t\033[96m Remove old total-results.json? Enter Y to Do.\033[0m')
            
            input_string = str(stdin.readline())
            
            if((input_string[0] == 'Y') | (input_string[0] == 'y')):
                os.remove("total-results.json")
                total_results = {
                    "total_numbers": 0,
                    "evm_code_coverage": 0,
                    "average_time": 0,
                    "average_length": 0,
                    "vulnerabilities": {
                        "unchecked_return_value": 0,
                        "reentrancy": 0,
                        "Crosschain_Function_Call": 0,
                        "Unprotected_Data_Injection": 0,
                    }
                }
            else:
                with open("total-results.json", "r") as f:
                    total_results = json.load(f)
                f.close()
        else:
            total_results = {
                "total_numbers": 0,
                "evm_code_coverage": 0,
                "average_time": 0,
                "average_length": 0,
                "vulnerabilities": {
                    "unchecked_return_value": 0,
                    "reentrancy": 0,
                    "Crosschain_Function_Call": 0,
                    "Unprotected_Data_Injection": 0,
                }
            }

        if (os.path.exists("totals.json") == True):
            print("[BridgeGuard]\t\033[96m totals.json is existed.\033[0m")
            print('[BridgeGuard]\t\033[96m Remove old totals.json? Enter Y to Do.\033[0m')
            
            input_string = str(stdin.readline())
            
            if((input_string[0] == 'Y') | (input_string[0] == 'y')):
                os.remove("totals.json")
                totals = {}
            else:
                with open("totals.json", "r") as f:
                    totals = json.load(f)

                f.close()
        else:
            totals = {}

        dataset = args.empirical_test

        for dir in os.listdir(dataset):
            contract_dir_path = dataset + dir

            if return_sol_numbers_of_dir(contract_dir_path) == 1:
                for root, dirs, files in os.walk(contract_dir_path):
                    for file in files:
                        if file[-4:] == ".sol":
                            contract_sol_path = contract_dir_path + "/" + file
                            
                            pool = multiprocessing.Pool(processes=1)
                            processReturn= pool.apply_async(analyze_solidity,(contract_sol_path,))
                            
                            try:
                                results = processReturn.get(timeout= 1800)
                            except:
                                pool.terminate()
                                print("[BridgeGuard]\t\033[91m %s Cannot Audit!!!!!!!!!\033[0m\n" %contract_dir_path)
                                with open("AuditFailed.txt", "a") as f:
                                    f.write("%s\n" % contract_dir_path)
                                if (os.path.exists(contract_dir_path) == True):
                                    shutil.move(contract_dir_path, "test-cannot")
                                continue
                            else:
                                pool.close()
                                pool.join()

                            if results == "compile error!":
                                continue

                            if results["evm_code_coverage"] <= global_controller.LOWERCOVERAGE:
                                shutil.move(contract_dir_path, "test-lowcoverage")
                                continue 
                            
                            totals[contract_sol_path] = results
                            total_results["total_numbers"] += 1

                            print("[BridgeGuard]\t\033[92m %s-th smartcantract is completed\033[0m\n" % total_results["total_numbers"])

                            total_results["evm_code_coverage"] = (results["evm_code_coverage"] + total_results["evm_code_coverage"] * (total_results["total_numbers"] - 1)) / total_results["total_numbers"]
                            total_results["average_time"] = (results["time_cost"] + total_results["average_time"] * (total_results["total_numbers"] - 1)) / total_results["total_numbers"]
                            total_results["average_length"] = (results["bytecode_length"] + total_results["average_length"] * (total_results["total_numbers"] - 1)) / total_results["total_numbers"]
                            
                            for vulnerablity in results["vulnerabilities"]:
                                if results["vulnerabilities"][vulnerablity]:
                                    total_results["vulnerabilities"][vulnerablity] += 1
                        
                            with open("total-results.json", "w") as f:
                                json.dump(total_results, f, indent=4)
                            f.close()

                            with open("totals.json", "w") as f:
                                json.dump(totals, f, indent=4)
                            f.close() 

                            res = changeResultstoList(contract_dir_path, results)
                            with open('testResults.csv', 'a') as file:
                                writer = csv.writer(file)
                                writer.writerow(res)
                            file.close()

                            shutil.move(contract_dir_path, "test-completed")               
                        else:
                            continue
            else:
                pool = multiprocessing.Pool(processes=1)
                processReturn= pool.apply_async(analyze_json_solidity,(contract_dir_path+ "/",))
                
                try:
                    results = processReturn.get(timeout= 1800)
                except:
                    pool.terminate()
                    print("[BridgeGuard]\t\033[91m %s Cannot Audit!!!!!!!!!\033[0m\n" %contract_dir_path)
                    
                    with open("AuditFailed.txt", "a") as f:
                        f.write("%s\n" % contract_dir_path)
                    if (os.path.exists(contract_dir_path) == True):
                        shutil.move(contract_dir_path, "test-cannot")
                    continue
                else:
                    pool.close()
                    pool.join()

                    if results == "compile error!":
                        continue
                
                if results["evm_code_coverage"] <= global_controller.LOWERCOVERAGE:
                    shutil.move(contract_dir_path, "test-lowcoverage")
                    continue 
                
                totals[contract_dir_path] = results
                total_results["total_numbers"] += 1

                print("[BridgeGuard]\t\033[92m %s-th smartcantract is completed\033[0m\n" % total_results["total_numbers"])
                
                total_results["evm_code_coverage"] = (results["evm_code_coverage"] + total_results["evm_code_coverage"] * (total_results["total_numbers"] - 1)) / total_results["total_numbers"]
                total_results["average_time"] = (results["time_cost"] + total_results["average_time"] * (total_results["total_numbers"] - 1)) / total_results["total_numbers"]
                total_results["average_length"] = (results["bytecode_length"] + total_results["average_length"] * (total_results["total_numbers"] - 1)) / total_results["total_numbers"]
                
                for vulnerablity in results["vulnerabilities"]:
                    if results["vulnerabilities"][vulnerablity]:
                        total_results["vulnerabilities"][vulnerablity] += 1
               
                with open("total-results.json", "w") as f:
                    json.dump(total_results, f, indent=4)
                f.close()
                
                with open("totals.json", "w") as f:
                    json.dump(totals, f, indent=4)
                f.close() 
                
                res = changeResultstoList(contract_dir_path, results)
                with open('testResults.csv', 'a') as file:
                    writer = csv.writer(file)
                    writer.writerow(res)
                file.close()

                shutil.move(contract_dir_path, "test-completed")

if __name__ == '__main__':
    main()

