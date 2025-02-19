import os
from subprocess import Popen, PIPE, STDOUT
import subprocess
import six
import logging
import re
import shutil

from global_utils import *

# Objective store source information.
class InputGenerator:
    BYTECODE = 0
    SOLIDITY = 1

    def __init__(self, input_type, **kwargs):
        self.input_type = input_type

        if input_type ==InputGenerator.BYTECODE:
            attr_defaults = {
                'source': None,
                'evm': False,
                'disasm': True,
            }

        elif input_type == InputGenerator.SOLIDITY:
            attr_defaults = {
                'source': None,
                'evm': False,
                'root_path': "",
                'compilation_err': False,
                'remap': "",
                'allow_paths': "",
                'compiled_contracts': [] 
            }

        for (attr, default) in six.iteritems(attr_defaults):
            val = kwargs.get(attr, default)
            
            if val == None:
                raise Exception("'%s' attribute cannot be None" % attr)
            
            else:
                setattr(self, attr, val)

    # Firstly, compiling the souce contract to get binary contract;
    # Secondly, disassemble the binary contract, get the assembly contract, and then write different files respectively.
    def get_inputs(self):
        inputs = []
        if self.input_type == InputGenerator.BYTECODE:
            with open(self.source, 'r') as f:
                bytecode = f.readline()
            
            self._prepare_disasm_file(self.source, bytecode)
      
            disasm_file = self._get_temporary_files(self.source)["disasm"]
  
            inputs.append({"disasm_file": disasm_file})
            
            inputs.append({"bytecode": self._removeSwarmHash(bytecode)})

        else:
            raise ValueError("Bytecode only!")
        
        return inputs

    # Write disasm files.
    def _prepare_disasm_file(self, contract, bytecode):
        self._write_evm_file(contract, bytecode)
        self._write_disasm_file(contract)

    # Write binary file.
    def _write_evm_file(self, contract, bytecode):
        evm_file = self._get_temporary_files(contract)["evm"]
        with open(evm_file, 'w') as of:
            of.write(self._removeSwarmHash(bytecode))
    
    # Write disasm file which includes opcodes.
    def _write_disasm_file(self, contract):
        tmp_file = self._get_temporary_files(contract)
        evm_file = tmp_file["evm"]
        
        disasm_file = tmp_file["disasm"]
        disasm_out = ""

        try:
            disasm_process = subprocess.Popen(
                ["evm", "disasm", evm_file], stdout=subprocess.PIPE)
            disasm_out = disasm_process.communicate()[0].decode('utf-8', 'strict')
            
        except:
            logging.critical("Disassembly failed.")
            exit()
    
        with open(disasm_file, 'w') as of:
            of.write(disasm_out)

    # Prepare names of disasm files, includes evm.evm, disasm.evm.disasm, log.evm.disasm.log
    def _get_temporary_files(self, contract):
        return {
            "evm": contract + ".evm",
            "disasm": contract + ".disasm",
            "log": contract + ".log"
        }

    def rm_tmp_files(self):
        if self.input_type == InputGenerator.BYTECODE:
            self._rm_tmp_files(self.source)

    def _rm_tmp_files(self, target):
        tmp_files = self._get_temporary_files(target)
        
        if not self.evm:
            self._rm_file(tmp_files["evm"])
        
        if not self.disasm:
            self._rm_file(tmp_files["disasm"])
        
        self._rm_file(tmp_files["log"])

    def _rm_file(self, path):
        if os.path.isfile(path):
            os.unlink(path)

    # Remove auxdata (SwarmHash) which is in the end of binary contract.
    def _removeSwarmHash(self, evm):
        evm_without_auxdata = re.sub(r"a165627a7a72305820\S{64}0029$", "", evm)
        evm_without_auxdata = re.sub(r"a2646970667358221220\S{82}0033$", "", evm_without_auxdata)
        evm_without_auxdata = re.sub(r"a265627a7a72305820\S{80}0032$", "", evm_without_auxdata)

        return evm_without_auxdata


# Use solc compile solidity file and generate abi and bin files.
def compile_solidity(filename):
    print('\033[1m[BridgeGuard]\t Compiling Solidity contract from a sol file %s ... \033[0m\n' % filename, end='')
    source_file = filename
    
    if (not os.path.isfile(source_file) ):
        print('[BridgeGuard]\t \033[91m[-] Contract file %s does NOT exist\033[0m' % source_file )
        return


    solc_version = find_max_solc_version(source_file)

    print("[BridgeGuard]\t\033[96m Installing solc version: %s\033[0m" % solc_version)
    
    run_command("solc-select install " + solc_version)
    
    print("[BridgeGuard]\t\033[92m Done\033[0m")

    print("[BridgeGuard]\t\033[96m Using solc version: %s\033[0m" % solc_version)
    
    run_command("solc-select use " + solc_version)
    
    print("[BridgeGuard] \t\033[92m Done\033[0m")
    
    print("[BridgeGuard] \t\033[96m Compiling ........ \033[0m")
    
    try:
        p = Popen(['solc','--bin-runtime', "--hashes", '-o', source_file[0:-4], source_file, '--overwrite'], stdout=PIPE, stdin=PIPE, stderr=STDOUT)
        solo = ''

        while p.poll() is None:
            l = p.stdout.readline()
            solo += bytes.decode(l)

        if 'error' in solo or "Error" in solo:
            print("[BridgeGuard]\t " +solo)
            exit()

        p.wait()

        print('[BridgeGuard]\t\033[92m Done \033[0m')

    except:
        print('[BridgeGuard]\t\033[91m [-] Cannot compile the contract \033[0m')
        raise
        with open("AuditFailed.txt", "a") as f:
            f.write("%s\n" % contract_dir_path)
        shutil.move(source_file, "test-cannot-compile")

def compile_json_dirs(json_format_path):
    deal_json_import_path(str(json_format_path))
    audit_bin_path = compile_json_format(json_format_path)
    return audit_bin_path

def deal_json_import_path(json_format_path):
    for file_name in os.listdir(json_format_path):
        if file_name[-4:] == ".sol":
            file_path = json_format_path + file_name
            
            with open(file_path, 'r') as file:
                alllines = file.readlines()
            file.close()
            
            with open(file_path, "w+") as file:
                for eachline in alllines:
                    if "import" in eachline[0:10]:
                        if "/" in eachline:
                            eachline_parts = eachline.split("/")
                            replace_line = 'import' + ' "./' + eachline_parts[-1].split(".")[0] + '.sol' +'";\n'
                            file.write(replace_line)
                        else:
                            eachline_parts = eachline.split(' "')
                            replace_line = 'import' + ' "./' + eachline_parts[-1].split(".")[0] + '.sol' +'";\n'
                            file.write(replace_line)
                        continue
                    file.write(eachline)

            file.close()

def compile_json_format(json_format_path):

    print('\033[1m[BridgeGuard]\t Compiling Solidity contract from the json dir %s ... \033[0m\n' % json_format_path, end='')

    all_solc_versions = []
    for root, dirs, files in os.walk(json_format_path):
        for file_name in files:
            if file_name[-4:] == ".sol":
                file_path = json_format_path + file_name
                all_solc_versions.append(find_max_solc_version(file_path))
    
    max_solc_version = find_max_version(all_solc_versions)

    print("[BridgeGuard]\t\033[96m Installing solc version: %s\033[0m" % max_solc_version)
    
    run_command("solc-select install " + max_solc_version)
    
    print("[BridgeGuard]\t\033[92m Done\033[0m")

    print("[BridgeGuard]\t\033[96m Using solc version: %s\033[0m" % max_solc_version)
    
    run_command("solc-select use " + max_solc_version)
    
    print("[BridgeGuard] \t\033[92m Done\033[0m")
    
    print("[BridgeGuard] \t\033[96m Compiling ........ \033[0m")


    for root, dirs, files in os.walk(json_format_path):
        for file_name in files:
            if file_name[-4:] == ".sol":
                file_path = json_format_path + file_name
                try:
                    p = Popen(['solc','--bin-runtime', "--hashes", '-o', file_path[0:-4], file_path, '--overwrite'], stdout=PIPE, stdin=PIPE, stderr=STDOUT)
                    solo = ''

                    while p.poll() is None:
                        l = p.stdout.readline()
                        solo += bytes.decode(l)

                    if 'error: ' in solo or "Error: " in solo:
                        print("[BridgeGuard]\t " +solo)
                        exit()

                    p.wait()          
                                        
                except:
                    print(file_path)
                    print('[BridgeGuard]\t\033[91m [-] Cannot compile the contract \033[0m')
                    raise
                
    final_dir = ""
    final_bin = ""
    max_bin = 0
    for root, dirs, files in os.walk(json_format_path):
        # print(dirs)
        for dir in dirs:
            bin_path = json_format_path + dir
            for file in os.listdir(bin_path):
                if file[-12:] == ".bin-runtime":
                    with open(bin_path+"/"+file, "r") as bin_file:
                        content = bin_file.readlines()
                        
                        if str(content) != "[]":
                            if len(content[0]) <= max_bin:
                                pass
                            else:
                                max_bin = len(content[0])
                                final_dir = dir
                                final_bin = file
    
    for root, dirs, files in os.walk(json_format_path):
        for dir in dirs:
            if dir != final_dir:
                shutil.rmtree(json_format_path + dir) 
    
    for file in os.listdir(json_format_path + final_dir):
        if file != final_bin and file != (final_bin[:-12] + ".signatures"):
            os.remove(json_format_path + final_dir + "/" + file)

    return json_format_path + final_dir + "/" + final_bin

def find_max(array):
    max_ele = 0
    for item in array:
        if item > max_ele:
            max_ele = item
    
    return max_ele

def find_max_version(solc_versions):
    solc_version_part1 = []
    solc_version_part2 = []
    solc_version_part3 = []


    versionToNum = []
    
    for i in range(len(solc_versions)):
        solc_verison_parts = solc_versions[i].split(".")
        num = int(solc_verison_parts[0]) * 10000 + int(solc_verison_parts[1]) * 100 + int(solc_verison_parts[2])
        versionToNum.append(num)

    maxnum = 0
    max_version = ""
    
    for i in range(len(solc_versions)):
        if versionToNum[i] > maxnum:
            maxnum = versionToNum[i]
            max_version = solc_versions[i]

    return max_version

def find_max_solc_version(file_name):
    solc_versions = []
    with open(file_name, 'r') as file:
        lines = file.readlines()
        
        for line in lines:
            if "pragma solidity" in line:
                pattern = r'[0-9].[0-9].[0-9]*'
                instr = re.findall(pattern, line)
                solc_versions.append(instr[0])

    file.close()

    max_version = find_max_version(solc_versions)

    return max_version

def return_sol_numbers_of_dir(path):
    sol_number = 0
    
    for root, dirs, files in os.walk(path):
        for file in files:
            if file[-4:] == ".sol":
                sol_number += 1
                
    return sol_number

    