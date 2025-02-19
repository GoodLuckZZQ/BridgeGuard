# Generate symbolic var.
class VarGenerator:
    def __init__(self):
        self.memcount = 0 
        self.sha3count = 0
        self.returndatasizecount = 0 
        self.gascount = 0
        self.createcount = 0 
        self.arbitraryaddresscount = 0
        self.arbitrarybalancecount = 0
        self.expcount = 0 
        self.SIGNEXTEND = 0
        self.storecount = 0

    def gen_signextend_var(self):
        self.SIGNEXTEND += 1
        return "SIGNEXTEND_" + str(self.SIGNEXTEND) 

    def gen_mem_var(self, memAddress):
        return "mem_[" + str(memAddress) +"]"

    # Generate an sh3 var name.
    def gen_sha3_var(self, content):
        return "sha3_" + content
    
    # Generate a balance var name.
    def gen_balance_var(self, address):
        return "balance_" + str(address)

    # Generate inputdata var name
    def get_Taint_Offchain_data_var(self, position):
        return "Taint_Calldata_" + "[" + str(position) + "]"

    def gen_code_var(self, address, code_start, number_bytes_of_code):
        return "code_[" + str(address) + "+" + str(code_start) + "+" + str(number_bytes_of_code) + ']'

    # Generate external code size var name.
    def gen_extcode_size_var(self, address):
        return "extcodesize_" + str(address)

    # Generate an extcode var name.
    def gen_extcode_var(self, address, code_start, length):
        return "extcode_[" + str(address) + "+" + str(code_start) + "+" + str(length) + ']'

    # Generate an returndata_size var name.
    def gen_returndata_size_var(self):
        return "returndata_size" 

    def gen_returndata_var(self, return_address, byte_length):
        return "returndata_" + "[" + str(return_address) + "+" + str(byte_length) + "]"

    # Generate an extcodehash var name.
    def gen_extcodehash_var(self, address):
        return "extcodehash_" + str(address)

    # Generate a owner_store var name.
    def gen_owner_store_var(self, position, var_name=""):
        self.storecount += 1

        return "Ia_store-" + str(self.storecount) 

    # Generate a gas var name.
    def gen_gas_var(self):
        self.gascount += 1
        return "gas_" + str(self.gascount)

    # Generate a Create contract var name.
    def gen_create_address(self):
        self.createcount += 1
        return "createaddress_" + str(self.createcount)

    # Generate an arbitrary_address var name.
    def gen_arbitrary_address_var(self):
        self.arbitraryaddresscount += 1
        return "some_address_" + str(self.arbitraryaddresscount)

    # Generate an arbitrary var name.
    def gen_arbitrary_blance_var(self):
        self.arbitrarybalancecount += 1
        return "some_balance_" + str(self.arbitrarybalancecount)

    def gen_exp_var(self):
        self.expcount += 1
        return "EXP-" + str(self.expcount)

