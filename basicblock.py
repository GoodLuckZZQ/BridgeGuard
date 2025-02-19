import six

# BasicBlock
class BasicBlock:
    def __init__(self, start_pc, end_pc):
        self.start_pc = start_pc
        self.end_pc = end_pc
        self.instructions = []
        self.jump_target = 0

    # Add instructions to the basic block.
    def add_instruction(self, instruction):
        self.instructions.append(instruction)

    # Get instructions to the basic block.
    def get_instructions(self):
        return self.instructions

    # Set jump_type of the basic block.
    def set_block_type(self, block_type):
        self.type = block_type

    # Set falls_to_target of the basic block.
    def set_falls_to(self, pc):
        self.falls_to = pc

    # Get falls_to_target of the basic block.
    def get_falls_to(self):
        return self.falls_to

    # Set jump_target of the basic block.
    def set_jump_target(self, pc):
        if isinstance(pc, six.integer_types):
            self.jump_target = pc
        else:
            self.jump_target = -1

    # Get jump_target of the basic block.
    def get_jump_target(self):
        return self.jump_target
    
    # Set branch_expression (If-else) of the basic block, if the block_type is conditional.
    def set_branch_expression(self, branch):
        self.branch_expression = branch

    # Get branch_expression (If-else) of the basic block, if the block_type is conditional.
    def get_branch_expression(self):
        return self.branch_expression

    # Display a basic block.
    def display(self):
        six.print_("===========================")
        
        six.print_("start pc: %d" % self.start_pc)
        six.print_("end pc: %d" % self.end_pc)
        six.print_("end statement type: " + self.type)

        for instr in self.instructions:
            six.print_(instr)