from binaryninja import *
from .consts import syscall_codes

def run(bv,func):
	syscall_tuples = []
	for function in bv.functions:
		# build list of tuples (function object, instruction object)
		# made up of functions containing syscalls
		syscall_tuples += get_syscall_instructions(function)
	# name says it all ;) 
	labeling_magic(bv, syscall_tuples)

def get_syscall_instructions(function):
	syscall_instructions= []
	# iterate through each instruction in the function
	for instruction in function.instructions:
		# check if instruction contains a syscall
		if instruction[0][0].text == 'svc':
			syscall_instructions.append((function,instruction))
	return syscall_instructions

def labeling_magic(bv, syscall_tuples):
	# unpack tuple of (function object, instruction object)
	for function,instruction in syscall_tuples:
		# extract syscall code from r7 register
		syscall_code = function.get_reg_value_at(instruction[1], 'r7').value
		# check that we have a corresponding entry for the syscall code
		if syscall_code in syscall_codes:
			label_syscall_function(bv, function, instruction[1], syscall_codes[syscall_code])

def label_syscall_function(bv, function, addr, syscall_name):
	print('[+] labeling syscall {} at {}'.format(syscall_name, hex(addr)))
	# comment the instruction using the syscall
	bv.set_comment_at(addr, syscall_name)
	# renaming functions with generic sub_* name
	if function.name.startswith('sub_'):
		print('[+] labeling function {} as calls_syscall_{}'.format(function.name, syscall_name))
		# function name will be "calls_syscall_<syscall name>"
		function.name = 'calls_syscall_{}'.format(syscall_name)


PluginCommand.register_for_address("ARM Syscall Resolver", "Resolve syscall codes for ARM binaries", run)
