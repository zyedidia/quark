.globl main
main:
	add sp, sp, #16
	b l1
	ret
l1:
	b l1
