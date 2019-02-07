all:
	make -C cloader32
	make -C cloader64
	make -C asm
	make -C c
