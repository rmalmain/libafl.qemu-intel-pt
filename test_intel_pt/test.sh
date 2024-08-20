nasm -o boot.bin boot.s

sudo ../build/qemu-system-x86_64 -drive format=raw,file=boot.bin -nographic -enable-kvm 2>log.txt

path/to/libipt/build/bin/ptdump --no-pad ipt_raw_trace >simple_asm_trace.txt
