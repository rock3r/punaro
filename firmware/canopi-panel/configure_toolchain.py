Import("env")

# Binutils 2.35 treats Zicsr/Zifencei as separate from I by default, while the
# ESP32-C3 Arduino 2.0.17 headers and libraries use the older RISC-V 2.2 model.
# GCC 8 does not accept the newer extension spelling in -march, so pass the ISA
# version directly to the assembler. Keep -march=rv32imc so GCC selects the
# integer-only multilib; its libgcc contains no floating-point CSR instructions.
env.AppendUnique(
    ASFLAGS=["-misa-spec=2.2"],
    CCFLAGS=["-Xassembler", "-misa-spec=2.2"],
)
env.Replace(ASPPFLAGS=["-Xassembler", "-misa-spec=2.2"])
