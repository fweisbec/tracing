#include "../../../../../arch/x86/include/asm/perf_regs_32.h"


#define BIT(x)	(1 << (x))

#define PERF_UNWIND_REGS_MASK	\
	(BIT(PERF_X86_32_REG_EAX) | BIT(PERF_X86_32_REG_EBX) |	\
	 BIT(PERF_X86_32_REG_ECX) | BIT(PERF_X86_32_REG_EDX) |	\
	 BIT(PERF_X86_32_REG_ESI) | BIT(PERF_X86_32_REG_EDI) |	\
	 BIT(PERF_X86_32_REG_EBP) | BIT(PERF_X86_32_REG_ESP) |	\
	 BIT(PERF_X86_32_REG_EIP))
