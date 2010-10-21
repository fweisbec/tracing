#ifndef _ASM_X86_PERF_REGS_32_H
#define _ASM_X86_PERF_REGS_32_H

#define PERF_X86_32_REG_VERSION		1ULL

enum perf_event_x86_32_regs {
	PERF_X86_32_REG_EAX,
	PERF_X86_32_REG_EBX,
	PERF_X86_32_REG_ECX,
	PERF_X86_32_REG_EDX,
	PERF_X86_32_REG_ESI,
	PERF_X86_32_REG_EDI,
	PERF_X86_32_REG_EBP,
	PERF_X86_32_REG_ESP,
	PERF_X86_32_REG_EIP,
	PERF_X86_32_REG_FLAGS,
	PERF_X86_32_REG_CS,
	PERF_X86_32_REG_DS,
	PERF_X86_32_REG_ES,
	PERF_X86_32_REG_FS,
	PERF_X86_32_REG_GS,

	/* Non ABI */
	PERF_X86_32_REG_MAX,
};

#ifdef __KERNEL__

#define PERF_X86_32_REG_RESERVED (~((1ULL << PERF_X86_32_REG_MAX) - 1ULL))

static inline u64 perf_reg_version(void)
{
	return PERF_X86_32_REG_VERSION;
}

static inline int perf_reg_validate(u64 mask)
{
	if (mask & PERF_X86_32_REG_RESERVED)
		return -EINVAL;

	return 0;
}

static inline u64 perf_reg_value(struct pt_regs *regs, int idx)
{
	switch (idx) {
	case PERF_X86_32_REG_EAX:
		return regs->ax;
	case PERF_X86_32_REG_EBX:
		return regs->bx;
	case PERF_X86_32_REG_ECX:
		return regs->cx;
	case PERF_X86_32_REG_EDX:
		return regs->dx;
	case PERF_X86_32_REG_ESI:
		return regs->si;
	case PERF_X86_32_REG_EDI:
		return regs->di;
	case PERF_X86_32_REG_EBP:
		return regs->bp;
	case PERF_X86_32_REG_ESP:
		return regs->sp;
	case PERF_X86_32_REG_EIP:
		return regs->ip;
	case PERF_X86_32_REG_FLAGS:
		return regs->flags;
	case PERF_X86_32_REG_CS:
		return regs->cs;
	case PERF_X86_32_REG_DS:
		return regs->ds;
	case PERF_X86_32_REG_ES:
		return regs->es;
	case PERF_X86_32_REG_FS:
		return regs->fs;
	case PERF_X86_32_REG_GS:
		return regs->gs;
	}

	/* Well... */
	return 0;
}

#endif /* __KERNEL__ */

#endif /* _ASM_X86_PERF_REGS_32_H */
