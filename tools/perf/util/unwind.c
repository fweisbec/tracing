/*
 * Post mortem Dwarf CFI based unwinding on top of regs and stack dumps.
 *
 * Lots of this code have been borrowed or heavily inspired from parts of
 * the libunwind 0.99 code which are (amongst other contributors I may have
 * forgotten):
 *
 * Copyright (C) 2002-2007 Hewlett-Packard Co
 *	Contributed by David Mosberger-Tang <davidm@hpl.hp.com>
 *
 * And the bugs have been added by:
 *
 * Copyright (C) 2010, Frederic Weisbecker <fweisbec@gmail.com>
 *
 */

#include "util.h"
#include <elf.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <linux/list.h>
#include <linux/err.h>
#include "thread.h"
#include "session.h"
#include "perf_regs.h"


#ifdef LIBUNWIND_SUPPORT

#include <libunwind-ptrace.h>
#include <libunwind.h>

struct pt_regs {
	unsigned long ebx;
	unsigned long ecx;
	unsigned long edx;
	unsigned long esi;
	unsigned long edi;
	unsigned long ebp;
	unsigned long eax;
	unsigned long ds;
	unsigned long es;
	unsigned long fs;
	unsigned long gs;
	unsigned long orig_ax;
	unsigned long eip;
	unsigned long cs;
	unsigned long flags;
	unsigned long esp;
	unsigned long ss;
};

#define DW_EH_PE_FORMAT_MASK	0x0f	/* format of the encoded value */
#define DW_EH_PE_APPL_MASK	0x70	/* how the value is to be applied */
/*
 * Flag bit.  If set, the resulting pointer is the address of the word
 * that contains the final address.
 */
#define DW_EH_PE_indirect	0x80

/* Pointer-encoding formats: */
#define DW_EH_PE_omit		0xff
#define DW_EH_PE_ptr		0x00	/* pointer-sized unsigned value */
#define DW_EH_PE_uleb128	0x01	/* unsigned LE base-128 value */
#define DW_EH_PE_udata2		0x02	/* unsigned 16-bit value */
#define DW_EH_PE_udata4		0x03	/* unsigned 32-bit value */
#define DW_EH_PE_udata8		0x04	/* unsigned 64-bit value */
#define DW_EH_PE_sleb128	0x09	/* signed LE base-128 value */
#define DW_EH_PE_sdata2		0x0a	/* signed 16-bit value */
#define DW_EH_PE_sdata4		0x0b	/* signed 32-bit value */
#define DW_EH_PE_sdata8		0x0c	/* signed 64-bit value */

/* Pointer-encoding application: */
#define DW_EH_PE_absptr		0x00	/* absolute value */
#define DW_EH_PE_pcrel		0x10	/* rel. to addr. of encoded value */
#define DW_EH_PE_textrel	0x20	/* text-relative (GCC-specific???) */
#define DW_EH_PE_datarel	0x30	/* data-relative */
/*
 * The following are not documented by LSB v1.3, yet they are used by
 * GCC, presumably they aren't documented by LSB since they aren't
 * used on Linux:
 */
#define DW_EH_PE_funcrel	0x40	/* start-of-procedure-relative */
#define DW_EH_PE_aligned	0x50	/* aligned pointer */

struct dwarf_instr_addr {
	u64			start;
	u64			end;
	struct dso		*dso;
	struct list_head	list;
};

struct unwind_info {
	struct sample_data	*sample;
	struct perf_session	*session;
	struct thread		*thread;
	struct list_head	dia_head;
};

static int
resolve_section_name(int fd, Elf32_Ehdr *ehdr, int idx, char *buf, int size)
{
	Elf32_Shdr shdr;
	int offset;
	int old;
	int i;
	char c;

	old = lseek(fd, 0, SEEK_CUR);
	offset = ehdr->e_shoff + (ehdr->e_shstrndx * ehdr->e_shentsize);
	lseek(fd, offset, SEEK_SET);
	if (read(fd, &shdr, ehdr->e_shentsize) == -1)
		return -errno;

	offset = shdr.sh_offset + idx;
	lseek(fd, offset, SEEK_SET);

	for (i = 0; i < size - 1; i++) {
		if (read(fd, &c, 1) == -1)
			return -errno;
		if (!c)
			break;
		buf[i] = c;
	}

	buf[i] = 0;
	lseek(fd, old, SEEK_SET);

	return 0;
}


static int eh_frame_section(int fd, Elf32_Ehdr *ehdr, Elf32_Shdr *shdr)
{
	int i, err;

	lseek(fd, ehdr->e_shoff + ehdr->e_shentsize, SEEK_SET);

	for (i = 1; i < ehdr->e_shnum; i++) {
		char buf[128];

		if (read(fd, shdr, ehdr->e_shentsize) == -1)
			return -errno;

		err = resolve_section_name(fd, ehdr, shdr->sh_name, buf, sizeof(buf));
		if (err)
			return err;

		if (!strcmp(buf, ".eh_frame"))
			return 0;
	}

	return -ENOENT;
}

static int parse_elf_headers(int fd, Elf32_Ehdr *ehdr)
{
	if (read(fd, ehdr, sizeof(*ehdr)) == -1)
		return -errno;

	if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
		ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
		ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
		ehdr->e_ident[EI_MAG3] != ELFMAG3) {

		return -EINVAL;
	}

	if (!ehdr->e_shoff)
		return -ENOENT;

	return 0;
}

static u64 dwarf_read_uleb128(int fd, u64 *val)
{
	u64 shift = 0;
	unsigned char byte;

	*val = 0;

	do {
		if (read(fd, &byte, sizeof(byte)) == -1)
			return -errno;

		*val |= (byte & 0x7f) << shift;
		shift += 7;
	} while (byte & 0x80);

	return 0;
}

static s64 dwarf_read_sleb128(int fd, s64 *val)
{
	s64 shift = 0;
	unsigned char byte;

	*val = 0;

	do {
		if (read(fd, &byte, sizeof(byte)) == -1)
			return -errno;
		*val |= (byte & 0x7f) << shift;
		shift += 7;
	} while (byte & 0x80);

	if (shift < 8 * sizeof(*val) && (byte & 0x40) != 0)
		/* sign-extend negative value */
		*val |= -1LL << shift;

	return 0;
}

static int dwarf_read_encoded_pointer(int fd, unsigned char encoding,
				      u64 drop __used, u64 *val)
{
	u64 base = lseek(fd, 0, SEEK_CUR);

	if (encoding == DW_EH_PE_omit || encoding == DW_EH_PE_aligned) {
		pr_err("Unsupported dwarf encoding\n");
		return -ENOSYS;
	}

	switch (encoding & DW_EH_PE_FORMAT_MASK) {
	case DW_EH_PE_ptr: {
		unsigned long lval;

		if (read(fd, &lval, sizeof(lval)) == -1)
			return -errno;
		*val = lval;
		break;
	}
	case DW_EH_PE_sdata4: {
		s32 s32val;
		s64 s64val;

		if (read(fd, &s32val, sizeof(s32val)) == -1)
			return -errno;
		s64val = s32val;
		*val = *(u64 *)&s64val;
		break;
	}
	default:
		pr_err("Unsupported encoded pointer: %d\n", encoding & DW_EH_PE_FORMAT_MASK);
		return -EINVAL;
	}

	switch (encoding & DW_EH_PE_APPL_MASK) {
	case DW_EH_PE_absptr:
		break;
	case DW_EH_PE_pcrel:
		*val += base;
		break;
	default:
		pr_err("Unsupported DW_EH_PE_APPL_MASK: %d\n", encoding & DW_EH_PE_APPL_MASK);
		return -EINVAL;
	}

	if (encoding & DW_EH_PE_indirect) {
		int prev_offset = lseek(fd, 0, SEEK_CUR);
		unsigned long lval;

		lseek(fd, *val, SEEK_SET);
		if (read(fd, &lval, sizeof(unsigned long)) == -1)
			return -errno;
		*val = lval;
		lseek(fd, prev_offset, SEEK_SET);
	}

	return 0;
}

struct cie {
	u32		length;
	u64		ext_length;
	union {
			u32 id32;
			u64 id64;
	};
	u8		version;
	u64		code_align;
	s64		data_align;
	u8		ret_column;
	u64		aug_length;
	u8		lsda_encoding;
	u8		fde_encoding; /* Should have defaults */
	u8		handler_encoding;
	u8		have_abi_marker;
	u64		handler;
	u64		instr;
	u64		end;
};

static int parse_cie(int fd, struct cie *cie)
{
	char aug_str[10];
	int size, end, base;
	int err;
	int i;

	memset(cie, 0, sizeof(*cie));

	if (read(fd, &cie->length, sizeof(cie->length)) == -1)
		return -errno;

	if (cie->length == 0xffffffff) {
		if (read(fd, &cie->ext_length, sizeof(cie->ext_length)) == -1)
			return -errno;

		size = cie->ext_length;
		base = lseek(fd, 0, SEEK_CUR);
		if (read(fd, &cie->id64, sizeof(cie->id64)) == -1)
			return -errno;

		if (cie->id64)
			return -EINVAL;
	} else {
		base = lseek(fd, 0, SEEK_CUR);
		if (read(fd, &cie->id32, sizeof(cie->id32)) == -1)
			return -errno;
		size = cie->length;
		if (cie->id32)
			return -EINVAL;
	}
	end = base + size;

	if (read(fd, &cie->version, sizeof(cie->version)) == -1)
		return -errno;

	/* Should be else in 64 bits? */
	if (cie->version != 1)
		return -EINVAL;

	memset(aug_str, 0, sizeof(aug_str));
	for (i = 0; i < (int)sizeof(aug_str); i++) {
		char c;

		if (read(fd, &c, 1) == -1)
			return -errno;

		aug_str[i] = c;
		if (!c)
			break;
	}

	if (!strcmp("eh", aug_str))
		lseek(fd, 4, SEEK_CUR);

	err = dwarf_read_uleb128(fd, &cie->code_align);
	if (err)
		return err;

	err = dwarf_read_sleb128(fd, &cie->data_align);
	if (err)
		return err;


	if (read(fd, &cie->ret_column, sizeof(cie->ret_column)) == -1)
		return -errno;

	if (aug_str[0] == 'z') {
		err = dwarf_read_uleb128(fd, &cie->aug_length);
		if (err)
			return err;
	}


	for (i = 1; aug_str[i]; i++) {
		switch (aug_str[i]) {
		case 'L':
			if (read(fd, &cie->lsda_encoding, sizeof(cie->lsda_encoding)) == -1)
				return -errno;
			break;
		case 'R':
			if (read(fd, &cie->fde_encoding, sizeof(cie->fde_encoding)) == -1)
				return -errno;
			break;
		case 'P':
			if (read(fd, &cie->handler_encoding, sizeof(cie->handler_encoding)) == -1)
				return -errno;

			err = dwarf_read_encoded_pointer(fd, cie->handler_encoding, 0,
								&cie->handler);
			if (err)
				return err;
			break;
		case 'S':
			if (read(fd, &cie->have_abi_marker, sizeof(cie->have_abi_marker)) == -1)
				return -errno;
			break;
		default:
			break;
		}
	}
	cie->instr = lseek(fd, 0, SEEK_CUR);
	cie->end = end;

	return 0;
}

struct fde {
	u32	length;
	u64	ext_length;
	union {
		u32	cie_offset32;
		u64	cie_offset64;
	};
	u64	pc_begin;
	u64	pc_range;
	u64	aug_length;
	u64	aug_end;
	u64	lsda;
	u16	abi;
	u16	tag;
	u64	end;
};

static int parse_fde(int fd, struct fde *fde, struct cie *cie, int fde_end)
{
	int ip_range_encoding;
	int err;

	memset(fde, 0, sizeof(*fde));
	ip_range_encoding = cie->fde_encoding & DW_EH_PE_FORMAT_MASK;

	err = dwarf_read_encoded_pointer(fd, cie->fde_encoding, 0, &fde->pc_begin);
	if (err)
		return err;
	err = dwarf_read_encoded_pointer(fd, ip_range_encoding, 0, &fde->pc_range);
	if (err)
		return err;
	fde->pc_range += fde->pc_begin;

	if (cie->aug_length) {
		err = dwarf_read_uleb128(fd, &fde->aug_length);
		if (err)
			return err;
		fde->aug_end = lseek(fd, 0, SEEK_CUR) + fde->aug_length;
	}

	err = dwarf_read_encoded_pointer(fd, cie->lsda_encoding, 0, &fde->lsda);
	if (err)
		return err;

	if (cie->have_abi_marker) {
		if (read(fd, &fde->abi, sizeof(fde->abi)) == -1)
			return -EINVAL;
		if (read(fd, &fde->tag, sizeof(fde->tag)) == -1)
			return -EINVAL;
	}

	if (!cie->aug_length)
		fde->aug_end = lseek(fd, 0, SEEK_CUR);
	fde->end = fde_end;

	return 0;
}

struct dwarf_cie_info {
	unw_word_t cie_instr_start;	/* start addr. of CIE "initial_instructions" */
	unw_word_t cie_instr_end;	/* end addr. of CIE "initial_instructions" */
	unw_word_t fde_instr_start;	/* start addr. of FDE "instructions" */
	unw_word_t fde_instr_end;	/* end addr. of FDE "instructions" */
	unw_word_t code_align;		/* code-alignment factor */
	unw_word_t data_align;		/* data-alignment factor */
	unw_word_t ret_addr_column;	/* column of return-address register */
	unw_word_t handler;		/* address of personality-routine */
	uint16_t abi;
	uint16_t tag;
	uint8_t fde_encoding;
	uint8_t lsda_encoding;
	unsigned int sized_augmentation : 1;
	unsigned int have_abi_marker : 1;
};

static int
cfi_match_fill(unw_word_t addr, struct cie *cie, struct fde *fde,
		unw_proc_info_t *pi, int need_unwind_info)
{
	struct dwarf_cie_info *dci;

	if (addr < fde->pc_begin || addr >= fde->pc_range)
		return -1;

	pi->start_ip = fde->pc_begin;
	pi->end_ip = fde->pc_range;
	pi->lsda = fde->lsda;
	pi->handler = cie->handler;
	pi->format = UNW_INFO_FORMAT_TABLE;

	if (!need_unwind_info)
		return 0;

	dci = calloc(1, sizeof(*dci));
	if (!dci)
		return -ENOMEM;

	dci->cie_instr_start = cie->instr;
	dci->cie_instr_end = cie->end;
	dci->fde_instr_start = fde->aug_end;
	dci->fde_instr_end = fde->end;
	dci->code_align = cie->code_align;
	dci->data_align = cie->data_align;
	dci->ret_addr_column = cie->ret_column;
	dci->handler = pi->handler;
	dci->abi = fde->abi;
	dci->tag = fde->tag;
	dci->fde_encoding = cie->fde_encoding;
	dci->lsda_encoding = cie->lsda_encoding;
	dci->sized_augmentation = !!cie->aug_length;
	dci->have_abi_marker = cie->have_abi_marker;
	pi->unwind_info_size = sizeof(*dci);
	pi->unwind_info = dci;

	return 0;
}

static int get_cfi_info(int fd, unw_word_t addr, Elf32_Shdr *eh_shdr,
			unw_proc_info_t *pi, int need_unwind_info)
{
	int start, end;

	start = eh_shdr->sh_offset;
	end = start + eh_shdr->sh_size;

	lseek(fd, start, SEEK_SET);

	/*
	 * For now, do a slow linear search of the fde matching that address.
	 * Support for binary search across .eh_frame_hdr will come after.
	 */
	for (;;) {
		int base, val_offset;
		struct cie cie;
		struct fde fde;
		u32 size32, val32;
		s64 size, val;

		base = lseek(fd, 0, SEEK_CUR);
		if (base >= end)
			break;

		if (read(fd, &size32, sizeof(size32)) == -1)
			return -EINVAL;

		if (size32 == 0xffffffff) {
			if (read(fd, &size, sizeof(size)) == -1)
				return -EINVAL;
			val_offset = lseek(fd, 0, SEEK_CUR);
			if (read(fd, &val, sizeof(val)) == -1)
				return -EINVAL;
		} else {
			val_offset = lseek(fd, 0, SEEK_CUR);
			if (read(fd, &val32, sizeof(val32)) == -1)
				return -EINVAL;
			val = val32;
			size = size32;
		}

		if (val) {
			int offset, err;

			offset = lseek(fd, 0, SEEK_CUR);
			lseek(fd, val_offset - val, SEEK_SET);
			if (parse_cie(fd, &cie)) {
				pr_debug("Incorrect cie %llx %llx\n", val_offset - val, val);
				break;
			}

			lseek(fd, offset, SEEK_SET);
			if (parse_fde(fd, &fde, &cie, size + val_offset)) {
				pr_debug("Incorrect fde\n");
				break;
			}

			err = cfi_match_fill(addr, &cie, &fde, pi, need_unwind_info);
			if (err != -1)
				return err;
			if (!err)
				return 0;
		}

		lseek(fd, val_offset + size, SEEK_SET);
	}

	return -ENOENT;
}

static void find_address_location(unw_word_t ip, struct unwind_info *ui,
				  struct addr_location *al)
{
	thread__find_addr_map(ui->thread, ui->session, PERF_RECORD_MISC_USER,
			   MAP__FUNCTION, ui->thread->pid, ip, al);
}

static int track_dwarf_instr_addr(unw_proc_info_t *pi, struct unwind_info *ui,
				  struct addr_location *al)
{
	struct dwarf_instr_addr *dia_cie, *dia_fde;
	struct dwarf_cie_info *dci;

	dia_cie = malloc(sizeof(*dia_cie));
	if (!dia_cie)
		return -ENOMEM;

	dci = (struct dwarf_cie_info *)pi->unwind_info;

	dia_cie->start = dci->cie_instr_start - 1;
	dia_cie->end = dci->cie_instr_end;
	dia_cie->dso = al->map->dso;

	list_add_tail(&dia_cie->list, &ui->dia_head);

	dia_fde = malloc(sizeof(*dia_fde));
	if (!dia_fde) {
		list_del(&dia_cie->list);
		free(dia_cie);
		return -ENOMEM;
	}

	dia_fde->start = dci->fde_instr_start - 1;
	dia_fde->end = dci->fde_instr_end;
	dia_fde->dso = al->map->dso;

	list_add_tail(&dia_fde->list, &ui->dia_head);

	return 0;
}

static int
find_proc_info(unw_addr_space_t as __used, unw_word_t ip, unw_proc_info_t *pi,
	      int need_unwind_info, void *arg)
{
	int err;
	int fd;
	unw_word_t addr;
	char *path;
	Elf32_Ehdr ehdr;
	Elf32_Shdr eh_shdr;
	struct addr_location al;
	struct unwind_info *ui = arg;

	find_address_location(ip, ui, &al);

	if (!al.map || !al.map->dso)
		return -EINVAL;

	path = al.map->dso->long_name;
	if (!path)
		return -ENOENT;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		close(fd);
		return fd;
	}

	err = parse_elf_headers(fd, &ehdr);
	if (err) {
		close(fd);
		return err;
	}

	err = eh_frame_section(fd, &ehdr, &eh_shdr);
	if (err) {
		close(fd);
		return err;
	}

	if (ehdr.e_type == ET_DYN)
		addr = al.map->map_ip(al.map, ip);
	else
		addr = ip;

	err = get_cfi_info(fd, addr, &eh_shdr, pi, need_unwind_info);
	if (err) {
		close(fd);
		return err;
	}

	if (need_unwind_info) {
		err = track_dwarf_instr_addr(pi, ui, &al);
		close(fd);
		return err;
	}

	close(fd);

	return 0;
}

static int access_fpreg(unw_addr_space_t __used as, unw_regnum_t __used num,
			unw_fpreg_t __used *val, int __used __write,
			void __used *arg)
{
	pr_warning("Unwind: fpreg unsupported yet\n");

	return -1;
}

static int get_dyn_info_list_addr(unw_addr_space_t __used as,
				  unw_word_t __used *dil_addr,
				  void __used *arg)
{
	return -UNW_ENOINFO;
}

static int resume(unw_addr_space_t __used as, unw_cursor_t __used *cu,
		  void __used *arg)
{
	pr_warning("Unwind: resume\n");

	return 0;
}

static int
get_proc_name(unw_addr_space_t __used as, unw_word_t __used addr,
		char __used *bufp, size_t __used buf_len,
		unw_word_t __used *offp, void __used *arg)
{
	*offp = 0;

	return 0;
}

static int access_dso_mem(struct unwind_info *ui, unw_word_t addr,
			  unw_word_t *valp)
{
	struct thread *thread = ui->thread;
	struct perf_session *session = ui->session;
	struct addr_location al;
	int fd;
	u64 offset;

	thread__find_addr_map(thread, session, PERF_RECORD_MISC_USER,
			   MAP__FUNCTION, thread->pid, addr, &al);
	if (!al.map) {
		pr_debug("unwind: not found map for %lx\n", (unsigned long)addr);
		return -1;
	}

	offset = al.map->map_ip(al.map, addr);
	fd = open(al.map->dso->long_name, O_RDONLY);
	if (fd < 0) {
		const char *name;

		name = al.map ? al.map->dso->long_name : "Sais pas";
		pr_debug("unwind: Can't open dso %s\n", name);

		return -1;
	}

	if (lseek(fd, offset, SEEK_SET) == -1) {
		close(fd);
		pr_err("unwind: Can't seek\n");
		return -1;
	}
	if (read(fd, valp, sizeof(*valp)) == -1) {
		close(fd);
		return -errno;
	}
	close(fd);

	pr_debug("access mem offset: %llx va: %lx val: %lx\n",
			offset, (unsigned long)addr, (unsigned long)*valp);

	return 0;
}

static int access_dwarf_instr(struct unwind_info *ui, unw_word_t addr,
			  unw_word_t *valp)
{
	struct dwarf_instr_addr *dia;
	int found = 0;
	int fd;

	/*
	 * This is quite crappy. There may be conflicts between dso adresses
	 * here. Probably we only need to keep track of the last dso here.
	 */
	list_for_each_entry(dia, &ui->dia_head, list) {
		if (addr >= dia->start && addr < dia->end) {
			found = 1;
			break;
		}
	}

	if (!found)
		return -ENOENT;

	fd = open(dia->dso->long_name, O_RDONLY);
	if (fd < 0)
		return -EINVAL;

	lseek(fd, addr, SEEK_SET);
	if (read(fd, valp, sizeof(*valp)) == -1)
		return -errno;

	close(fd);

	return 0;
}

static int reg_value(unw_word_t *valp, struct user_regs *regs, int id,
		     u64 sample_regs)
{
	int i, idx = 0;

	if (!(sample_regs & (1 << id)))
		return -EINVAL;

	for (i = 0; i < id; i++) {
		if (sample_regs & (1 << i))
			idx++;
	}

	*valp = regs->regs[idx];

	return 0;
}

static int access_mem(unw_addr_space_t __used as,
                      unw_word_t addr, unw_word_t *valp,
                      int __write, void *arg)
{
	struct unwind_info *ui = arg;
	struct user_stack_dump *stack = &ui->sample->stack;
	unw_word_t start, end;
	unw_word_t *val;
	int offset;
	int ret;

	/* Don't support write, probably not needed */
	if (__write || !stack || !ui->sample->uregs.version) {
		*valp = 0;
		return 0;
	}

	ret = reg_value(&start, &ui->sample->uregs, PERF_X86_32_REG_ESP,
			ui->session->sample_uregs);
	if (ret)
		return ret;

	end = start + stack->size;

	ret = access_dwarf_instr(ui, addr, valp);
	if (!ret)
		return 0;

	if (addr < start || addr + sizeof(unw_word_t) >= end) {
		ret = access_dso_mem(ui, addr, valp);
		if (ret) {
			pr_debug("access_mem %p not inside range %p-%p\n",
				(void *)addr, (void *)start, (void *)end);
			*valp = 0;
			return ret;
		}
		return 0;
	}

	offset = addr - start;
	val = (void *)&stack->data[offset];
	*valp = *val;

	pr_debug("access_mem %p %lx\n", (void *)addr, (unsigned long)*valp);

	return 0;
}

static int access_reg(unw_addr_space_t __used as,
                      unw_regnum_t regnum, unw_word_t *valp,
                      int __write, void *arg)
{
	struct unwind_info *ui = arg;
	int id, ret;

	/* Don't support write, I suspect we don't need it */
	if (__write) {
		pr_err("access_reg w %d\n", regnum);
		return 0;
	}

	if (!ui->sample->uregs.version) {
		*valp = 0;
		return 0;
	}

	switch (regnum) {
	case UNW_X86_EAX:
		id = PERF_X86_32_REG_EAX;
		break;
	case UNW_X86_EDX:
		id = PERF_X86_32_REG_EDX;
		break;
	case UNW_X86_ECX:
		id = PERF_X86_32_REG_ECX;
		break;
	case UNW_X86_EBX:
		id = PERF_X86_32_REG_EBX;
		break;
	case UNW_X86_ESI:
		id = PERF_X86_32_REG_ESI;
		break;
	case UNW_X86_EDI:
		id = PERF_X86_32_REG_EDI;
		break;
	case UNW_X86_EBP:
		id = PERF_X86_32_REG_EBP;
		break;
	case UNW_X86_ESP:
		id = PERF_X86_32_REG_ESP;
		break;
	case UNW_X86_EIP:
		id = PERF_X86_32_REG_EIP;
		break;
	default:
		pr_err("can't read reg %d\n", regnum);
		return -EINVAL;
	}

	ret = reg_value(valp, &ui->sample->uregs, id, ui->session->sample_uregs);
	if (ret) {
		pr_err("can't read reg %d\n", regnum);
		return ret;
	}

	pr_debug("reg: %d val: %lx\n", regnum, (unsigned long)*valp);

	return 0;
}

static void put_unwind_info(unw_addr_space_t __used as, unw_proc_info_t *pi,
			    void *arg)
{
	struct unwind_info *ui = arg;
	struct dwarf_instr_addr *dia, *tmp;

	if (pi->unwind_info) {
		free(pi->unwind_info);
		pi->unwind_info = NULL;
	}

	list_for_each_entry_safe(dia, tmp, &ui->dia_head, list) {
		list_del(&dia->list);
		free(dia);
	}
}

static unw_accessors_t accessors = {
	.find_proc_info		= find_proc_info,
	.put_unwind_info	= put_unwind_info,
	.get_dyn_info_list_addr	= get_dyn_info_list_addr,
	.access_mem		= access_mem,
	.access_reg		= access_reg,
	.access_fpreg		= access_fpreg,
	.resume			= resume,
	.get_proc_name		= get_proc_name,
};

static int
append_dwarf_chain(struct dwarf_callchain *callchain,
		   struct addr_location *al)
{
	struct dwarf_callchain_entry *entry;

	entry = calloc(sizeof(*entry), 1);
	if (!entry)
		return -ENOMEM;

	entry->ip = al->addr;
	entry->ms.map = al->map;
	entry->ms.sym = al->sym;

	list_add_tail(&entry->list, &callchain->chain_head);

	callchain->nb++;

	return 0;
}


static void callchain_unwind_release(struct dwarf_callchain *callchain)
{
	struct dwarf_callchain_entry *entry, *tmp;

	list_for_each_entry_safe(entry, tmp, &callchain->chain_head, list) {
		list_del(&entry->list);
		free(entry);
	}

	free(callchain);
}


struct dwarf_callchain *callchain_unwind(struct perf_session *session,
					 struct thread *thread,
					 struct sample_data *data)
{
	struct dwarf_callchain *callchain;
	unw_addr_space_t addr_space;
	struct addr_location al;
	struct unwind_info ui;
	unw_cursor_t c;
	unw_word_t ip;
	int ret;

	if (!data->uregs.version)
		return NULL;

	callchain = malloc(sizeof(*callchain));
	if (!callchain)
		return ERR_PTR(-ENOMEM);

	callchain->nb = 0;
	INIT_LIST_HEAD(&callchain->chain_head);

	ret = reg_value(&ip, &data->uregs, PERF_X86_32_REG_EIP,
			session->sample_uregs);
	if (ret)
		return ERR_PTR(ret);

	thread__find_addr_location(thread, session,
				   PERF_RECORD_MISC_USER,
				   MAP__FUNCTION, thread->pid,
				   ip, &al, NULL);

	ret = append_dwarf_chain(callchain, &al);
	if (ret)
		goto fail;

	memset(&ui, 0, sizeof(ui));
	addr_space = unw_create_addr_space(&accessors, 0);
	if (!addr_space) {
		pr_err("Can't create unwind address space\n");
		goto fail;
	}

	pr_debug("\n----- %s -----\n", al.map ? al.map->dso->long_name : "Unknown");
	ui.sample = data;
	ui.thread = thread;
	ui.session = session;
	INIT_LIST_HEAD(&ui.dia_head);

	ret = unw_init_remote(&c, addr_space, &ui);
	switch (ret) {
	case UNW_EINVAL:
		pr_err("Unwind: only supports local\n");
		break;
	case UNW_EUNSPEC:
		pr_err("Unwind: unspecified error\n");
		break;
	case UNW_EBADREG:
		pr_err("Unwind: register unavailable\n");
		break;
	default:
		break;
	}

	if (ret)
		goto fail_addrspace;

	if (al.sym)
		pr_debug("%s:ip = %llx\n", al.sym->name, al.addr);
	else
		pr_debug("ip = %llx\n", al.addr);

	while (unw_step(&c) > 0) {
		char name[250];
		unsigned int offset;

		unw_get_reg(&c, UNW_REG_IP, &ip);

		thread__find_addr_location(thread, session,
				   PERF_RECORD_MISC_USER,
				   MAP__FUNCTION, thread->pid,
				   ip, &al, NULL);

		unw_get_proc_name(&c, name, sizeof(name), &offset);
		if (al.sym)
			pr_debug("%s:ip = %lx\n", al.sym->name, (unsigned long)ip);
		else
			pr_debug("ip = %lx (%llx)\n", (unsigned long)ip,
					al.map ? al.map->map_ip(al.map, ip) : (u64)ip);

		ret = append_dwarf_chain(callchain, &al);
		if (ret)
			goto fail_addrspace;
	}

	unw_destroy_addr_space(addr_space);

	return callchain;

fail_addrspace:
	unw_destroy_addr_space(addr_space);
fail:
	callchain_unwind_release(callchain);
	return ERR_PTR(ret);
}

#else /* LIBUNWIND_SUPPORT */

struct dwarf_callchain *callchain_unwind(struct perf_session *session __used,
					 struct thread *thread __used,
					 struct sample_data *data __used)
{
	return NULL;
}

#endif
