/* ASSEMBLER MACROS */

#define COPY_BIT(dst, src, bit)					\
	__asm__ __volatile__ (					\
		"bst	%2, %3			\n\t"		\
		"bld	%0, %3			\n\t"		\
		: "=r" (dst)					\
		: "0" (dst), "r" (src), "I" (bit)		\
	)

#define COPY_BUF(dst, src, len)					\
	asm_dst = dst;						\
	asm_src = src;						\
	asm_len = len;						\
	do {							\
		asm volatile(					\
			"ld	r24, Z+		\n\t"		\
			"st	X+, r24		\n\t"		\
			: "=x" (asm_dst), "=z" (asm_src)	\
			: "0"  (asm_dst), "1"  (asm_src)	\
			: "r24"					\
		);						\
	} while(--asm_len)

#define XCHG_BUF(dst, src, len)					\
	asm_dst = dst;						\
	asm_src = src;						\
	asm_len = len;						\
	do {							\
		asm volatile(					\
			"ld	r25, Z		\n\t"		\
			"ld	r24, X		\n\t"		\
			"st	Z+, r24		\n\t"		\
			"st	X+, r25		\n\t"		\
			: "=x" (asm_dst), "=z" (asm_src)	\
			: "0"  (asm_dst), "1"  (asm_src)	\
			: "r24", "r25"				\
		);						\
	} while(--asm_len)

#define FILL_BUF(dst, val, len)					\
	asm_dst = dst;						\
	asm_len = len;						\
	do {							\
		asm volatile(					\
			"st	X+, %2		\n\t"		\
			: "=x" (asm_dst)			\
			: "0"  (asm_dst), "r" ((uint8_t)(val))	\
		);						\
	} while(--asm_len)

