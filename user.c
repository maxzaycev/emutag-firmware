/********************************************************************************************
 **  EMUTAG SDK EXAMPLE FOR ULTRALIGHT EV1 (41 PAGE VERSION) EMULATION WITH AUTH SNIFFING  **
 ********************************************************************************************/

#include <avr/io.h>
#include <avr/pgmspace.h>
#include "main.h"
#include "macros.h"

// commands
#define C_REQA		0x26
#define C_WUPA		0x52
#define C_SEL1		0x93
#define C_SEL2		0x95
#define C_HALT		0x50
#define C_GET_VERSION	0x60
#define C_READ		0x30
#define C_FAST_READ	0x3A
#define C_WRITE		0xA2
#define C_COMPAT_WRITE	0xA0
#define C_READ_CNT	0x39
#define C_INCR_CNT	0xA5
#define C_PWD_AUTH	0x1B
#define C_READ_SIG	0x3C
#define C_CHK_TEAR	0x3E
#define C_VCSL		0x4B

//flash commands
#define FC_READ		0xF0
#define FC_WRITE	0xF1
#define	FC_SHIFT	0xF2

// response constants
#define R_ATQA_H	0x00
#define R_ATQA_L	0x44
#define R_SAK		0x00
#define R_CT		0x88

// 4-bit responses are left-shifted by 4 bits, as data is shifted out left MSB first
#define R_ACK		0xA0
#define R_OVF		0x40
#define R_ERR		0x10
#define R_NAK		0x00

// states
#define S_IDLE		0
#define S_READY1	1
#define S_READY2	2
#define S_ACTIVE	3
#define S_COMPAT_WRITE	4

// block-locking bit positions
#define BL_OTP		0
#define BL_94		1
#define BL_FA		2

// configuration page addresses and page ranges
#define NUM_PAGES	41
#define USR_PAGES_END	36
#define SIG_PAGE0	46
#define SIG_PAGES_END	54
#define P_CNT0		43
#define P_CNT1		44
#define P_CNT2		45
#define P_PACK		(NUM_PAGES - 1)
#define P_PASSWD	(NUM_PAGES - 2)
#define P_CFG1		(NUM_PAGES - 3)
#define P_CFG0		(NUM_PAGES - 4)
#define P_DYNL		(NUM_PAGES - 5)

// configuration byte addresses
#define B_LOCK_L	10
#define B_LOCK_H	11
#define B_DYNL_0	(P_DYNL * 4 + 0)
#define B_DYNL_1	(P_DYNL * 4 + 1)
#define B_DYNL_2	(P_DYNL * 4 + 2)
#define B_MIRROR	(P_CFG0 * 4 + 0)
#define B_AUTH0		(P_CFG0 * 4 + 3)
#define B_ACCESS	(P_CFG1 * 4 + 0)
#define B_VCTID		(P_CFG1 * 4 + 1)

// Flash address of signature page (last page)
#define SIG_ADDR	0x0FC0
//Flash address of Dumps
#define DUMP_1	0x0E40	//3648
#define DUMP_2	0x0F00

// Simulation of write delay to internal EEPROM: 4.1 ms fixed from request
// TIMER0 is counting with prescaler = 1024 with count reset after receiving incoming message
// bitrate = F_CPU / 128, TIMER0 prescaler = 1024, ratio = 8
// 4.1 ms / (9 bit char / bitrate) = 48 byte frames
// (48 frames * 9 - 3 (turnaround bit buffer compensation)) / 8 = 53 timer counts
#define WRITE_DELAY	53

// registers contents are saved between function calls, except for shared registers
register volatile uint8_t state    asm("r6");
register volatile uint8_t lock_b0  asm("r7");
register volatile uint8_t lock_b1  asm("r8");
register volatile uint8_t lock_b2  asm("r9");
register volatile uint8_t lock_b3  asm("r10");
register volatile uint8_t lock_b4  asm("r11");

register volatile uint8_t flash_state  asm("r12");
#define NEED_WRITE	7
#define NEED_READ	6

// To save registers, lock switch position will be stored in MSB of lock_b4 containing BL-bits for pages 16-39
#define lock_sw		lock_b4
#define LOCK_SW_BIT	7

// To save registers, authentication state will be stored in bit 6 of lock_b4 containing BL-bits for pages 16-39
#define state_auth	lock_b4
#define S_AUTH_BIT	6

const uint8_t perm_tab[8]  PROGMEM = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}; // used by write_perm()
const uint8_t ntag_ver[8]  PROGMEM = {0x00, 0x04, 0x03, 0x01, 0x01, 0x00, 0x0E, 0x03}; // used by GET_VERSION command

uint8_t mem_array[NUM_PAGES * 4]; // namely the memory storage array
uint8_t passwd[6]; // passwd and passwd-ack backup fields concatenated
uint8_t cnt0[3], cnt1[3], cnt2[3]; // one-way counters
uint8_t sig_pages; // each bit marks if each 4-byte page of tag signature has been loaded into Flash page buffer
uint8_t wrap;  // mem_array page where READ and FAST_READ functions end, updated on REQA/WUPA and PWD_AUTH
uint8_t auth0; // mem_array page from which WRITE and COMPAT_WRITE functions are restricted in locked mode, updated on REQA/WUPA and PWD_AUTH

uint8_t passwd_tries, passwd_limit; // passwd_limit is updated on REQA/WUPA
#define NWR_NFC_CNT	7
#define NWR_AUTH_CNT	6
#define SNIFF_MODE_1	5
#define SNIFF_MODE_0	4

// HACK: pwr_flags also holds SNIFF_MODE bits, which are updated immediately
uint8_t pwr_flags; // updated on power cycle
#define CFG_READONLY	6

//uint8_t prot_rd; // updated on REQA/WUPA
#define AUTH_PROT_RD	7

/* FUNCTIONS */

// WARNING! call next two defined functions only from user_proc() to keep minimum stack depth
#define reply_std_frame(ptr, len)  reply(ptr, 0, len); return
#define reply_status(status)  reply_status_noret(status); return

void reply_status_noret(uint8_t status) __attribute__((noinline));
void reply_status_noret(uint8_t status) {
	if(status != R_ACK) state = S_IDLE;
	rx_buf[0] = status;
	ctrl_flags |= 1 << F_TX_CRC_OFF | 1 << F_TX_PAR_OFF;
	reply(rx_buf, 4, 1);
}

/*  user_init() : Called from main code once at boot time. Can be used to initialize memory.
 *              : This function is required to be present. Leave empty if not used.
 */
void user_init(void);

/*  user_pwr_cycle() : Called from main code at boot time and when carrier is lost for >100 usec. Can be used to reset tag state.
 *                   : This function is required to be present. Leave empty if not used.
 */
void user_pwr_cycle(void);

/*  user_frame_end() : Called from main code after optionally sending response frame.
 *                   : Can be used for operations longer than frame response timeout, such as writing Flash or EEPROM.
 *                   : This function is required to be present. Leave empty if not used. Keep as short as possible in locked mode.
 */
void user_frame_end(void);

/*  user_proc() : Called from main code when an incoming message has been received and stored in rx_buf[].
 *
 *  rx_bytes      = number of complete bytes stored in rx_buf[]
 *  rx_bits       = number of additional bits received if the last byte is incomplete
 *  rx_bits_total = rx_bytes * 9 + rx_bits, cached for faster comparisons
 *  __attribute__((OS_main)) tells the compiler not to save any registers on stack, as main code reloads everything
 */
void user_proc(uint8_t rx_bytes, uint8_t rx_bits, uint8_t rx_bits_total) __attribute__((OS_main));

/*  write_data() : Performs common block for WRITE and COMPATIBILITY_WRITE commands.
 *
 *  page = number of 4-byte block in memory which needs to be written with incoming data
 *  src  = offset in rx_buf[] to start transferring data from
 *  returns status code for reply
 */
uint8_t write_data(uint8_t page, uint8_t src);

/*  buf_save() : Writes bytes from rx_buf[] to mem_array[] in WRITE or COMPATIBILITY_WRITE commands.
 *             : Data is transferred according to rules defined in MIFARE Ultralight write access conditions.
 *             : E.g. page 3 (OTP) is OR'ed with incoming data in locked mode, and overwritten in unlocked mode.
 *
 *  page = number of 4-byte block in memory which needs to be written with incoming data
 *  src  = offset in rx_buf[] to start transferring data from
 */
void buf_save(uint8_t page, uint8_t src);

/*  buf_cmp() : Compares bytes and bits in rx_buf[] from offsets 2 and 10 during anticollision.
 *
 *  len  = total number of complete bytes in rx_buf[] before offset 10
 *  bits = number of additional bits in rx_buf[]
 *  returns 0 if all bits of partial UID match in rx_buf[2] and rx_buf[10], 1 otherwise
 */
uint8_t buf_cmp(uint8_t *src_ptr, uint8_t *dst_ptr, uint8_t len, uint8_t bits) __attribute__((noinline));

void prepare_read(void) __attribute__((noinline));

void user_init(void) {
	uint8_t *asm_dst, asm_len; // for macro
	
	FILL_BUF(passwd, 0xFF, 4);
	
	lock_b0 = lock_b1 = lock_b2 = lock_b3 = lock_b4 = 0;

	asm volatile(
		"in	r24, %1		\n\t"
		"bst	r24, %2		\n\t"
		"bld	%0, %3		\n\t"
		"bld	%0, %4		\n\t"
		"ldi	r24, %5		\n\t"
		"eor	%0, r24		\n\t" // invert S_AUTH_BIT in lock_b4 (same as lock_sw and state_auth)
		: "=r" (lock_sw)
		: "I" (_SFR_IO_ADDR(LOCK_PORT)), "I" (LOCK_PIN),
			"I" (LOCK_SW_BIT), "I" (S_AUTH_BIT), "M" (1 << S_AUTH_BIT), "0" (lock_sw)
		: "r24"
	);

	memcpy_P (mem_array, (PGM_VOID_P*) ((lock_sw & 1 << LOCK_SW_BIT) ? DUMP_1 : DUMP_2), NUM_PAGES*4);
	user_pwr_cycle();
}

void user_pwr_cycle(void) {
	state = S_IDLE;
	ctrl_flags &= ~(1 << F_ST_HALT);

	if(flash_state & 1 << NEED_WRITE){
		uint8_t *asm_src =  mem_array; // for macro

		asm volatile(
			"ldi	r28, 3		\n\t"
			"ldi	r24, 3		\n\t" // Flash erase command = 00000011
			"out	%1, r24		\n\t"
			"spm			\n\t"
			"cli			\n\t"  // r1 is cleared by interrupt
			"ldi	r24, 1		\n\t" // Flash buffer fill command = 00000001
			"ld	r0, X+		\n\t"
			"ld	r1, X+		\n\t"
			"out	%1, r24		\n\t"
			"spm			\n\t"
			"adiw	r30, 2		\n\t"
			"ldi	r25, 63		\n\t"
			"and	r25, r30		\n\t"
			"brne	.-16		\n\t"
			"sei			\n\t"
			"clr	r1		\n\t"
			"sbiw	r30, 32		\n\t"
			"sbiw	r30, 32		\n\t"
			"ldi	r24, 5		\n\t" // Flash write command = 00000101
			"out	%1, r24		\n\t"
			"spm			\n\t"
			"adiw	r30, 32		\n\t"
			"adiw	r30, 32		\n\t"
			"dec	r28		\n\t"
			"brne	.-48		\n\t"
			: "=x" (asm_src)
			: "I" (_SFR_IO_ADDR(SPMCSR)), "0" (asm_src), "z" (((lock_sw & 1 << LOCK_SW_BIT) ? DUMP_1 : DUMP_2))
			: "r0", "r24", "r25", "r28"
		);

		flash_state &= ~(1 << NEED_WRITE);
	}

	sig_pages = 0;
	SPMCSR = 1 << CTPB; // clear Flash page buffer

	//pwr_flags = mem_array[B_ACCESS] & 1 << CFG_READONLY;
	COPY_BIT(pwr_flags, mem_array[B_ACCESS], CFG_READONLY);
}

void user_frame_end(void) {
	if(sig_pages == 0xff) {
		// erase Flash page and write values from page buffer
		asm volatile(
			"ldi	r24, 3		\n\t" // Flash erase command = 00000011
			"out	%0, r24		\n\t"
			"spm			\n\t"
			"ldi	r24, 5		\n\t" // Flash write command = 00000101
			"out	%0, r24		\n\t"
			"spm			\n\t"
			: : "I" (_SFR_IO_ADDR(SPMCSR)), "z" (SIG_ADDR)
			  : "r24"
		);
		
		sig_pages = 0;
		SPMCSR = 1 << CTPB; // clear Flash page buffer
	}
}

void user_proc(uint8_t rx_bytes, uint8_t rx_bits, uint8_t rx_bits_total) {
	uint8_t *asm_dst, *asm_src, asm_len; // for macro
	
	uint8_t op, arg, i, old_state;
	static uint8_t compat_wr_addr;
	
	if(ctrl_flags & 1 << F_RX_CHR_ERR) return;
	if(ctrl_flags & 1 << F_RX_OVF_ERR) return;
	
	// COMPATIBILITY_WRITE command consists of 2 request/response frames, need to save as special state
	if(state == S_COMPAT_WRITE) {
		state = S_ACTIVE; // TODO: determine using NFC Shell how state is handled with errors in 2nd part of COMPAT_WRITE command
		
		if(rx_bits) return;
		if(rx_bytes != 18) return;
		
		if((ctrl_flags & 1 << F_RX_PAR_ERR) || crc_chk(rx_bytes)) { reply_status(R_ERR);                         }
		else                                                      { reply_status(write_data(compat_wr_addr, 0)); }
	}
	
	// other commands or first part of COMPATIBILITY_WRITE command
	else {
		op = rx_buf[0];
		
		// REQA / WUPA frames
		if(rx_bits_total == 7) {
			if(op == C_REQA || op == C_WUPA) {
				if(state == S_IDLE && (op == C_WUPA || (~ctrl_flags & 1 << F_ST_HALT))) {
					// strobe lock switch position into shared register's bit and initialize state_auth
					asm volatile(
						"in	r24, %1		\n\t"
						"bst	r24, %2		\n\t"
						"bld	%0, %3		\n\t"
						"bld	%0, %4		\n\t"
						"ldi	r24, %5		\n\t"
						"eor	%0, r24		\n\t" // invert S_AUTH_BIT in lock_b4 (same as lock_sw and state_auth)
						: "=r" (lock_sw)
						: "I" (_SFR_IO_ADDR(LOCK_PORT)), "I" (LOCK_PIN),
						  "I" (LOCK_SW_BIT), "I" (S_AUTH_BIT), "M" (1 << S_AUTH_BIT), "0" (lock_sw)
						: "r24"
					);
					//asm volatile("in %0, %1" : "=r" (lock_sw) : "I" (_SFR_IO_ADDR(LOCK_PORT)));
					
					//state_auth = (lock_sw & 1 << LOCK_SW_BIT) ? 0 : 1;
					
					i = mem_array[B_ACCESS];
					passwd_limit = i & 7;
					//prot_rd = i & 1 << AUTH_PROT_RD;
					auth0 = mem_array[B_AUTH0];
					
					if((state_auth & 1 << S_AUTH_BIT) || (~i & 1 << AUTH_PROT_RD)) {
						wrap = NUM_PAGES;
					}
					else {
						i = mem_array[B_AUTH0];
						
						if(i > NUM_PAGES) i = NUM_PAGES;
						wrap = i;
					}
					
					state = S_READY1;
					rx_buf[0] = R_ATQA_L;
					rx_buf[1] = R_ATQA_H;
					ctrl_flags |= 1 << F_TX_CRC_OFF;
					reply_std_frame(rx_buf, 2);
				}
				else state = S_IDLE;
			}
			else return;
		}
		
		if(rx_bits_total < 18) return;
		
		// other frames
		if(ctrl_flags & 1 << F_RX_PAR_ERR) { reply_status(R_ERR); }
		
		arg = rx_buf[1];
		
		// ANTICOLLISION / SELECT commands using anticollision frames
		if(op == C_SEL1 || op == C_SEL2) {
			if(arg == 0x70) {
				if(crc_chk(rx_bytes)) { reply_status(R_ERR); }
				rx_bytes -= 2;
			}
			
			// Check NVB for valid range
			if(arg & 8) return;
			if(arg < 0x20 || arg > 0x70) return;
			
			// Check NVB against actual data length
			if((arg >> 4) != rx_bytes) return;
			if((arg & 0x0f) != rx_bits) return;
			
			old_state = state;
			state = S_IDLE;
			
			if(op == C_SEL1) {
				rx_buf[10] = R_CT;
				COPY_BUF(rx_buf+11, mem_array+0, 4); // extract R_CT UID0 UID1 UID2 BCC0
			}
			else {
				COPY_BUF(rx_buf+10, mem_array+4, 5); // extract UID3 UID4 UID5 UID6 BCC1
			}
			
			if(buf_cmp(rx_buf+2, rx_buf+10, rx_bytes-2, rx_bits)) return;
			
			if(old_state == S_READY2 || (old_state == S_READY1 && op == C_SEL1)) {
				state = old_state;
				if(arg == 0x70) {
					state++;
					if(op == C_SEL1) rx_buf[0] = R_SAK | 0x04; // cascade bit
					else             rx_buf[0] = R_SAK;
					reply_std_frame(rx_buf, 1);
				}
				else {
					ctrl_flags |= 1 << F_TX_CRC_OFF;
					reply(rx_buf+8+rx_bytes, rx_bits, 7-rx_bytes); return;
				}
			}
		}
		
		// other commands using standard frames
		else {
			if(rx_bits) return;
			if(crc_chk(rx_bytes)) { reply_status(R_ERR); }
			rx_bytes -= 2;
			
			if(op == C_READ) {
				if(rx_bytes != 2) return;
				old_state = state;
				state = S_IDLE;
				
				if(arg < wrap && ((!arg && old_state != S_IDLE) || (old_state == S_ACTIVE))) {
					state = S_ACTIVE;
					
					prepare_read();
					
					arg <<= 2;
					i = 16;
					asm_src = mem_array + arg;
					asm_dst = rx_buf;
					while(i) {
						*asm_dst++ = *asm_src++;
						if(asm_src == mem_array + (uint8_t)(wrap << 2)) asm_src = mem_array;
						asm volatile("dec %0" : "=r" (i) : "0" (i)); // speed up copying using assembler...
					}
					
					reply_std_frame(rx_buf, 16);
				}
				else if(arg >= wrap && old_state == S_ACTIVE) { reply_status(R_NAK); }
			}
			
			if(op == C_HALT) {
				if(rx_bytes != 2) return;
				if(arg) return;
				if(state == S_ACTIVE) ctrl_flags |= 1 << F_ST_HALT;
				state = S_IDLE; // will return anyway from state check below
			}
			
			if(state != S_ACTIVE) {
				state = S_IDLE;
				return;
			}
			
			if(op == C_WRITE || op == C_COMPAT_WRITE) {
				if(op == C_WRITE) i = 6;
				else              i = 2;
				
				if(rx_bytes != i) return;
				
				if((arg < NUM_PAGES) || (arg >= P_CNT0 && arg < SIG_PAGES_END)) {
					if(op == C_WRITE) {
						reply_status(write_data(arg, 2));
					}
					else {
						state = S_COMPAT_WRITE;
						compat_wr_addr = arg;
						reply_status(R_ACK);
					}
				}
				else { reply_status(R_NAK); }
			}
			
			if(op == C_FAST_READ) {
				if(rx_bytes != 3) return;
				i = rx_buf[2];
				if(i < arg || i >= wrap) { reply_status(R_NAK); }
				
				prepare_read();
				
				reply_std_frame(mem_array + (uint8_t)(arg << 2), (i - arg + 1) << 2);
			}
			
			if(op == C_PWD_AUTH) {
				if(rx_bytes != 5) return;
				
				if(pwr_flags & 3 << SNIFF_MODE_0) {
					COPY_BUF(passwd, rx_buf+1, 4);
				}
				
				if(pwr_flags & 1 << SNIFF_MODE_1) { rx_buf[4] = ~rx_buf[4]; }
				
				if(passwd_limit) {
					if(passwd_tries > passwd_limit) { reply_status(R_OVF); }
					
					if(buf_cmp(rx_buf+1, passwd, 4, 0)) {
						if(~pwr_flags & 1 << SNIFF_MODE_1) { passwd_tries++; }
						state = S_IDLE;
						return; // failed auth apparently replies with timeout
					}
					
					passwd_tries = 0;
				}
				else {
					if(buf_cmp(rx_buf+1, passwd, 4, 0)) {
						state = S_IDLE;
						return; // failed auth apparently replies with timeout
					}
				}
				
				state_auth |= 1 << S_AUTH_BIT;
				wrap = NUM_PAGES;
				
				reply_std_frame(passwd+4, 2);
			}
			
			if(op == C_INCR_CNT) {
				if(rx_bytes != 6) return;
				
				if(arg < 2) {
					if(!arg)     { asm_dst = cnt0;      }
					else         { asm_dst = cnt1;      }
				}
				else {
					if(arg == 2) { asm_dst = cnt2;      }
					else         { reply_status(R_NAK); }
				}
				
				asm_src = rx_buf + 2;
				asm_len = 0; // asm_len will be used to store success/failure of increment
				asm volatile(
					"ld	r24, X+		\n\t"
					"ld	r25, X+		\n\t"
					"ld	r28, X+		\n\t"
					"ld	r29, Z+		\n\t"
					"add	r24, r29	\n\t"
					"ld	r29, Z+		\n\t"
					"adc	r25, r29	\n\t"
					"ld	r29, Z+		\n\t"
					"adc	r28, r29	\n\t"
					"brcs	.+8		\n\t" // if overflow, skip store and status change to success
					"st	-X, r28		\n\t"
					"st	-X, r25		\n\t"
					"st	-X, r24		\n\t"
					"inc	%2		\n\t"
					: "=x" (asm_dst), "=z" (asm_src), "=r" (asm_len)
					: "0"  (asm_dst), "1"  (asm_src), "2"  (asm_len)
					: "r24", "r25", "r28", "r29"
				);
				
				if(asm_len) { reply_status(R_ACK); }
				else        { reply_status(R_OVF); }
			}
			
			if(op == C_READ_CNT) {
				if(rx_bytes != 2) return;
				
				if(arg < 2) {
					if(!arg)     { reply_std_frame(cnt0, 3); }
					else         { reply_std_frame(cnt1, 3); }
				}
				else {
					if(arg == 2) { reply_std_frame(cnt2, 3); }
					else         { reply_status(R_NAK);      }
				}
			}
			
			if(op == C_CHK_TEAR) {
				if(rx_bytes != 2) return;
				if(arg > 2) { reply_status(R_NAK); }
				
				rx_buf[0] = 0xBD;
				reply_std_frame(rx_buf, 1);
			}
			
			if(op == C_VCSL) {
				if(rx_bytes != 21) return;
				
				reply_std_frame(mem_array + B_VCTID, 1);
			}
			
			if(op == C_READ_SIG) {
				if(rx_bytes != 2) return;
				if(arg) { reply_status(R_NAK); }
				
				reply_std_frame((uint8_t*)(SIG_ADDR | 0x8000), 32); // address with MSB set: read from Flash
			}
			
			if(op == C_GET_VERSION) {
				if(rx_bytes != 1) return;
				
				reply_std_frame((uint8_t*)((uint16_t)(&ntag_ver) | 0x8000), 8); // read from Flash
			}

			if(op == FC_WRITE){
				flash_state |= 1 << NEED_WRITE;
				reply_status(R_ACK);
			}

			if(op == FC_READ){
				memcpy_P (mem_array, (PGM_VOID_P*) ((lock_sw & 1 << LOCK_SW_BIT) ? DUMP_1 : DUMP_2), NUM_PAGES*4);
				reply_status(R_ACK);
			}
		}
	}
}

uint8_t write_data(uint8_t page, uint8_t src) {
	uint8_t *asm_dst, *asm_src, asm_len; // for macro
	
	uint8_t *cnt_num;
	uint8_t msb;
	
	if(page == 1 && rx_buf[src] == R_CT) {
		// prevent storing cascade tag in UID3
		// Level 3 (10-byte) UIDs not supported
		return R_NAK;
	}
	else if(page >= SIG_PAGE0) {
		page -= SIG_PAGE0;
		if(sig_pages & pgm_read_byte(&(perm_tab[page]))) return R_ACK;
		sig_pages |= pgm_read_byte(&(perm_tab[page]));
		page <<= 2;
		
		// fill Flash buffer with 4 bytes
		asm_src = rx_buf + src;
		asm volatile(
			"ldi	r24, 1		\n\t" // Flash buffer fill command = 00000001
			"ld	r0, X+		\n\t"
			"cli			\n\t"
			"ld	r1, X+		\n\t" // r1 is cleared by interrupt
			"out	%1, r24		\n\t"
			"sei			\n\t"
			"spm			\n\t"
			"ori	r30, 2		\n\t" // next Flash address
			"ld	r0, X+		\n\t"
			"cli			\n\t"
			"ld	r1, X+		\n\t" // r1 is cleared by interrupt
			"out	%1, r24		\n\t"
			"sei			\n\t"
			"spm			\n\t"
			"clr	r1		\n\t"
			: "=x" (asm_src)
			: "I"  (_SFR_IO_ADDR(SPMCSR)), "0" (asm_src), "z" (SIG_ADDR+page)
			: "r0", "r24"
		);
	}
	else if(page >= NUM_PAGES) {
		if(page < P_CNT2) {
			if(page == P_CNT0) cnt_num = cnt0;
			else               cnt_num = cnt1;
			COPY_BUF(cnt_num, rx_buf+src, 3);
		}
		else {
			msb = rx_buf[src+3];
			if(~msb & 1 << NWR_NFC_CNT)  { COPY_BUF(cnt2, rx_buf+src, 3); }
			if(~msb & 1 << NWR_AUTH_CNT) { passwd_tries = msb & 0x0f; }
			
			msb &= 3 << SNIFF_MODE_0;
			if(msb) {
				if(msb == 3 << SNIFF_MODE_0) { msb = 0; }
				COPY_BIT(pwr_flags, msb, SNIFF_MODE_0);
				COPY_BIT(pwr_flags, msb, SNIFF_MODE_1);
			}
		}
	}
	else { buf_save(page, src); }
	
	return R_ACK;
}

void buf_save(uint8_t page, uint8_t src) {
	uint8_t *dst_ptr, *src_ptr;
	dst_ptr = mem_array + (uint8_t)(page << 2);
	src_ptr = rx_buf + src;
	
	uint8_t src0;
	uint8_t src1;
	uint8_t src2;
	uint8_t src3;
	
	// force load registers using X pointer to keep Z pointer free for LDD instructions
	asm volatile(
		"ld	%0, X+		\n\t"
		"ld	%1, X+		\n\t"
		"ld	%2, X+		\n\t"
		"ld	%3, X+		\n\t"
		: "=r" (src0), "=r" (src1), "=r" (src2), "=r" (src3), "=x" (src_ptr)
		: "4"  (src_ptr)
	);
	
	if(page == 2) { src0 = *(dst_ptr+0); } // do not update BCC1
	
	// recompute BCC0 and BCC1
	if(page == 0)  src3 = R_CT ^ src0 ^ src1 ^ src2;
	if(page == 1) *(dst_ptr+4) = src0 ^ src1 ^ src2 ^ src3;
	
	// store
	*(dst_ptr+0) = src0;
	*(dst_ptr+1) = src1;
	*(dst_ptr+2) = src2;
	*(dst_ptr+3) = src3;
	
	// update passwd
	if(page == P_PASSWD) {
		dst_ptr = passwd;
		asm volatile(
			"st	X+, %1		\n\t"
			"st	X+, %2		\n\t"
			"st	X+, %3		\n\t"
			"st	X+, %4		\n\t"
			: "=x" (dst_ptr)
			: "r"  (src0), "r" (src1), "r" (src2), "r" (src3), "0" (dst_ptr)
		);
	}
	
	// update passwd-ack
	if(page == P_PACK) {
		dst_ptr = passwd + 4;
		asm volatile(
			"st	X+, %1		\n\t"
			"st	X+, %2		\n\t"
			: "=x" (dst_ptr)
			: "r"  (src0), "r" (src1), "0" (dst_ptr)
		);
	}
	
	while(TCNT0 < WRITE_DELAY);
}

uint8_t buf_cmp(uint8_t *src_ptr, uint8_t *dst_ptr, uint8_t len, uint8_t bits) {
	uint8_t tmp1, tmp2, mask = 0xff;
	
	// speed up comparison using assembler...
	while(len) {
		asm volatile("ld %0, X+" : "=r" (tmp1), "=x" (src_ptr) : "1" (src_ptr));
		asm volatile("ld %0, Z+" : "=r" (tmp2), "=z" (dst_ptr) : "1" (dst_ptr));
		if(tmp1 != tmp2) return 1;
		asm volatile("dec %0" : "=r" (len) : "0" (len));
	}
	
	// replace default implementation of shifting by multiple bits:
	// mask <<= bits;
	// assembler code replaces default loop of 4 instructions with loop of 3 instructions
	asm volatile(
		"and	%2, %2	\n\t"
		"breq	.+6	\n\t"
		"add	%0, %0	\n\t"
		"dec	%2	\n\t"
		"brne	.-6	\n\t"
		: "=r" (mask)
		: "0"  (mask), "r" (bits)
	);
	
	if((*dst_ptr | mask) != (*src_ptr | mask)) return 1;
	
	return 0;
}

void prepare_read(void) {
	uint8_t *asm_dst, *asm_src, asm_len; // for macro
	
	if(lock_sw & 1 << LOCK_SW_BIT) {
		FILL_BUF(mem_array + P_PASSWD * 4, 0, 6);
	}
	else {
		COPY_BUF(mem_array + P_PASSWD * 4, passwd, 6);
	}
}

