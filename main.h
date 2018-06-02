/***********************************
 **  EMUTAG SDK MAIN HEADER FILE  **
 ***********************************/

#define F_CPU		13560000

#define nop()	__asm__ __volatile__("nop")

/* LOCK SWITCH */
#define LOCK_PORT	PIND
#define LOCK_PIN	PD4

/* CONTROL & STATUS FLAGS used to pass conditions to and from user code */
register volatile uint8_t ctrl_flags asm("r16");
#define F_RX_CHR_ERR	0
// Bit 0 becomes set if collision or field loss is detected (2 consecutive gaps in carrier in 1 Manchester-encoded bit).
#define F_RX_OVF_ERR	1
// Bit 1 becomes set if the incoming message is longer than 207 bits (23 data bytes) to indicate overflow.
#define F_RX_PAR_ERR	2
// Bit 2 becomes set if any of the received characters contains a parity error.
#define F_RESERVED_0	3
// Reserved for internal operations of main code. Do not write.
#define F_TX_CRC_OFF	4
// Set bit 4 to disable automatic calculation of response CRC and appending it to the response. Set bit 4 to send "as is".
// CRC is calculated and sent "on-the-fly" since SDK v3 and no longer needs 2 bytes at the end of the buffer.
#define F_TX_PAR_OFF	5
// Set bit 5 to disable transmission of parity bits after EVERY message byte. Clear bit 5 to transmit parity bits.
#define F_ST_HALT	6
// Bit 6 is automatically cleared when a loss of carrier field is detected for >100 usec.
#define F_RESERVED_1	7
// Reserved for internal operations of main code. Do not write.
// Bits 0 - 2 and 4 - 5 are automatically cleared every time before user_proc() is called.

/* RESERVED REGISTERS, DO NOT WRITE */
register volatile uint8_t _reserved_0 asm("r2");
register volatile uint8_t _reserved_1 asm("r3");
register volatile uint8_t _reserved_2 asm("r4");
register volatile uint8_t _reserved_3 asm("r5");
/* ALSO, DO NOT WRITE r0, r1, r18-r31, as they are often used by avr-gcc */

/* RECEIVE BUFFER: may be also used to transmit reply message */
/* The longest command VCSL (0x4B) in EV1 is 21 bytes + 2 bytes CRC */
/* DO NOT CHANGE this, as it's hard-coded in main.o for overflow check */
#define RX_BUF_SIZE	23
extern uint8_t rx_buf[RX_BUF_SIZE];

/* FUNCTIONS */

/*  crc_chk() : Used to check CRC of received message.
 *
 *  end = length of message in rx_buf[] including CRC
 *  returns 0 if CRC is correct, 1 otherwise
 */
extern uint8_t crc_chk(uint8_t end);

/*  reply() : Used to send a response to NFC reader.
 *          : If nothing needs to be transmitted, since SDK v3 the function user_proc() can simply return.
 *          : If reply() is called more than once, only the first instance will execute and others ignored.
 *
 *  tx_start = pointer to first byte to transmit from a user-defined array
               MSB of tx_start selects memory type to read from: 0 = RAM, 1 = Flash
 *  tx_bits  = if non-zero, the number of bits to transmit from the first byte by left-shifting them out
 *  tx_len   = number of bytes transmit from a user-defined array
 *
 *  NOTE: since SDK v3, this function no longer trashes the source array by appending CRC
 */
extern void reply(uint8_t* tx_start, uint8_t tx_bits, uint8_t tx_len);

