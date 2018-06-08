PROGRAMMER = -c usbasp  # Change these to configure your own programmer

DEVICE     = attiny4313
CFLAGS     = -Wall -Os -mmcu=$(DEVICE) -Wl,--relax
LFLAGS     = -Wl,-Map=main.map,--cref

all: build
all: disasm
all: size

flash: build
	avrdude $(PROGRAMMER) -p $(DEVICE) -U flash:w:main.bin:r -U eeprom:w:common.eep:r -U efuse:w:0xfe:m -U hfuse:w:0xdf:m -U lfuse:w:0xdf:m

flash-only:
	avrdude $(PROGRAMMER) -p $(DEVICE) -U flash:w:main.bin:r -U eeprom:w:common.eep:r -U efuse:w:0xfe:m -U hfuse:w:0xdf:m -U lfuse:w:0xdf:m

clean:
	rm -f user.o main.elf main.bin main.lst main.map

compile:
	avr-gcc -c $(CFLAGS) -o user.o user.c

link: compile
	avr-gcc $(CFLAGS) $(LFLAGS) -o main.elf main-lowpwr.o user.o

build: link
	avr-objcopy -O binary main.elf main.bin

disasm: link
	avr-objdump -d main.elf > main.lst

size: link
	avr-size -C --mcu=$(DEVICE) main.elf

