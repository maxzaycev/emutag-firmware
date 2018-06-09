PROGRAMMER = -c usbasp  # Change these to configure your own programmer

DEVICE     = attiny4313
CFLAGS     = -Wall -Os -mmcu=$(DEVICE) -Wl,--relax
LFLAGS     = -Wl,-Map=main.map,--cref

all: copy
all: disasm
all: size

flash: copy
	avrdude $(PROGRAMMER) -p $(DEVICE) -U flash:w:firmware.bin:r -U eeprom:w:common.eep:r -U efuse:w:0xfe:m -U hfuse:w:0xdf:m -U lfuse:w:0xdf:m

copy: build
	cp tmpl.bin firmware.bin
	dd if=main.bin of=firmware.bin conv=notrunc

flash-only:
	avrdude $(PROGRAMMER) -p $(DEVICE) -U flash:w:firmware.bin:r -U eeprom:w:common.eep:r -U efuse:w:0xfe:m -U hfuse:w:0xdf:m -U lfuse:w:0xdf:m

clean:
	rm -f user.o main.elf main.bin main.lst main.map firmware.bin

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

