/* Generated by Malelficus */


unsigned char shellcode[] = 
			"\xba\x19\x00\x00\x00\x6a\x0a\x68\x20\x21"
			"\x21\x21\x68\x20\x41\x4d\x4f\x68\x55\x20"
			"\x54\x45\x68\x41\x2c\x20\x45\x68\x49\x45"
			"\x4c\x4c\x68\x47\x41\x42\x52\x89\xe1\xbb"
			"\x01\x00\x00\x00\xb8\x04\x00\x00\x00\xcd"
			"\x80\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x31\xc0"
			"\x31\xdb\x31\xc9\x31\xd2"

			/* mov eax, XXXX */
			"\xb8\x00\x00\x00\x00"
			/* jmp eax */
			"\xff\xe0";

unsigned int patch_offset = 67;

