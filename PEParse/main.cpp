#include "peparser.h"
#include <assert.h>

int CanShow(char ch) {
	switch (ch) {
	case 0x20:
	case 0x0d:
	case 0x0a:
		return false;
	default:
		return true;
	}
}

void ShowSection(int index) {
	BYTE* position = Section[index];
	size_t size = SectionHeader[index]->SizeOfRawData;
	printf("\nSection [%s]\n", SectionHeader[index]->Name);
	printf("StartPosition : 0x%p\n", position);
	printf("Size: %d\n", size);

	for (size_t i = 0; i < size; i += 16) {
		for (size_t j = i; j < size && j < i + 16; j++) {
			printf("%02x ", position[j]);
			if (j % 8 == 7) printf(" ");
		}
		for (size_t j = i; j < size && j < i + 16; j++) {
			char ch = position[j];
			if (CanShow(ch)) printf("%c", ch);
			else printf(" ");
		}

		printf("\n");
	}
}

int main(int argc, char* argv[]) {
	Parse(argv[0]);
	Show();
}

