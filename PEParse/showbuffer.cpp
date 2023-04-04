#include "peparser.h"

using namespace std;

namespace PEParse {
	void printBuffer(BYTE* buffer, size_t size) {
		for (size_t i = 0; i < size; i += 16) {
			for (size_t j = i; j < size && j < i + 16; j++) {
				printf("%02x ", buffer[j]);
				if (j % 8 == 7) printf(" ");
			}
			for (size_t j = i; j < size && j < i + 16; j++) {
				char ch = buffer[j];
				if (isprint(ch)) tcout << ch << endl;
				else tcout << "." << endl;
			}

			printf("\n");
		}
	}
}