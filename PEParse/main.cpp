#include "peparser.h"

using namespace PEParse;

int main(int argc, char* argv[]) {
	PEParser parser = argv[1];
	parser.show();
	return 0;
}