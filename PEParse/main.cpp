#include "peparser.h"

using namespace PEParse;

int main(int argc, char* argv[]) {
	PEParser parser = argv[1];
	parser.Show();
	return 0;
}

