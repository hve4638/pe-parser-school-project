#include "PEParser.h"
#include "PEPrinter.h"
#include "PEUtils.h"
#include "ReserveDelete.h"
#include "HashMD5Utils.h"
#include "HashMD5Utils.h"

using namespace PEParse;
using namespace PELog;
using namespace PEUtils;

int main(int argc, char* argv[]) {
    auto md5 = new HashMD5Utils();
    {
        HashMD5Use use = md5.use();
    }


    PEParser parser;
    PEPrinter printer;
    auto path = _T("C:\\Users\\hve46\\Documents\\Project\\main\\pe-parser-school-project\\KeyHook86.dll");
    //auto path = _T("C:\\Users\\hve46\\Documents\\project\\git\\pe-parser-school-project\\HEMacro.dll");
    //auto path = _T("C:\\Windows\\System32\\shell32.dll");

    parser.parsePEFile(path);
    const PEStructure pe = parser.getPEStructure();

    printer.printPEStructure(pe);


	return 0;
}