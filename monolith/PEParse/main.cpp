#include "PEParser.h"
#include "PEPrinter.h"
#include "PEUtils.h"
#include "ReserveDelete.h"
#include "HashMD5Utils.h"

using namespace PEParse;
using namespace PELog;
using namespace PEUtils;

int _tmain(int argc, TCHAR* argv[]) {
    setlocale(LC_ALL, "");
    PEParser parser;
    PEPrinter printer;
    auto path = _T("C:\\Users\\hve46\\Documents\\project\\git\\pe-parser\\DetectMe.exe");
    //auto path = _T("C:\\Users\\hve46\\Documents\\project\\git\\pe-parser-school-project\\HEMacro.dll");
    //auto path = _T("C:\\Windows\\System32\\shell32.dll");

    parser.parsePEFile(path);

    auto pe = parser.getPEStructure();
    printer.reset(pe);
    //printer.printPEStructure();
    
    tstring hash;
    parser.tryGetSectionHash(_T(".text"), hash);
    tcout << "hash: " << hash << endl;

    hash.clear();
    parser.tryGetEntryPointSectionHash(hash);
    tcout << "hash: " << hash << endl;

    hash.clear();
    parser.tryGetPDBFilePathHash(hash);
    tcout << "hash: " << hash << endl;


	return 0;
}