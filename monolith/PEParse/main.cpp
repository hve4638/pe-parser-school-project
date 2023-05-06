#include "PEParser.h"
#include "PEPrinter.h"
#include "PEUtils.h"
#include "ReserveDelete.h"
#include "HashMD5Utils.h"
#include "TCharArgs.h"
#include "TStringArgs.h"
#include <map>
#include "CommandNode.h"
#include "CommandLineParser.h"
#include "PECommandLineParser.h"

using namespace CommandLineUtils;
using namespace PEParse;
using namespace PELog;
using namespace PEUtils;

void testPE();
int _tmain(int argc, TCHAR* argv[]) {
    setlocale(LC_ALL, "");
    PECommandLineParser cmdRunner;

    auto args = makeArgs(_T("scan file C:\\Temp\\DetectMe.exe 60754a02d83c8dca4384b1f2bdeb86a8"));
    cmdRunner.runCommand(args);

    args.reset();
    args = makeArgs(_T("scan file  C:\\Temp\\DetectMe.exe 26978c26dfd84a5645d0190214bbada7"));
    cmdRunner.runCommand(args);

    args.reset();
    //args = makeArgs(_T("print file C:\\Temp\\DetectMe.exe"));
    //cmdRunner.runCommand(args);
    
    return 0;
}

void testPE() {
    PEParser parser;
    PEPrinter printer;
    //auto path = _T("C:\\Users\\hve46\\Documents\\project\\git\\pe-parser\\KeyHook86.dll");
    //auto path = _T("C:\\Users\\hve46\\Documents\\project\\git\\pe-parser-school-project\\HEMacro.dll");
    auto path = _T("C:\\Windows\\System32\\shell32.dll");

    parser.parsePEFile(path);

    auto pe = parser.getPEStructure();

    tcout << "sizeOfHeaders : " << pe->ntHeader64.OptionalHeader.SizeOfHeaders << endl;
    tcout << "baseOfCode: " << pe->ntHeader64.OptionalHeader.BaseOfCode << endl;

    printer.reset(pe);
    printer.printPEStructure();

    tstring hash;
    parser.tryGetSectionHash(_T(".text"), hash);
    tcout << "hash: " << hash << endl;

    hash.clear();
    parser.tryGetCodeSectionHash(hash);
    tcout << "hash: " << hash << endl;

    hash.clear();
    parser.tryGetEntryPointSectionHash(hash);
    tcout << "hash: " << hash << endl;

    hash.clear();
    parser.tryGetPDBFilePathHash(hash);
    tcout << "hash: " << hash << endl;
}