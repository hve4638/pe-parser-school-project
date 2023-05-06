#include <format>
#include <string>
#include "PECommandLineParser.h"
#include "peparser.h"
#include "PEPrinter.h"

using namespace PEParse;
using namespace PELog;
//using namespace PEUtils;

namespace CommandLineUtils {
    PECommandLineParser::PECommandLineParser() {
        addCommand(_T("help"),
            [](IArgsPtr args) {
                tcout << _T("¹¹") << endl;
            }
        );
        addCommand(_T("print file"),
            [](IArgsPtr args) {
                tstring filename = args->next();

                PEParser parser;
                parser.parsePEFile(filename.c_str());

                PEPrinter printer = parser.getPEStructure();
                printer.printPEStructure();
            }
        );
        addCommand(_T("print pid"),
            [](IArgsPtr args) {
                int pid = std::stoi(args->next());

                PEParser parser;
                parser.parsePEProcess(pid);

                PEPrinter printer = parser.getPEStructure();
                printer.printPEStructure();
            }
        );

        addCommand(_T("scan file"),
            [](IArgsPtr args) {
                tstring filename = args->next();
                tstring expectedHash = args->next();

                PEParser parser;
                parser.parsePEFile(filename.c_str());

                tstring textSectionHash = _T("");
                tstring codeSectionHash = _T("");
                tstring entryPointHash = _T("");
                tstring pdbHash = _T("");
                parser.tryGetSectionHash(_T(".text"), textSectionHash);
                parser.tryGetEntryPointSectionHash(entryPointHash);
                parser.tryGetCodeSectionHash(codeSectionHash);
                parser.tryGetPDBFilePathHash(pdbHash);


                tcout << _T("<Scanning>") << endl;
                tcout << format(_T("Hash : {:s}"), expectedHash) << endl;
                tcout << format(_T("File : {:s}"), filename) << endl;
                tcout << _T("----------------------------------------") << endl;
                if (expectedHash.compare(textSectionHash) == 0) {
                    tcout << format(_T("Detected (.text section)")) << endl;
                }
                if (expectedHash.compare(entryPointHash) == 0) {
                    tcout << format(_T("Detected (Entry point section)")) << endl;
                }
                if (expectedHash.compare(codeSectionHash) == 0) {
                    tcout << format(_T("Detected (code Section)")) << endl;
                }
                if (expectedHash.compare(pdbHash) == 0) {
                    tcout << format(_T("Detected (PDB file path)")) << endl;
                }
                tcout << endl;
            }
        );

        addCommand(_T("scan pid"),
            [](IArgsPtr args) {
                int pid = std::stoi(args->next());

                tstring filename = args->next();
                tstring expectedHash = args->next();

                PEParser parser;
                parser.parsePEProcess(pid);

                tstring textSectionHash = _T("");
                tstring codeSectionHash = _T("");
                tstring entryPointHash = _T("");
                tstring pdbHash = _T("");
                parser.tryGetSectionHash(_T(".text"), textSectionHash);
                parser.tryGetEntryPointSectionHash(entryPointHash);
                parser.tryGetCodeSectionHash(codeSectionHash);
                parser.tryGetPDBFilePathHash(pdbHash);


                tcout << format(_T("Hash = {:s}"), expectedHash) << endl;
                tcout << endl;
                if (expectedHash.compare(textSectionHash) == 0) {
                    tcout << format(_T("Detected (.text section)")) << endl;
                }
                if (expectedHash.compare(entryPointHash) == 0) {
                    tcout << format(_T("Detected (Entry point section)")) << endl;
                }
                if (expectedHash.compare(codeSectionHash) == 0) {
                    tcout << format(_T("Detected (code Section)")) << endl;
                }
                if (expectedHash.compare(pdbHash) == 0) {
                    tcout << format(_T("Detected (PDB file path)")) << endl;
                }
            }
        );
    }
}