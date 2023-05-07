#pragma once
#include "PEPrinter.h"
#include <format>

using namespace std;

namespace PELog {

    PEPrinter::PEPrinter() {
        m_PEStructure.reset();
    };
    PEPrinter::PEPrinter(shared_ptr<PEStructure> peStructWeakPtr) {
        m_PEStructure = peStructWeakPtr;
    };
    void PEPrinter::reset(shared_ptr<PEStructure> peStructWeakPtr) {
        m_PEStructure = peStructWeakPtr;
    }

    PEPrinter::~PEPrinter() { };

    static auto println = []() { tcout << std::endl << _T("---------------------------------------------------------------------------------") << std::endl; };

    void PEPrinter::printPEStructure() {
        println();
        printBaseAddress();
        println();
        printDosHeader();
        println();
        printNTHeader();
        println();
        printSectionHeader();
        println();
        printEAT();
        println();
        printIAT();
        println();
        printTLS();
        println();
    };
};

