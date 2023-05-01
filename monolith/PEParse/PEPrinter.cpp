#pragma once
#include "PEPrinter.h"
#include <format>

using namespace std;

namespace PELog {
    static auto println = []() { tcout << std::endl << _T("---------------------------------------------------------------------------------") << std::endl; };

    PEPrinter::PEPrinter() {
        m_PEStructure.reset();
    };
    PEPrinter::PEPrinter(shared_ptr<PEStructure> peStructWeakPtr) {
        m_PEStructure = peStructWeakPtr;
    };
    PEPrinter::~PEPrinter() { };

    void PEPrinter::reset(shared_ptr<PEStructure> peStructWeakPtr) {
        m_PEStructure = peStructWeakPtr;
    }

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

