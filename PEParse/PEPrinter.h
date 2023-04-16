#pragma once
#include "typedef.h"

namespace PELog {
    class PEPrinter {
    private:
        void printBaseAddress(const PEStructure& peStructure);
        void printDosHeader(const PEStructure& peStructure);
        void printNTHeader(const PEStructure& peStructure);
        void printSectionHeader(const PEStructure& peStructure);
        void printEAT(const PEStructure& peStructure);
        void printIAT(const PEStructure& peStructure);
        void printTLS(const PEStructure& peStructure);

    public:
        PEPrinter();
        ~PEPrinter();
        void printPEStructure(const PEStructure& peStructure);
    };
};

