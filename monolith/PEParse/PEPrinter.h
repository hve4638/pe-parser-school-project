#pragma once
#include "typedef.h"

namespace PELog {
    class PEPrinter {
        shared_ptr<PEStructure> m_PEStructure;

    private:
        void printBaseAddress();
        void printDosHeader();
        void printNTHeader();
        void printSectionHeader();
        void printEAT();
        void printIAT();
        void printTLS();

    public:
        PEPrinter();
        PEPrinter(shared_ptr<PEStructure> peStructWeakPtr);
        ~PEPrinter();
        void reset(shared_ptr<PEStructure> peStructWeakPtr);

        void printPEStructure();
    };
};

