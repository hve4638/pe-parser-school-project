#pragma once
#include "PEPrinter.h"
#include <format>

using namespace std;

namespace PELog {
    void PEPrinter::printBaseAddress() {
        auto peStructure = m_wkPEStruct.get();
        tcout << format(_T("PE file: 0x{:x}, {:s}"), (ULONGLONG)peStructure->baseAddress, peStructure->filePath) << endl;
    };

    void PEPrinter::printDosHeader() {
        auto peStructure = m_wkPEStruct.get();
        tcout << format(_T("DOS signature:                0x{:x}"), (WORD)peStructure->dosHeader.e_magic) << endl;
    };

    void PEPrinter::printNTHeader() {
        auto peStructure = m_wkPEStruct.get();
        if (peStructure->machineType == x86) {
            auto ntHeader = peStructure->ntHeader32;
            tcout << format(_T("Machine type:                 0x{:x}"), (WORD)ntHeader.FileHeader.Machine) << endl;
            tcout << format(_T("Number of sections:           0x{:x}"), (WORD)ntHeader.FileHeader.NumberOfSections) << endl;
            tcout << format(_T("Timestamp:                    0x{:x}"), (DWORD)ntHeader.FileHeader.TimeDateStamp) << endl;
            tcout << format(_T("Magic:                        0x{:x}"), (DWORD)ntHeader.OptionalHeader.Magic) << endl;
            tcout << format(_T("Entry point address:          0x{:x}"), (DWORD)ntHeader.OptionalHeader.AddressOfEntryPoint) << endl;
            tcout << format(_T("Image base address:           0x{:x}"), (ULONGLONG)ntHeader.OptionalHeader.ImageBase) << endl;
            tcout << format(_T("Section alignment:            0x{:x}"), (DWORD)ntHeader.OptionalHeader.SectionAlignment) << endl;
            tcout << format(_T("File alignment:               0x{:x}"), (DWORD)ntHeader.OptionalHeader.FileAlignment) << endl;
            tcout << format(_T("Size of image:                0x{:x}"), (DWORD)ntHeader.OptionalHeader.SizeOfImage) << endl;
            tcout << format(_T("Size of headers:              0x{:x}"), (DWORD)ntHeader.OptionalHeader.SizeOfHeaders) << endl;
            tcout << format(_T("Subsystem:                    0x{:x}"), (WORD)ntHeader.OptionalHeader.Subsystem) << endl;
            tcout << format(_T("Number of RVA and sizes:      0x{:x}"), (DWORD)ntHeader.OptionalHeader.NumberOfRvaAndSizes) << endl;
        }
        else {
            auto peStructure = m_wkPEStruct.get();
            auto ntHeader = peStructure->ntHeader64;
            tcout << format(_T("Machine type:                 0x{:x}"), (WORD)ntHeader.FileHeader.Machine) << endl;
            tcout << format(_T("Number of sections:           0x{:x}"), (WORD)ntHeader.FileHeader.NumberOfSections) << endl;
            tcout << format(_T("Timestamp:                    0x{:x}"), (DWORD)ntHeader.FileHeader.TimeDateStamp) << endl;
            tcout << format(_T("Magic:                        0x{:x}"), (DWORD)ntHeader.OptionalHeader.Magic) << endl;
            tcout << format(_T("Entry point address:          0x{:x}"), (DWORD)ntHeader.OptionalHeader.AddressOfEntryPoint) << endl;
            tcout << format(_T("Image base address:           0x{:x}"), (ULONGLONG)ntHeader.OptionalHeader.ImageBase) << endl;
            tcout << format(_T("Section alignment:            0x{:x}"), (DWORD)ntHeader.OptionalHeader.SectionAlignment) << endl;
            tcout << format(_T("File alignment:               0x{:x}"), (DWORD)ntHeader.OptionalHeader.FileAlignment) << endl;
            tcout << format(_T("Size of image:                0x{:x}"), (DWORD)ntHeader.OptionalHeader.SizeOfImage) << endl;
            tcout << format(_T("Size of headers:              0x{:x}"), (DWORD)ntHeader.OptionalHeader.SizeOfHeaders) << endl;
            tcout << format(_T("Subsystem:                    0x{:x}"), (WORD)ntHeader.OptionalHeader.Subsystem) << endl;
            tcout << format(_T("Number of RVA and sizes:      0x{:x}"), (DWORD)ntHeader.OptionalHeader.NumberOfRvaAndSizes) << endl;
        }
    };

    void PEPrinter::printSectionHeader() {
        auto peStructure = m_wkPEStruct.get();
        for (auto const& element : peStructure->sectionList) {

            tcout << format(_T("Section Name: {:s}"), element.Name) << endl;
            tcout << format(_T("          > VirtualAddress:   0x{:x}"), element.VirtualAddress) << endl;
            tcout << format(_T("          > PointerToRawData: 0x{:x}"), element.PointerToRawData) << endl;
            tcout << format(_T("          > SizeOfRawData:    0x{:x}"), element.SizeOfRawData) << endl;
            tcout << format(_T("          > Characteristics:  0x{:x}"), element.Characteristics) << endl;
        }
    };

    void PEPrinter::printEAT() {
        auto peStructure = m_wkPEStruct.get();
        for (auto const& element : peStructure->exportList) {
            tcout << format(_T("EAT Module: {:s}"), element.Name) << endl;
            for (auto const& funcElement : element.FunctionInfo) {
                tcout << format(_T("          > 0x{:x}, 0x{:x}, {:s}"), funcElement.AddressOfIAT, funcElement.Ordinal, funcElement.Name) << endl;
            }
        }
    };

    void PEPrinter::printIAT() {
        auto peStructure = m_wkPEStruct.get();
        for (auto const& element : peStructure->importList) {
            tcout << format(_T("IAT Module: {:s}"), element.Name) << endl;
            for (auto const& funcElement : element.FunctionInfo) {
                tcout << format(_T("          > 0x{:x}, 0x{:x}, {:s}"), funcElement.AddressOfIAT, funcElement.Ordinal, funcElement.Name) << endl;
            }
        }
    };

    void PEPrinter::printTLS() {
        auto peStructure = m_wkPEStruct.get();
        if (peStructure->tlsCallbackList.size() > 0) {
            tcout << format(_T("TLS AddressOfCallBacks: ")) << endl;
            for (auto const& element : peStructure->tlsCallbackList) {
                tcout << format(_T("          > 0x{:x}"), element) << endl;
            }
        }
    };
};

