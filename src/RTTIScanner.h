#pragma once

#include "PE.h"
#include <immintrin.h>

#include <iostream>

class RTTIScanner {
public:
	struct SectionData {
		SectionData(PEParser::PESections* text, PEParser::PESections* data, PEParser::PESections* rdata) : text(text), data(data), rdata(rdata) {}
		PEParser::PESections* text;
		PEParser::PESections* data;
		PEParser::PESections* rdata;
	};

#pragma pack(push, 1) // pack the struct to preserve instruction layout
	struct InstructionEncoding {
		unsigned char leaRexPrefix;
		unsigned char : 8;
		unsigned char leaOperands;
		int RIPOffset;
		unsigned char movRexPrefix;
		unsigned char : 8;
		unsigned char movOperands;
		unsigned char movExtraOp;
	};
#pragma pack(pop)

	struct CompleteObjectLocator {
		unsigned int signature;
		unsigned int offset;
		unsigned int constructorDisp;
		PEParser::ibo32 iboTypeDescriptor;
		PEParser::ibo32 iboClassDescriptor;
	};

	struct TypeDescriptor {
		void** type_info_vft;
		void** spare;
		const char name[256];
	};

	struct ClassHierarchyDescriptor {
		unsigned int signature;
		unsigned int flags;
		unsigned int numBaseClasses;
		PEParser::ibo32 iboBaseClassDescriptor;
	};

	struct BaseClassDescriptor {
		int offsetTypeDescriptor;
		unsigned int numExtendedClasses;
		int displacements[3];
		unsigned int flags;
		PEParser::ibo32 iboClassDescriptor;
	};

	class RTTI {
	public:
		RTTI(void** pVFT,
			RTTIScanner::CompleteObjectLocator* pCOL,
			RTTIScanner::TypeDescriptor* pTD,
			RTTIScanner::ClassHierarchyDescriptor* pCHD,
			RTTIScanner::BaseClassDescriptor* pBCD) :
			pVirtualFunctionTable(pVFT),
			pCompleteObjectLocator(pCOL),
			pTypeDescriptor(pTD),
			pClassHierarchyDescriptor(pCHD),
			pBaseClassDescriptor(pBCD) {}

		~RTTI() {}

		/// <summary>
		/// Get the demangled class name from its type descriptor.
		/// </summary>
		/// <returns>the demangled name on success, otherwise empty string</returns>
		std::string getName()
		{
			return demangleName(this->pTypeDescriptor->name);
		}

		/// <summary>
		/// Demangle a mangled C++ symbol name.
		/// </summary>
		/// <param name="name">: pointer to a null terminated char string</param>
		/// <returns>the demangled name on success, otherwise empty string</returns>
		static std::string demangleName(const char* name)
		{
			char output[256];

			// in memory, mangled class names may start with a dot, which we do not want to pass to the demangler
			if (name[0] == "."[0]) {
				name++;
			}

			// UnDecorateSymbolName returns the total length of the demangled string on success, 0 on failure
			if (!UnDecorateSymbolName(name, output, sizeof(output), UNDNAME_NO_ARGUMENTS | UNDNAME_NAME_ONLY | UNDNAME_32_BIT_DECODE | UNDNAME_NO_MS_KEYWORDS | UNDNAME_NO_LEADING_UNDERSCORES)) {
				return "";
			}
			else {
				return output;
			}
		}

		void** pVirtualFunctionTable;
		RTTIScanner::CompleteObjectLocator* pCompleteObjectLocator;
		RTTIScanner::TypeDescriptor* pTypeDescriptor;
		RTTIScanner::ClassHierarchyDescriptor* pClassHierarchyDescriptor;
		RTTIScanner::BaseClassDescriptor* pBaseClassDescriptor;
	};

	RTTIScanner() { RTTIScanner::parser.reset(new PEParser()); }
	~RTTIScanner() { RTTIScanner::parser.reset(); RTTIScanner::classRTTI.clear(); RTTIScanner::sectionData.reset(); }

	/// <summary>
	/// Scans the executable's text section(s) to retrieve class RTTI by matching instruction patterns inside class object constructors.
	/// Pointers to RTTI structs are mapped on a RTTIScanner::classRTTI map, using class names as keys.
	/// </summary>
	/// <param name="pInfo">: (optional) a pointer to a PEParser::ProcessInfo struct overriding the default process information used by the parser</param>
	/// <returns>true on success, false on initialization failure</returns>
	bool scan(PEParser::ProcessInfo* pInfo = nullptr)
	{
		// parse the PE headers and get section addresses and process information
		if (!RTTIScanner::parser->parse(pInfo) || !this->setSectionData()) return false;

		auto processInfo = this->parser->getProcessInfo();
		if (!processInfo) return false;

		//get executable base address and sections
		unsigned char* base = reinterpret_cast<unsigned char*>(processInfo->mInfo->lpBaseOfDll);

		PEParser::PESections* text = this->sectionData->text;
		PEParser::PESections* data = this->sectionData->data;
		PEParser::PESections* rdata = this->sectionData->rdata;

		if (!text || !data || !rdata) return false;

		for (auto& section : *rdata) {
			auto pCOL = section->start.as<CompleteObjectLocator**>(base);
			auto end = section->end.as<CompleteObjectLocator**>(base);
			while (pCOL++ < end) {
				auto COL = *pCOL;
				if (!PEParser::isAddressInSection(COL, rdata)) continue;
				if (!PEParser::isAddressInSection(*(++pCOL), text)) continue;
				if (COL->signature != 1) continue;
				if (!PEParser::isIbo32InSection(COL->iboTypeDescriptor, data)) continue;
				if (!PEParser::isIbo32InSection(COL->iboClassDescriptor, rdata)) continue;
				TypeDescriptor* TD = COL->iboTypeDescriptor.as<TypeDescriptor*>(base);
				ClassHierarchyDescriptor* CHD = COL->iboClassDescriptor.as<ClassHierarchyDescriptor*>(base);

				if (!PEParser::isIbo32InSection(CHD->iboBaseClassDescriptor, rdata)) continue;
				BaseClassDescriptor* pBCD = CHD->iboBaseClassDescriptor.as< BaseClassDescriptor*>(base);

				// demangleName will return an empty string if the class name is invalid
				std::string name = RTTI::demangleName(TD->name);
				if (name.empty()) continue;

				RTTIScanner::classRTTI.emplace(name, std::make_unique<RTTI>(reinterpret_cast<void**>(pCOL), COL, TD, CHD, pBCD));
			}
		}

		return true;
	}

	/// <summary>
	/// Retrieves a pointer to the RTTI of a class after a scan, by name.
	/// </summary>
	/// <param name="name">: name of the class to get RTTI of</param>
	/// <returns>a pointer to class RTTI on success, otherwise nullptr</returns>
	static RTTI* getClassRTTI(std::string name)
	{ 
		auto iter = RTTIScanner::classRTTI.find(name); 
		return iter != RTTIScanner::classRTTI.end() ? RTTIScanner::classRTTI[name].get() : nullptr; 
	}

private:
	static inline std::unique_ptr<PEParser> parser{};
	static inline std::unordered_map<std::string, std::unique_ptr<RTTI>> classRTTI{};
	static inline std::unique_ptr<SectionData> sectionData{};

	// REX.W lea reg1,[rip]
	// REX.W mov [reg2],reg1
	const __m128i signature = _mm_setr_epi8(0x48, 0x8D, 0x05, 0x0, 0x0, 0x0, 0x0, 0x48, 0x89, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0);
	const __m128i bitmask = _mm_setr_epi8(0b00000100, 0, 0b00111000, -1, -1, -1, -1, 0b00000101, 0, 0b00111111, -1, -1, -1, -1, -1, -1);

	bool setSectionData()
	{
		RTTIScanner::sectionData.reset();

		PEParser::PESections* text = RTTIScanner::parser->getSectionsWithName(".text");
		PEParser::PESections* data = RTTIScanner::parser->getSectionsWithName(".data");
		PEParser::PESections* rdata = RTTIScanner::parser->getSectionsWithName(".rdata");

		if (!text || !data || !rdata) return false;

		RTTIScanner::sectionData.reset(new SectionData(text, data, rdata));

		return true;
	}
};
