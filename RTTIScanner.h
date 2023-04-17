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

		// set up registers with constants for pattern matching:
		__m128i sigFill = _mm_set1_epi8(_mm_extract_epi8(this->signature, 0));
		__m128i maskFillNot = _mm_sub_epi8(_mm_set1_epi8(-1), _mm_set1_epi8(_mm_extract_epi8(this->bitmask, 0)));
		__m128i sigShift = _mm_insert_epi8(_mm_srli_si128(this->signature, 1), 0, 15);
		__m128i maskShiftNot = _mm_sub_epi8(_mm_set1_epi8(-1), _mm_insert_epi8(_mm_srli_si128(this->bitmask, 1), -1, 15));

		for (std::unique_ptr<PEParser::Section>& textSection : *text) {
			// iterate over .text sections, get start and end addresses
			unsigned char* textStart = textSection->start.as(base);
			unsigned char* textEnd = textSection->end.as(base);

			__m128i bytes = _mm_loadu_si128(reinterpret_cast<__m128i*>(textStart));

			for (unsigned char* curr = textStart; curr < textEnd;) {
				// match instruction pattern, and-ing out masked bits
				bytes = _mm_and_si128(bytes, maskFillNot);
				bytes = _mm_cmpeq_epi8(bytes, sigFill);

				// locate the byte offset at which a matching byte was found
				short match = _tzcnt_u16(_mm_movemask_epi8(bytes));
				curr += match + 1;

				bytes = _mm_loadu_si128(reinterpret_cast<__m128i*>(curr));
				if (match == 16) continue; // 0 bytes matched

				// final pattern equality comparison, and out masked bits before xor-ing with pattern
				__m128i bytes_ = _mm_and_si128(bytes, maskShiftNot);
				bytes_ = _mm_xor_si128(bytes_, sigShift);
				if (_mm_testz_si128(bytes_, bytes_)) {
					// compare instruction encodings to match our pattern, make sure the registers and prefixes in both instructions match
					InstructionEncoding* inst = reinterpret_cast<InstructionEncoding*>(curr - 1);
					if ((inst->movOperands & 0b00000111) == 0b00000101 && (!(inst->movOperands & 0b01000000) || inst->movExtraOp)) continue;
					if ((inst->leaRexPrefix & 0b00000100) != (inst->movRexPrefix & 0b00000100)) continue;
					if ((inst->leaOperands ^ inst->movOperands) & 0b00111000) continue;

					// the pointer to the COL is above the VFT address
					void** pVFT = reinterpret_cast<void**>(curr + inst->RIPOffset + 6);
					CompleteObjectLocator** ppCOL = reinterpret_cast<CompleteObjectLocator**>(curr + inst->RIPOffset - 2);
					if (!PEParser::isAddressInSection(ppCOL, rdata)) continue;

					// the COL address should be in .rdata
					CompleteObjectLocator* pCOL = *ppCOL;
					if (!PEParser::isAddressInSection(pCOL, rdata)) continue;

					// the signature should equal 1 in x86-64 code
					if (pCOL->signature != 1) continue;

					// get and match RTTI structures
					if (!PEParser::isIbo32InSection(pCOL->iboTypeDescriptor, data)) continue;
					if (!PEParser::isIbo32InSection(pCOL->iboClassDescriptor, rdata)) continue;

					TypeDescriptor* pTD = pCOL->iboTypeDescriptor.as<TypeDescriptor*>(base);
					ClassHierarchyDescriptor* pCHD = pCOL->iboClassDescriptor.as<ClassHierarchyDescriptor*>(base);

					if (!PEParser::isIbo32InSection(pCHD->iboBaseClassDescriptor, rdata)) continue;
					BaseClassDescriptor* pBCD = pCHD->iboBaseClassDescriptor.as< BaseClassDescriptor*>(base);

					// demangleName will return an empty string if the class name is invalid
					std::string name = RTTI::demangleName(pTD->name);
					if (name.empty()) continue;

					RTTIScanner::classRTTI.emplace(name, std::make_unique<RTTI>(pVFT, pCOL, pTD, pCHD, pBCD));
				}
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
