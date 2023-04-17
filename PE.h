#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <DbgHelp.h>
#pragma comment(lib, "DbgHelp")
#include <Psapi.h>

#include <memory>
#include <string>
#include <vector>
#include <stdexcept>
#include <unordered_map>

class PEParser {
public:
	struct ProcessInfo {
		HANDLE hProcess;
		HMODULE hProcessModule;
		std::unique_ptr<MODULEINFO> mInfo;
	};

	static std::shared_ptr<ProcessInfo> getProcessInfo() { return pInfo; }

	/// <summary>
	/// Static. Sets the PEParser::ProcessInfo struct if passed as an argument, or fills it out with information about the current process.
	/// Transfers ownership of PEParser::ProcessInfo to the parser instance.
	/// Invalidates the section map pointer. PEParser::parse must be called again after modifying process info.
	/// </summary>
	/// <param name="pInfo">: (optional) a pointer to a PEParser::ProcessInfo struct containing process information</param>
	/// <returns>true on success, false on failure to retrieve process module information</returns>
	static std::shared_ptr<PEParser::ProcessInfo> setProcessInfo(ProcessInfo* pInfo = nullptr)
	{
		// calling setProcessInfo likely renders the current section map invalid, so its ownership is released
		sectionMap.reset();

		if (!pInfo) {
			// make sure the ProcessInfo pointer does not point to an incomplete struct if the GetModuleInformation call fails 
			PEParser::pInfo.reset();

			auto pInfo = std::make_unique<ProcessInfo>();

			pInfo->hProcess = GetCurrentProcess();
			pInfo->hProcessModule = GetModuleHandleA(NULL);
			pInfo->mInfo = std::make_unique<MODULEINFO>();

			// fill out the MODULEINFO struct. We are interested in .lpBaseOfDll to find the process's base address
			if (GetModuleInformation(pInfo->hProcess, pInfo->hProcessModule, pInfo->mInfo.get(), sizeof(MODULEINFO))) {
				// transfer ownership of pInfo
				PEParser::pInfo = std::move(pInfo);
			}
		}
		else {
			PEParser::pInfo.reset(pInfo);
		}

		return PEParser::pInfo;
	}

	class ibo32 {
	public:
		ibo32() : val(0) {}
		ibo32(int offset) : val(offset) {}

		/// <summary>
		/// Constructs an integer base offset given an address.
		/// It is recommended to call PEParser::setProcessInfo before this function, otherwise it will call it with default arguments,
		/// and will throw if the call fails.
		/// </summary>
		/// <param name="address">: the address to be calculated as an ibo</param>
		template <typename T> ibo32(T* address)
		{
			this->val = static_cast<int>(reinterpret_cast<uintptr_t>(address) - reinterpret_cast<uintptr_t>(this->getProcessInfo()->mInfo->lpBaseOfDll));
		}

		/// <summary>
		/// Constructs an integer base offset from an address and an explicitly given base address. Does not throw.
		/// </summary>
		/// <param name="address">: the address to be calculated as an ibo</param>
		/// <param name="base">: the base address to calculate the ibo from</param>
		template <typename T1, typename T2> ibo32(T1* address, T2* base) noexcept
		{
			this->val = static_cast<int>(reinterpret_cast<uintptr_t>(address) - reinterpret_cast<uintptr_t>(base));
		}

		/// <summary>
		/// Calculates a pointer from the integer base offset.
		/// It is recommended to call PEParser::setProcessInfo before this function, otherwise it will call it with default arguments,
		/// and will throw if the call fails.
		/// </summary>
		/// <returns>a pointer calculated from the ibo</returns>
		template <typename T = unsigned char*> T as()
		{
			return reinterpret_cast<T>(reinterpret_cast<unsigned char*>(this->getProcessInfo()->mInfo->lpBaseOfDll) + this->val);
		}

		/// <summary>
		/// Calculates a pointer from the integer base offset and an explicitly given base address. Does not throw.
		/// </summary>
		/// <param name="base">: the base address to add the ibo to</param>
		/// <returns>a pointer calculated from the ibo</returns>
		template <typename T1 = unsigned char*, typename T2> T1 as(T2* base) noexcept
		{
			return reinterpret_cast<T1>(reinterpret_cast<unsigned char*>(base) + this->val);
		}

		/// <summary>
		/// Returns the integer base offset as a signed 32 bit integer.
		/// </summary>
		/// <returns>ibo as an int</returns>
		int as() noexcept
		{
			return this->val;
		}

		bool operator == (const ibo32& other) { return this->val == other.val; }
		bool operator != (const ibo32& other) { return this->val != other.val; }
		bool operator < (const ibo32& other) { return this->val < other.val; }
		bool operator > (const ibo32& other) { return this->val > other.val; }
		bool operator <= (const ibo32& other) { return this->val <= other.val; }
		bool operator >= (const ibo32& other) { return this->val >= other.val; }

	private:
		int val;

		/// <summary>
		/// Internal function called when PEParser::setProcessInfo had not been called until now. 
		/// Will throw if the call fails.
		/// It is recommended to first create a parser instance or call PEParser::setProcessInfo manually.
		/// </summary>
		/// <returns></returns>
		std::shared_ptr<ProcessInfo> getProcessInfo()
		{
			auto pInfo = PEParser::getProcessInfo();

			if (!pInfo) {
				pInfo = setProcessInfo();

				if (!pInfo) {
					throw std::runtime_error("Unable to get process information");
				}
			}

			return pInfo;
		}
	};

	struct Section {
		std::string name;
		size_t size;
		ibo32 start;
		ibo32 end;
	};

	typedef std::vector<std::unique_ptr<PEParser::Section>> PESections;

	class SectionMap {
	public:
		// internal function, refer to PEParser::getSectionsWithName
		PESections* getSectionsWithName(std::string name)
		{
			auto iter = this->sectionMap.find(name);

			if (iter != this->sectionMap.end()) {
				return &iter->second;
			}
			else {
				return nullptr;
			}
		}

		/// <summary>
		/// Internal function. Adds a section to the section map.
		/// </summary>
		/// <param name="section"></param>
		/// <returns>true on success, false if section argument is nullptr</returns>
		bool addSection(Section* section)
		{
			if (!section) return false;

			auto iter = this->sectionMap.find(section->name);

			if (iter != this->sectionMap.end()) {
				std::unique_ptr<Section> sp;
				sp.reset(section);
				iter->second.push_back(std::move(sp));
			}
			else {
				this->sectionMap[section->name].emplace_back(std::make_unique<Section>());
				this->sectionMap[section->name].back().reset(section);
			}

			return true;
		}

	private:
		std::unordered_map<std::string, std::vector<std::unique_ptr<Section>>> sectionMap;
	};

	/// <summary>
	/// Creates a new instance of PEParser, filling in the PEParser::ProcessInfo struct,
	/// unless one is already passed as the argument.
	/// </summary>
	/// <param name="pInfo">: (optional) a pointer to a PEParser::ProcessInfo struct containing process information</param>
	PEParser(ProcessInfo* pInfo = nullptr)
	{
		PEParser::setProcessInfo(pInfo);
	}

	~PEParser() { PEParser::pInfo.reset(); PEParser::sectionMap.reset(); };

	/// <summary>
	/// Parses the target process's (specified by ProcessInfo) PE headers, mapping them out in a SectionMap.
	/// Multiple calls create new SectionMap instances.
	/// </summary>
	/// <param name="pInfo">: (optional) a pointer to a PEParser::ProcessInfo struct overriding the default process information</param>
	/// <returns>true on success, false if ProcessInfo is missing or the PE headers do not match those of an executable image</returns>
	bool parse(ProcessInfo* pInfo = nullptr)
	{
		// the ProcessInfo struct is necessary to get the base address of the executable
		PEParser::setProcessInfo(pInfo);

		unsigned char* base = reinterpret_cast<unsigned char*>(PEParser::pInfo->mInfo->lpBaseOfDll);
		if (!base || *reinterpret_cast<short*>(base) != 0x5A4D) return false; // executable image magic number

		base += *reinterpret_cast<int*>(base + 0x3C);
		if (*reinterpret_cast<int*>(base) != 0x4550) return false; // PE header magic number

		const short sectionCount = *reinterpret_cast<short*>(base + 0x06);

		base += *reinterpret_cast<short*>(base + 0x14) + 0x18; // add COFF and optional header sizes

		PEParser::sectionMap = std::make_shared<SectionMap>();

		for (int i = 0; i < sectionCount; i++) {
			auto section = new Section;

			section->name = reinterpret_cast<const char*>(base);
			section->size = *reinterpret_cast<int*>(base + 0x08); // virtual size of section
			section->start = *reinterpret_cast<int*>(base + 0x0C); // virtual address of section
			section->end = section->start.as() + section->size;

			PEParser::sectionMap->addSection(section);

			base += 0x28; // size of a section header
		}

		return true;
	}

	/// <summary>
	/// Retrieve a pointer to a vector of pointers to Section structures with a matching name. A single executable image can have multiple sections with identical names.
	/// </summary>
	/// <param name="name">: sections to match</param>
	/// <returns>a pointer to a vector of pointers to Section structures with a matching name; if PEParser::parse had not been called or the section is missing, nullptr </returns>
	PESections* getSectionsWithName(std::string name)
	{
		if (!PEParser::sectionMap) return nullptr;

		return PEParser::sectionMap->getSectionsWithName(name);
	}

	/// <summary>
	/// Static. Checks if a given address is inside any of the given sections.  
	/// </summary>
	/// <param name="address">: the address to be checked</param>
	/// <param name="sections">: a pointer to the PESections vector</param>
	/// <returns>true if address is in one of the sections, otherwise false</returns>
	template <typename T> static bool isAddressInSection(T* address, PESections* sections)
	{
		for (std::unique_ptr<PEParser::Section>& section : *sections) {
			if (reinterpret_cast<uintptr_t>(address) >= section->start.as<uintptr_t>()
				&& reinterpret_cast<uintptr_t>(address) < section->end.as<uintptr_t>()) {
				return true;
			}
		}
		return false;
	}

	/// <summary>
	/// Checks if a given address is inside any of the given sections, by name.  
	/// </summary>
	/// <param name="address">: the address to be checked</param>
	/// <param name="sections">: name of the section(s)</param>
	/// <returns>true if address is in one of the sections, otherwise false</returns>
	template <typename T> bool isAddressInSection(T* address, std::string name)
	{
		return isAddressInSection(address, this->getSectionsWithName(name));
	}

	/// <summary>
	/// Static. Checks if a given integer base offset is inside any of the given sections.  
	/// </summary>
	/// <param name="ibo">: the ibo to be checked</param>
	/// <param name="sections">: a pointer to the PESections vector</param>
	/// <returns>true if ibo is in one of the sections, otherwise false</returns>
	static bool isIbo32InSection(ibo32 ibo, PESections* sections)
	{
		for (std::unique_ptr<Section>& section : *sections) {
			if (ibo >= section->start
				&& ibo < section->end) {
				return true;
			}
		}
		return false;
	}

	/// <summary>
	/// Checks if a given integer base offset is inside any of the given sections, by name.  
	/// </summary>
	/// <param name="ibo">: the ibo to be checked</param>
	/// <param name="sections">: name of the section(s)</param>
	/// <returns>true if ibo is in one of the sections, otherwise false</returns>
	bool isIbo32InSection(ibo32 ibo, std::string name)
	{
		return isIbo32InSection(ibo, this->getSectionsWithName(name));
	}

private:
	static inline std::shared_ptr<ProcessInfo> pInfo{};
	static inline std::shared_ptr<SectionMap> sectionMap{};
};
