#include <Windows.h>
#include <string>
#include <algorithm>
#include <Psapi.h>

const char* MemoryTypeToString(DWORD type) {
	switch (type) {
	case MEM_IMAGE: return "Image";
	case MEM_MAPPED: return "Mapped";
	case MEM_PRIVATE: return "Private";
	}
	return "";
}

// thank you pavel!
char * ProtectionToString(DWORD protection) {
	static const struct {
		PCSTR Text;
		DWORD Value;
	} prot[] = {
		{ "", 0 },
		{ "Execute", PAGE_EXECUTE },
		{ "Execute/Read", PAGE_EXECUTE_READ },
		{ "WriteCopy", PAGE_WRITECOPY },
		{ "Execute/Read/Write", PAGE_EXECUTE_READWRITE },
		{ "Execute/WriteCopy", PAGE_EXECUTE_WRITECOPY },
		{ "No Access", PAGE_NOACCESS },
		{ "Read", PAGE_READONLY },
		{ "Read/Write", PAGE_READWRITE },
	};

	std::string text = std::find_if(std::begin(prot), std::end(prot), [protection](auto& p) {
		return p.Value == (protection & 0xff);
		})->Text;

	static const struct {
		PCSTR Text;
		DWORD Value;
	} extra[] = {
		{ "Guard", PAGE_GUARD },
		{ "No Cache", PAGE_NOCACHE },
		{ "Write Combine", PAGE_WRITECOMBINE },
		{ "Targets Invalid", PAGE_TARGETS_INVALID },
		{ "Targets No Update", PAGE_TARGETS_NO_UPDATE },
	};

	std::for_each(std::begin(extra), std::end(extra), [&text, protection](auto& p) {
		if (p.Value & protection)
			((text += "/") += p.Text);
		});

	char *textbuf = (char *) malloc(100);
	strcpy_s(textbuf, 100, text.c_str());
	return textbuf;
}

std::string getMappedImage(HANDLE hProcess, MEMORY_BASIC_INFORMATION& mbi) {
	if (mbi.State != MEM_COMMIT)
		return "";

	if (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) {
		char path[MAX_PATH];
		if (::GetMappedFileNameA(hProcess, mbi.BaseAddress, path, sizeof(path)) > 0)
			return path;
	}
	return "";
}