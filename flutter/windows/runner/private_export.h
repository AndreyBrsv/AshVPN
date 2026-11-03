#ifndef RUNNER_PRIVATE_EXPORT_H_
#define RUNNER_PRIVATE_EXPORT_H_

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

// Returns a Win32 error. The old destination is never opened for writing.
DWORD SavePrivateExport(const std::wstring& path,
                        const std::vector<uint8_t>& bytes);

#endif
