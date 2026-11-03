#include "../private_export.h"
#include <aclapi.h>
#include <sddl.h>
#include <objbase.h>
#include <filesystem>
#include <fstream>
#include <iostream>

#define CHECK(condition) do { if (!(condition)) { std::cerr << "Failed at line " << __LINE__ << ", error " << GetLastError() << "\n"; return 1; } } while (false)

std::string Read(const std::wstring& path) {
  std::ifstream input(std::filesystem::path(path), std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(input), {});
}

bool Protected(HANDLE file) {
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  PACL acl = nullptr;
  PSID owner = nullptr;
  if (GetSecurityInfo(file, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                      &owner, nullptr, &acl, nullptr, &descriptor) != ERROR_SUCCESS) return false;
  SECURITY_DESCRIPTOR_CONTROL control{};
  DWORD revision = 0;
  void* raw = nullptr;
  bool ok = GetSecurityDescriptorControl(descriptor, &control, &revision) &&
      (control & SE_DACL_PROTECTED) && acl && acl->AceCount == 1 && GetAce(acl, 0, &raw);
  if (ok) {
    const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
    ok = ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && ace->Header.AceFlags == 0 &&
        EqualSid(owner, const_cast<DWORD*>(&ace->SidStart));
  }
  LocalFree(descriptor);
  return ok;
}

int wmain() {
  wchar_t base[MAX_PATH]{};
  CHECK(GetTempPathW(MAX_PATH, base));
  GUID guid{};
  CHECK(SUCCEEDED(CoCreateGuid(&guid)));
  wchar_t id[40]{};
  CHECK(StringFromGUID2(guid, id, 40));
  const std::wstring directory = std::wstring(base) + L"ashapp-native-export-" + id;
  // Only this disposable synthetic-data directory is deliberately shared.
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(
      L"D:PAI(A;OICI;FA;;;WD)", SDDL_REVISION_1, &descriptor, nullptr));
  SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
  const BOOL made = CreateDirectoryW(directory.c_str(), &attributes);
  LocalFree(descriptor);
  CHECK(made);
  struct Cleanup {
    std::wstring path;
    ~Cleanup() { std::error_code error; std::filesystem::remove_all(path, error); }
  } cleanup{directory};
  const std::wstring path = directory + L"\\private.conf";
  const std::vector<uint8_t> secret{'n', 'e', 'w', '-', 't', 'e', 's', 't'};
  CHECK(SavePrivateExport(path, secret) == ERROR_SUCCESS);
  HANDLE file = CreateFileW(path.c_str(), READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
  CHECK(file != INVALID_HANDLE_VALUE);
  CHECK(Protected(file));
  CloseHandle(file);
  CHECK(Read(path) == "new-test");
  // Existing harmless data is readable through a held descriptor and hard link.
  const std::wstring existing = directory + L"\\existing.conf";
  { std::ofstream output{std::filesystem::path(existing)}; output << "old-harmless"; }
  const std::wstring alias = directory + L"\\alias.conf";
  CHECK(CreateHardLinkW(alias.c_str(), existing.c_str(), nullptr));
  HANDLE reader = CreateFileW(existing.c_str(), GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
  CHECK(reader != INVALID_HANDLE_VALUE);
  CHECK(SavePrivateExport(existing, secret) == ERROR_SUCCESS);
  char bytes[32]{};
  DWORD count = 0;
  CHECK(ReadFile(reader, bytes, sizeof(bytes), &count, nullptr));
  CloseHandle(reader);
  CHECK(std::string(bytes, count) == "old-harmless");
  CHECK(Read(alias) == "old-harmless");
  CHECK(Read(existing) == "new-test");
  file = CreateFileW(existing.c_str(), READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
  CHECK(file != INVALID_HANDLE_VALUE);
  CHECK(Protected(file));
  CloseHandle(file);
  // If replacement is prevented by another handle, the old file stays intact.
  reader = CreateFileW(existing.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
  CHECK(reader != INVALID_HANDLE_VALUE);
  CHECK(SavePrivateExport(existing, {'x'}) != ERROR_SUCCESS);
  CloseHandle(reader);
  CHECK(Read(existing) == "new-test");
  CHECK(SavePrivateExport(directory, secret) != ERROR_SUCCESS);
  CHECK(SavePrivateExport(path + L":stream", secret) != ERROR_SUCCESS);
  CHECK(SavePrivateExport(L"relative.conf", secret) != ERROR_SUCCESS);
  const std::wstring unicode = directory + L"\\caf\u00e9.conf";
  CHECK(SavePrivateExport(unicode, {}) == ERROR_SUCCESS);
  CHECK(Read(unicode).empty());
  const std::wstring link = directory + L"\\link.conf";
  if (CreateSymbolicLinkW(link.c_str(), existing.c_str(), SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
    CHECK(SavePrivateExport(link, secret) != ERROR_SUCCESS);
    CHECK(Read(existing) == "new-test");
  } else {
    CHECK(GetLastError() == ERROR_PRIVILEGE_NOT_HELD);
    std::cout << "SKIP symlink creation: Developer Mode is unavailable\n";
  }
  for (const auto& item : std::filesystem::directory_iterator(directory)) {
    CHECK(item.path().filename().wstring().find(L".ashapp-export-") != 0);
  }
  std::cout << "PASS private DACL, inherited/old ACL replacement, retained reader, hard links, failed replacement, invalid paths, Unicode and empty export\n";
  return 0;
}
