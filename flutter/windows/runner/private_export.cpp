#include "private_export.h"

#include <aclapi.h>
#include <sddl.h>
#include <objbase.h>
#include <cstring>
#include <limits>

namespace {
class Handle {
 public:
  explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) : value_(value) {}
  ~Handle() { if (value_ != INVALID_HANDLE_VALUE && value_ != nullptr) CloseHandle(value_); }
  HANDLE get() const { return value_; }
 private:
  HANDLE value_;
};

DWORD RegularFile(HANDLE file) {
  BY_HANDLE_FILE_INFORMATION info{};
  if (GetFileType(file) != FILE_TYPE_DISK || !GetFileInformationByHandle(file, &info))
    return ERROR_INVALID_HANDLE;
  if (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))
    return ERROR_INVALID_NAME;
  return ERROR_SUCCESS;
}

bool PrivateAcl(HANDLE file, PSID user) {
  PACL acl = nullptr;
  PSID owner = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                      &owner, nullptr, &acl, nullptr, &descriptor) != ERROR_SUCCESS) return false;
  SECURITY_DESCRIPTOR_CONTROL control{};
  DWORD revision = 0;
  void* raw = nullptr;
  bool valid = owner && EqualSid(owner, user) && acl && acl->AceCount == 1 &&
      GetSecurityDescriptorControl(descriptor, &control, &revision) &&
      (control & SE_DACL_PROTECTED) && GetAce(acl, 0, &raw);
  if (valid) {
    const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
    valid = ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && ace->Header.AceFlags == 0 &&
        EqualSid(const_cast<DWORD*>(&ace->SidStart), user) &&
        (ace->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS;
  }
  LocalFree(descriptor);
  return valid;
}
}  // namespace

DWORD SavePrivateExport(const std::wstring& path, const std::vector<uint8_t>& bytes) {
  // The file picker returns absolute local paths. Refuse streams/device/UNC paths.
  if (path.size() < 4 || path.find(L'\0') != std::wstring::npos ||
      !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) ||
      path[1] != L':' || (path[2] != L'\\' && path[2] != L'/') ||
      path.find(L':', 2) != std::wstring::npos || bytes.size() > 1024 * 1024)
    return ERROR_INVALID_NAME;
  std::vector<wchar_t> absolute(32768);
  const DWORD length = GetFullPathNameW(path.c_str(), static_cast<DWORD>(absolute.size()), absolute.data(), nullptr);
  if (!length || length >= absolute.size()) return ERROR_INVALID_NAME;
  const std::wstring full(absolute.data(), length);
  const UINT drive = GetDriveTypeW(full.substr(0, 3).c_str());
  if (drive != DRIVE_FIXED && drive != DRIVE_REMOVABLE) return ERROR_NOT_SUPPORTED;
  const auto separator = full.find_last_of(L"\\/");
  const std::wstring leaf = full.substr(separator + 1);
  if (leaf.empty() || leaf == L"." || leaf == L".." || leaf.back() == L'.' || leaf.back() == L' ')
    return ERROR_INVALID_NAME;
  const std::wstring parent = full.substr(0, separator + 1);
  Handle directory(CreateFileW(parent.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
      nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (directory.get() == INVALID_HANDLE_VALUE) return GetLastError();
  BY_HANDLE_FILE_INFORMATION parent_info{};
  if (!GetFileInformationByHandle(directory.get(), &parent_info) ||
      !(parent_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
      (parent_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) return ERROR_INVALID_NAME;
  DWORD flags = 0;
  if (!GetVolumeInformationByHandleW(directory.get(), nullptr, 0, nullptr, nullptr, &flags, nullptr, 0) ||
      !(flags & FILE_PERSISTENT_ACLS)) return ERROR_NOT_SUPPORTED;
  std::vector<wchar_t> canonical(32768);
  const DWORD count = GetFinalPathNameByHandleW(directory.get(), canonical.data(),
      static_cast<DWORD>(canonical.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (!count || count >= canonical.size()) return ERROR_INVALID_NAME;
  const std::wstring folder = std::wstring(canonical.data(), count) + L"\\";
  const std::wstring destination = folder + leaf;
  Handle existing(CreateFileW(destination.c_str(), FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
      FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
  if (existing.get() != INVALID_HANDLE_VALUE) {
    const DWORD checked = RegularFile(existing.get());
    if (checked != ERROR_SUCCESS) return checked;
  } else if (GetLastError() != ERROR_FILE_NOT_FOUND) {
    return GetLastError();
  }

  HANDLE raw_token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token)) return GetLastError();
  Handle token(raw_token);
  DWORD token_size = 0;
  GetTokenInformation(token.get(), TokenUser, nullptr, 0, &token_size);
  if (!token_size) return GetLastError();
  std::vector<BYTE> token_data(token_size);
  if (!GetTokenInformation(token.get(), TokenUser, token_data.data(), token_size, &token_size)) return GetLastError();
  PSID user = reinterpret_cast<TOKEN_USER*>(token_data.data())->User.Sid;
  LPWSTR sid = nullptr;
  if (!ConvertSidToStringSidW(user, &sid)) return GetLastError();
  const std::wstring sddl = L"O:" + std::wstring(sid) + L"D:P(A;;FA;;;" + sid + L")";
  LocalFree(sid);
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr))
    return GetLastError();
  SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
  GUID guid{};
  if (FAILED(CoCreateGuid(&guid))) { LocalFree(descriptor); return ERROR_GEN_FAILURE; }
  wchar_t identifier[40]{};
  if (!StringFromGUID2(guid, identifier, 40)) { LocalFree(descriptor); return ERROR_GEN_FAILURE; }
  const std::wstring temporary = folder + L".ashapp-export-" + identifier;
  HANDLE raw_file = CreateFileW(temporary.c_str(), GENERIC_WRITE | FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE, 0,
      &attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  const DWORD create_error = GetLastError();
  LocalFree(descriptor);
  if (raw_file == INVALID_HANDLE_VALUE) return create_error;
  Handle file(raw_file);
  DWORD result = RegularFile(file.get());
  if (result == ERROR_SUCCESS && !PrivateAcl(file.get(), user)) result = ERROR_ACCESS_DENIED;
  DWORD written = 0;
  if (result == ERROR_SUCCESS && (!WriteFile(file.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) ||
      written != bytes.size() || !FlushFileBuffers(file.get()))) result = ERROR_WRITE_FAULT;
  if (result == ERROR_SUCCESS) {
    const size_t size = sizeof(FILE_RENAME_INFO) + destination.size() * sizeof(wchar_t);
    std::vector<BYTE> data(size, 0);
    auto* rename = reinterpret_cast<FILE_RENAME_INFO*>(data.data());
    rename->Flags = FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS;
    rename->FileNameLength = static_cast<DWORD>(destination.size() * sizeof(wchar_t));
    std::memcpy(rename->FileName, destination.data(), rename->FileNameLength);
    if (!SetFileInformationByHandle(file.get(), FileRenameInfoEx, rename, static_cast<DWORD>(size))) result = GetLastError();
  }
  if (result != ERROR_SUCCESS) {
    FILE_DISPOSITION_INFO remove{TRUE};
    SetFileInformationByHandle(file.get(), FileDispositionInfo, &remove, sizeof(remove));
  }
  return result;
}
