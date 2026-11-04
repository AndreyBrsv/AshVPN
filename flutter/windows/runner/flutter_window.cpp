#include "flutter_window.h"

#include <optional>
#include <shlobj.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <bcrypt.h>
#include <flutter/standard_method_codec.h>
#include "private_export.h"

#include "flutter/generated_plugin_registrant.h"

namespace {
bool VerifyInstallerDigest(HANDLE file, const std::string& expected) {
  if (expected.size() != 64 || expected.find_first_not_of("0123456789abcdef") != std::string::npos) return false;
  LARGE_INTEGER length;
  if (!GetFileSizeEx(file, &length) || length.QuadPart <= 0 || length.QuadPart > 1024LL * 1024 * 1024) return false;
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return false;
  DWORD size = 0, received = 0;
  bool valid = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
      reinterpret_cast<PUCHAR>(&size), sizeof(size), &received, 0) >= 0;
  std::vector<UCHAR> object(size), buffer(64 * 1024), digest(32);
  if (valid) valid = BCryptCreateHash(algorithm, &hash, object.data(), size, nullptr, 0, 0) >= 0;
  while (valid) {
    DWORD count = 0;
    if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &count, nullptr)) { valid = false; break; }
    if (count == 0) break;
    valid = BCryptHashData(hash, buffer.data(), count, 0) >= 0;
  }
  if (valid) valid = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0;
  if (hash) BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  if (!valid) return false;
  const char* hex = "0123456789abcdef";
  std::string actual;
  for (auto value : digest) { actual += hex[value >> 4]; actual += hex[value & 15]; }
  return actual == expected;
}
}

FlutterWindow::FlutterWindow(const flutter::DartProject& project)
    : project_(project) {}

FlutterWindow::~FlutterWindow() {}

bool FlutterWindow::OnCreate() {
  if (!Win32Window::OnCreate()) {
    return false;
  }

  RECT frame = GetClientArea();

  // The size here must match the window dimensions to avoid unnecessary surface
  // creation / destruction in the startup path.
  flutter_controller_ = std::make_unique<flutter::FlutterViewController>(
      frame.right - frame.left, frame.bottom - frame.top, project_);
  // Ensure that basic setup of the controller was successful.
  if (!flutter_controller_->engine() || !flutter_controller_->view()) {
    return false;
  }
  RegisterPlugins(flutter_controller_->engine());
  update_channel_ = std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
      flutter_controller_->engine()->messenger(), "ashapp/app-update",
      &flutter::StandardMethodCodec::GetInstance());
  update_channel_->SetMethodCallHandler([this](const auto& call, auto result) {
    if (call.method_name() == "info") {
      flutter::EncodableMap info;
      info[flutter::EncodableValue("version")] = flutter::EncodableValue(FLUTTER_VERSION);
#if defined(_M_X64)
      info[flutter::EncodableValue("target")] = flutter::EncodableValue("windows-x64");
#else
      info[flutter::EncodableValue("target")] = flutter::EncodableValue("unsupported");
#endif
      result->Success(flutter::EncodableValue(info));
      return;
    }
    if (call.method_name() == "quit") {
      result->Success();
      PostMessage(GetHandle(), WM_CLOSE, 0, 0);
      return;
    }
    if (call.method_name() != "openInstaller") { result->NotImplemented(); return; }
    const auto* args = std::get_if<flutter::EncodableMap>(call.arguments());
    if (!args) { result->Error("update_failed", "Invalid installer."); return; }
    const auto item = args->find(flutter::EncodableValue("path"));
    const auto* text = item == args->end() ? nullptr : std::get_if<std::string>(&item->second);
    const auto sha = args->find(flutter::EncodableValue("sha256"));
    const auto* expected = sha == args->end() ? nullptr : std::get_if<std::string>(&sha->second);
    if (!text || !expected || text->empty() || text->size() > 30000 || text->find('\0') != std::string::npos) {
      result->Error("update_failed", "Invalid installer."); return;
    }
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text->data(), static_cast<int>(text->size()), nullptr, 0);
    std::wstring file(count > 0 ? count : 0, L'\0');
    PWSTR local = nullptr;
    if (count <= 0 || !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text->data(), static_cast<int>(text->size()), file.data(), count) ||
        FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &local))) {
      result->Error("update_failed", "Invalid installer."); return;
    }
    const std::wstring prefix = std::wstring(local) + L"\\Ashapp\\updates\\download-";
    const std::wstring installed = std::wstring(local) + L"\\Programs\\Ashapp\\ashapp.exe";
    CoTaskMemFree(local);
    wchar_t current[MAX_PATH];
    const DWORD current_length = GetModuleFileNameW(nullptr, current, MAX_PATH);
    if (current_length == 0 || current_length >= MAX_PATH || _wcsicmp(current, installed.c_str()) != 0) {
      result->Error("update_failed", "Install Ashapp in your user Programs folder before using background updates."); return;
    }
    const DWORD attributes = GetFileAttributesW(file.c_str());
    if (file.compare(0, prefix.size(), prefix) != 0 || file.find(L"..") != std::wstring::npos ||
        file.find(L':', 2) != std::wstring::npos || file.size() < 4 || file.substr(file.size() - 4) != L".exe" ||
        attributes == INVALID_FILE_ATTRIBUTES || (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) {
      result->Error("update_failed", "Invalid installer."); return;
    }
    // Preserve Windows attachment/antivirus policy and Mark of the Web for
    // bytes fetched by Dart rather than a browser. Never silently unblock them.
    IAttachmentExecute* attachment = nullptr;
    HRESULT marked = CoCreateInstance(CLSID_AttachmentServices, nullptr, CLSCTX_INPROC_SERVER,
                                      IID_PPV_ARGS(&attachment));
    if (SUCCEEDED(marked)) {
      marked = attachment->SetClientTitle(L"Ashapp update");
      if (SUCCEEDED(marked)) marked = attachment->SetLocalPath(file.c_str());
      if (SUCCEEDED(marked)) marked = attachment->SetSource(L"https://github.com/AndreyBrsv/Ashapp/releases");
      if (SUCCEEDED(marked)) marked = attachment->Save();
      attachment->Release();
    }
    if (FAILED(marked)) { result->Error("update_failed", "Windows security policy refused this download."); return; }
    // Deny writes/deletion while rehashing and handing this exact file to Windows.
    HANDLE verified = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (verified == INVALID_HANDLE_VALUE || !VerifyInstallerDigest(verified, *expected)) {
      if (verified != INVALID_HANDLE_VALUE) CloseHandle(verified);
      result->Error("update_failed", "The prepared update changed. Download it again."); return;
    }
    SHELLEXECUTEINFOW launch = {};
    launch.cbSize = sizeof(launch);
    launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    launch.hwnd = GetHandle();
    launch.lpVerb = L"open";
    launch.lpFile = file.c_str();
    // Fixed app-owned switches only; never accept remote installer arguments.
    // The new installer waits for our mutex, then relaunches on success.
    launch.lpParameters = L"/VERYSILENT /SP- /NORESTART /NOCLOSEAPPLICATIONS /ASHAPPUPDATE";
    launch.nShow = SW_HIDE;
    if (!ShellExecuteExW(&launch)) {
      CloseHandle(verified);
      result->Error("update_failed", "Could not start the update."); return;
    }
    CloseHandle(verified);
    if (launch.hProcess) CloseHandle(launch.hProcess);
    result->Success();
  });
  export_channel_ = std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
      flutter_controller_->engine()->messenger(), "ashapp/private-export",
      &flutter::StandardMethodCodec::GetInstance());
  export_channel_->SetMethodCallHandler([](const auto& call, auto result) {
    const auto* arguments = std::get_if<flutter::EncodableMap>(call.arguments());
    if (call.method_name() != "save" || !arguments) { result->NotImplemented(); return; }
    const auto path = arguments->find(flutter::EncodableValue("path"));
    const auto bytes = arguments->find(flutter::EncodableValue("bytes"));
    if (path == arguments->end() || bytes == arguments->end()) { result->Error("export_failed", "Invalid export."); return; }
    const auto* text = std::get_if<std::string>(&path->second);
    const auto* data = std::get_if<std::vector<uint8_t>>(&bytes->second);
    if (!text || !data || text->find('\0') != std::string::npos || text->size() > 131072) {
      result->Error("export_failed", "Invalid export."); return;
    }
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text->data(), static_cast<int>(text->size()), nullptr, 0);
    std::wstring wide(count > 0 ? count : 0, L'\0');
    if (count <= 0 || !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text->data(), static_cast<int>(text->size()), wide.data(), count) ||
        SavePrivateExport(wide, *data) != ERROR_SUCCESS) {
      result->Error("export_failed", "Could not save private configuration."); return;
    }
    result->Success();
  });
  SetChildContent(flutter_controller_->view()->GetNativeWindow());

  flutter_controller_->engine()->SetNextFrameCallback([&]() {
    this->Show();
  });

  // Flutter can complete the first frame before the "show window" callback is
  // registered. The following call ensures a frame is pending to ensure the
  // window is shown. It is a no-op if the first frame hasn't completed yet.
  flutter_controller_->ForceRedraw();

  return true;
}

void FlutterWindow::OnDestroy() {
  update_channel_ = nullptr;
  export_channel_ = nullptr;
  if (flutter_controller_) {
    flutter_controller_ = nullptr;
  }

  Win32Window::OnDestroy();
}

LRESULT
FlutterWindow::MessageHandler(HWND hwnd, UINT const message,
                              WPARAM const wparam,
                              LPARAM const lparam) noexcept {
  // Give Flutter, including plugins, an opportunity to handle window messages.
  if (flutter_controller_) {
    std::optional<LRESULT> result =
        flutter_controller_->HandleTopLevelWindowProc(hwnd, message, wparam,
                                                      lparam);
    if (result) {
      return *result;
    }
  }

  switch (message) {
    case WM_FONTCHANGE:
      flutter_controller_->engine()->ReloadSystemFonts();
      break;
  }

  return Win32Window::MessageHandler(hwnd, message, wparam, lparam);
}
