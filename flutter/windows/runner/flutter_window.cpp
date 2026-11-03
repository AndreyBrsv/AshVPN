#include "flutter_window.h"

#include <optional>
#include <shlobj.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <flutter/standard_method_codec.h>
#include "private_export.h"

#include "flutter/generated_plugin_registrant.h"

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
    if (!text || text->empty() || text->size() > 30000 || text->find('\0') != std::string::npos) {
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
    CoTaskMemFree(local);
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
    SHELLEXECUTEINFOW launch = {};
    launch.cbSize = sizeof(launch);
    launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    launch.hwnd = GetHandle();
    launch.lpVerb = L"open";
    launch.lpFile = file.c_str();
    launch.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&launch)) { result->Error("update_failed", "Could not open the system installer."); return; }
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
