#if defined(_WIN32)
#include <windows.h>
#endif

#include <filesystem>

int main(int argc, char** argv) {
#if !defined(_WIN32)
    (void)argc;
    (void)argv;
    return 0;
#else
    if (argc != 3) {
        return 1;
    }

    const std::filesystem::path consumer_path =
        std::filesystem::absolute(std::filesystem::path(argv[1]));
    const std::wstring burner_module_name =
        std::filesystem::path(argv[2]).wstring();

    HMODULE consumer = ::LoadLibraryW(consumer_path.c_str());
    if (consumer == nullptr) {
        return 2;
    }

    using InitializeFn = int (*)();
    auto initialize = reinterpret_cast<InitializeFn>(
        ::GetProcAddress(consumer, "InitializeMaximumGhostFromSharedConsumer"));
    if (initialize == nullptr || initialize() != 0) {
        ::FreeLibrary(consumer);
        return 3;
    }

    if (::GetModuleHandleW(burner_module_name.c_str()) == nullptr) {
        ::FreeLibrary(consumer);
        return 4;
    }

    if (!::FreeLibrary(consumer)) {
        return 5;
    }

    return ::GetModuleHandleW(burner_module_name.c_str()) != nullptr ? 0 : 6;
#endif
}
