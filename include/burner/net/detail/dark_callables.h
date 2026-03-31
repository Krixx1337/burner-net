#pragma once

#include <concepts>
#include <memory>
#include <type_traits>
#include <utility>

namespace burner::net::detail {

template <typename T>
class SecureHandle {
public:
    SecureHandle() noexcept = default;

    explicit SecureHandle(T* pointer) noexcept
        : pointer_(pointer) {
        if constexpr (!std::is_void_v<T>) {
            destroy_ = [](const void* raw) { delete static_cast<const T*>(raw); };
            clone_ = [](const void* raw) -> void* { return new std::remove_const_t<T>(*static_cast<const T*>(raw)); };
        }
    }

    template <typename U, typename... Args>
    [[nodiscard]] static SecureHandle make(Args&&... args) {
        auto* value = new U(std::forward<Args>(args)...);
        return SecureHandle(
            static_cast<T*>(value),
            [](const void* raw) { delete static_cast<const U*>(raw); },
            [](const void* raw) -> void* { return new U(*static_cast<const U*>(raw)); });
    }

    SecureHandle(const SecureHandle& other) {
        copy_from(other);
    }

    SecureHandle(SecureHandle&& other) noexcept
        : pointer_(std::exchange(other.pointer_, nullptr)),
          destroy_(std::exchange(other.destroy_, nullptr)),
          clone_(std::exchange(other.clone_, nullptr)) {}

    SecureHandle& operator=(const SecureHandle& other) {
        if (this != &other) {
            reset();
            copy_from(other);
        }
        return *this;
    }

    SecureHandle& operator=(SecureHandle&& other) noexcept {
        if (this != &other) {
            reset();
            pointer_ = std::exchange(other.pointer_, nullptr);
            destroy_ = std::exchange(other.destroy_, nullptr);
            clone_ = std::exchange(other.clone_, nullptr);
        }
        return *this;
    }

    ~SecureHandle() {
        reset();
    }

    void reset() noexcept {
        if (pointer_ != nullptr && destroy_ != nullptr) {
            destroy_(pointer_);
        }
        pointer_ = nullptr;
        destroy_ = nullptr;
        clone_ = nullptr;
    }

    [[nodiscard]] T* get() noexcept { return pointer_; }
    [[nodiscard]] const T* get() const noexcept { return pointer_; }
    [[nodiscard]] T* operator->() noexcept { return pointer_; }
    [[nodiscard]] const T* operator->() const noexcept { return pointer_; }
    [[nodiscard]] explicit operator bool() const noexcept { return pointer_ != nullptr; }

private:
    using destroy_fn = void (*)(const void*);
    using clone_fn = void* (*)(const void*);

    SecureHandle(T* pointer, destroy_fn destroy, clone_fn clone) noexcept
        : pointer_(pointer), destroy_(destroy), clone_(clone) {}

    void copy_from(const SecureHandle& other) {
        destroy_ = other.destroy_;
        clone_ = other.clone_;
        pointer_ = (other.pointer_ != nullptr && clone_ != nullptr)
            ? static_cast<T*>(clone_(other.pointer_))
            : nullptr;
    }

    T* pointer_ = nullptr;
    destroy_fn destroy_ = nullptr;
    clone_fn clone_ = nullptr;
};

template <typename Signature>
class CompactCallable;

template <typename R, typename... Args>
class CompactCallable<R(Args...)> {
public:
    CompactCallable() noexcept = default;

    CompactCallable(std::nullptr_t) noexcept {}

    template <typename Fn>
    requires (!std::same_as<std::remove_cvref_t<Fn>, CompactCallable>)
    CompactCallable(Fn&& fn) {
        emplace(std::forward<Fn>(fn));
    }

    CompactCallable(const CompactCallable& other) {
        copy_from(other);
    }

    CompactCallable(CompactCallable&& other) noexcept
        : context_(std::exchange(other.context_, nullptr)),
          invoke_(std::exchange(other.invoke_, nullptr)),
          clone_(std::exchange(other.clone_, nullptr)),
          destroy_(std::exchange(other.destroy_, nullptr)) {}

    CompactCallable& operator=(const CompactCallable& other) {
        if (this != &other) {
            reset();
            copy_from(other);
        }
        return *this;
    }

    CompactCallable& operator=(CompactCallable&& other) noexcept {
        if (this != &other) {
            reset();
            context_ = std::exchange(other.context_, nullptr);
            invoke_ = std::exchange(other.invoke_, nullptr);
            clone_ = std::exchange(other.clone_, nullptr);
            destroy_ = std::exchange(other.destroy_, nullptr);
        }
        return *this;
    }

    ~CompactCallable() {
        reset();
    }

    template <typename Fn>
    requires (!std::same_as<std::remove_cvref_t<Fn>, CompactCallable>)
    void emplace(Fn&& fn) {
        using stored_type = std::decay_t<Fn>;

        reset();
        auto* stored = new stored_type(std::forward<Fn>(fn));
        context_ = stored;
        invoke_ = [](const void* raw, Args&&... args) -> R {
            return (*static_cast<const stored_type*>(raw))(std::forward<Args>(args)...);
        };
        clone_ = [](const void* raw) -> void* {
            return new stored_type(*static_cast<const stored_type*>(raw));
        };
        destroy_ = [](void* raw) {
            delete static_cast<stored_type*>(raw);
        };
    }

    void reset() noexcept {
        if (context_ != nullptr && destroy_ != nullptr) {
            destroy_(context_);
        }
        context_ = nullptr;
        invoke_ = nullptr;
        clone_ = nullptr;
        destroy_ = nullptr;
    }

    [[nodiscard]] explicit operator bool() const noexcept {
        return invoke_ != nullptr;
    }

    [[nodiscard]] R operator()(Args... args) const {
        if (invoke_ == nullptr) {
            if constexpr (std::is_void_v<R>) {
                return;
            } else {
                return R{};
            }
        }
        return invoke_(context_, std::forward<Args>(args)...);
    }

private:
    using invoke_fn = R (*)(const void*, Args&&...);
    using clone_fn = void* (*)(const void*);
    using destroy_fn = void (*)(void*);

    void copy_from(const CompactCallable& other) {
        invoke_ = other.invoke_;
        clone_ = other.clone_;
        destroy_ = other.destroy_;
        context_ = other.context_ != nullptr && other.clone_ != nullptr
            ? other.clone_(other.context_)
            : nullptr;
    }

    void* context_ = nullptr;
    invoke_fn invoke_ = nullptr;
    clone_fn clone_ = nullptr;
    destroy_fn destroy_ = nullptr;
};

} // namespace burner::net::detail
