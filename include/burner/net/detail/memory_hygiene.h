#pragma once

#include "burner/net/export.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#ifndef HOSTILE_CORE_EXPORT
#define HOSTILE_CORE_EXPORT
#endif

namespace burner::net::obf {

HOSTILE_CORE_EXPORT void secure_wipe(void* ptr, std::size_t size) noexcept;

inline void secure_wipe(std::string& value) noexcept {
    secure_wipe(value.data(), value.capacity());
    value.clear();
}

template <typename T>
inline void secure_wipe(std::vector<T>& value) noexcept {
    secure_wipe(value.data(), value.capacity() * sizeof(T));
    value.clear();
}

template <typename T>
inline void secure_wipe(std::span<T> value) noexcept {
    secure_wipe(value.data(), value.size_bytes());
}

} // namespace burner::net::obf

namespace burner::net {

class SecureString {
public:
    using value_type = std::string::value_type;
    using size_type = std::string::size_type;

    SecureString() {
        new (&m_storage) std::string();
        m_engaged = true;
    }

    SecureString(const char* value) {
        new (&m_storage) std::string(value == nullptr ? "" : value);
        m_engaged = true;
    }

    SecureString(std::string value) {
        new (&m_storage) std::string(std::move(value));
        m_engaged = true;
    }

    SecureString(std::string_view value) {
        new (&m_storage) std::string(value);
        m_engaged = true;
    }

    SecureString(const SecureString& other) {
        new (&m_storage) std::string(other.str());
        m_engaged = true;
    }

    SecureString(SecureString&& other) noexcept {
        new (&m_storage) std::string(std::move(other.str()));
        m_engaged = true;
        other.wipe_and_reset();
    }

    SecureString& operator=(const SecureString& other) {
        if (this != &other) {
            str() = other.str();
        }
        return *this;
    }

    SecureString& operator=(SecureString&& other) noexcept {
        if (this != &other) {
            str() = std::move(other.str());
            other.wipe_and_reset();
        }
        return *this;
    }

    SecureString& operator=(const char* value) {
        str() = value == nullptr ? "" : value;
        return *this;
    }

    SecureString& operator=(std::string value) {
        str() = std::move(value);
        return *this;
    }

    SecureString& operator=(std::string_view value) {
        str() = value;
        return *this;
    }

    ~SecureString() {
        wipe_and_reset();
    }

    [[nodiscard]] std::string& str() noexcept { return *ptr(); }
    [[nodiscard]] const std::string& str() const noexcept { return *ptr(); }

    [[nodiscard]] char* data() noexcept { return str().data(); }
    [[nodiscard]] const char* data() const noexcept { return str().data(); }
    [[nodiscard]] const char* c_str() const noexcept { return str().c_str(); }
    [[nodiscard]] bool empty() const noexcept { return str().empty(); }
    [[nodiscard]] size_type size() const noexcept { return str().size(); }
    [[nodiscard]] size_type capacity() const noexcept { return str().capacity(); }

    void clear() noexcept { str().clear(); }
    void reserve(size_type new_capacity) { str().reserve(new_capacity); }
    void resize(size_type count) { str().resize(count); }
    void resize(size_type count, char value) { str().resize(count, value); }
    void append(std::string_view value) { str().append(value); }
    void append(const char* value, size_type count) { str().append(value, count); }
    void push_back(char value) { str().push_back(value); }

    [[nodiscard]] operator std::string&() noexcept { return str(); }
    [[nodiscard]] operator const std::string&() const noexcept { return str(); }
    [[nodiscard]] operator std::string_view() const noexcept { return str(); }

private:
    using storage_type = std::aligned_storage_t<sizeof(std::string), alignof(std::string)>;

    [[nodiscard]] std::string* ptr() noexcept {
        return std::launder(reinterpret_cast<std::string*>(&m_storage));
    }

    [[nodiscard]] const std::string* ptr() const noexcept {
        return std::launder(reinterpret_cast<const std::string*>(&m_storage));
    }

    void wipe_and_reset() noexcept {
        if (!m_engaged) {
            return;
        }

        std::string* value = ptr();
        obf::secure_wipe(value->data(), value->capacity());
        value->clear();
        std::destroy_at(value);
        obf::secure_wipe(&m_storage, sizeof(m_storage));
        m_engaged = false;
    }

    storage_type m_storage{};
    bool m_engaged = false;
};

class SecureBuffer {
public:
    using value_type = std::uint8_t;
    using storage_type = std::vector<value_type>;
    using size_type = storage_type::size_type;

    SecureBuffer() {
        new (&m_storage) storage_type();
        m_engaged = true;
    }

    SecureBuffer(std::initializer_list<value_type> values) {
        new (&m_storage) storage_type(values);
        m_engaged = true;
    }

    explicit SecureBuffer(storage_type value) {
        new (&m_storage) storage_type(std::move(value));
        m_engaged = true;
    }

    SecureBuffer(const SecureBuffer& other) {
        new (&m_storage) storage_type(other.buffer());
        m_engaged = true;
    }

    SecureBuffer(SecureBuffer&& other) noexcept {
        new (&m_storage) storage_type(std::move(other.buffer()));
        m_engaged = true;
        other.wipe_and_reset();
    }

    SecureBuffer& operator=(const SecureBuffer& other) {
        if (this != &other) {
            buffer() = other.buffer();
        }
        return *this;
    }

    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            buffer() = std::move(other.buffer());
            other.wipe_and_reset();
        }
        return *this;
    }

    ~SecureBuffer() {
        wipe_and_reset();
    }

    [[nodiscard]] storage_type& buffer() noexcept { return *ptr(); }
    [[nodiscard]] const storage_type& buffer() const noexcept { return *ptr(); }

    [[nodiscard]] value_type* data() noexcept { return buffer().data(); }
    [[nodiscard]] const value_type* data() const noexcept { return buffer().data(); }
    [[nodiscard]] bool empty() const noexcept { return buffer().empty(); }
    [[nodiscard]] size_type size() const noexcept { return buffer().size(); }
    [[nodiscard]] size_type capacity() const noexcept { return buffer().capacity(); }

    void clear() noexcept { buffer().clear(); }
    void reserve(size_type new_capacity) { buffer().reserve(new_capacity); }
    void resize(size_type count) { buffer().resize(count); }
    void push_back(value_type value) { buffer().push_back(value); }

    [[nodiscard]] operator storage_type&() noexcept { return buffer(); }
    [[nodiscard]] operator const storage_type&() const noexcept { return buffer(); }

private:
    using raw_storage_type = std::aligned_storage_t<sizeof(storage_type), alignof(storage_type)>;

    [[nodiscard]] storage_type* ptr() noexcept {
        return std::launder(reinterpret_cast<storage_type*>(&m_storage));
    }

    [[nodiscard]] const storage_type* ptr() const noexcept {
        return std::launder(reinterpret_cast<const storage_type*>(&m_storage));
    }

    void wipe_and_reset() noexcept {
        if (!m_engaged) {
            return;
        }

        storage_type* value = ptr();
        obf::secure_wipe(value->data(), value->capacity() * sizeof(value_type));
        value->clear();
        std::destroy_at(value);
        obf::secure_wipe(&m_storage, sizeof(m_storage));
        m_engaged = false;
    }

    raw_storage_type m_storage{};
    bool m_engaged = false;
};

} // namespace burner::net
