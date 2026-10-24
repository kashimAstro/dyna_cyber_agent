#pragma once
#include <string>
#include <utility>
#include <variant>

namespace agent {

struct Error {
  std::string message;
};

// Minimal std::expected stand-in (C++20 has no std::expected).
template <typename T>
class Result {
 public:
  Result(T value) : v_(std::move(value)) {}
  Result(Error err) : v_(std::move(err)) {}

  bool ok() const { return std::holds_alternative<T>(v_); }
  explicit operator bool() const { return ok(); }
  T& value() { return std::get<T>(v_); }
  const T& value() const { return std::get<T>(v_); }
  const std::string& error() const { return std::get<Error>(v_).message; }

 private:
  std::variant<T, Error> v_;
};

inline Error err(std::string m) { return Error{std::move(m)}; }

}  // namespace agent
