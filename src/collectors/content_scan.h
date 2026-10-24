#pragma once
#include <string>
#include <vector>

namespace agent {

// Looks for classic persistence/backdoor idioms in the text of a script, cron line, unit file or shell profile.
// Tags: pipe_to_shell, base64_exec, reverse_shell, ld_preload, anti_forensics, alias_hijack, volatile_dir_reference.
// This is deliberately simple substring matching: fast, predictable, and easy to extend.
std::vector<std::string> suspiciousContentTags(const std::string& text);

bool inVolatileDir(const std::string& path);  // /tmp, /var/tmp, /dev/shm
bool inSystemBinaryDir(const std::string& path);

}  // namespace agent
