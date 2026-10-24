#pragma once
#include <memory>

#include "core/config.h"
#include "transport/transport.h"

namespace agent {

Result<std::unique_ptr<ITransport>> makeTransport(const TargetConfig& target);

}  // namespace agent
