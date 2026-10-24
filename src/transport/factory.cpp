#include "transport/factory.h"

#include "transport/local_transport.h"
#include "transport/ssh_transport.h"

namespace agent {

Result<std::unique_ptr<ITransport>> makeTransport(const TargetConfig& target) {
  if (target.transport == "local") return std::unique_ptr<ITransport>(std::make_unique<LocalTransport>());
  if (target.transport == "ssh") {
    SshOptions o;
    o.host = target.ssh.host;
    o.port = target.ssh.port;
    o.user = target.ssh.user;
    o.key_file = target.ssh.key_file;
    o.known_hosts = target.ssh.known_hosts;
    o.proxy_jump = target.ssh.proxy_jump;
    o.ssh_binary = target.ssh.ssh_binary;
    o.gate_mode = target.ssh.gate;
    o.gate_path = target.ssh.gate_path;
    o.sudo = target.ssh.sudo;
    o.connect_timeout = std::chrono::seconds(target.ssh.connect_timeout);
    o.op_timeout = std::chrono::seconds(target.ssh.op_timeout);
    return std::unique_ptr<ITransport>(std::make_unique<SshTransport>(std::move(o)));  // connects on first use
  }
  return err("unknown transport '" + target.transport + "' (target '" + target.name + "')");
}

}  // namespace agent
