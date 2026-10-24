#include "transport/transport.h"

#include "core/util.h"

namespace agent {

Result<TailResult> ITransport::tailFile(const std::string&, uint64_t, uint64_t) { return err("tailFile not supported by this transport"); }
Result<JournalResult> ITransport::journal(const std::string&, const std::string&, uint64_t) { return err("journal not supported by this transport"); }
Result<std::vector<ScanEntry>> ITransport::scan(const std::string&) { return err("scan not supported by this transport"); }

std::vector<OpResult> ITransport::bulk(const std::vector<ReadOp>& ops) {
  std::vector<OpResult> out;
  out.reserve(ops.size());
  for (const auto& op : ops) {
    OpResult r;
    auto fail = [&](const std::string& m) {
      r.ok = false;
      r.error = m;
    };
    switch (op.kind) {
      case ReadOp::Kind::ReadFile:
        if (auto x = readFile(op.path, op.limit)) { r.ok = true; r.file = std::move(x.value()); } else fail(x.error());
        break;
      case ReadOp::Kind::ReadLink:
        if (auto x = readLink(op.path)) { r.ok = true; r.text = std::move(x.value()); } else fail(x.error());
        break;
      case ReadOp::Kind::ListDir:
        if (auto x = listDir(op.path)) { r.ok = true; r.entries = std::move(x.value()); } else fail(x.error());
        break;
      case ReadOp::Kind::Stat:
        if (auto x = stat(op.path)) { r.ok = true; r.info = x.value(); } else fail(x.error());
        break;
      case ReadOp::Kind::Sha256:
        if (auto x = sha256File(op.path, op.limit)) { r.ok = true; r.text = std::move(x.value()); } else fail(x.error());
        break;
      case ReadOp::Kind::RwxMapCount:
        if (auto x = readFile(op.path, 16u << 20)) { r.ok = true; r.count = util::countRwxMappings(x.value().data); } else fail(x.error());
        break;
      case ReadOp::Kind::Tail:
        if (auto x = tailFile(op.path, op.offset, op.limit)) { r.ok = true; r.tail = std::move(x.value()); } else fail(x.error());
        break;
      case ReadOp::Kind::Journal:
        if (auto x = journal(op.path, op.arg, op.limit)) { r.ok = true; r.journal = std::move(x.value()); } else fail(x.error());
        break;
      case ReadOp::Kind::Scan:
        if (auto x = scan(op.path)) { r.ok = true; r.scan = std::move(x.value()); } else fail(x.error());
        break;
      case ReadOp::Kind::SocketInodes: {
        auto fds = listDir(op.path);
        if (!fds) { fail(fds.error()); break; }
        r.ok = true;
        for (const auto& fd : fds.value()) {
          auto l = readLink(op.path + "/" + fd.name);
          if (!l || !util::startsWith(l.value(), "socket:[") || l.value().size() < 10) continue;
          if (const auto inode = util::parseUint(l.value().substr(8, l.value().size() - 9))) r.inodes.push_back(*inode);
        }
        break;
      }
    }
    out.push_back(std::move(r));
  }
  return out;
}

}  // namespace agent
