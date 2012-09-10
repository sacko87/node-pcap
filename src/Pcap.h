#include <node.h>
#include <pcap/pcap.h>
#include <netinet/in.h>

class Pcap : node::ObjectWrap {
public:
  static void Init(v8::Handle<v8::Object> Target);

  static v8::Handle<v8::Value> FindAllDevices(const v8::Arguments& Args);
  static v8::Handle<v8::Value> LibraryVersion(const v8::Arguments& Args);
private:
  Pcap();
  ~Pcap();

  static v8::Handle<v8::Value> NtoP(struct sockaddr *SocketAddress);
};
