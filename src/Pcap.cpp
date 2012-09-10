#include "Pcap.h"

using namespace v8;

Pcap::Pcap() { }
Pcap::~Pcap() { }

void
Pcap::Init(Handle<Object> Target) {
  HandleScope scope;
}

Handle<Value>
Pcap::FindAllDevices(const Arguments& Args) {
  HandleScope scope;
  char pcapErrorBuffer[PCAP_ERRBUF_SIZE];

  pcap_if_t *allDevices, *currentDevice;

  if(pcap_findalldevs(&allDevices, pcapErrorBuffer) == -1 || allDevices == NULL) {
    return ThrowException(Exception::TypeError(String::New(pcapErrorBuffer)));
  }

  Local<Array> DeviceArray = Array::New();

  int deviceIndex = 0;
  for(currentDevice = allDevices; currentDevice != NULL; currentDevice = currentDevice->next) {
    Local<Object> Device = Object::New();
    Device->Set(String::NewSymbol("name"), String::New(currentDevice->name));
    if(currentDevice->description != NULL)
      Device->Set(String::NewSymbol("description"), String::New(currentDevice->description));

    int addressIndex = 0;
    Local<Array> AddressArray = Array::New();
    for(pcap_addr_t *currentAddress = currentDevice->addresses; currentAddress != NULL; currentAddress = currentAddress->next) {
      int AddressFamily = currentAddress->addr->sa_family;
      if(AddressFamily == AF_INET || AddressFamily == AF_INET6) {
        Local<Object> Address = Object::New();

        Handle<Value> Addr;
#define PCAP_ADDR_FIELD(addrField) \
        if(currentAddress->addrField != NULL) {\
          Addr = Pcap::NtoP(currentAddress->addrField);\
          if(Addr->IsString())\
            Address->Set(String::NewSymbol(#addrField), Addr);\
        }

        PCAP_ADDR_FIELD(addr)
        PCAP_ADDR_FIELD(netmask)
        PCAP_ADDR_FIELD(broadaddr)
        PCAP_ADDR_FIELD(dstaddr)

#undef PCAP_ADDR_FIELD

        if(Address->GetPropertyNames()->Length() > 0)
          AddressArray->Set(Integer::New(addressIndex++), Address);
      }
    }

    if(AddressArray->Length() > 0)
      Device->Set(String::NewSymbol("addresses"), AddressArray);
    DeviceArray->Set(Integer::New(deviceIndex++), Device);
  }

  return DeviceArray;
}

Handle<Value>
Pcap::NtoP(struct sockaddr *SocketAddress) {
  char ipAddress[INET6_ADDRSTRLEN + 1] = { 0 }, *addrPtr = 0;
  socklen_t ipAddressLen = 0;

  struct sockaddr_in *sockAddr = NULL;
  struct sockaddr_in6 *sockAddr6 = NULL;

  if(SocketAddress->sa_family == AF_INET) {
    sockAddr = (struct sockaddr_in*) SocketAddress;
    ipAddressLen = INET_ADDRSTRLEN;
    addrPtr = (char*) &(sockAddr->sin_addr);
  } else {
    sockAddr6 = (struct sockaddr_in6*) SocketAddress;
    ipAddressLen = INET6_ADDRSTRLEN;
    addrPtr = (char*) &(sockAddr6->sin6_addr);
  }

  const char *ipAddressReturn = inet_ntop(SocketAddress->sa_family, addrPtr, ipAddress, ipAddressLen);
  if(ipAddressReturn != NULL)
    return String::New(ipAddressReturn);

  return Undefined();
}

extern "C" void Init(Handle<Object> Target) {
  HandleScope scope;
  Target->Set(String::NewSymbol("FindAllDevices"), FunctionTemplate::New(Pcap::FindAllDevices)->GetFunction());

  Pcap::Init(Target);
}

NODE_MODULE(pcap, Init)
