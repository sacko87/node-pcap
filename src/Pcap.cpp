#include "Pcap.h"

using namespace v8;

Pcap::Pcap() :
  pcapHandle_(NULL)
{ }

void
Pcap::Init(Handle<Object> target) {
  HandleScope scope;

  Local<FunctionTemplate> functionTemplate = FunctionTemplate::New(Pcap::New);
  functionTemplate->SetClassName(String::NewSymbol("Pcap"));
  functionTemplate->InstanceTemplate()->SetInternalFieldCount(1);

  NODE_SET_PROTOTYPE_METHOD(functionTemplate, "close", Pcap::Close);
  
  target->Set(String::NewSymbol("Pcap"),
      Persistent<FunctionTemplate>::New(functionTemplate)->GetFunction());
}

Handle<Value>
Pcap::New(const Arguments& args) {
  HandleScope scope;

  Pcap *wrap = new Pcap();
  wrap->Wrap(args.This());

  return args.This();
}

Handle<Value>
Pcap::Close(const Arguments& args) {
  HandleScope scope;

  UNWRAP(Pcap);
  // do we have a handle?
  if(wrap->pcapHandle_ != NULL) {
    // close it preventing anything else.
    pcap_close(wrap->pcapHandle_);
  }

  return scope.Close(Undefined());
}

Handle<Value>
Pcap::FindAllDevices(const Arguments& args) {
  HandleScope scope;
  // space for the pcap error messages
  char pcapErrorBuffer[PCAP_ERRBUF_SIZE];

  // a pointer for interfaces
  pcap_if_t *allDevices, *currentDevice;

  // attempt to get all device information on this host
  if(pcap_findalldevs(&allDevices, pcapErrorBuffer) == -1 || allDevices == NULL) {
    return ThrowException(Exception::TypeError(String::New(pcapErrorBuffer)));
  }

  // this is what will be returned
  Local<Array> DeviceArray = Array::New();

  int deviceIndex = 0; // so we can add a device to an incremented index
  // loop through each interface on this system
  for(currentDevice = allDevices; currentDevice != NULL; currentDevice = currentDevice->next) {
    Local<Object> Device = Object::New(); // this device's information
    // add the name to the object
    Device->Set(String::NewSymbol("name"), String::New(currentDevice->name));
    if(currentDevice->description != NULL) // if we have a description ...
      // then add it to the object
      Device->Set(String::NewSymbol("description"), String::New(currentDevice->description));

    int addressIndex = 0; // so we can add an address to an incremented index
    Local<Array> AddressArray = Array::New(); // this interface's address information
    // loop though each address  on this interface
    for(pcap_addr_t *currentAddress = currentDevice->addresses; currentAddress != NULL; currentAddress = currentAddress->next) {
      // get the address family
      int AddressFamily = currentAddress->addr->sa_family;
      // win only care (at the moment for AF_INET(6)?
      if(AddressFamily == AF_INET || AddressFamily == AF_INET6) {
        Local<Object> Address = Object::New(); // this addres's information

        Handle<Value> Addr; // the object that may contain an address

// if the given field isn't null attempt to get the string representation
// of the address and add it to the address information object.
#define X(name) \
        if(currentAddress->name != NULL) {\
          Addr = Pcap::NtoP(currentAddress->name);\
          if(Addr->IsString())\
            Address->Set(String::NewSymbol(#name), Addr);\
        }

        X(addr)
        X(netmask)
        X(broadaddr)
        X(dstaddr)

#undef X

        // if we have any fields ...
        if(Address->GetPropertyNames()->Length() > 0)
          // ... add it to the list of address interfaces
          AddressArray->Set(Integer::New(addressIndex++), Address);
      }
    }

    // if we have any addresses ...
    if(AddressArray->Length() > 0)
      // ... attach it to the device
      Device->Set(String::NewSymbol("addresses"), AddressArray);

    // add the device to the device array
    DeviceArray->Set(Integer::New(deviceIndex++), Device);
  }

  return DeviceArray;
}

Handle<Value>
Pcap::LibraryVersion(const Arguments& args) {
  HandleScope scope;
  // return the string representation of the pcap library version
  return scope.Close(String::New(pcap_lib_version()));
}

Handle<Value>
Pcap::NtoP(struct sockaddr *socketAddress) {
  // get some space for the ip address and a pointer for the address structure
  char ipAddress[INET6_ADDRSTRLEN + 1] = { 0 }, *addrPtr = NULL;
  socklen_t ipAddressLen = 0; // the length of the socket structure

  // initialise them both (so thet continue to exist)
  struct sockaddr_in *sockAddr = NULL;
  struct sockaddr_in6 *sockAddr6 = NULL;

  // are we using AF_INET?
  if(socketAddress->sa_family == AF_INET) {
    // cast the socket address to the correct type
    sockAddr = (struct sockaddr_in*) socketAddress;
    ipAddressLen = INET_ADDRSTRLEN; // get the address length
    // cast the socket address to a char* (for inet_pton(3))
    addrPtr = (char*) &(sockAddr->sin_addr);
  // are we using AF_INET6
  } else if(socketAddress->sa_family == AF_INET6) {
    // cast the socket address to the correct type
    sockAddr6 = (struct sockaddr_in6*) socketAddress;
    ipAddressLen = INET6_ADDRSTRLEN; // get the address length
    // cast the socket address to a char* (for inet_pton(3))
    addrPtr = (char*) &(sockAddr6->sin6_addr);
  }

  // is it /AF_INET(6)?/?
  if(addrPtr != NULL) {
    // attempt to get the string representation of an ip address
    const char *ipAddressReturn = inet_ntop(socketAddress->sa_family, addrPtr, ipAddress, ipAddressLen);
    if(ipAddressReturn != NULL) // did we succeed?
      return String::New(ipAddressReturn); // return the string
  }

  // we haven't managed to translate it :(
  return Undefined();
}

extern "C" void Init(Handle<Object> target) {
  HandleScope scope;
  target->Set(String::NewSymbol("findAllDevices"), FunctionTemplate::New(Pcap::FindAllDevices)->GetFunction());
  target->Set(String::NewSymbol("libraryVersion"), FunctionTemplate::New(Pcap::LibraryVersion)->GetFunction());

  Pcap::Init(target);
}

NODE_MODULE(pcap, Init)
