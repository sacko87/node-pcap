#include "Pcap.h"

#if defined(__APPLE_CC__) || defined(__APPLE__)
# include <net/bpf.h>
# include <sys/ioctl.h>
#endif

#include <pcap/pcap.h>
#include <netinet/in.h>

using namespace v8;

Pcap::Pcap() :
  handle(NULL)
{ }

void
Pcap::Init(Handle<Object> target) {
  HandleScope scope;

  Local<FunctionTemplate> functionTemplate = FunctionTemplate::New(Pcap::New);
  functionTemplate->SetClassName(String::NewSymbol("Pcap"));
  functionTemplate->InstanceTemplate()->SetInternalFieldCount(1);

  NODE_SET_PROTOTYPE_METHOD(functionTemplate, "openOnline", Pcap::OpenOnline);
  NODE_SET_PROTOTYPE_METHOD(functionTemplate, "setFilter", Pcap::SetFilter);
  NODE_SET_PROTOTYPE_METHOD(functionTemplate, "stats", Pcap::Stats);
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
Pcap::OpenOnline(const Arguments& args) {
  HandleScope scope;
  // space for the pcap error messages
  char pcapErrorBuffer[PCAP_ERRBUF_SIZE];

  uint8_t argsLen = args.Length();
  
  if(argsLen <= 0 && args[0]->IsString())
    return ThrowException(Exception::TypeError(String::New("Usage: OpenOnline();")));

  UNWRAP(Pcap);

  // have we already connected?
  if(wrap->handle == NULL) {
    // get the device string from arguments passed
    String::Utf8Value deviceName(args[0]->ToString());
    bool promiscMode = false;
    if(argsLen > 1) {
      if(args[1]->IsBoolean()) {
        promiscMode = args[1]->ToBoolean()->Value();
      } else {
        return ThrowException(Exception::TypeError(String::New("Usage: OpenOnline(); Promiscuouse Mode must be a boolean.")));
      }
    }
      
    // attempt to open the live capture
    wrap->handle = pcap_open_live(*deviceName, BUFSIZ, promiscMode, 1000, pcapErrorBuffer);
    if(wrap->handle == NULL) { // did we succeed?
      return ThrowException(Exception::TypeError(String::New(pcapErrorBuffer)));
    }

    // Work around buffering bug in BPF on OSX 10.6 as of May 19, 2010
    // This may result in dropped packets under load because it disables the (broken) buffer
    // http://seclists.org/tcpdump/2010/q1/110
#if defined(__APPLE_CC__) || defined(__APPLE__)
    int fd = pcap_get_selectable_fd(wrap->handle);
    int v = 1;
    ioctl(fd, BIOCIMMEDIATE, &v);
    // TODO - check return value
#endif

    // set non blocking mode on
    if(pcap_setnonblock(wrap->handle, 1, pcapErrorBuffer) == -1) {
      return ThrowException(Exception::Error(String::New(pcapErrorBuffer)));
    }
  } else {
    return ThrowException(Exception::Error(String::New("Already running.")));
  }

  return scope.Close(True());
}

Handle<Value>
Pcap::SetFilter(const Arguments& args) {
  HandleScope scope;

  if(args.Length() != 1 && !args[0]->IsString())
    return ThrowException(Exception::TypeError(String::New("SetFilter() was expecting a string.")));

  // get the filter string from arguments passed
  String::Utf8Value filterString(args[0]->ToString());

  UNWRAP(Pcap);

  // do we have a handle?
  if(wrap->handle != NULL) {
    // the compiled filter
    struct bpf_program compiledFilter;
    // attempt to compile the filter
    if(pcap_compile(wrap->handle, &compiledFilter, *filterString, 1, PCAP_NETMASK_UNKNOWN) == 0) {
      // attempt to set the filter
      bool filterApplied = pcap_setfilter(wrap->handle, &compiledFilter) == 0;

      // free the compiled filter
      pcap_freecode(&compiledFilter);

      if(!filterApplied) // did we succeed?
        return ThrowException(Exception::TypeError(String::New(pcap_geterr(wrap->handle))));
    } else {
      return ThrowException(Exception::TypeError(String::New(pcap_geterr(wrap->handle))));
    }
  }

  return scope.Close(Undefined());
}

Handle<Value>
Pcap::Stats(const Arguments& args) {
  HandleScope scope;

  UNWRAP(Pcap);

  if(wrap->handle != NULL) {
    struct pcap_stat ps;
    if(pcap_stats(wrap->handle, &ps) == -1) {
      return ThrowException(Exception::Error(String::New(pcap_geterr(wrap->handle))));
    }

    Local<Object> StatsObject = Object::New();

#define X(name) \
    StatsObject->Set(String::NewSymbol(#name), Integer::NewFromUnsigned(ps.name));

    X(ps_recv)
    X(ps_drop)
    X(ps_ifdrop)

#undef X

    return scope.Close(StatsObject);
  }

  return scope.Close(Undefined());
}

Handle<Value>
Pcap::Close(const Arguments& args) {
  HandleScope scope;

  UNWRAP(Pcap);

  if(wrap->handle != NULL) {
    // close it preventing anything else.
    pcap_close(wrap->handle);
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

  return scope.Close(DeviceArray);
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
