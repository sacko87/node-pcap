#include "Pcap.h"

#if defined(__APPLE_CC__) || defined(__APPLE__)
# include <net/bpf.h>
# include <sys/ioctl.h>
#endif

#include <pcap/pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

#include <node_buffer.h>
#include <slab_allocator.h>

using namespace v8;
using namespace node;

#define SLAB_SIZE (1024 * 1024)
static SlabAllocator *slabAllocator;
static void DeleteSlabAllocator(void*) {
  delete slabAllocator;
  slabAllocator = NULL;
}

Persistent<String> onpacket;

void
Pcap::PollCb(uv_poll_t *handle, int status, int events) {
  Pcap *wrap = reinterpret_cast<Pcap*>(handle->data);
  if(status == 0 && (events & UV_READABLE) == UV_READABLE) {
    int dispatchReturn = pcap_dispatch(wrap->handle, -1, DispatchCb, (unsigned char*) wrap);
    if(dispatchReturn == -1) {
      // TODO handle error (I could do with handling 2)
    }
  }
}

void
Pcap::DispatchCb(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *bytes) {
  Pcap *wrap = reinterpret_cast<Pcap*>(user);
  char *buffer = slabAllocator->Allocate(wrap->handle_, h->caplen);
  uv_buf_t buf = uv_buf_init(buffer, h->caplen);

  memcpy(buf.base, bytes, h->caplen);

  Local<Object> slab = slabAllocator->Shrink(wrap->handle_, buffer, h->caplen); 

  Local<Object> packetTimeInformation = Object::New();

#define X(name) \
  packetTimeInformation->Set(String::NewSymbol(#name), Integer::NewFromUnsigned(h->ts.name));

  X(tv_sec)
  X(tv_usec)

#undef X

  Local<Object> packetHeader = Object::New();

#define X(name) \
  packetHeader->Set(String::NewSymbol(#name), Integer::NewFromUnsigned(h->name));

  X(caplen)
  X(len)
  packetHeader->Set(String::NewSymbol("ts"), packetTimeInformation);

#undef X

  Local<Value> argv[] = {
    Local<Object>::New(wrap->handle_),
    slab,
    Integer::NewFromUnsigned(buf.base - Buffer::Data(slab)),
    Integer::NewFromUnsigned(h->caplen),
    packetHeader
  };
  MakeCallback(wrap->handle_, onpacket, ARRAY_SIZE(argv), argv);
}

Pcap::Pcap() :
  handle(NULL)
{ }

void
Pcap::Init(Handle<Object> target) {
  HandleScope scope;

  slabAllocator = new SlabAllocator(SLAB_SIZE);
  AtExit(DeleteSlabAllocator, NULL);

  onpacket = NODE_PSYMBOL("onpacket");

  Local<FunctionTemplate> functionTemplate = FunctionTemplate::New(Pcap::New);
  functionTemplate->SetClassName(String::NewSymbol("Pcap"));
  functionTemplate->InstanceTemplate()->SetInternalFieldCount(1);

  NODE_SET_PROTOTYPE_METHOD(functionTemplate, "openOnline", Pcap::OpenOnline);
#if 0
  NODE_SET_PROTOTYPE_METHOD(functionTemplate, "openOffline", Pcap::OpenOffline);
#endif

  NODE_SET_PROTOTYPE_METHOD(functionTemplate, "setFilter", Pcap::SetFilter);
  NODE_SET_PROTOTYPE_METHOD(functionTemplate, "stats", Pcap::Stats);
  NODE_SET_PROTOTYPE_METHOD(functionTemplate, "dispatch", Pcap::Dispatch);
  NODE_SET_PROTOTYPE_METHOD(functionTemplate, "inject", Pcap::Inject);

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

  assert(args.Length() > 1);
  assert(args[0]->IsString());

  UNWRAP(Pcap);
  assert(wrap->handle == NULL);

  // space for the pcap error messages
  char pcapErrorBuffer[PCAP_ERRBUF_SIZE];

  // get the device string from arguments passed
  String::Utf8Value deviceName(args[0]->ToString());
  bool promiscMode = false;
  if(args.Length() > 1) {
    assert(args[1]->IsBoolean());
    promiscMode = args[1]->ToBoolean()->Value();
  }
      
  // attempt to open the live capture
  wrap->handle = pcap_open_live(*deviceName, ETHER_MAX_LEN, promiscMode, 1000, pcapErrorBuffer);
  if(wrap->handle == NULL) // did we succeed?
    return ThrowException(Exception::Error(String::Concat(String::New("pcap_open_online(): "), String::New(pcapErrorBuffer))));

  // Work around buffering bug in BPF on OSX 10.6 as of May 19, 2010
  // This may result in dropped packets under load because it disables the (broken) buffer
  // http://seclists.org/tcpdump/2010/q1/110
#if defined(__APPLE_CC__) || defined(__APPLE__)
  int fileDescriptor = pcap_get_selectable_fd(wrap->handle);
  int value = 1;
  assert(ioctl(fileDescriptor, BIOCIMMEDIATE, &value) != -1);
  // TODO handle errors
#endif

  // set non blocking mode on
  if(pcap_setnonblock(wrap->handle, 1, pcapErrorBuffer) == -1)
    return ThrowException(Exception::Error(String::Concat(String::New("pcap_setnonblock(): "), String::New(pcapErrorBuffer))));

  return scope.Close(True());
}

#if 0
Handle<Value>
Pcap::OpenOffline(const Arguments& args) {
  HandleScope scope;

  assert(args.Length() == 1);
  assert(args[0]->IsString());

  UNWRAP(Pcap);
  assert(wrap->handle == NULL);

  // space for the pcap error messages
  char pcapErrorBuffer[PCAP_ERRBUF_SIZE];

  // get the device string from arguments passed
  String::Utf8Value fileName(args[0]->ToString());

  // attempt to open the live capture
  wrap->handle = pcap_open_offline(*fileName, pcapErrorBuffer);
  if(wrap->handle == NULL) // did we succeed?
    return ThrowException(Exception::Error(String::Concat(String::New("pcap_open_offline(): "), String::New(pcapErrorBuffer))));

  // set non blocking mode on
  if(pcap_setnonblock(wrap->handle, 1, pcapErrorBuffer) == -1)
    return ThrowException(Exception::Error(String::Concat(String::New("pcap_setnonblock(): "), String::New(pcapErrorBuffer))));

  return scope.Close(True());
}
#endif

Handle<Value>
Pcap::SetFilter(const Arguments& args) {
  HandleScope scope;

  assert(args.Length() == 1);
  assert(args[0]->IsString());

  UNWRAP(Pcap);
  assert(wrap->handle != NULL);

  // get the filter string from arguments passed
  String::Utf8Value filterString(args[0]->ToString());

  // the compiled filter
  struct bpf_program compiledFilter;
  // attempt to compile the filter
  if(pcap_compile(wrap->handle, &compiledFilter, *filterString, 1, PCAP_NETMASK_UNKNOWN) != 0)
    return ThrowException(Exception::Error(String::Concat(String::New("pcap_compile(): "), String::New(pcap_geterr(wrap->handle)))));

  // attempt to set the filter
  bool filterApplied = pcap_setfilter(wrap->handle, &compiledFilter) == 0;

  // free the compiled filter
  pcap_freecode(&compiledFilter);

  if(!filterApplied) // did we succeed?
    return ThrowException(Exception::Error(String::Concat(String::New("pcap_setfilter(): "), String::New(pcap_geterr(wrap->handle)))));

  return scope.Close(Undefined());
}

Handle<Value>
Pcap::Stats(const Arguments& args) {
  HandleScope scope;

  assert(args.Length() == 0);

  UNWRAP(Pcap);
  assert(wrap->handle != NULL);

  struct pcap_stat ps;
  // attempt to get the statistics for this interface
  if(pcap_stats(wrap->handle, &ps) == -1) // did we succeed?
    return ThrowException(Exception::Error(String::Concat(String::New("pcap_stats(): "), String::New(pcap_geterr(wrap->handle)))));

  Local<Object> statsObject = Object::New();

#define X(name) \
  statsObject->Set(String::NewSymbol(#name), Integer::NewFromUnsigned(ps.name));

  X(ps_recv)
  X(ps_drop)
  X(ps_ifdrop)

#undef X

  return scope.Close(statsObject);
}

Handle<Value>
Pcap::Dispatch(const Arguments& args) {
  HandleScope scope;

  UNWRAP(Pcap);
  assert(wrap->handle != NULL);

  int fileDescriptor = pcap_fileno(wrap->handle);
  if(fileDescriptor != -1) {
    uv_poll_init(uv_default_loop(), &wrap->handlePoll, fileDescriptor);
    wrap->handlePoll.data = wrap;
    uv_poll_start(&wrap->handlePoll, UV_READABLE, PollCb);
#if 0
  } else {
    // TODO offline mode!
#endif
  }
  
  return scope.Close(Undefined());
}

Handle<Value>
Pcap::Inject(const Arguments& args) {
  HandleScope scope;

  assert(args.Length() == 1);
  assert(Buffer::HasInstance(args[0]));

  UNWRAP(Pcap);
  assert(wrap->handle != NULL);

  // the number of bytes put upon the wire
  int bytesSent = 0;
  // aquire the buffer object
  Local<Object> bufferObject = args[0]->ToObject();
  // get it's attributes
  char *buffer = Buffer::Data(bufferObject);
  size_t bufferLen = Buffer::Length(bufferObject);

  // attempt to get put the message on the wire
  bytesSent = pcap_inject(wrap->handle, buffer, bufferLen);
  if(bytesSent == -1) // did we succeed?
    return ThrowException(Exception::Error(String::Concat(String::New("pcap_inject(): "), String::New(pcap_geterr(wrap->handle)))));

  return scope.Close(Integer::New(bytesSent));
}

Handle<Value>
Pcap::Close(const Arguments& args) {
  HandleScope scope;

  UNWRAP(Pcap);
  assert(wrap->handle != NULL);

  if(pcap_fileno(wrap->handle) != -1)
    uv_poll_stop(&wrap->handlePoll);

  // close it preventing anything else.
  pcap_close(wrap->handle); wrap->handle = NULL;

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
  if(pcap_findalldevs(&allDevices, pcapErrorBuffer) == -1 || allDevices == NULL)
    return ThrowException(Exception::Error(String::Concat(String::New("pcap_findalldevs(): "), String::New(pcapErrorBuffer))));

  // this is what will be returned
  Local<Array> deviceArray = Array::New();

  int deviceIndex = 0; // so we can add a device to an incremented index
  // loop through each interface on this system
  for(currentDevice = allDevices; currentDevice != NULL; currentDevice = currentDevice->next) {
    Local<Object> device = Object::New(); // this device's information
    // add the name to the object
    device->Set(String::NewSymbol("name"), String::New(currentDevice->name));
    if(currentDevice->description != NULL) // if we have a description ...
      // then add it to the object
      device->Set(String::NewSymbol("description"), String::New(currentDevice->description));

    int addressIndex = 0; // so we can add an address to an incremented index
    Local<Array> addressArray = Array::New(); // this interface's address information
    // loop though each address  on this interface
    for(pcap_addr_t *currentAddress = currentDevice->addresses; currentAddress != NULL; currentAddress = currentAddress->next) {
      // get the address family
      int addressFamily = currentAddress->addr->sa_family;
      // win only care (at the moment for AF_INET(6)?
      if(addressFamily == AF_INET || addressFamily == AF_INET6) {
        Local<Object> address = Object::New(); // this addres's information

        Handle<Value> addr; // the object that may contain an address

// if the given field isn't null attempt to get the string representation
// of the address and add it to the address information object.
#define X(name) \
        if(currentAddress->name != NULL) {\
          addr = Pcap::NtoP(currentAddress->name);\
          if(addr->IsString())\
            address->Set(String::NewSymbol(#name), addr);\
        }

        X(addr)
        X(netmask)
        X(broadaddr)
        X(dstaddr)

#undef X

        // if we have any fields ...
        if(address->GetPropertyNames()->Length() > 0)
          // ... add it to the list of address interfaces
          addressArray->Set(Integer::New(addressIndex++), address);
      }
    }

    // if we have any addresses ...
    if(addressArray->Length() > 0)
      // ... attach it to the device
      device->Set(String::NewSymbol("addresses"), addressArray);

    // add the device to the device array
    deviceArray->Set(Integer::New(deviceIndex++), device);
  }

  return scope.Close(deviceArray);
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
