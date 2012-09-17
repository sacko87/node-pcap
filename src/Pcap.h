#ifndef _NODE_PCAP_H
#define _NODE_PCAP_H

#define BUILDING_NODE_EXTENSION
#include <node.h>

struct pcap;
struct sockaddr;

/**
  \class Pcap "Pcap.h"
  \brief Node bindings for PCAP.
 */
class Pcap : node::ObjectWrap {
public:
  /**
    \brief Actually bind these functions to Node.

    \param[in] target               The superduper binding object to bind the bindings.
   */
  static void Init(v8::Handle<v8::Object> target);


  /**
    \brief Create a new, wrapped, instance of Pcap.

    \param[in] args                 The arguments passed via Node.
    \return                         The wrapped instance of Pcap.
   */
  static v8::Handle<v8::Value> New(const v8::Arguments& args);


  /**
    \brief Open a live PCAP session.

    \param[in] args                 The arguments passed via Node.
    \return                         Whether the capture was opened successfully.
   */
  static v8::Handle<v8::Value> OpenOnline(const v8::Arguments& args);


  /**
    \brief Open a PCAP `savefile'.

    \param[in] args                 The arguments passed via Node.
    \return                         Whether the capture was opened successfully.
   */
  static v8::Handle<v8::Value> OpenOffline(const v8::Arguments& args);


  /**
    \brief Set the filter for this PCAP handle.
    
    \param[in] args                 The arguments passed via Node.
    \retval v8::Handle<v8::Boolean> Whether the filter has been set successfully.
   */
  static v8::Handle<v8::Value> SetFilter(const v8::Arguments& args);


  /**
    \brief Get the statistics from the start of the capture.

    The JavaScript object returned has the same structure as the actual result of
    pcap_stats(3).
    
    \param[in] args                 The arguments passed via Node.
    \retval v8::Handle<v8::Object>  The result of pcap_findalldevs(3).
   */
  static v8::Handle<v8::Value> Stats(const v8::Arguments& args);


  /**
    \brief Close and cleanup the PCAP handle.
    
    \param[in] args                   The arguments passed via Node.
    \retval v8::Handle<v8::Primitive> v8::Undefined()
   */
  static v8::Handle<v8::Value> Close(const v8::Arguments& args);


  /**
    \brief A binding for pcap_findalldevs(3).

    The JavaScript object returned has the same structure as the actual result of
    pcap_findalldevs(3).

    \param[in] args                 The arguments passed via Node.
    \retval v8::Handle<v8::Object>  The result of pcap_findalldevs(3).
   */
  static v8::Handle<v8::Value> FindAllDevices(const v8::Arguments& args);


  /**
    \brief A binding for pcap_lib_version(3).

    \param[in] args                 The arguments passed via Node.
    \retval v8::Handle<v8::String>  The result of pcap_lib_version(3).
   */
  static v8::Handle<v8::Value> LibraryVersion(const v8::Arguments& args);

private:
  /**
    \brief Initialise any required attributes.
   */
  Pcap();


  /**
    \brief A PCAP handle.
   */
  struct pcap *handle;


  /**
    \brief A reusable wrapper for inet_pton(3).

    \param[in] socketAddress        The internal representation of the socket address.
    \retval v8::String              The string representation of the socket address.
    \retval v8::Undefined()         If the address is not AF_INET(6)? or if inet_pton(3) failed.
   */
  static v8::Handle<v8::Value> NtoP(struct sockaddr *socketAddress);
};

#endif//_NODE_PCAP_H
