var events = require('events');
var binding = require('./build/Release/pcap');

function onPacket(handle, slab, start, len, pktinfo) {
  var self = handle.owner;
  if(!slab) return self.emit('error');
  self.emit('packet', slab.slice(start, start + len), pktinfo);
}

function Pcap() {
  events.EventEmitter.call(this);
  this._handle = new binding.Pcap();
  this._handle.owner = this;
  this._handle.onpacket = onPacket;
  this.isOpen = false;
  this.isLive = false; 
}
require('util').inherits(Pcap, events.EventEmitter);

Pcap.prototype._healthCheck = function() {
  if (!this._handle)
    throw new Error('Not running');
};

Pcap.prototype.setFilter = function(filter) {
  this._healthCheck();
  if(typeof filter == 'string')
    this._handle.setFilter(filter)
}

Pcap.prototype.stats = function() {
  this._healthCheck();
  return this._handle.stats();
}

Pcap.prototype.dispatch = function(callback) {
  this._healthCheck();
  if(typeof callback === 'function')
    this.on('packet', callback);
  this._handle.dispatch();
  this.isRunning = true;
}

Pcap.prototype.inject = function(buffer) {
  this._healthCheck();
  return this._handle.inject(buffer);
}

Pcap.prototype.close = function() {
  this._healthCheck();
  this._handle.close();
  this._handle = null;
  this.emit('close');
}

exports.createOnlineSession = function(device, promisc) {
  var session = new Pcap();
  session._handle.openOnline(device, promisc || false);
  session.isOpen = true;
  session.isLive = true;
  return session;
}

/**
exports.createOfflineSession = function(file) {
  var session = new Pcap();
  session._handle.openOffline(file);
  session.isOpen = true;
  return session;
}
*/

exports.findAllDevices = binding.findAllDevices;

exports.libraryVersion = function() {
  // get the library version for the first time
  libraryVersion = binding.libraryVersion();

  // override the libraryVersion() function
  // to simply return the text provided by the binding
  // there is no need to call C++ again for this instance
  exports.libraryVersion = function() {
    return libraryVersion;
  }

  return libraryVersion;
}
