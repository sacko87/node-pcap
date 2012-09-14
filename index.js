var events = require('events');
var binding = require('./build/Release/pcap');

function Pcap() {
  events.EventEmitter.call(this);
  this._handle = new binding.Pcap();
  this._handle.owner = this;
  
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

Pcap.prototype.close = function() {
  this._healthCheck();
  this._handle.close();
  this._handle = null;
  this.emit('close');
}

exports.findAllDevices = binding.findAllDevices;
exports.libraryVersion = binding.libraryVersion;
