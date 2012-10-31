/**
  A fairly nonsensical example.

  This will print out the details of tcp packets with HTTP within them.
  Obviously you'd usually include them in the filter (ports 80, 8080, etc).
 */
// get the module
var pcap = require('pcap')
// create a session that isn't in promiscuous mode
var pcapSession = pcap.createOnlineSession('en1', false)
// a regular expression
var match = /HTTP/i

// when we close ...
pcapSession.on('close', function() {
  console.log('closed')
})

// when we receive a packet ...
pcapSession.on('packet', function(data, pinfo) {
  // do we have any data? does it contain 'HTTP'?
  if(data && /HTTP/i.test(data.toString())) {
    // print the buffer (not string)
    console.log(data) // cleaner this way
    console.dir(pinfo) // print the packet header (struct pcap_pkthdr)
    console.log() // new line
  }
})

// we only want tcp packets
pcapSession.setFilter("tcp");

// start listening
pcapSession.dispatch()

// after five seconds ...
setTimeout(function() {
  // print the stats of the capture
  // pcap_stats(3)
  console.dir(pcapSession.stats())
  pcapSession.close() // close the capture
}, 5000)
