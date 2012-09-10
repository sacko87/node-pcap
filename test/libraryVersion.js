var pcap = require('../')

console.log(
  require('util').inspect(
    pcap.libraryVersion(), false, null
  )
)
