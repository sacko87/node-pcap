var pcap = require('../')

console.log(
  require('util').inspect(
    pcap.findAllDevices(), false, null
  )
)
