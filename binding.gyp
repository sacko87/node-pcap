{
  "targets": [
    {
      "target_name": "pcap",
      "sources": [ "src/Pcap.cpp" ],
      "link_settings": {
        "libraries": [
          "-lpcap"
        ]
      },
      "defines": [
        "NODE_WANT_INTERNALS"
      ]
    }
  ]
}
