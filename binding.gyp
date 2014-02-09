{
  "targets": [
    {
      "target_name": "wfutil",
      "sources": [
        "src/wfutil.cpp",
        "src/lzf/lzf_c.cc",
        "src/lzf/lzf_d.cc",
        "src/lzf/lzf.h",
        "src/lzf/lzfP.h",
        "src/crc32/crc32.h",
        "src/crc32/crc32.cpp",
        "src/whirlpool/whirlpool.h",
        "src/whirlpool/whirlpool.cpp"
      ],
      'conditions': [
        [ 'OS=="linux" or OS=="freebsd" or OS=="openbsd" or OS=="solaris"', {
          'cflags': ['-O2']
        }],
        ['OS=="mac"', {
          'xcode_settings': {
            'OTHER_CFLAGS': ['-O2']
          }
        }]
      ]
    }
  ]
}
