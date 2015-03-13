{
    'target_defaults': {
        'default_configuration': 'Release',
            'configurations': {
                'Release': {
                    'cflags': [
                        '-O3',
                    '-fpermissive'
                        ],
                    'xcode_settings': {
                        'GCC_OPTIMIZATION_LEVEL': '3',
                        'GCC_GENERATE_DEBUGGING_SYMBOLS': 'NO',
                    },
                    'msvs_settings': {
                        'VCCLCompilerTool': {
                            'Optimization': 3,
                            'FavorSizeOrSpeed': 1,
                        },
                    },
                }
            },
    },
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
            "conditions": [
                ['OS=="linux"', {
                    "libraries": [
                        '-lip4tc',
                        '-liptc',
                        '-lxtables',
                        '-lnetfilter_conntrack'
                    ]
                }],
                ['OS=="win"', {
                    "libraries": [
                        'ws2_32.lib'
                    ]
                }],
            ]
        }
    ]
}
