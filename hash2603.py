####################################################################################################################################################################################
####################################################################################################################################################################################
"""                            ooooo   ooooo                    oooo          .oooo.       .ooo     .oooo.     .oooo.   
                               `888'   `888'                    `888        .dP""Y88b    .88'      d8P'`Y8b  .dP""Y88b  
                                888     888   .oooo.    .oooo.o  888 .oo.         ]8P'  d88'      888    888       ]8P' 
                                888ooooo888  `P  )88b  d88(  "8  888P"Y88b      .d8P'  d888P"Ybo. 888    888     <88b.  
                                888     888   .oP"888  `"Y88b.   888   888    .dP'     Y88[   ]88 888    888      `88b. 
                                888     888  d8(  888  o.  )88b  888   888  .oP     .o `Y88   88P `88b  d88' o.   .88P  
                               o888o   o888o `Y888""8o 8""888P' o888o o888o 8888888888  `88bod8'   `Y8bd8P'  `8bd88P'   
                               ----------------------------------------------------------------------------------------
                               Under digest algo of sha256   --   ============================  --  Made By Unkn0wn2603
"""
####################################################################################################################################################################################
####################################################################################################################################################################################
def rotate(n, b):
    return ((n >> b) | (n << (32 - b))) & 0xFFFFFFFF
  
def Unkn0wn_process(H, K, message):
    lengths = [64, 128, 256, 512, 1024]
    length = lengths[0]
    output_length = 64
    pad_length = (length - (len(message) + 8) % length) % length
    padded_message = message + b'\x80' + b'\x00' * pad_length + (len(message) * 8).to_bytes(8, 'little')
    num_blocks = len(padded_message) // length
    for block in range(num_blocks):
        words = [padded_message[block * length + i:block * length + i + 4] for i in range(0, length, 4)]
        words = [int.from_bytes(word, 'little') for word in words]
        W = words + [0] * (length - len(words))
        for i in range(16, length):
            s0 = (rotate(W[i - 15], 7) ^ rotate(W[i - 15], 18) ^ (W[i - 15] >> 3))
            s1 = (rotate(W[i - 2], 17) ^ rotate(W[i - 2], 19) ^ (W[i - 2] >> 10))
            W[i] = (W[i - 16] + s0 + W[i - 7] + s1) & 0xFFFFFFFF
        a, b, c, d, e, f, g, h = H[block % 8]
        for i in range(length):
            S1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + K[i] + W[i]) & 0xFFFFFFFF
            S0 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF
            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF
        H[block % 8] = [((x + y) & 0xFFFFFFFF) for x, y in zip(H[block % 8], [a, b, c, d, e, f, g, h])]
    hash_value = ''.join(f'{x:08x}' for h in H for x in h)[:output_length]
    return hash_value

def Unkn0wn_math(message, rounds = 10):
    # print(message, rounds)
    h0 = [[0x5135a225, 0x85886844, 0x3495430c, 0xd471352b, 0x88f1b15a, 0x5215ae30, 0x3f06668a, 0xaa49b1f5, ],
    [0xe2325399, 0x7cd3eec1, 0x42667d56, 0x40535ddb, 0x4ef11d6b, 0xc6cba275, 0x6cb49836, 0x4bb72f61, ],
    [0x5fa94379, 0xf28ea869, 0x6cc00243, 0x43094689, 0x73b213a4, 0x057fcd13, 0x51252431, 0xf2e45112, ],
    [0xc013302f, 0xbcfa02bc, 0x46e5e28b, 0x498ccfa7, 0xbaff1339, 0xfbd95d5b, 0x20bee797, 0xf80fb341, ],
    [0xc61ed4c9, 0x1b654916, 0xe3ff5832, 0x8d5e128e, 0x22b79018, 0xe7655221, 0xfc084130, 0x631174a3, ],
    [0x9551869d, 0x2b243b0b, 0xd137cc7d, 0x8d6b934f, 0xaf751622, 0x17fa2b3d, 0x72bae76f, 0x6f61eab8, ],
    [0x777dd4d4, 0x8b712762, 0x6d1befb7, 0x335f646c, 0x6502829d, 0x3826f9e9, 0x01a8f877, 0x29f8f541, ],
    [0x98829b3c, 0xf910c79e, 0x2ff7fceb, 0x56bd053d, 0xf23b1a8d, 0x72181d9b, 0xf8bc279e, 0xb96c28fc, ]]
    h1 = [[0x4c2eb89c, 0x4be51e17, 0x09aa274d, 0x475e0ead, 0x1c8ec634, 0x853a5bc7, 0xccd86eab, 0x551f3427, ],
    [0x284c4a7d, 0x7eb84215, 0x2d99ba5f, 0x8bbd2bcc, 0x623737e2, 0xf32a2d65, 0x3d888422, 0x06267c85, ],
    [0xa14fc217, 0xfb06cc55, 0x817f9f01, 0x681dfd8d, 0xb42dc039, 0x308ad15f, 0xa6e6007a, 0x6fede4ce, ],
    [0x4b94078e, 0x62c1ef58, 0xd656aec6, 0x3c85f883, 0x0b72d70c, 0x6cac1372, 0x5f4d21f0, 0x5a3e7007, ],
    [0xa0885e3b, 0x3ddeb2a6, 0x3ca556c0, 0xc2aefbe1, 0x16ada626, 0xb146135d, 0xe7552278, 0xca31d31f, ],
    [0x1e40582a, 0xfef4ef4b, 0x6f0e927e, 0x956f774f, 0xb68b5ac3, 0x130a5f19, 0xc5037cd5, 0xb8fc45e8, ],
    [0xe34774cc, 0x11ac5040, 0x19b78384, 0x7c320d94, 0x633fd17b, 0x6b5d7717, 0xe0ee7f1f, 0xa0f0bcaa, ],
    [0x7f6eb2ad, 0x7bc39fe8, 0xe7721fac, 0x281aafce, 0x0be05cc3, 0x2257076d, 0xcb9f4f37, 0x9c69f076, ]]
    h2 = [[0x38a7d0b4, 0x396a81a2, 0x5f5a3fb8, 0xfcc90b0a, 0xcc11d0ca, 0xa3a5cd2a, 0xb0eb95f7, 0x4984d0db, ],
    [0x685cf6dd, 0x304c01ce, 0xe9132245, 0xf50307d4, 0x255a54bd, 0xc2c6f84e, 0x8d81e449, 0x8eaefc43, ],
    [0x75aed8bc, 0xc214822d, 0x97b00736, 0x2ae036b5, 0xbaadce43, 0x8f19e52d, 0xc9f2ab95, 0xaab302a3, ],
    [0xbf5243d6, 0x665afccf, 0xad73751d, 0xd14da990, 0x4f058242, 0xf7583e12, 0x6ec778c3, 0x21b7d13a, ],
    [0xa4430bad, 0x287b1efe, 0xa96bd7c2, 0xe68b4c47, 0xf65edeba, 0x21640b49, 0x2f08f5a8, 0x8a153b85, ],
    [0x30aae580, 0xe486a42a, 0x9b098c6d, 0x7600e92b, 0xcb5e82c3, 0x960df8fc, 0x2c62c3f7, 0x67b8670d, ],
    [0xf60c2c75, 0x4bfa07e2, 0x472aa792, 0x4d29eb49, 0x3ca48374, 0xd04d948b, 0x381a9d26, 0xa8f85203, ],
    [0x4daca89e, 0xd93f889f, 0xbe6be4d2, 0xd601c26d, 0x516f9be5, 0x1388ebe1, 0xfa6357fc, 0x50cbdeb8, ]]
    h3 = [[0x5f135710, 0xb85705df, 0x12ffc423, 0x26a5991a, 0x20257eb1, 0xb13accd4, 0xb04a2478, 0x9fb48f93, ],
    [0xbc03a6cb, 0xe79bfba0, 0x0c816295, 0x0d0c12e8, 0x18136631, 0xe3d9d343, 0x9afeecb1, 0x37743501, ],
    [0xff93a1fd, 0x7883311b, 0x30b36e4d, 0xae1d6775, 0x396dc0fd, 0x7e6e01af, 0xca73f6ad, 0x6e93b982, ],
    [0xf9cb648d, 0x7bfbe81d, 0xebfddd69, 0x7257bac2, 0xcc3d3ca4, 0x76d83359, 0x295ec7a2, 0x420c2e8e, ],
    [0x2dfcb6eb, 0x8a90175b, 0x68e24a37, 0x827f5e7e, 0xd0a95932, 0x0d24f6df, 0xd8887989, 0xa7ebb9c5, ],
    [0xff644aa4, 0x5291519c, 0x15b1ba7c, 0xa65c29c1, 0x8444d7b0, 0xfdc972d1, 0x2ff91400, 0x2949c50c, ],
    [0x2c128cc5, 0x4c916fad, 0xe69a5339, 0xc49ff617, 0xf1de6104, 0x3474f560, 0xce86460e, 0x7d7d67b9, ],
    [0x8b79f45e, 0x9ffdb98e, 0xc40af82f, 0x371ac046, 0xadcf8a5b, 0xc87ed184, 0x9d2ec241, 0xe8aa46e8, ]]
    h4 = [[0x7217ef39, 0xcc7fc8f2, 0x1fc6e5a0, 0xf9c74cce, 0xecab99d2, 0x869a2cda, 0x50bfa4ff, 0xdc0488f9, ],
    [0x0a399213, 0xa3dc0329, 0x6d14a11a, 0x42606362, 0x9c37ef1b, 0x53530b7c, 0x921e4721, 0x168e1eb7, ],
    [0x2ae369cd, 0xe18f473f, 0xbf92e932, 0x1494e97c, 0x5bc53cda, 0x0925b7fc, 0x4b78be03, 0xd72bf69b, ],
    [0xc23cc3b8, 0x072b1497, 0x594453c3, 0x3f2983d6, 0x34b3bd35, 0x5d6f8d65, 0x3c20b878, 0x3e56a554, ],
    [0x4a7e38d0, 0x9ca10680, 0x29c45861, 0x19a3cdf0, 0x577e2a0a, 0x5a4ab56a, 0x396eca80, 0x133e770d, ],
    [0x5a43761d, 0x01fd6f43, 0x429d2559, 0xdb6416ec, 0x903be1c6, 0x0ee16bd0, 0x4638ff8d, 0x0d246fd6, ],
    [0xd09c30e4, 0x6c17f913, 0x257bce52, 0xf94aa5be, 0xc7998a9c, 0xb99f7ce0, 0x7fdba74a, 0xccf4070f, ],
    [0xc810e2f1, 0xa5e39846, 0x68e262c7, 0x26938388, 0x5f75e8f0, 0xcc70afc8, 0x2595b16a, 0xab2043a3, ]]
    h5 = [[0xc1410072, 0x1d31acdb, 0xcd3558e4, 0xab14afd5, 0x39aa4d7e, 0x345dd57d, 0xfdca6e63, 0x861aa643, ],
    [0x1514a4f9, 0xdc1744e0, 0x6ed0fc95, 0x545b57a0, 0x355f327b, 0x20ab85a3, 0x852dbe0d, 0x156923b5, ],
    [0xf26ee593, 0x002f2766, 0xb3ee05c0, 0x416ae05e, 0x5e9d5a61, 0xd570fa9c, 0xb5ae235e, 0x21786219, ],
    [0x6257d2e2, 0xcbdf583a, 0x7e74ed23, 0xc70a974a, 0xae1eba25, 0x46ba7931, 0x142b373b, 0xe5b6285d, ],
    [0xd0e94adb, 0x979d10b3, 0x80549343, 0x720497d9, 0x44f5178d, 0x25d73dfc, 0x0d394c74, 0x3ed3b240, ],
    [0xdb132686, 0x97f505f9, 0x41f79f7e, 0x920bf238, 0xd146d10e, 0x31379a83, 0xcb3d15ec, 0x939456d4, ],
    [0xdcc427f1, 0x6ec8c1d2, 0xdc42c5a2, 0xcb720169, 0x6553c964, 0x1602d46b, 0x631f34f5, 0x26b98a34, ],
    [0x70ef9cdb, 0x576be49e, 0xaad5f840, 0x901ff342, 0x0343ab61, 0x0f433500, 0xeabd6677, 0x902e1697, ]]
    h6 = [[0x4be95b6a, 0x8dc124bf, 0xd66e0a2e, 0x0f8e4d1e, 0x26db7f15, 0xef469285, 0xf3eb83ae, 0xe6675963, ],
    [0x4f8b81ab, 0x21990014, 0xfbf32c45, 0xb1277bdd, 0x3934fc5e, 0x479855a5, 0x2413723f, 0x573321e6, ],
    [0x6d7691aa, 0x9a412ba1, 0xcca1aca6, 0xccef6169, 0xc76c50cc, 0x67a87cdb, 0xef21e0c4, 0x7522e756, ],
    [0xe42332a4, 0xd9840a6d, 0x44603ac9, 0x2c966208, 0x99359a16, 0x8ea72681, 0xd335cb7e, 0xada194e4, ],
    [0xc0cd0164, 0x931bf45a, 0x15c39fd2, 0x6427153a, 0x54fe9e9c, 0x8ceb2857, 0xa4b661fd, 0x50ab5360, ],
    [0x6f467bb1, 0xd445d62a, 0xbbfc58e3, 0x593be7b8, 0xc262815c, 0x49237fe1, 0xb75583cc, 0xf41d0714, ],
    [0x5f1d2ce5, 0xbb69ef00, 0x8ca10627, 0x703f2c30, 0xdc559ada, 0x445513a1, 0x62cf982e, 0x3a8f458a, ],
    [0xd8f541e9, 0x3ef3b353, 0xa1c6269e, 0x6ed698ce, 0xe3c67b57, 0xf2ff0ccc, 0x8fcd855d, 0x851e8fa9, ]]
    h7 = [[0x27d55096, 0xcf43008f, 0x4289891d, 0x44dfbf4d, 0x24acd28e, 0xe133e3d0, 0xdae47884, 0x7fcd0fed, ],
    [0xc0d4892b, 0x9c5cd7a3, 0x21283422, 0xb55b74be, 0x313b0919, 0xd9c836e6, 0xa4de799d, 0xf8edac3e, ],
    [0xc1e73289, 0xce3c9be9, 0xddefc814, 0x9c34cff2, 0x6c3df150, 0x8af1217f, 0x103c0fdc, 0x3c58b763, ],
    [0x31a0a47d, 0x015f0747, 0xade56917, 0x50f1986e, 0xe6884a95, 0x769ad895, 0x9a3f5b05, 0xa33967c9, ],
    [0xb6f71e9d, 0xb55f8798, 0x1ac23f81, 0x218c23ed, 0xd8d332cf, 0xfd1dfd76, 0xc13f6062, 0x26036c3c, ],
    [0xb77ab705, 0x6b28786e, 0x5a558d84, 0xd848bb64, 0x3be592b0, 0x6b89ca43, 0x315cdd27, 0x3980ba86, ],
    [0xe34aff86, 0x451e7508, 0xfeb06396, 0x734ffe3a, 0x73837267, 0xacecc832, 0xf364887c, 0x201f9544, ],
    [0x842c5111, 0x3f9ec7bf, 0x4f90aa14, 0x453cf0f3, 0x7b371d63, 0x8c700d44, 0xd9897842, 0xeffed1ed, ]]
    h8 = [[0x7c402e7d, 0x2fd9ce4b, 0x09fee9a8, 0x688bc228, 0xe5332951, 0xc0fc6564, 0x4acd9f8f, 0x048bdb34, ],
    [0x8207ad50, 0xfb6c4a6e, 0xf52f33e5, 0x91ee41fa, 0x111578ab, 0xa08d6876, 0xf66ca778, 0xbb3acfab, ],
    [0x9948b9a0, 0xd09df211, 0x2ee7b172, 0x7c080254, 0xc4e741e1, 0xdc9e537a, 0xaedab709, 0x1b35b331, ],
    [0xec084dc0, 0x8f939fd5, 0x88233c93, 0x8dbebb69, 0x07c09b49, 0xb49ee0ac, 0x86d91503, 0xc5151702, ],
    [0xc1bd4c2f, 0xf6f15c0d, 0x39638e00, 0x5ccab5b6, 0xb39a5227, 0x2bf6bc50, 0xa0183420, 0x28943bb3, ],
    [0xb9ed8168, 0x766ac306, 0xd34c03e8, 0xcfcdce85, 0x913b9100, 0xb91bdf2f, 0x19ddef88, 0x65d6a089, ],
    [0x9d13251b, 0xa77bcd89, 0x5039d6cb, 0xbe8108ef, 0x68f4181d, 0x289e312e, 0x15e72fb1, 0x574c00e1, ],
    [0x5be4a193, 0xd21b8e2b, 0x4a1774fe, 0xa711eace, 0xa3c2268d, 0x113d4871, 0x266e1da7, 0x3f1c5279, ]]
    h9 = [[0x9099cffb, 0x1725ef1d, 0x1680d874, 0x40b4fb37, 0x35c574a5, 0x383418de, 0x994ed02c, 0xd7abf0c7, ],
    [0x88a82854, 0x0dcaa974, 0x1c92b123, 0xe5e570b3, 0x3fa7d416, 0xd46bd19d, 0x59520c9a, 0xd514d01b, ],
    [0x3dee7387, 0xce102255, 0x10cb6634, 0x7ad20674, 0x413f9d25, 0xa0652aed, 0xc35afc93, 0x242c0a6f, ],
    [0x5dd9b7d8, 0xaf3daad0, 0x49c0554e, 0xf7920f9e, 0xd18297c1, 0x80e59596, 0x7d30e261, 0x8a72535a, ],
    [0xf161e8b5, 0xd98d2fc7, 0x494857c4, 0x2db1fe4f, 0x3f5d7cd1, 0x177068d5, 0x20ba9155, 0x6a34d4bc, ],
    [0x795616f6, 0x697b66b8, 0x92759fe7, 0x33247b5b, 0x31a3d2b2, 0x6452769d, 0xbc36ad74, 0x5dd3aa7d, ],
    [0x02318e6e, 0xca4f7b56, 0xffa5134c, 0x86c65c7e, 0x04c08f7c, 0xeeab57fd, 0x7e45a7dc, 0x45a4065c, ],
    [0xf7567fe9, 0x20d8c994, 0x90c7ba96, 0x52d455f8, 0x057f6de1, 0xdb4a72c9, 0x4900db63, 0x978e40f6, ]]
    k0 = [0xc373d2bd, 0xe8bfdb90, 0x66245994, 0x10753626, 0xf3c1496a, 0xe8270e1d, 0x3561e3e8, 0xed0e8be5,
    0x5af9b83b, 0x87f4d857, 0xd374811c, 0xa1babec7, 0x81804b24, 0xe972f1a6, 0x85957a0b, 0xb767fe16,
    0x57f0e09e, 0xa6738967, 0xfbc8453d, 0x449e2b72, 0x03441f83, 0x4c1ce734, 0x647511b7, 0x41bf297c,
    0x3297a372, 0xa2d6e24e, 0x0df0ce6c, 0xd11b8fb0, 0x606d85d1, 0x1dcdc604, 0xd979b2fc, 0xaa18d44e,
    0x6c5526ec, 0x906d8f7f, 0x78787f34, 0xa38a4132, 0xbbd5168c, 0xbd785752, 0x41697722, 0xd7c8aafb,
    0x135c543f, 0x0e7d6a36, 0x16d6dd80, 0x9aef24b1, 0xbbbff5a8, 0x16e93119, 0x0d3cf420, 0x6ec94b2f,
    0x0dee57c9, 0x73c974f9, 0x930a7461, 0x26faec31, 0x32992720, 0x4b7bf2c7, 0x9f505854, 0x8c4b60f5,
    0x04617825, 0x917aa705, 0x79d84d21, 0xc9afe084, 0xf5202b4d, 0xb6ea0354, 0x96c0f59c, 0xcd03d32f]
    k1 = [0x18c4308c, 0x6c4ff8a7, 0x7a628013, 0x55d2ab24, 0xf5347611, 0xed5b6ec8, 0x93ca314b, 0x7a0f0396,
    0x2aee704e, 0x6a35185e, 0xc1d03fd2, 0x7e132235, 0xebdb4484, 0x16da6b13, 0xa9fe5993, 0x5115a219,
    0x6f1c9159, 0x9b3f6c2f, 0x50b185c8, 0xf223ddd0, 0x5abe1503, 0xf0d9fa7f, 0x0fafaea6, 0xd1ac0186,
    0xe7ada94a, 0x7e40e30f, 0xdf44f5ab, 0x37e22468, 0x1c18a5a9, 0x873fbc74, 0xd1ce61d9, 0x66a11cd9,
    0x6b1e8ea8, 0x48ef2e41, 0x90cda6cd, 0x397ab392, 0x91637192, 0xabe24901, 0xf5625a34, 0x682d2ab3,
    0xc5706c9a, 0x2b3d2573, 0x88824b01, 0xd929e2eb, 0xee5abc81, 0x618e4f09, 0xbb06ab7a, 0x32df83a8,
    0x032285ff, 0x569f32e5, 0x26f3fe94, 0x415fb145, 0x3847a366, 0x205aacd4, 0xdc70533c, 0x70545ef4,
    0x670cd754, 0x9b2ba5b0, 0xcfc06529, 0x1dacdbbc, 0xa9b36d54, 0x6059558a, 0x06d060db, 0x0176ccdc]
    k2 = [0x09d190de, 0xa387bfb2, 0xe8c6c277, 0x7961a992, 0x6d35afa0, 0x6ebc78fd, 0xa2dd1b9c, 0xbe215c07,
    0xcb8f30f5, 0x52c75898, 0x7fa781a6, 0x7197a796, 0x432d5127, 0x8d464482, 0x4a819e4a, 0x9b7a3418,
    0xc6472fdc, 0x7c0f62c1, 0xe19c9d23, 0xb6e811f5, 0x1fd8e2c6, 0x3d0b1bbb, 0xb431afe6, 0x85a0a586,
    0xcd5970eb, 0x088c7b1e, 0x84921774, 0x6553ad56, 0x36146b64, 0xc56f355d, 0x1a1c9cea, 0xfe5b1f5d,
    0xf7b8d381, 0x74cc9a89, 0x7bd68765, 0x8f3600d2, 0xa2db3ba0, 0xa647cccd, 0xa08975b3, 0x9f120795,
    0x2bdeea0d, 0x179eb86f, 0x13dfe624, 0x2f4c4c53, 0x9d50d105, 0x26b1732a, 0x5e2ebc69, 0x6c9cc2a6,
    0xb6936163, 0xf2535b54, 0x0dce7671, 0xf43fb3ed, 0xd949c3d6, 0x33e2ac84, 0xda032dfb, 0x2aafc7d4,
    0x9cb12bb4, 0x730a2e2d, 0x0d8f5ff4, 0x6fc7e8f7, 0xfb176b0c, 0x8388f4d6, 0xb90153f9, 0x0505e3dd]
    k3 = [0xe6be3505, 0x5de4084f, 0x3095e95c, 0xb8c15938, 0x17179ab2, 0x6a631485, 0x4fdc40f5, 0xec8911e8,
    0x64b7363c, 0x3a7fa0b4, 0x50c18825, 0x3421aab7, 0x8a4bf4e8, 0xc228ad6b, 0x59543250, 0x1451c474,
    0x20548032, 0x71195bf9, 0x45f1fd49, 0xf35047d1, 0x1727a934, 0xe5de5299, 0xeb7c7b98, 0x6affe640,
    0xf6173400, 0x2eebdc9a, 0xf7938c23, 0x6c0b7e8a, 0x791ec0c5, 0x98715892, 0xe7920185, 0xdc9c22e3,
    0xb56c2ba8, 0x8353e069, 0xdaae0af1, 0xd121a0a4, 0xd2537af3, 0x897d59c0, 0xb36418d7, 0x3d8e7288,
    0xe753f04a, 0x913737be, 0x8beffb7f, 0xe9c6ebd8, 0xd3cee752, 0x269c4feb, 0x9c7cddf8, 0x7d342db7,
    0x0ed3ac2c, 0xb24d3edc, 0x9e65aea4, 0x74b8d8b8, 0xd9858817, 0x24276d1c, 0xedcadc10, 0x8ad78cda,
    0x8e715682, 0x49acad8c, 0x348abd89, 0xad128db2, 0x6f4211b7, 0xa68d773b, 0x15ce0c4e, 0xb6fbe330]
    k4 = [0x02aae7c4, 0x3730dfdf, 0x7f43836d, 0x0f275fad, 0xd4c0d0c2, 0x445d50cc, 0xd030f059, 0x9f6e7548,
    0x53477d25, 0xec0aaa45, 0x747bc38c, 0x36a427da, 0x46079533, 0x783aee76, 0xe23c445e, 0x9fe9ce23,
    0x831ae87f, 0xef97a333, 0x07e042b4, 0xe2371efb, 0xda0625c7, 0x38202e94, 0x95d7976f, 0x3d0dba42,
    0xd2d8da77, 0xf3cef82b, 0xc3a748e8, 0x009a2a1d, 0x49f517c0, 0x273b7afa, 0x817346dc, 0x70a2803f,
    0xa9c88a40, 0x5c1b2cb5, 0x967a93bc, 0x7f5cf62c, 0x85aa2ea4, 0xaa67f81f, 0xe0d76ddb, 0x2b796ee3,
    0x8b3b8c7a, 0xaa37c326, 0x56d06cfb, 0x86def3e6, 0x0c48d410, 0x825b1b4c, 0x642b1f8a, 0xe099187a,
    0x04aecc81, 0xbe5ae159, 0x668e1ef1, 0x032d3feb, 0x4b5d962f, 0x2819c343, 0x15a2a998, 0x40dec893,
    0x3d837792, 0x134fc906, 0xc6af278d, 0x380bfd8f, 0x99269bba, 0xeb7a758a, 0x10e39429, 0x7e950630]
    k5 = [0x2c91aead, 0x25cc9aab, 0x58ea1ab0, 0x881fa7cf, 0x132c948c, 0xa9f640ee, 0xf5c38866, 0x36c8043e,
    0x13b4d620, 0x47e9f480, 0x6d48a3fb, 0x4388a9ee, 0x42d73656, 0xb38ee700, 0x88435b7e, 0x5bbec034,
    0xffb3ee5e, 0x4cae469d, 0xb6942924, 0xd1e09711, 0x7f9734af, 0x1f50ea96, 0x5413a28e, 0x527c2d56,
    0x6003b96c, 0x6c5599ac, 0xc9328ee9, 0x0680699a, 0x71b2fb6f, 0x285986ad, 0xcbac5edd, 0x08ff6b89,
    0xe7f31ca6, 0xcfd3e218, 0x6f7317ea, 0xc6632f94, 0xb4bf7768, 0x3d685cc5, 0x793f12a0, 0x60b7327e,
    0x18487005, 0x70066bad, 0x32f08b4c, 0xf5dab36a, 0x31030d2b, 0x650455fc, 0x4bb9c94f, 0x7866273d,
    0xefdadcf7, 0xec86a157, 0x8b99a0e8, 0x2875c21a, 0xa30bd6ee, 0x890e2035, 0x36d1a1ce, 0x20854c11,
    0xa1e54084, 0xb5164c1c, 0x55c76a77, 0x644956c4, 0xb1fa3de3, 0x22338a91, 0xa191e2c5, 0xe8a53601]
    k6 = [0x71410e4a, 0xd93685dc, 0x9fb5918b, 0x219dba49, 0xf55b6f95, 0xf66af904, 0x364efc46, 0x81a63a90,
    0x423cc095, 0x1e071b6d, 0xf87a4498, 0x3c39af49, 0x441cf22f, 0xa8115ec1, 0x261ffe7c, 0x2e9134ff,
    0x60568081, 0xba84f7a8, 0xd8eea04d, 0xcfcea94d, 0x183b2c80, 0x5586b9f7, 0x46e324e8, 0x0e0e6e0d,
    0x0b563ed8, 0x38261495, 0xfb3a6a0c, 0x81064b1f, 0x6e06acb1, 0xa659df92, 0x1f52491e, 0x556160e0,
    0x8dc96ad4, 0xa4dcfc21, 0x20463c6a, 0x666a4cf3, 0x54d89d33, 0xc0df1fed, 0x40eda7f1, 0x69f1df2f,
    0x423a12b0, 0x0548bf04, 0x8e88482d, 0xa5a74c6d, 0x4c7be487, 0x2c8db422, 0x8043df07, 0x3afbc136,
    0x9666e9bf, 0xa7df1f9e, 0xa80bab71, 0x8caddd38, 0xa413cc61, 0x990f3951, 0xcaa34eca, 0x934c1f09,
    0x840859da, 0x72a53c4d, 0x3e5b7a83, 0x2b12bf3c, 0x04c51ab1, 0x22971da7, 0xb4acbfba, 0xb2aa53a1]
    k7 = [0x48f46f12, 0x38be571c, 0x05a5abab, 0x3cf25b69, 0x09230bdd, 0x68aff49e, 0x4bf904a6, 0xcbc57f36,
    0xccbe935d, 0xf02f0e6b, 0x83ef7770, 0x8ebe5391, 0x7446b106, 0xa0bcf828, 0x13d75fd0, 0x46870408,
    0x577261cc, 0x1bd7c8e8, 0x989503d5, 0xe06656ab, 0x1d6842bb, 0xad40eb03, 0x65d309ea, 0x1915396e,
    0xc6bf9b2c, 0x29d2d994, 0x881d7647, 0xb232fd44, 0xa945b8ec, 0x421d6b91, 0xa130a9ae, 0x0ed9aacf,
    0x15014a17, 0xfbd47cbc, 0xb74adda4, 0x33644cbf, 0x660dd8ce, 0x92437dbd, 0xf4f07bce, 0x61a9fcb7,
    0xd0b952d6, 0xa843cdff, 0xb1222c6b, 0x3f43c3aa, 0xe8a29609, 0xfa2675b5, 0x5b202fb4, 0x9ccb14ef,
    0xf41d33f6, 0x5588c5e1, 0xd01c2a12, 0x9d674bec, 0x289889a9, 0x98ef25e1, 0x640d62c4, 0xacc2ba6c,
    0x47b749e5, 0x759611cf, 0xf967957d, 0xb484d52b, 0x7d60faea, 0x534278cb, 0xc514ef68, 0x5e2d922a]
    k8 = [0xb2b9e822, 0xaf964d9b, 0x5b2ba219, 0xfec7196a, 0x752aa513, 0xc07e8ee9, 0xe34a0f67, 0x7ade5879,
    0xf4996336, 0x6a422330, 0x5d891da6, 0x70a1b15f, 0xadb3e594, 0xcac67d9e, 0xc30ed7f0, 0x28ac6f80,
    0x31e0cedd, 0x03baff48, 0x341e199f, 0x8a7f39ec, 0x1d46572d, 0x88aa3a6e, 0x3f845023, 0x9c31944d,
    0x0be53458, 0x314f2b30, 0x49b72cd4, 0xd659732c, 0x1c3debc2, 0xa62784f1, 0x46eb33a2, 0x74654d8d,
    0x96134824, 0xe96c4b9a, 0x2dddcc43, 0xa9bb2526, 0x0a1050af, 0x97f9e08d, 0x1e317c96, 0x2dc4d809,
    0xbae6a1da, 0x8f68b936, 0xc6783ecf, 0x52ddc368, 0x3a10e9dc, 0x7c555c21, 0x02972edb, 0x4c5af350,
    0x95df673f, 0xef07fd95, 0xa92e5d34, 0x9d8063f2, 0x56daf739, 0x0671a63a, 0xdf6886c2, 0x6250e79e,
    0xf5ab8b5d, 0x90f49036, 0xd46bff20, 0x7f5a91b3, 0x8dd78c0a, 0x7c855c2d, 0x7fd653b6, 0xe5157f38]
    k9 = [0xec360af2, 0xa67025af, 0xcfbc53a2, 0xebe3b045, 0x2a257ec5, 0xbba4b666, 0x57b174ba, 0x37d6156a,
    0x27d3b91a, 0x05a25800, 0xa03472fc, 0x8c86b940, 0x4ced4788, 0x9b226447, 0x36e8762d, 0x6afb76e7,
    0xbd209111, 0x0e4f6add, 0x12bb2c54, 0xd6f08794, 0xfff4ba7e, 0xc995f63b, 0x16615fd4, 0x6ac823fb,
    0x136268b1, 0x10b75174, 0x28a357ea, 0x0a0c2234, 0x7770f80d, 0xf67d6bc7, 0x1472d8c4, 0xfe636ec9,
    0xc6e3c0e6, 0x9261d72b, 0x3ff6dd6a, 0xb66ac967, 0x0c08d7ec, 0x0cda2d5f, 0xdef2bf43, 0x8f9d060f,
    0x1b97379e, 0x5680581f, 0xcbd232c1, 0xe2b7798d, 0x3915d4a2, 0x3d8f366e, 0xff5f809e, 0x7a4a4766,
    0xce755469, 0x58b94e00, 0x9df17715, 0x16b3d2cf, 0x84758b73, 0x23ab7a26, 0xdc96ed75, 0x4941c685,
    0xe5d0d72f, 0xe8b2d3c8, 0x025d722d, 0xd0a58246, 0x18783100, 0x4d51140c, 0xa6a33540, 0xf7211d0a]
    totals = []
    cnostents = [[h0, k0], [h1, k1], [h2, k2], [h3, k3], [h4, k4], [h5, k5], [h6, k6], [h7, k7], [h8, k8], [h9, k9] ]
    compressed = []
    rounde_rounded = 0

    for H,K in cnostents:
        if rounde_rounded >= rounds:
            break
        line = Unkn0wn_process(H, K, message)
        compressed.append(line)
        totals.append(line)
        rounde_rounded += 1
    squared_list = []
    for element in compressed:
        decimal_value = int(element, 16)
        squared_list.append(decimal_value ** 2)
        totals.append(hex(decimal_value ** 2))
    total = 0
    for hex_value in totals:
        decimal_value = int(hex_value, 16)
        if total == 0:
            total += decimal_value
        else:
            total += decimal_value * total
    hex_total = hex(total)[2:]
    selected_hex = ''.join([hex_total[i] for i in range(1, len(hex_total), 2)][:400])
    add_wb = 2048 - len(hex_total)
    final_output = hex_total + str(selected_hex[:add_wb])
    return final_output

def hash2603(input_data, rounds):
    try:
        with open(input_data, 'rb') as file:
            message = file.read()
    except:
        try:
            message = input_data.encode()
        except:
            try:
                message = input_data
            except:
                raise ValueError("Unsupported input type. Only string, bytes, and file inputs are supported.")
    return Unkn0wn_math(message, rounds)

class Hash2603:
    """
    This class represents a hash function with various hashing methods.

    Usage:
    >>> hash_obj = Hash2603("input")
    >>> hash_value = hash_obj.UR1hash0()

    Note, If your machine is low-end you can use lower limit_name in function After UR. 
    [ UR7hash128() here UR7 = 7 round of hashing, and hash128 = hash output limits ].
    You can use UR1 or UR2 To UR10 with your available digit limits.

    And here are limits: 0,1,2,4,8,16,32,64 or 128 digits with 1-10 round | 256 digits with 2-10 round | 512 digits with 4-10 round | 1024 digit with 9/10 round
    """
    def __init__(self, inpts, rounds = 10):
        if isinstance(inpts, int):
            inpts = str(inpts)
        self.inpts = inpts



    ##################  B0  ##################
    def UR1hash0(self):
        try:
            hash0 = hash2603(self.inpts, 1)
            return hash0[0:1]
        except:
            return None
    def UR2hash0(self):
        try:
            hash0 = hash2603(self.inpts, 2)
            return hash0[0:1]
        except:
            return None
    def UR3hash0(self):
        try:
            hash0 = hash2603(self.inpts, 3)
            return hash0[0:1]
        except:
            return None
    def UR4hash0(self):
        try:
            hash0 = hash2603(self.inpts, 4)
            return hash0[0:1]
        except:
            return None
    def UR5hash0(self):
        try:
            hash0 = hash2603(self.inpts, 5)
            return hash0[0:1]
        except:
            return None
    def UR6hash0(self):
        try:
            hash0 = hash2603(self.inpts, 6)
            return hash0[0:1]
        except:
            return None
    def UR7hash0(self):
        try:
            hash0 = hash2603(self.inpts, 7)
            return hash0[0:1]
        except:
            return None
    def UR8hash0(self):
        try:
            hash0 = hash2603(self.inpts, 8)
            return hash0[0:1]
        except:
            return None
    def UR9hash0(self):
        try:
            hash0 = hash2603(self.inpts, 9)
            return hash0[0:1]
        except:
            return None
    def UR10hash0(self):
        try:
            hash0 = hash2603(self.inpts, 10)
            return hash0[0:1]
        except:
            return None


    ##################  B1  ##################
    def UR1hash1(self):
        try:
            hash1 = hash2603(self.inpts, 1)
            return hash1[1:2]
        except:
            return None
    def UR2hash1(self):
        try:
            hash1 = hash2603(self.inpts, 2)
            return hash1[1:2]
        except:
            return None
    def UR3hash1(self):
        try:
            hash1 = hash2603(self.inpts, 3)
            return hash1[1:2]
        except:
            return None
    def UR4hash1(self):
        try:
            hash1 = hash2603(self.inpts, 4)
            return hash1[1:2]
        except:
            return None
    def UR5hash1(self):
        try:
            hash1 = hash2603(self.inpts, 5)
            return hash1[1:2]
        except:
            return None
    def UR6hash1(self):
        try:
            hash1 = hash2603(self.inpts, 6)
            return hash1[1:2]
        except:
            return None
    def UR7hash1(self):
        try:
            hash1 = hash2603(self.inpts, 7)
            return hash1[1:2]
        except:
            return None
    def UR8hash1(self):
        try:
            hash1 = hash2603(self.inpts, 8)
            return hash1[1:2]
        except:
            return None
    def UR9hash1(self):
        try:
            hash1 = hash2603(self.inpts, 9)
            return hash1[1:2]
        except:
            return None
    def UR10hash1(self):
        try:
            hash1 = hash2603(self.inpts, 10)
            return hash1[1:2]
        except:
            return None


    ##################  B2  ##################
    def UR1hash2(self):
        try:
            hash2 = hash2603(self.inpts, 1)
            return hash2[2:4]
        except:
            return None
    def UR2hash2(self):
        try:
            hash2 = hash2603(self.inpts, 2)
            return hash2[2:4]
        except:
            return None
    def UR3hash2(self):
        try:
            hash2 = hash2603(self.inpts, 3)
            return hash2[2:4]
        except:
            return None
    def UR4hash2(self):
        try:
            hash2 = hash2603(self.inpts, 4)
            return hash2[2:4]
        except:
            return None
    def UR5hash2(self):
        try:
            hash2 = hash2603(self.inpts, 5)
            return hash2[2:4]
        except:
            return None
    def UR6hash2(self):
        try:
            hash2 = hash2603(self.inpts, 6)
            return hash2[2:4]
        except:
            return None
    def UR7hash2(self):
        try:
            hash2 = hash2603(self.inpts, 7)
            return hash2[2:4]
        except:
            return None
    def UR8hash2(self):
        try:
            hash2 = hash2603(self.inpts, 8)
            return hash2[2:4]
        except:
            return None
    def UR9hash2(self):
        try:
            hash2 = hash2603(self.inpts, 9)
            return hash2[2:4]
        except:
            return None
    def UR10hash2(self):
        try:
            hash2 = hash2603(self.inpts, 10)
            return hash2[2:4]
        except:
            return None


    ##################  B4  ##################        
    def UR1hash4(self):
        try:
            hash4 = hash2603(self.inpts, 1)
            return hash4[4:8]
        except:
            return None
    def UR2hash4(self):
        try:
            hash4 = hash2603(self.inpts, 2)
            return hash4[4:8]
        except:
            return None
    def UR3hash4(self):
        try:
            hash4 = hash2603(self.inpts, 3)
            return hash4[4:8]
        except:
            return None
    def UR4hash4(self):
        try:
            hash4 = hash2603(self.inpts, 4)
            return hash4[4:8]
        except:
            return None
    def UR5hash4(self):
        try:
            hash4 = hash2603(self.inpts, 5)
            return hash4[4:8]
        except:
            return None
    def UR6hash4(self):
        try:
            hash4 = hash2603(self.inpts, 6)
            return hash4[4:8]
        except:
            return None
    def UR7hash4(self):
        try:
            hash4 = hash2603(self.inpts, 7)
            return hash4[4:8]
        except:
            return None
    def UR8hash4(self):
        try:
            hash4 = hash2603(self.inpts, 8)
            return hash4[4:8]
        except:
            return None
    def UR9hash4(self):
        try:
            hash4 = hash2603(self.inpts, 9)
            return hash4[4:8]
        except:
            return None
    def UR10hash4(self):
        try:
            hash4 = hash2603(self.inpts, 10)
            return hash4[4:8]
        except:
            return None


    ##################  B8  ##################
    def UR1hash8(self):
        try:
            hash8 = hash2603(self.inpts, 1)
            return hash8[8:16]
        except:
            return None
    def UR2hash8(self):
        try:
            hash8 = hash2603(self.inpts, 2)
            return hash8[8:16]
        except:
            return None
    def UR3hash8(self):
        try:
            hash8 = hash2603(self.inpts, 3)
            return hash8[8:16]
        except:
            return None
    def UR4hash8(self):
        try:
            hash8 = hash2603(self.inpts, 4)
            return hash8[8:16]
        except:
            return None
    def UR5hash8(self):
        try:
            hash8 = hash2603(self.inpts, 5)
            return hash8[8:16]
        except:
            return None
    def UR6hash8(self):
        try:
            hash8 = hash2603(self.inpts, 6)
            return hash8[8:16]
        except:
            return None
    def UR7hash8(self):
        try:
            hash8 = hash2603(self.inpts, 7)
            return hash8[8:16]
        except:
            return None
    def UR8hash8(self):
        try:
            hash8 = hash2603(self.inpts, 8)
            return hash8[8:16]
        except:
            return None
    def UR9hash8(self):
        try:
            hash8 = hash2603(self.inpts, 9)
            return hash8[8:16]
        except:
            return None
    def UR10hash8(self):
        try:
            hash8 = hash2603(self.inpts, 10)
            return hash8[8:16]
        except:
            return None


    ##################  B16  ##################
    def UR1hash16(self):
        try:
            hash16 = hash2603(self.inpts, 1)
            return hash16[16:32]
        except:
            return None
    def UR2hash16(self):
        try:
            hash16 = hash2603(self.inpts, 2)
            return hash16[16:32]
        except:
            return None
    def UR3hash16(self):
        try:
            hash16 = hash2603(self.inpts, 3)
            return hash16[16:32]
        except:
            return None
    def UR4hash16(self):
        try:
            hash16 = hash2603(self.inpts, 4)
            return hash16[16:32]
        except:
            return None
    def UR5hash16(self):
        try:
            hash16 = hash2603(self.inpts, 5)
            return hash16[16:32]
        except:
            return None
    def UR6hash16(self):
        try:
            hash16 = hash2603(self.inpts, 6)
            return hash16[16:32]
        except:
            return None
    def UR7hash16(self):
        try:
            hash16 = hash2603(self.inpts, 7)
            return hash16[16:32]
        except:
            return None
    def UR8hash16(self):
        try:
            hash16 = hash2603(self.inpts, 8)
            return hash16[16:32]
        except:
            return None
    def UR9hash16(self):
        try:
            hash16 = hash2603(self.inpts, 9)
            return hash16[16:32]
        except:
            return None
    def UR10hash16(self):
        try:
            hash16 = hash2603(self.inpts, 10)
            return hash16[16:32]
        except:
            return None


    ##################  B32  ##################
    def UR1hash32(self):
        try:
            hash32 = hash2603(self.inpts, 1)
            return hash32[32:64]
        except:
            return None
    def UR2hash32(self):
        try:
            hash32 = hash2603(self.inpts, 2)
            return hash32[32:64]
        except:
            return None
    def UR3hash32(self):
        try:
            hash32 = hash2603(self.inpts, 3)
            return hash32[32:64]
        except:
            return None
    def UR4hash32(self):
        try:
            hash32 = hash2603(self.inpts, 4)
            return hash32[32:64]
        except:
            return None
    def UR5hash32(self):
        try:
            hash32 = hash2603(self.inpts, 5)
            return hash32[32:64]
        except:
            return None
    def UR6hash32(self):
        try:
            hash32 = hash2603(self.inpts, 6)
            return hash32[32:64]
        except:
            return None
    def UR7hash32(self):
        try:
            hash32 = hash2603(self.inpts, 7)
            return hash32[32:64]
        except:
            return None
    def UR8hash32(self):
        try:
            hash32 = hash2603(self.inpts, 8)
            return hash32[32:64]
        except:
            return None
    def UR9hash32(self):
        try:
            hash32 = hash2603(self.inpts, 9)
            return hash32[32:64]
        except:
            return None
    def UR10hash32(self):
        try:
            hash32 = hash2603(self.inpts, 10)
            return hash32[32:64]
        except:
            return None


    ##################  B64  ##################
    def UR1hash64(self):
        try:
            hash64 = hash2603(self.inpts, 1)
            return hash64[64:128]
        except:
            return None
    def UR2hash64(self):
        try:
            hash64 = hash2603(self.inpts, 2)
            return hash64[64:128]
        except:
            return None
    def UR3hash64(self):
        try:
            hash64 = hash2603(self.inpts, 3)
            return hash64[64:128]
        except:
            return None
    def UR4hash64(self):
        try:
            hash64 = hash2603(self.inpts, 4)
            return hash64[64:128]
        except:
            return None
    def UR5hash64(self):
        try:
            hash64 = hash2603(self.inpts, 5)
            return hash64[64:128]
        except:
            return None
    def UR6hash64(self):
        try:
            hash64 = hash2603(self.inpts, 6)
            return hash64[64:128]
        except:
            return None
    def UR7hash64(self):
        try:
            hash64 = hash2603(self.inpts, 7)
            return hash64[64:128]
        except:
            return None
    def UR8hash64(self):
        try:
            hash64 = hash2603(self.inpts, 8)
            return hash64[64:128]
        except:
            return None
    def UR9hash64(self):
        try:
            hash64 = hash2603(self.inpts, 9)
            return hash64[64:128]
        except:
            return None
    def UR10hash64(self):
        try:
            hash64 = hash2603(self.inpts, 10)
            return hash64[64:128]
        except:
            return None


    ##################  B128  ##################
    def UR1hash128(self):
        try:
            hash128 = hash2603(self.inpts, 1)
            return hash128[128:256]
        except:
            return None
    def UR2hash128(self):
        try:
            hash128 = hash2603(self.inpts, 2)
            return hash128[128:256]
        except:
            return None
    def UR3hash128(self):
        try:
            hash128 = hash2603(self.inpts, 3)
            return hash128[128:256]
        except:
            return None
    def UR4hash128(self):
        try:
            hash128 = hash2603(self.inpts, 4)
            return hash128[128:256]
        except:
            return None
    def UR5hash128(self):
        try:
            hash128 = hash2603(self.inpts, 5)
            return hash128[128:256]
        except:
            return None
    def UR6hash128(self):
        try:
            hash128 = hash2603(self.inpts, 6)
            return hash128[128:256]
        except:
            return None
    def UR7hash128(self):
        try:
            hash128 = hash2603(self.inpts, 7)
            return hash128[128:256]
        except:
            return None
    def UR8hash128(self):
        try:
            hash128 = hash2603(self.inpts, 8)
            return hash128[128:256]
        except:
            return None
    def UR9hash128(self):
        try:
            hash128 = hash2603(self.inpts, 9)
            return hash128[128:256]
        except:
            return None
    def UR10hash128(self):
        try:
            hash128 = hash2603(self.inpts, 10)
            return hash128[128:256]
        except:
            return None


    ##################  B256  ##################
    def UR2hash256(self):
        try:
            hash256 = hash2603(self.inpts, 2)
            return hash256[256:512]
        except:
            return None
    def UR3hash256(self):
        try:
            hash256 = hash2603(self.inpts, 3)
            return hash256[256:512]
        except:
            return None
    def UR4hash256(self):
        try:
            hash256 = hash2603(self.inpts, 4)
            return hash256[256:512]
        except:
            return None
    def UR5hash256(self):
        try:
            hash256 = hash2603(self.inpts, 5)
            return hash256[256:512]
        except:
            return None
    def UR6hash256(self):
        try:
            hash256 = hash2603(self.inpts, 6)
            return hash256[256:512]
        except:
            return None
    def UR7hash256(self):
        try:
            hash256 = hash2603(self.inpts, 7)
            return hash256[256:512]
        except:
            return None
    def UR8hash256(self):
        try:
            hash256 = hash2603(self.inpts, 8)
            return hash256[256:512]
        except:
            return None
    def UR9hash256(self):
        try:
            hash256 = hash2603(self.inpts, 9)
            return hash256[256:512]
        except:
            return None
    def UR10hash256(self):
        try:
            hash256 = hash2603(self.inpts, 10)
            return hash256[256:512]
        except:
            return None
            

    ##################  B512  ##################
    def UR4hash512(self):
        try:
            hash512 = hash2603(self.inpts, 4)
            return hash512[512:1024]
        except:
            return None
    def UR5hash512(self):
        try:
            hash512 = hash2603(self.inpts, 5)
            return hash512[512:1024]
        except:
            return None
    def UR6hash512(self):
        try:
            hash512 = hash2603(self.inpts, 6)
            return hash512[512:1024]
        except:
            return None
    def UR7hash512(self):
        try:
            hash512 = hash2603(self.inpts, 7)
            return hash512[512:1024]
        except:
            return None
    def UR8hash512(self):
        try:
            hash512 = hash2603(self.inpts, 8)
            return hash512[512:1024]
        except:
            return None
    def UR9hash512(self): 
        try:
            hash512 = hash2603(self.inpts, 9)
            return hash512[512:1024]
        except:
            return None
    def UR10hash512(self):
        try:
            hash512 = hash2603(self.inpts, 10)
            return hash512[512:1024]
        except:
            return None


    ##################  B1024  ##################
    def UR9hash1024(self):
        try:
            hash1024 = hash2603(self.inpts, 9)
            return hash1024[1024:2048]
        except:
            return None
    def UR10hash1024(self):
        try:
            hash1024 = hash2603(self.inpts, 10)
            return hash1024[1024:2048]
        except:
            return None
