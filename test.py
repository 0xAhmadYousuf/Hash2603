# B0 = LEN OF OUTPUT IS 1
# B1 = LEN OF OUTPUT IS 1
# B2 = LEN OF OUTPUT IS 2
# B4 = LEN OF OUTPUT IS 4
# B8 = LEN OF OUTPUT IS 8
# B16 = LEN OF OUTPUT IS 16
# B32 = LEN OF OUTPUT IS 32
# B64 = LEN OF OUTPUT IS 64
# B128 = LEN OF OUTPUT IS 128
# B256 = LEN OF OUTPUT IS 256
# B512 = LEN OF OUTPUT IS 512
# B1024 = LEN OF OUTPUT IS 1024

# UR = UNKN0WN ROUND
# IT MEAMS HOW MUCH SEAT OF CONSTENT WILL BE USED TO GENARATE HASH

# FOR DEFINDING HASH LENTH YOU NEED TO CHANGE VELUR AFTER HASH,
# AND
# FOR DEFINDING HASH ROUND YOU NEED TO CHANGE VELUR AFTER UR,
# FOR EXAMPLE I NEED TO MAKE A HASH WITH 4 ROUND WITH 128 BIT
# SO THE HASH CODE WILL BE :
# >>> hash_obj = Hash2603("HERE WILL BE FILE NAME OR BYTES OR TEXTS")
# >>> hash_value = hash_obj.UR4hash128() # HERE UR4 MEANS 4 ROUND AND HASH128 MEANS 128 BIT OUTPUT

# ALSO AS I SAID HERE IS UR / ROUNDS, SO ITS COMMON THAT IN LOWER ROUND LONG HASHES CANNOT BE OBTAINED, AND USERS MAY FACE SOME PROBLEMS
# FOR FIXING THIS I HAVE CREATED THOSE FUNCTIONS
# NOW FOR MAKING THINGS CLEAR, I WANT TO PRESENTING SOME INFO ABOUT THIS HASH PROGRAM

# TOTAL POSSIBLE HASH OUTPUTS FROM SAME INPUT : 108
# HASHES THAT CAN BE OBTAINED FROM UR10 - UR1 : B0, B1, B2, B4, B8, B16, B32, B64, B128
# OTHERS : B256 FORM UR10 - UR2 || B512 FROM UR10 - UR4 || B1024 FROM UR10 & UR9

# THIS HASH FUNCTION IS JUST FOR USING ON MINI FILES OR TEXTS OR FOR PASSWORD OR SECURE INFO VERIFING OR CHECKING
# THERE IS ANOTHER VERSION OF THIS HASH CALLED HASH2600, WHICH IS BATTER FOR USING IN MORE SECRET WORKS

# BELOW IS EXAMPLE OF EVERY TYPE OF HASH OUTPUT




from hash2603 import Hash2603

# making a obj and passing into class
hash_obj = Hash2603("HERE WILL BE FILE NAME OR BYTES OR TEXTS")


##################  B0  ################## 10
UR1hash0    =   hash_obj.UR1hash0()
UR2hash0    =   hash_obj.UR2hash0()
UR3hash0    =   hash_obj.UR3hash0()
UR4hash0    =   hash_obj.UR4hash0()
UR5hash0    =   hash_obj.UR5hash0()
UR6hash0    =   hash_obj.UR6hash0()
UR7hash0    =   hash_obj.UR7hash0()
UR8hash0    =   hash_obj.UR8hash0()
UR9hash0    =   hash_obj.UR9hash0()
UR10hash0   =   hash_obj.UR10hash0()
################  B1  ################## 10
UR1hash1    =   hash_obj.UR1hash1()
UR2hash1    =   hash_obj.UR2hash1()
UR3hash1    =   hash_obj.UR3hash1()
UR4hash1    =   hash_obj.UR4hash1()
UR5hash1    =   hash_obj.UR5hash1()
UR6hash1    =   hash_obj.UR6hash1()
UR7hash1    =   hash_obj.UR7hash1()
UR8hash1    =   hash_obj.UR8hash1()
UR9hash1    =   hash_obj.UR9hash1()
UR10hash1   =   hash_obj.UR10hash1()
################  B2  ################## 10
UR1hash2     =   hash_obj.UR1hash2()
UR2hash2     =   hash_obj.UR2hash2()
UR3hash2     =   hash_obj.UR3hash2()
UR4hash2     =   hash_obj.UR4hash2()
UR5hash2     =   hash_obj.UR5hash2()
UR6hash2     =   hash_obj.UR6hash2()
UR7hash2     =   hash_obj.UR7hash2()
UR8hash2     =   hash_obj.UR8hash2()
UR9hash2     =   hash_obj.UR9hash2()
UR10hash2     =   hash_obj.UR10hash2()
################  B4  ################## 10
UR1hash4     =   hash_obj.UR1hash4()
UR2hash4     =   hash_obj.UR2hash4()
UR3hash4     =   hash_obj.UR3hash4()
UR4hash4     =   hash_obj.UR4hash4()
UR5hash4     =   hash_obj.UR5hash4()
UR6hash4     =   hash_obj.UR6hash4()
UR7hash4     =   hash_obj.UR7hash4()
UR8hash4     =   hash_obj.UR8hash4()
UR9hash4     =   hash_obj.UR9hash4()
UR10hash4     =   hash_obj.UR10hash4()
################  B8  ################## 10
UR1hash8     =   hash_obj.UR1hash8()
UR2hash8     =   hash_obj.UR2hash8()
UR3hash8     =   hash_obj.UR3hash8()
UR4hash8     =   hash_obj.UR4hash8()
UR5hash8     =   hash_obj.UR5hash8()
UR6hash8     =   hash_obj.UR6hash8()
UR7hash8     =   hash_obj.UR7hash8()
UR8hash8     =   hash_obj.UR8hash8()
UR9hash8     =   hash_obj.UR9hash8()
UR10hash8     =   hash_obj.UR10hash8()
###############  B16  ################## 10
UR1hash16     =   hash_obj.UR1hash16()
UR2hash16     =   hash_obj.UR2hash16()
UR3hash16     =   hash_obj.UR3hash16()
UR4hash16     =   hash_obj.UR4hash16()
UR5hash16     =   hash_obj.UR5hash16()
UR6hash16     =   hash_obj.UR6hash16()
UR7hash16     =   hash_obj.UR7hash16()
UR8hash16     =   hash_obj.UR8hash16()
UR9hash16     =   hash_obj.UR9hash16()
UR10hash16     =   hash_obj.UR10hash16()
###############  B32  ################## 10
UR1hash32     =   hash_obj.UR1hash32()
UR2hash32     =   hash_obj.UR2hash32()
UR3hash32     =   hash_obj.UR3hash32()
UR4hash32     =   hash_obj.UR4hash32()
UR5hash32     =   hash_obj.UR5hash32()
UR6hash32     =   hash_obj.UR6hash32()
UR7hash32     =   hash_obj.UR7hash32()
UR8hash32     =   hash_obj.UR8hash32()
UR9hash32     =   hash_obj.UR9hash32()
UR10hash32     =   hash_obj.UR10hash32()
###############  B64  ################## 10
UR1hash64     =   hash_obj.UR1hash64()
UR2hash64     =   hash_obj.UR2hash64()
UR3hash64     =   hash_obj.UR3hash64()
UR4hash64     =   hash_obj.UR4hash64()
UR5hash64     =   hash_obj.UR5hash64()
UR6hash64     =   hash_obj.UR6hash64()
UR7hash64     =   hash_obj.UR7hash64()
UR8hash64     =   hash_obj.UR8hash64()
UR9hash64     =   hash_obj.UR9hash64()
UR10hash64     =   hash_obj.UR10hash64()
##############  B128  ################## 10
UR1hash128     =   hash_obj.UR1hash128()
UR2hash128     =   hash_obj.UR2hash128()
UR3hash128     =   hash_obj.UR3hash128()
UR4hash128     =   hash_obj.UR4hash128()
UR5hash128     =   hash_obj.UR5hash128()
UR6hash128     =   hash_obj.UR6hash128()
UR7hash128     =   hash_obj.UR7hash128()
UR8hash128     =   hash_obj.UR8hash128()
UR9hash128     =   hash_obj.UR9hash128()
UR10hash128    =   hash_obj.UR10hash128()
##############  B256  ################## 
UR2hash256     =   hash_obj.UR2hash256()
UR3hash256     =   hash_obj.UR3hash256()
UR4hash256     =   hash_obj.UR4hash256()
UR5hash256     =   hash_obj.UR5hash256()
UR6hash256     =   hash_obj.UR6hash256()
UR7hash256     =   hash_obj.UR7hash256()
UR8hash256     =   hash_obj.UR8hash256()
UR9hash256     =   hash_obj.UR9hash256()
UR10hash256    =   hash_obj.UR10hash256()
##################  B512  ################## 7
UR4hash512     =   hash_obj.UR4hash512()
UR5hash512     =   hash_obj.UR5hash512()
UR6hash512     =   hash_obj.UR6hash512()
UR7hash512     =   hash_obj.UR7hash512()
UR8hash512     =   hash_obj.UR8hash512()
UR9hash512     =   hash_obj.UR9hash512()
UR10hash512    =   hash_obj.UR10hash512()
#################  B1024  ################## 2
UR9hash1024    =   hash_obj.UR9hash1024()
UR10hash1024   =   hash_obj.UR10hash1024()





list_hashes = [
    UR1hash0, UR2hash0, UR3hash0, UR4hash0, UR5hash0,
    UR6hash0, UR7hash0, UR8hash0, UR9hash0, UR10hash0,
    UR1hash1, UR2hash1, UR3hash1, UR4hash1, UR5hash1,
    UR6hash1, UR7hash1, UR8hash1, UR9hash1, UR10hash1,
    UR1hash2, UR2hash2, UR3hash2, UR4hash2, UR5hash2,
    UR6hash2, UR7hash2, UR8hash2, UR9hash2, UR10hash2,
    UR1hash4, UR2hash4, UR3hash4, UR4hash4, UR5hash4,
    UR6hash4, UR7hash4, UR8hash4, UR9hash4, UR10hash4,
    UR1hash8, UR2hash8, UR3hash8, UR4hash8, UR5hash8,
    UR6hash8, UR7hash8, UR8hash8, UR9hash8, UR10hash8,
    UR1hash16, UR2hash16, UR3hash16, UR4hash16, UR5hash16,
    UR6hash16, UR7hash16, UR8hash16, UR9hash16, UR10hash16,
    UR1hash32, UR2hash32, UR3hash32, UR4hash32, UR5hash32,
    UR6hash32, UR7hash32, UR8hash32, UR9hash32, UR10hash32,
    UR1hash64, UR2hash64, UR3hash64, UR4hash64, UR5hash64,
    UR6hash64, UR7hash64, UR8hash64, UR9hash64, UR10hash64,
    UR1hash128, UR2hash128, UR3hash128, UR4hash128, UR5hash128,
    UR6hash128, UR7hash128, UR8hash128, UR9hash128, UR10hash128,
    UR2hash256, UR3hash256, UR4hash256, UR5hash256, UR6hash256,
    UR7hash256, UR8hash256, UR9hash256, UR10hash256, UR4hash512,
    UR5hash512, UR6hash512, UR7hash512, UR8hash512, UR9hash512,
    UR10hash512, UR9hash1024, UR10hash1024,
    ]
variable_names = [
    "UR1hash0", "UR2hash0", "UR3hash0", "UR4hash0", "UR5hash0",
    "UR6hash0", "UR7hash0", "UR8hash0", "UR9hash0", "UR10hash0",
    "UR1hash1", "UR2hash1", "UR3hash1", "UR4hash1", "UR5hash1",
    "UR6hash1", "UR7hash1", "UR8hash1", "UR9hash1", "UR10hash1",
    "UR1hash2", "UR2hash2", "UR3hash2", "UR4hash2", "UR5hash2",
    "UR6hash2", "UR7hash2", "UR8hash2", "UR9hash2", "UR10hash2",
    "UR1hash4", "UR2hash4", "UR3hash4", "UR4hash4", "UR5hash4",
    "UR6hash4", "UR7hash4", "UR8hash4", "UR9hash4", "UR10hash4",
    "UR1hash8", "UR2hash8", "UR3hash8", "UR4hash8", "UR5hash8",
    "UR6hash8", "UR7hash8", "UR8hash8", "UR9hash8", "UR10hash8",
    "UR1hash16", "UR2hash16", "UR3hash16", "UR4hash16", "UR5hash16",
    "UR6hash16", "UR7hash16", "UR8hash16", "UR9hash16", "UR10hash16",
    "UR1hash32", "UR2hash32", "UR3hash32", "UR4hash32", "UR5hash32",
    "UR6hash32", "UR7hash32", "UR8hash32", "UR9hash32", "UR10hash32",
    "UR1hash64", "UR2hash64", "UR3hash64", "UR4hash64", "UR5hash64",
    "UR6hash64", "UR7hash64", "UR8hash64", "UR9hash64", "UR10hash64",
    "UR1hash128", "UR2hash128", "UR3hash128", "UR4hash128", "UR5hash128",
    "UR6hash128", "UR7hash128", "UR8hash128", "UR9hash128", "UR10hash128",
    "UR2hash256", "UR3hash256", "UR4hash256", "UR5hash256", "UR6hash256",
    "UR7hash256", "UR8hash256", "UR9hash256", "UR10hash256", "UR4hash512",
    "UR5hash512", "UR6hash512", "UR7hash512", "UR8hash512", "UR9hash512",
    "UR10hash512", "UR9hash1024", "UR10hash1024",
]


for variable, hashes in zip(variable_names , list_hashes):
    d = 13-len(variable)
    print(f"Velue of {variable}{' '*d} is :{hashes}")


# output will be like below
'''
Velue of UR1hash0      is :1
Velue of UR2hash0      is :5
Velue of UR3hash0      is :a
Velue of UR4hash0      is :3
Velue of UR5hash0      is :8
Velue of UR6hash0      is :6
Velue of UR7hash0      is :6
Velue of UR8hash0      is :1
Velue of UR9hash0      is :2
Velue of UR10hash0     is :f
Velue of UR1hash1      is :2
Velue of UR2hash1      is :5
Velue of UR3hash1      is :b
Velue of UR4hash1      is :9
Velue of UR5hash1      is :c
Velue of UR6hash1      is :a
Velue of UR7hash1      is :6
Velue of UR8hash1      is :c
Velue of UR9hash1      is :2
Velue of UR10hash1     is :8
Velue of UR1hash2      is :d5
Velue of UR2hash2      is :06
Velue of UR3hash2      is :a4
Velue of UR4hash2      is :47
Velue of UR5hash2      is :df
Velue of UR6hash2      is :eb
Velue of UR7hash2      is :02
Velue of UR8hash2      is :31
Velue of UR9hash2      is :17
Velue of UR10hash2     is :b7
Velue of UR1hash4      is :58f8
Velue of UR2hash4      is :f1a7
Velue of UR3hash4      is :4b57
Velue of UR4hash4      is :75dd
Velue of UR5hash4      is :2668
Velue of UR6hash4      is :cdff
Velue of UR7hash4      is :f93c
Velue of UR8hash4      is :e4bb
Velue of UR9hash4      is :be4f
Velue of UR10hash4     is :3d31
Velue of UR1hash8      is :b0776f03
Velue of UR2hash8      is :27230855
Velue of UR3hash8      is :37efbbd8
Velue of UR4hash8      is :0d22f58b
Velue of UR5hash8      is :a6495e30
Velue of UR6hash8      is :0623efc7
Velue of UR7hash8      is :7fda290a
Velue of UR8hash8      is :96ebc64f
Velue of UR9hash8      is :b84521d0
Velue of UR10hash8     is :26928db2
Velue of UR1hash16     is :5d788ec8330907f3
Velue of UR2hash16     is :6ad013e2e9947f1e
Velue of UR3hash16     is :4176dc1424d40500
Velue of UR4hash16     is :56beceef865780c7
Velue of UR5hash16     is :e8e947771afee9f8
Velue of UR6hash16     is :1abaa7610f7414f3
Velue of UR7hash16     is :67c5918ded4b6b64
Velue of UR8hash16     is :40235eafe12c2dbc
Velue of UR9hash16     is :8f37c8d5014f4da1
Velue of UR10hash16    is :0f966b20a5fad809
Velue of UR1hash32     is :34758ccb620d19f098dc4ac22de42ad4
Velue of UR2hash32     is :9f35eb72a0f64df75d732657de8b1016
Velue of UR3hash32     is :d4607ba87ca1f7ea58e92dce2458f90b
Velue of UR4hash32     is :9536cd80e67be23d4d525c03641ae636
Velue of UR5hash32     is :58242ea59802eebb1b5d21c444bff4ce
Velue of UR6hash32     is :7af8ed59333b1984d802bccd89e67a62
Velue of UR7hash32     is :e94ad4ed2e764ace91b65d667ce1e545
Velue of UR8hash32     is :be4ed81ed9de1d8d275879bd87c9c73e
Velue of UR9hash32     is :a7cd59bebf0c87f8d46740316cff1933
Velue of UR10hash32    is :c902c30e0bd41cd2d429a0c96584cec8
Velue of UR1hash64     is :8359e3559daed316d08aadb7e56adfdbbb93bb5eb79123a1ddbe81820defe926
Velue of UR2hash64     is :f481148063998e95dcb4dc09d2d576392912a2683dfb504369dbacd8130d9366
Velue of UR3hash64     is :000c10acaad54fa3b277c04ca785b0ae4670b065b8c4dc686493a8017f23a62d
Velue of UR4hash64     is :8bc2f855c535e2a97dd2b44f541240f7584878a67ae26f7670daa23f7b763071
Velue of UR5hash64     is :b48a107ca4899f93f761f77baf2dc7c66a2f3227e58f3f6703fffcbd9e667609
Velue of UR6hash64     is :cf6bcb32dda6d07cd0c5382d00ac74a60ac144161f511b9064e25642a22a4f6e
Velue of UR7hash64     is :39dfcb25275daa47a43c035f4ea7c1696b3380f3a811dead1522c04193a6035f
Velue of UR8hash64     is :586bfdf43463cc2112f51f17933faa541674d66b9b1dfd743c5123a8435c47a7
Velue of UR9hash64     is :f33d66161a72ee3a1c418257f66e3f346bb8086b5e1763bef80ab7acd2ae1504
Velue of UR10hash64    is :f221e919fb42eda191e19e6c230fc5a8d29ece69a3bb971f8cff577732aafafb
Velue of UR1hash128    is :5aad736f851e6edbb4d89894f0d23ba78a5b81347c9d8655e2406e2ffccd12258807f3d8e8397345cb2d908ca2d4a43935de360ad75afbb3be7131de12df96ad
Velue of UR2hash128    is :77a8e14170c99a0c4c5f8c53681d4c72e1c24458abd13b51bd56c1aa495d85e72ed3e1ba6eb1de04fc539be8686b46f8e9b145c4353b524bd05eb0a3e7b8ac1f
Velue of UR3hash128    is :65898d3cc670f456e391c372520d1111b7b7c649fdd3c64097759379b90221d4b0b27ff86bd79ee35b2d3abd54cc685df8d93b5ad6977fa3b41ce07d3197fd2f
Velue of UR4hash128    is :a1caf751d241179976d808be4364ec35502c64439f0971cc509c7e5fdd38b29cf2ce7b3e5ca95ece491ba222186eca694e22e96497468e67b1b3aa310ae8ebf5
Velue of UR5hash128    is :a677419e26f75527107c07d024b4594e8e887e99ac5e01f3f1e1962096697c93e730ebe6ce1a9ab9074694a4850fc1c9eab2f23d24b262a24c5f9114c35d1b6e
Velue of UR6hash128    is :29a4437ab1bc0105fe8d027eac97532d7105b7a816de860e2e2dd27c54c07d570125862b6cb46488e4231c6846ab5f775a4d50b04e09ae60ff94e59bb4fedce8
Velue of UR7hash128    is :0f33e8eed30af24b03cc9854e86d0fb45f4cb6ea683c24f328655d95cf6b0384d4da9c1a480510ed355d0fca299bc14951ea1e55d91141b6e3271c536b648d5b
Velue of UR8hash128    is :027c4b1a8ddd0d0b96d4dbb1e9fd91a35e205a48390e6a34e9f9bc538f067992e0e44acc39f2d6fcf8eecb67e2c6c2297cc23c8a3fdd089f356321b02aece2ad
Velue of UR9hash128    is :c9dbd8ac2886559f8c7fe587295c3116fc9426e067f2c2d009c1ae630059ba55105d47e38708dab579c105120f364452dd36acba13f73ef67e1d6055b6ac6c07
Velue of UR10hash128   is :4a0d7d2754264a299ce044a1f8aa78a02de437a5284043f51ea0c91613fbd8e23a523390653c2272a2f808e25fcbafd3df46631066b67ed20526610da28c9aa5
Velue of UR2hash256    is :14c106eae223edb8778c778a8ec08c2ea315f16a5c61ce81419bf069ec397bbf486545378463baeed39f1bd2c1e6b54aa32e5c1ca87e109c9848269b4c256177385a03294fef5b206d7d367eb06414039e5c4c925699228db039bc83d36781109accfc38dc21248b1b1d61a9d57e31ae1e4c3b88b6891545b2b0e0378cf416a2
Velue of UR3hash256    is :7e64b685d1571aa599e3aedc82040abab3b9cf05e063358b3b2db9bc0e5e1bbff7344650e80b9ae84c171952a420d74df46c9f1a56bbf87de9ed7f1b2c2ef45422ff506f8983069d8dae8ddc353ad783e62efab3e6ef25ba9565b1cf9b40df1eacf5066df1074f61b9fd86dc3ca5689f0b3c0ca162504d67c8c49865c3bd330f
Velue of UR4hash256    is :616baaf4acc0c69284ee861e324edbb7a8ee605dd6ff07dc60a2a8a041a5e7f9177d9a1211a79a446b57174d7993df4a6698df49f683b85d02930940c03ad33574ba931d0cada53f801d956829d782d5889e70891752a206fc877594746b122f6d3f0ac00ccb68c2963368c13da69b0d4f1fcbc7edf806ed918f1776aaf9add2
Velue of UR5hash256    is :ead7e703795918af764b28e17abe91986bfcc0c5e23af14a6b9bcdafe6f6d2d0c9c78091434028065e111ac8186996290ea0652a9a00a8b88e03564577ed540fa801e89b0ae41771bee5c2a853b83c22ecef62e7bea0e999efc719a04af878dead548e031f15a6f3fdb152613625d6adf75a89fe9fe1f9917df8c833b7e08c6e
Velue of UR6hash256    is :5882b6c4b4670bc5b866d00e7d100d63393b0ffe180f4bb28640b2c871dc6465f8dc7d19f1612753b4178a9c36be308a4357a7853f5ce0c3a2c8c8dbd8f56287c5c91624f0ab4ebf731838af6154bceeb9f4d715daa2d889f89bda0aa76524d434a3b0bee611fd59a0bfb6b7bdd4150a32f0e8c34c7dee323583ba60a8254147
Velue of UR7hash256    is :40f1903a981ae66539a47faf747813719b6aa2990f742adba119549ae83a76897e73b2007d852eb7dbbc536381605968ea66388844721bccb7f8f5220feba86aa8e6a838413ef93e5b805ed50c3150a8f078b7a5a97a18363bacb2f78f8f94cfc1a0eafcbb7eb58373e7a36748e6b7f866e4fcc8ced6054e4ff59f80ea0302fd
Velue of UR8hash256    is :46ab0214ef2238865432824adbc3fed5d77a60396e85dc1601c5e5f5c38ebe70d067dd44b74e5c1b1c4769e111863cdea5008d8d2355cb5af1c716699487fb6bcf47fa121da1d9ea5f0e1c8cb7a9367c3db22a73b2d8143833beef60b72ddbe58c37f304cf60d6b945e28d245290186418ee7b15719138c46ab986efabe49e75
Velue of UR9hash256    is :21dfc57d8adc8098bf7201059ab5f4a2c86ac002778ab8570cdf85d4d77aec8ae73fc7cc7f50f0dbb30b640ead9476a38e0899ce068e28d5ec1c965692a7029376ffadec528ff4c2b9eb530da2385bebc378c3ffd00ddf7447d063deb59110bcbc7310c99776afe55696d00d60c44f90acde1153d4f87652660ba157b6cc8bbb
Velue of UR10hash256   is :d7166b6ca13a2615d59bc7347ae9455fb4a8ed4ff6ba7a4bb85e0e2287f389e63cd5d2a7abbce064c36cebc982a903ce7648a335abab2c1b4fc7de5e0d8ed7746633bb1670b9563a94b0600553c77c3458cbf868f6f10ddc937873e7108f2163fd7df5a10a1046ce962c3ec24deb83da9cc95111aa71ce4715138544d930fd1b
Velue of UR4hash512    is :21068e6e4df8091d48d7e9d95e230b2de3e1479e6528351c50a862eaa6f459b7161ddf38c9214e5d45e3b58a00bedd0613ea0de8452e297c32c3ef66e9c418b376ead045db123243e3b4e1cab3d8dfc26c93f3a9bd1a7a588ef144c6bedc517b68ac7c3352ead1f5a1df6e8c84938340640f69eced099748bc4c8975dd25b6eef670756d06b2dd2c34a66b2855529d24f42078886a2f60a2fb6011a712179688e34c50c43f91c0cefd82c2ebec9ee9b228ea9e29476e713a1a8b51ba4c0624e6e2eb78e0d6f7c028015797da217a4b77d93fa68f9638d23900a354a3dcd5f0d5897258e097226c7544b2fdfa0cb826381d6bdffb7d86d1f76a9d216eed89d879
Velue of UR5hash512    is :93aedd125b0abb9d2e6f493c6bce9fe464a49edd97c0cd68a0831abf6f37d66c8332ba14c894b6296fa56b4aa925d933b9413a939d5abf51394e3a4c3ed4258e893b21937bb3db60656a66ae5fee5a9108e6da46c920419af19ad802bfd5c9c3a4348cc085d9eb9a51e4455ff100e80295cc015941b3f7d151482bab9c9cd25318e9c341d9e02982adab97b7c004e0c890db2fb387528e12eae9f7fba4d5a27a4bf6698d63dda3108f0c146853e9f26027635c5b83f45d834b99ce720f8254adbc41ae75fa64e5a2e09ba4d0a1cec76c5b67933b56f073f6b160cf6869e08977ae9884e582ebbd144f4e4a0c49f3717bfd76af275ff73fcde669671e67570c70
Velue of UR6hash512    is :a9c94b8cbda6281b5c491cb4bcfd7a0a7f936618e6b5db0b1774428fbbdefca8a2464ed97aa5ec50176882903d83e82e1f108c3dcdd7a9d93c2a77f73b67b00ed149ffea885691341b822dae0336b03453d002a091e1134a4baba3e6db49acfa39f8872b5bc7fed0ed7f2797aa6c6d0ddb2faf44437cfee1af10832753db745dcf90ca77eec23be780d4b4454c21362a880eceb5002140f4a3465dc4f66c02f92c1471c1185f753b3b4d14c338cca08b48a7875d80c04a5693090836e5eb80478d921346fb4ac5876d6aa72527cb3a0203bee5cd1e52cd62877cbc1fef2155171060eb905da36992b26b4dbefc6517eac5669f09d52f116f807b2501a2e9dcb1
Velue of UR7hash512    is :94f8eb30f0fce9c75950116a1b0bb15324268f8dfd7f7f016fb557f3f41a697b5f569a3378a214c840ebbf696e3034ef437f34cd0838350debb4f0e0035749f2efccb80f2f79a918d53b0543211de29f68601744776dee47220961db2eb60afe850f6db96d9fa0a90f70a37eb09b95763511b434c76cd774972a7b5e50a4559932517bad35230e79a594a02ffceb694db331a171f73855f3e52f5b6f082244d941d6a9d1ab97884135345dbf0dba719a12cc074c331ef67e86337f99ef2fd6a766f01b8e390eb4eec39ed87b325d728e0b663cfe1d7d27be693a93d2c91131fdb6f4b6bbaba5b30e26b381edd09fb00d108ea66ab407578c8ca25210ed7d0b34
Velue of UR8hash512    is :3d0707c0d168d0b631b7ac7b4a6c72b0bce50050ea12bdf2cb65615ca48a519922a63d8f54a66273eeaebb48d649a6b488c98760504ffb8e2b9a519f08afb62d0534fdf55ccb65a14626231ea4d9552a2cd51476ce9e5d57c7eb0447731ebf6175433e0daacc336448fd2c4280875aeeeeb782f9231bfd9cfb57f1fc28a546160cddade18830a865c2faf09ecc05669b9e5090e336a77840a35c3b4c721d04ead63004a3ff776767fc7e23034fd3eb92cf5559d9ba3c4ab61d43fece313ba5276cddc5edc9544dac0344dfa35c71e4cbbcd9ba1c6ade017a04c1cb45d118e2df243ee6e103f79c84430c567654c36873f82ace877f647947132071bb3c6b2dcd
Velue of UR9hash512    is :f498f53ce54d16b376efa24801ecf1913edaf2f89c5842a3abd3c70975f40e1a55b2b3543a3fa8d1bf78c44979b1960230a809140fde82f7a1fe09bfde2f100b5e7513bf737b30d76d69208733f39b5601869a9ad6548e7099c7007f1ba414dc25f032bd3b9b5f56d934e3e4df9c89cc95b2014ee24fd9fbace6ef1bcaefddae51c56df8609850fbd3c12bdd8856c0006ec0ebdb9958bc4ea6a4fdccff95442be80be0ae85d51d91a312ce8be167ff9bbbd864343002304908697e1000b5a0b2557c81c4c07629800d88f0c91190f3c5f382f6423cc5e7375697e1f4c7b0e53a5c884d89eb9b6f43f5fd2cb97443f198632e536d8a09df2a7870e738cfd7e557
Velue of UR10hash512   is :bc8fa7499a9dba19c4e8c30b63b722b825f0b88dec03ea7acb311222d8055860e127e037d3dba8934ad7d4e7600d854a7db0560bfd38c338bfbc1a431e232ab7513eb5fb08d136e571e35c907d7ac312a96b69507ca31c34d3b00925c5908979a1ad5b96b75246c1ede0949504e93a5fad8b853174ac66692b921e9cfa48240f7c1e62dc1e6cb161c083707978585892ed736cdba7ce67ba6b4118360ecff822a5274a98a24c8791f82ec15a2759040ce6ae46b8b7e7827c0f82118ad50d3912e023503c4b8d6ed39676822cb7ae58fe43dba824110ff831afe8afb5a8c86da0dbff8f805b548afa0cabfaebf1d9b8b547af50962755838c029b26f051c0c65d
Velue of UR9hash1024   is :ef156b40ed6a67ced79add7379ca66186c80017945c92ac68acacd01cf2fd2a4d329833adb85e45ace269edb1e3eb5b5ff22fe5fbc3f71a54be695c5aa9e58f03169d39251503123a223bdc74ef9983f8a7f2b6c2f8f0028376ef86192d1dc61e64fb089b28665937d21647626af0d1fe4a19600627da083d1675096eeac69af5b55c6b02b91e4a0db78251d3a083c1481e5a7f3f62c38d7537ee5501ddcb85dcef598882510e477f524fd4975af5dbfea9b77c39fe311a570c0f54f4ade8dc66542b428c6a622ef279a72ac70d1fe15473c2e05c210b3092c0a26f1f58300760cd84de4aeb8c26cfefe18c078a0914016917e25855dbd3496e92c77ac6926754a4d8efd1f89e9e37e8cc87f6b4fb5b25d8aa228946c14cf0baf7b54c58f5c1c2150c76a69e6bdfaa88ad0b4edfa4e61260bd9ccb6d4f917c254034826e75528f796c854e63835e73b785914d3a3c11f7e3537f59fb845c0027ef8510f7851fd17d9efc784701cf933d66a2eac1276ef4b88be73e8a7c2e549b8c865fcf579c16c460722091e309a50d7378a59152f642d6ca37e6ed056cc71f5dac08f215a5428a027a87cf547aca7f7cf00b3b4ed463e89e6e85cc6627236fdc2f429b3d28bb383f0df4703e510cc30976f5660d04f0ce1348626b176cbb485c5d636f281c11ea28c823b37954ea5234af81f84991620894fe271e9fef0be53f3b07d90733b
Velue of UR10hash1024  is :c0ac58f8fd1d132c05961ee2e176f5905dac03a5261b33fe01df03d5b642a02ce38afe75933fc40db56d67c0dc89a4a5442d5dd4a74c30a83d646107adb32fdc50defa2d25f4ed68800034607882cf3624f4d3e801aebe2f4c9eecf8900844c0b6e8d13289ce4f1e1ca2f51f1480cf73fa742cf75ec6012ea945014e51412f74cc5e7fab5e68c3e472ac5847f1a0ad2bdc532dd7e50bd8cf0c4d32041e71529c4fb2503b7e5c1d03bae571956611e20bd4b69ee0981febad0aadb0e24cccdb4e6ffea1e36b82d8dec9c3ffdd357ca255f9d77fa92057e58daee5572beb8e34053901860274ddfdd62d16d383755e69bc72de96570fcdb52fedde4d4b2f3649bc017257b35f735f53afe3113c62913cc48e609a0bcae4678c830a61bd5227e8c4594556ee2fbe96a195935bfcc3470e163eed150f12c2d9b4db61759036f7cc7e349f7f514bf4813f78c6a304d5545210378cfeeae884fd1e68fcbc6aac9398579670af19cf2ad96abdfaf19f15c963a6adcbbe28655a5828c71b6e89bd81240be5c5ea27219d7c86a5ed4c2a4816ef09d124b5420f840a0e9803f75d375cd8bb86fe70877d704e6859efa84436fed99e8f2c6f96f338f00087d162d2f6b05a89923eb4c2490954e82199b2d111ec3f582ee93b7fcf772aabadd746a9c0418a80d4758035e0963b82a2305c222882fbf3f63066e2561d2ca576bc1a655b74a95f
'''
