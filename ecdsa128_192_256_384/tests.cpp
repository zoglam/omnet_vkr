#include "gtest/gtest.h"
#include <iostream>
#include "ecc.h"

TEST(ECC, EncryptDecrypt)
{
    uint8_t *p_publicKey;
	uint8_t *p_privateKey;
	uint8_t *p_hash;
	uint8_t *p_signature;

	ASSERT_EQ(ecc_make_key(p_publicKey, p_privateKey), 1);
	ASSERT_EQ(ecdsa_sign(p_privateKey, p_hash, p_signature), 1);
	ASSERT_EQ(ecdsa_verify(p_publicKey, p_hash, p_signature), 1);
}

int main(int argc, char *argv[])
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}