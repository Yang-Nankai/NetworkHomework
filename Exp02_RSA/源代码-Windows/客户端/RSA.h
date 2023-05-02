#pragma once
#include "BigInt.h"

namespace ycdfwzy {

	// the RSA class provides some functions to implement RSA
	class RSA {
	public:
		/* Name: divide
			* Description: calculate @a ^ @b mod @m
			* return value
			*				a^b mod m
			*/
		static BigInt qck(BigInt a, BigInt b, const BigInt& m);

		/* Name: isPrime
			* Description: check if @a is a Prime
			* return value
			*              true if a is Prime, false otherwise
			*/
		static bool isPrime(const BigInt& a);

		static bool MillerRabin(const BigInt&, const BigInt&,
			int, const BigInt&, const BigInt&);

		static int getPrime(size_t);

		static BigInt randomPrime(unsigned bitSize = 512);
		static BigInt randomPrime(const BigInt&, unsigned bitSize = 512);


		static void rsa(BigInt&, BigInt&, BigInt&, BigInt&, BigInt&, unsigned bitSize = 768);
		static void rsa(BigInt&, BigInt&, BigInt&, unsigned bitSize = 768);

		static int exgcd(int a, int b, int& x, int& y);

		static BigInt encrypt(const BigInt& m, const BigInt& d, const BigInt& N);
		static BigInt decrypt(const BigInt& c, const BigInt& e, const BigInt& N);

		static std::vector<BigInt> encrypt(const std::string& str, const BigInt& d, const BigInt& N);
		static std::string decrypt(const std::vector<BigInt>& h, const BigInt& e, const BigInt& N);

	private:
		static std::vector<int> vPrimes;
		static std::vector<int> vMillerRabinCheckList;
	};

} // namespace ycdfwzy