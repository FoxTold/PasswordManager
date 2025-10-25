#include <files.h>
#include <hex.h>
#include <iostream>
#include <osrng.h>
#include <SQLiteCpp/Database.h>

#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>

int main(void)
{
  CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
  CryptoPP::SecByteBlock salt(16);
  CryptoPP::SecByteBlock key(32);
  CryptoPP::AutoSeededRandomPool prng;
  auto db = SQLite::Database("dupa.db",SQLite::OPEN_CREATE | SQLite::OPEN_READWRITE);
  db.exec("CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT)");

  prng.GenerateBlock(salt,salt.size());

  constexpr uint32_t iterations =  10000;

  std::string password = "MojeSuperTajneHaslo123!";

  pbkdf2.DeriveKey(key.data(), key.size(), 0, reinterpret_cast<CryptoPP::byte*>(password.data()), password.size(),
                   salt.data(), salt.size(), iterations);

  CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));

  std::cout << "Hasło: " << password << std::endl;

  std::cout << "Sól (hex): ";
  encoder.Put(salt, salt.size());
  encoder.MessageEnd();
  std::cout << std::endl;

  std::cout << "Wygenerowany klucz (hex): ";
  encoder.Put(key, key.size());
  encoder.MessageEnd();
  std::cout << std::endl;
    return 0;
}
