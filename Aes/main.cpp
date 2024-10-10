# include <iostream>
# include <string>
# include "AesAPI.h"

int main ()
{
    unsigned char key[17] = "qwertyuiopasdfgh";
    Plant p1, p2;
    Cipher c;

    // while(1)
    // {

    std::cout<< "输入明文"<< std::endl;
    
    std::cin>> p1.plant;
    
    encrypt(p1, &c, key);

    std::cout<< "密文："<< c.cipher<< std::endl;

    decrypt(c, &p2, key);

    std::cout<< "解密后的明文"<< std::endl;

    std::cout<< p2.plant<< std::endl;
    // }

    return 0;
}