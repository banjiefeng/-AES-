# include "AesAPI.h"

static int getIntFromChar(char c);
// 数组转化为字符串
static void convertArrayToStr(int array[4][4], char *str);
// 写文件
void writeStrToFile(char *str, int len, char *fileName);
// 异或初始化向量
void xorWithIv(unsigned char iv[4][4], unsigned char B[4][4]);


// 将char转化为int
static int getIntFromChar(char c)
{
    int result = (int)c;
    return result & 0x000000ff; //&000000ff防止int字节中存放其他值
}

// 把4X4数组转回字符串
static void convertArrayToStr(int array[4][4], std::string &result)
{
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            result += (char)array[j][i];
}


// 和偏移向量进行异或
void xorWithIv(unsigned char iv[4][4], unsigned char B[4][4])
{
    for (int i = 0; i <= 3; i++)
    {
        for (int j = 0; j <= 3; j++)
        {
            B[i][j] ^= iv[i][j];
        }
    }
}

// 处理小段序将其转化为大端序
unsigned int compose(unsigned int t)
{
    return ((t >> 24) & 0x000000ff) | ((t >> 16) & 0x0000ff00) |
           ((t << 8) & 0x00ff0000) | ((t << 24) & 0xff000000);
}

// 将字节转化为整形
unsigned int char2Int(unsigned char *c)
{
    unsigned int t = 0;

    t = (c[0] << 24) & 0xff00000000 | (c[1] << 16) & 0x00ff0000 |
        (c[2] << 8) & 0x0000ff00 | (c[3]) & 0x000000ff;

    return compose(t);
}

// 密钥拓展
void keyExpansion(unsigned char * str, unsigned char (*keys)[44])
{

    // 轮常量表
    unsigned char Rcon[11] = {0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54};

    // 负责存储当前所遍历的第[i-1]列
    unsigned char past[4];

    int i, j;

    int k = 0;

    // 将密钥数组放入前4列拓展密钥中
    for (i = 0; i <= 3; i++)
    {
        for (j = 0; j <= 3; j++)
        {
            keys[j][i] = getIntFromChar(str[k]);
            k++;
        }
    }

    // 选取D2和D4分别生成两个伪随机字
    unsigned char D2[4], D4[4];
    unsigned char DW2, DW4;

    // 选取1和3两列
    for (int i = 0; i < 4; i++)
    {
        D2[i] = keys[i][0];
        D4[i] = keys[i][2];
    }

    // 将两个字由16进制转化为10进制
    unsigned int d2 = char2Int(D2);
    unsigned int d4 = char2Int(D4);

    // 根据初始种子d2生成伪随机数DW2
    srand(d2);

    unsigned int dw2 = rand();

    // 将整数转化为字节流形式,即获取伪随机数DW2
    DW2 = dw2 & 0x000000ff;

    // 根据初始种子d4获取伪随机数
    srand(d4);

    unsigned int dw4 = rand();

    DW4 = dw4 & 0x000000ff;

    // 根据当前生成的伪随机密钥进行密钥拓展
    // 将2列上移1位
    for (int i = 0; i < 3; i++)
    {
        keys[i][1] = keys[i + 1][1];
    }
    keys[3][1] = DW2;

    // 将4列下移1位
    for (int i = 3; i > 0; i--)
    {
        keys[i][3] = keys[i - 1][3];
    }
    keys[0][3] = DW4;

    // 进行密钥拓展

    /* 密钥拓展

        [当前列] % 4 == 0

        [当前列 - 4] ^ [轮常量异或](字节代换(列位移(当前列-1)))

        首先根据初始
    */
    // 采用128位拓展10论，也就是再拓展40列
    for (i = 4; i <= 43; i++)
    {
        if (i % 4 == 0)
        { // 如果能被4整除，特殊处理
            // 把前一个密钥移位赋值给数组
            // 列移位,将当前列向上移动一个字节
            for (j = 1; j <= 4; j++)
                past[j - 1] = keys[j % 4][i - 1];

            // 此时并未进行列位移
            for (j = 0; j <= 3; j++)
            {
                if (j == 0)
                    keys[j][i] = S_BOX[past[j] >> 4][past[j] % 16] ^ Rcon[i / 4] ^ keys[j][i - 4];
                else
                    keys[j][i] = S_BOX[past[j] / 16][past[j] % 16] ^ keys[j][i - 4];
            }
        }

        else
        {
            for (j = 0; j <= 3; j++)
            {
                keys[j][i] = keys[j][i - 4] ^ keys[j][i - 1];
            }
        }
    }
}

// 列混淆运算用到的乘2函数
unsigned char xtime(unsigned char input)
{ // x乘法('02'乘法)

    int temp;
    temp = input << 1;

    if (input & 0x80)
    {
        temp ^= 0x1b;
    }

    return temp;
}

// 列混淆运算
// 使用GF(2^8)对[列混淆左乘矩阵的行]与[当前字节恶的列]进行矩阵乘法
void mixColumn(unsigned char (*input)[4])
{ // 列混淆

    int i, j;
    unsigned char output[4][4];

    // 先所有列求出,在求行
    for (j = 0; j <= 3; j++)
        for (i = 0; i <= 3; i++)
            output[i][j] = xtime(input[i % 4][j])                                   // 0x02乘法
                           ^ (input[(i + 1) % 4][j] ^ xtime(input[(i + 1) % 4][j])) // 0x03乘法
                           ^ input[(i + 2) % 4][j]                                  // 0x01乘法
                           ^ input[(i + 3) % 4][j];                                 // 0x01乘法

    for (i = 0; i <= 3; i++)
        for (j = 0; j <= 3; j++)
            input[i][j] = output[i][j];
}

// 行移位
// 第一行保持不变，第2行向左循环移动过1字节，第3行想左循环移动2字节，第4行向循环移动3字节
void shiftRow(unsigned char (*B)[4])
{

    int i, temp;
    temp = B[1][0];

    // 第2行左移1字节
    for (i = 0; i <= 2; i++)
        B[1][i] = B[1][i + 1];
    B[1][3] = temp;

    // 第3行左移动2字节
    for (i = 0; i <= 1; i++)
    {
        temp = B[2][i];
        B[2][i] = B[2][i + 2];
        B[2][i + 2] = temp;
    }

    // 第3行左移动3位
    temp = B[3][3];
    for (i = 3; i >= 1; i--)
        B[3][i] = B[3][i - 1];
    B[3][0] = temp;
}

// 字节变换
void byteConvert(unsigned char (*B)[4])
{

    register int i, j;

    for (i = 0; i <= 3; i++)
        for (j = 0; j <= 3; j++)
            B[i][j] = S_BOX[B[i][j] / 16][B[i][j] % 16];
}

// 逆行移位
void invShiftRow(unsigned char (*B)[4])
{

    int i, temp;

    temp = B[1][3];

    // 向右循环移动1位
    for (i = 3; i >= 1; i--)
        B[1][i] = B[1][i - 1];
    B[1][0] = temp;

    // 向右循环移动过2位
    for (i = 0; i <= 1; i++)
    {
        temp = B[2][i];
        B[2][i] = B[2][i + 2];
        B[2][i + 2] = temp;
    }

    // 向右循环移动3位
    temp = B[3][0];

    for (i = 0; i <= 2; i++)
        B[3][i] = B[3][i + 1];
    B[3][3] = temp;
}

// 逆列混淆运算
void invMixColum(unsigned char (*input)[4])
{

    int i, j;
    unsigned char output[4][4];

    // 求完每一列后将当前列向上进行移动
    for (j = 0; j < 4; j++)
        for (i = 0; i < 4; i++)
            output[i][j] = (xtime(xtime(xtime(input[i % 4][j]))) ^ xtime(xtime(input[i % 4][j])) ^ xtime(input[i % 4][j]))              // 0x0E乘法
                           ^ (xtime(xtime(xtime(input[(i + 1) % 4][j]))) ^ xtime(input[(i + 1) % 4][j]) ^ input[(i + 1) % 4][j])        // 0x0B乘法
                           ^ (xtime(xtime(xtime(input[(i + 2) % 4][j]))) ^ xtime(xtime(input[(i + 2) % 4][j])) ^ input[(i + 2) % 4][j]) // 0x0D乘法
                           ^ (xtime(xtime(xtime(input[(i + 3) % 4][j]))) ^ input[(i + 3) % 4][j]);                                      // 0x09乘法

    for (i = 0; i <= 3; i++)
        for (j = 0; j <= 3; j++)
            input[i][j] = output[i][j];
}

// 逆字节变换
void invByteConvert(unsigned char (*B)[4])
{

    register int i, j;

    for (i = 0; i <= 3; i++)
        for (j = 0; j <= 3; j++)
            B[i][j] = N_S_BOX[B[i][j] / 16][B[i][j] % 16];
}

//输出明文得出密文
void encrypt(Plant plant, Cipher *cipher, unsigned char * key)
{
    // unsigned char e;
    unsigned char B[4][4];  // 存储每一组的密文
    unsigned char iv[4][4]; // 存储初始向量

    // 密钥拓展
    unsigned char keys[4][44];

    int i, j;
    int level;
    int cArray[4][4];  // 存储字符串
    int len, k, l;

    len = plant.plant.size();
    unsigned char str[len];

    //将string转化为str
    memcpy(str, plant.plant.c_str(), sizeof str);

    if (len % 16 != 0)
    {
        // 采用PKCS7Paddi进行填充,即距离16个字节缺几个就在后面填充几个
        int padding = 16 - len % 16;
        cipher->padding = padding;//将填充长度放入
        for (int i = 0; i < padding; i++)
        {
            str[len + i] = (padding & 0x000000ff);
        }

        len += padding;
    }

    keyExpansion(key, keys);

    k = 0;

    // 分组加密过程
    for (l = 0; l < len; l += 16)
    {

        k = l;
        // 每16个字符进行分一次组
        for (i = 0; i <= 3; i++)
        {
            for (j = 0; j <= 3; j++)
            {
                B[j][i] = getIntFromChar(str[k]);
                k++;
            }
        }
        // 采用CBC模式，iv[i][j]为初始向量,初始时iv全为0
        if (l == 0)
        {
            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    //	iv[i][j] = B[i][j];
                    iv[i][j] = 0;
                }
            }
        }

        // CBC模式,先及那个明文与iv进行异或
        xorWithIv(iv, B);

        // 第0轮  轮密钥加
        for (i = 0; i <= 3; i++)
            for (j = 0; j <= 3; j++)
            {
                B[i][j] ^= keys[i][j];
            }

        // 9轮轮密钥加，分别执行字节代换，行移位，列混淆，轮密钥加
        for (level = 1; level <= 9; level++)
        {                          // 1到9轮循环
            byteConvert(B); // 字节代换
            shiftRow(B);           // 行移位
            mixColumn(B);          // 列混合

            // 轮密钥加
            for (i = 0; i <= 3; i++)
                for (j = 0; j <= 3; j++)
                    B[i][j] ^= keys[i][level * 4 + j];
        }

        // 第10轮循环只有字节代换，行移位和轮密钥加
        byteConvert(B); // 第10轮循环
        shiftRow(B);

        for (i = 0; i <= 3; i++)
        {
            for (j = 0; j <= 3; j++)
            {
                B[i][j] ^= keys[i][40 + j];
                cArray[i][j] = (int)B[i][j];
            }
        }

        // 将密文结果转换为连续的字符串
        convertArrayToStr(cArray, cipher->cipher);

        // 因为采用CBC模式需要将当前得出的密文与下一组的明文进行异或，使得更加安全
        for (i = 0; i < 4; i++)
        {
            for (j = 0; j < 4; j++)
            {
                iv[i][j] = B[i][j]; // 存储当前密文
            }
        }
    }
}

//输入密文，得出明文
void decrypt(Cipher cipher, Plant *plant, unsigned char * key)
{

    unsigned char B[4][4], iv[4][4], bef[4][4];
    unsigned char keys[4][44];
    int temp, i, j;
    int level;
    int padding = cipher.padding;//获取密文填充长度
    int realLens = cipher.cipher.size() - padding;//真实长度

    // char str[1024];
    // char result[1024];
    int cArray[4][4];
    int len, l, k;

    //得出密文的长度
    len = cipher.cipher.size();
    unsigned char str[len];

    //将密文传入str中
    memcpy(str, cipher.cipher.c_str(), sizeof str);


    //求出拓展子密钥
    keyExpansion(key, keys);

    for (l = 0; l < len; l += 16)
    {
        k = l;
        for (i = 0; i <= 3; i++)
        {
            for (j = 0; j <= 3; j++)
            {
                B[j][i] = getIntFromChar(str[k]);
                bef[j][i] = B[j][i];
                k++;
            }
        }

        if (l == 0)
        {
            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    //	iv[i][j] = bef[i][j];
                    iv[i][j] = 0;
                }
            }
        }

        for (i = 0; i <= 3; i++)
            for (j = 0; j <= 3; j++)
                B[i][j] ^= keys[i][j + 40];

        for (level = 1; level <= 9; level++)
        {

            invShiftRow(B);
            invByteConvert(B);

            for (i = 0; i <= 3; i++)
                for (j = 0; j <= 3; j++)
                    B[i][j] ^= keys[i][40 - level * 4 + j];

            invMixColum(B);
        }

        invShiftRow(B);
        invByteConvert(B);

        for (i = 0; i <= 3; i++)
            for (j = 0; j <= 3; j++)
            {
                B[i][j] ^= keys[i][j];
            }

        // 通过先求解初始向量，解出密文一同样可以得出所有密文
        xorWithIv(iv, B);

        // iv=B
        for (i = 0; i < 4; i++)
        {
            for (j = 0; j < 4; j++)
            {
                iv[i][j] = bef[i][j];
                cArray[i][j] = (int)B[i][j];
            }
        }

        convertArrayToStr(cArray, plant->plant);
    }

    for(int i = realLens; i < 16; i ++)
    plant->plant[i] = '\0';
}