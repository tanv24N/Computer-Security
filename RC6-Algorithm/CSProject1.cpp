#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <cstdint>
#include <fstream> 

const int w = 32;
const int r = 20;
const int byte_var = (w / 8);
#define c ((b + byte_var - 1) / byte_var)
const int r_var = (2 * r + 4);
const int lgw_var = 5;

std::uint32_t s_var[r_var - 1];

#define rotate_left(x, y) (((x) << (y&(w-1))) | ((x) >> (w-(y&(w-1)))))
#define rotate_right(x, y) (((x) >> (y&(w-1))) | ((x) << (w-(y&(w-1)))))

// Key schedule for RC6
void key_schedule(unsigned char *K, int b) {
    int i, j;
    int n, m;
    std::uint32_t L[(32 + byte_var - 1) / byte_var];
    std::uint32_t A, B;
    L[c - 1] = 0;

    // Convert key to words
    for (i = b - 1; i >= 0; i--)
        L[i / byte_var] = (L[i / byte_var] << 8) + K[i];

    s_var[0] = 0xB7E15163;
    for (i = 1; i <= 2 * r + 3; i++)
        s_var[i] = s_var[i - 1] + 0x9E3779B9;

    A = B = i = j = 0;
    m = r_var;
    if (c > m) m = c;
    m *= 3;
    for (n = 1; n <= m; n++) {
        A = s_var[i] = rotate_left(s_var[i] + A + B, 3);
        B = L[j] = rotate_left(L[j] + A + B, A + B);
        i = (i + 1) % r_var;
        j = (j + 1) % c;
    }
}

// Encryption for RC6
void encryption_rc6(std::uint32_t *plaintext, std::uint32_t *ciphertext) {
    std::uint32_t A = plaintext[0];
    std::uint32_t B = plaintext[1];
    std::uint32_t C = plaintext[2];
    std::uint32_t D = plaintext[3];

    B += s_var[0];
    D += s_var[1];

    for (int i = 2; i <= 2 * r; i += 2) {
        std::uint32_t t = rotate_left(B * (2 * B + 1), lgw_var);
        std::uint32_t u = rotate_left(D * (2 * D + 1), lgw_var);

        A = rotate_left(A ^ t, u) + s_var[i];
        C = rotate_left(C ^ u, t) + s_var[i + 1];

        // Manually swap values without using std::swap
        std::uint32_t tempVar = A;
        A = B;
        B = C;
        C = D;
        D = tempVar;
    }

    A += s_var[2 * r + 2];
    C += s_var[2 * r + 3];

    ciphertext[0] = A;
    ciphertext[1] = B;
    ciphertext[2] = C;
    ciphertext[3] = D;
}


// Decryption for RC6
void decryption_rc6(std::uint32_t *ciphertext, std::uint32_t *plaintext) {
    std::uint32_t A, B, C, D;
    std::uint32_t f, q, l;
    int i, j;

    A = ciphertext[0];
    B = ciphertext[1];
    C = ciphertext[2];
    D = ciphertext[3];
    C -= s_var[2 * r + 3];
    A -= s_var[2 * r + 2];

    for (i = 2 * r; i >= 2; i -= 2) {
        //swap
        l = D;
        D = C;
        C = B;
        B = A;
        A = l;
        q = rotate_left(D * (2 * D + 1), lgw_var);
        f = rotate_left(B * (2 * B + 1), lgw_var);
        C = rotate_right(C - s_var[i + 1], f) ^ q;
        A = rotate_right(A - s_var[i], q) ^ f;
    }
    D -= s_var[1];
    B -= s_var[0];
    plaintext[0] = A;
    plaintext[1] = B;
    plaintext[2] = C;
    plaintext[3] = D;
}

// Function to format and write encryption or decryption data to file
void formate_encryption_decryption(unsigned int n, bool end, std::ofstream &file) {
    unsigned char *p = reinterpret_cast<unsigned char *>(&n);
    for (int i = 0; i < 4; i++) {
        file << std::setw(2) << std::setfill('0') << std::hex << static_cast<unsigned int>(*(p + i));
        if (!end || i < 3) {
            file << ' ';
        }
    }
    if (end) {
        file << " ";
    }
}

//Main fucntion
int main(int argc, char* argv[]) {
    std::uint32_t ciphertext_var[4], enciphertext_var[4], deciphertext_var[4];
    std::uint32_t inputText[16];
    unsigned char key[32];
    int keylen = 16;
    int i;
    std::ofstream file;
    bool detect_line1 = true;
    char length[20];
    //if algorithm is 0 then Encryption and if 1 then Decryption
    int algorithm; 
    unsigned char temp_var1 = 0, temp_var2 = 0;

    if (argc != 3)
    {
        std::cerr << "Usage: " << argv[0] << " ./input.txt ./output.txt\n";
        return 1;
    }

    std::ifstream infile(argv[1]);
    if (!infile.is_open()) {
        std::cerr << "Unable to open file " << argv[1] << std::endl;
        return 1;
    }

// Read data from the input file
while (!infile.eof()) {
    if (detect_line1) {
        detect_line1 = false;
        infile >> length;
        if (strcmp(length, "Encryption") == 0) {
            algorithm = 0;
            //std::cout << "Encryption" << std::endl;
        }
        else {
            algorithm = 1;
            //std::cout << "Decryption" << std::endl;
        }
    }
    else {
        infile >> length;
        infile >> std::hex >> inputText[0] >> inputText[1] >> inputText[2] >> inputText[3]
               >> inputText[4] >> inputText[5] >> inputText[6] >> inputText[7]
               >> inputText[8] >> inputText[9] >> inputText[10] >> inputText[11]
               >> inputText[12] >> inputText[13] >> inputText[14] >> inputText[15];

        for (i = 0; i < 4; i++) {
            ciphertext_var[i] = inputText[i * 4 + 0] + (inputText[i * 4 + 1] << 8) + (inputText[i * 4 + 2] << 16) + (inputText[i * 4 + 3] << 24);
        }

        infile >> length;
        keylen = 0;
        // Read key data from the file
        while (infile >> std::noskipws >> temp_var1) {
        if (isxdigit(temp_var1)) {
            infile >> std::noskipws >> temp_var2;
            if (isxdigit(temp_var2)) {
                int digit1 = isdigit(temp_var1) ? temp_var1 - '0' : tolower(temp_var1) - 'a' + 10;
                int digit2 = isdigit(temp_var2) ? temp_var2 - '0' : tolower(temp_var2) - 'a' + 10;
                key[keylen] = digit1 * 16 + digit2;
                keylen++;
            }
        }
    }
        break;
    }
}

    file.close();

    file.open(argv[2], std::ios::out);
    if (!file.is_open()) {
        std::cout << "Unable to open " << argv[2] << std::endl;
        return 0;
    }

    // Perform Encryption or Decryption based on the input
    if (algorithm == 0) {
        file << "ciphertext: ";
        key_schedule(key, keylen);
        encryption_rc6(ciphertext_var, enciphertext_var);
        for (int i = 0; i < 4; ++i) {
            formate_encryption_decryption(enciphertext_var[i], i < 3, file);
        }
    } else {
        file << "plaintext: ";
        key_schedule(key, keylen);
        decryption_rc6(ciphertext_var, deciphertext_var);
        for (int i = 0; i < 4; ++i) {
            formate_encryption_decryption(deciphertext_var[i], i < 3, file);
        }
    }

    file.close();
    return 0;
}