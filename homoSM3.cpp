/*
 * @Author: Wei Benqiang 
 * @Date: 2022-01-03 17:07:57 
 * @Last Modified by: James
 * @Last Modified time: 2022-01-12 10:35:12
 */

#include <iostream>
#include <tfhe/tfhe_core.h>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_garbage_collector.h>
#include <time.h>
#include "SM3.h"
using namespace std;

const int nb_bits = 32;

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n, b, i)                      \
    {                                              \
        (b)[(i)] = (unsigned char)((n) >> 24);     \
        (b)[(i) + 1] = (unsigned char)((n) >> 16); \
        (b)[(i) + 2] = (unsigned char)((n) >> 8);  \
        (b)[(i) + 3] = (unsigned char)((n));       \
    }
#endif

typedef struct
{
    LweSample *byte;
} CipherByte;

typedef struct
{
    LweSample *word;
} CipherWord;

typedef struct
{
    CipherWord state[8];
    unsigned int length;
    unsigned int curlen;
    CipherByte buf[64];
} CipherState;

void HexToBinStr(int hex, int *bin_str)
{
    for (int i = 0; i < 8; ++i)
    {
        bin_str[i] = hex % 2;
        hex /= 2;
    }
}

void BinStrToHex(int &dex_hex, int *bin_str)
{
    for (int i = 0; i < 8; i++)
    {
        dex_hex += bin_str[i] * pow(2, 7 - i);
    }
}

void NewCipherWord(CipherWord *sample, const TFheGateBootstrappingParameterSet *params)
{
    sample->word = new_gate_bootstrapping_ciphertext_array(32, params);
}

void DecryptCipherWord(CipherWord *sample, const TFheGateBootstrappingSecretKeySet *key)
{
    for (int j = 0; j < 4; j++)
    {
        int bin[8] = {0};
        int hexvalue = 0;
        for (int k = 0; k < 8; k++)
        {
            bin[k] = bootsSymDecrypt(sample->word + 8 * j + k, key);
        }
        BinStrToHex(hexvalue, bin);
        printf("%02x", hexvalue);
    }
    cout << " ";
}

void CopyCipher(CipherByte result, LweSample *src, int n, TFheGateBootstrappingSecretKeySet *key)
{
    for (int i = 0; i < n; i++)
    {
        lweCopy((result.byte) + i, src + i, key->params->in_out_params);
    }
}

void CopyCipherWord(CipherWord *result, CipherWord *src, TFheGateBootstrappingSecretKeySet *key)
{
    for (int i = 0; i < 32; i++)
    {
        lweCopy(result->word + i, src->word + i, key->params->in_out_params);
    }
}

void homoSM3_init(CipherState *md, const TFheGateBootstrappingParameterSet *params, TFheGateBootstrappingSecretKeySet *key)
{
    md->curlen = md->length = 0;
    unsigned char a[4];
    // md->state[0] = SM3_IVA;
    PUT_ULONG_BE(SM3_IVA, a, 0);
    for (int i = 0; i < 4; i++)
    {
        int bin_str[8];
        HexToBinStr(a[i], bin_str);
        for (int j = 0; j < 8; j++)
        {
            bootsSymEncrypt(md->state[0].word + 8 * i + j, bin_str[7 - j], key);
        }
    }

    // md->state[1] = SM3_IVB;
    PUT_ULONG_BE(SM3_IVB, a, 0);
    for (int i = 0; i < 4; i++)
    {
        int bin_str[8];
        HexToBinStr(a[i], bin_str);
        for (int j = 0; j < 8; j++)
        {
            bootsSymEncrypt(md->state[1].word + 8 * i + j, bin_str[7 - j], key);
        }
    }

    // md->state[2] = SM3_IVC;
    PUT_ULONG_BE(SM3_IVC, a, 0);
    for (int i = 0; i < 4; i++)
    {
        int bin_str[8];
        HexToBinStr(a[i], bin_str);
        for (int j = 0; j < 8; j++)
        {
            bootsSymEncrypt(md->state[2].word + 8 * i + j, bin_str[7 - j], key);
        }
    }
    // md->state[3] = SM3_IVD;
    PUT_ULONG_BE(SM3_IVD, a, 0);
    for (int i = 0; i < 4; i++)
    {
        int bin_str[8];
        HexToBinStr(a[i], bin_str);
        for (int j = 0; j < 8; j++)
        {
            bootsSymEncrypt(md->state[3].word + 8 * i + j, bin_str[7 - j], key);
        }
    }
    // md->state[4] = SM3_IVE;
    PUT_ULONG_BE(SM3_IVE, a, 0);
    for (int i = 0; i < 4; i++)
    {
        int bin_str[8];
        HexToBinStr(a[i], bin_str);
        for (int j = 0; j < 8; j++)
        {
            bootsSymEncrypt(md->state[4].word + 8 * i + j, bin_str[7 - j], key);
        }
    }
    // md->state[5] = SM3_IVF;
    PUT_ULONG_BE(SM3_IVF, a, 0);
    for (int i = 0; i < 4; i++)
    {
        int bin_str[8];
        HexToBinStr(a[i], bin_str);
        for (int j = 0; j < 8; j++)
        {
            bootsSymEncrypt(md->state[5].word + 8 * i + j, bin_str[7 - j], key);
        }
    }
    // md->state[6] = SM3_IVG;
    PUT_ULONG_BE(SM3_IVG, a, 0);
    for (int i = 0; i < 4; i++)
    {
        int bin_str[8];
        HexToBinStr(a[i], bin_str);
        for (int j = 0; j < 8; j++)
        {
            bootsSymEncrypt(md->state[6].word + 8 * i + j, bin_str[7 - j], key);
        }
    }
    // md->state[7] = SM3_IVH;
    PUT_ULONG_BE(SM3_IVH, a, 0);
    for (int i = 0; i < 4; i++)
    {
        int bin_str[8];
        HexToBinStr(a[i], bin_str);
        for (int j = 0; j < 8; j++)
        {
            bootsSymEncrypt(md->state[7].word + 8 * i + j, bin_str[7 - j], key);
        }
    }
}

void ByteToWord(CipherByte *buf, CipherWord *W, const TFheGateBootstrappingParameterSet *params,
                TFheGateBootstrappingSecretKeySet *key)
{
    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            for (int k = 0; k < 8; k++)
            {
                lweCopy(W[i].word + 8 * j + k, buf[4 * i + j].byte + k, params->in_out_params);
            }
        }
    }
}

void homoWordXor(CipherWord *result, CipherWord *a, CipherWord *b, const TFheGateBootstrappingParameterSet *params,
                 TFheGateBootstrappingSecretKeySet *key)
{
    for (int i = 0; i < 32; i++)
    {
        bootsXOR(result->word + i, a->word + i, b->word + i, &key->cloud);
    }
}

void homoWordAnd(CipherWord *result, CipherWord *a, CipherWord *b, const TFheGateBootstrappingParameterSet *params,
                 TFheGateBootstrappingSecretKeySet *key)
{
    for (int i = 0; i < 32; i++)
    {
        bootsAND(result->word + i, a->word + i, b->word + i, &key->cloud);
    }
}

void homoWordOr(CipherWord *result, CipherWord *a, CipherWord *b, const TFheGateBootstrappingParameterSet *params,
                TFheGateBootstrappingSecretKeySet *key)
{
    for (int i = 0; i < 32; i++)
    {
        bootsOR(result->word + i, a->word + i, b->word + i, &key->cloud);
    }
}

void homoWordNot(CipherWord *result, CipherWord *a, const TFheGateBootstrappingParameterSet *params,
                 TFheGateBootstrappingSecretKeySet *key)
{
    for (int i = 0; i < 32; i++)
    {
        bootsNOT(result->word + i, a->word + i, &key->cloud);
    }
}

void homoSM3_rotl32(CipherWord *result, CipherWord *src, int n, const TFheGateBootstrappingParameterSet *params,
                    TFheGateBootstrappingSecretKeySet *key)
{
    for (int i = 0; i < 32 - n; i++)
    {
        lweCopy(result->word + i, src->word + i + n, params->in_out_params);
    }
    for (int i = 32 - n; i < 32; i++)
    {
        lweCopy(result->word + i, src->word + i - (32 - n), params->in_out_params);
    }
}

void homoSM3_p0(CipherWord *result, CipherWord *src, const TFheGateBootstrappingParameterSet *params,
                TFheGateBootstrappingSecretKeySet *key)
{
    //#define SM3_p0(x) (x ^ SM3_rotl32(x, 9) ^ SM3_rotl32(x, 17))
    CipherWord tmp1, tmp2, tmp3;

    NewCipherWord(&tmp1, params);
    NewCipherWord(&tmp2, params);
    NewCipherWord(&tmp3, params);

    homoSM3_rotl32(&tmp1, src, 9, params, key);
    homoSM3_rotl32(&tmp2, src, 17, params, key);

    homoWordXor(&tmp3, &tmp1, &tmp2, params, key);
    homoWordXor(result, src, &tmp3, params, key);

    delete_gate_bootstrapping_ciphertext_array(32, tmp1.word);
    delete_gate_bootstrapping_ciphertext_array(32, tmp2.word);
    delete_gate_bootstrapping_ciphertext_array(32, tmp3.word);
}

void homoSM3_p1(CipherWord *result, CipherWord *src, const TFheGateBootstrappingParameterSet *params,
                TFheGateBootstrappingSecretKeySet *key)
{
    //#define SM3_p1(x) (x ^ SM3_rotl32(x, 15) ^ SM3_rotl32(x, 23))
    CipherWord tmp1, tmp2, tmp3;
    // tmp1.word = new_gate_bootstrapping_ciphertext_array(32, params);
    // tmp2.word = new_gate_bootstrapping_ciphertext_array(32, params);
    // tmp3.word = new_gate_bootstrapping_ciphertext_array(32, params);

    NewCipherWord(&tmp1, params);
    NewCipherWord(&tmp2, params);
    NewCipherWord(&tmp3, params);

    homoSM3_rotl32(&tmp1, src, 15, params, key);
    homoSM3_rotl32(&tmp2, src, 23, params, key);

    homoWordXor(&tmp3, &tmp1, &tmp2, params, key);
    homoWordXor(result, src, &tmp3, params, key);

    delete_gate_bootstrapping_ciphertext_array(32, tmp1.word);
    delete_gate_bootstrapping_ciphertext_array(32, tmp2.word);
    delete_gate_bootstrapping_ciphertext_array(32, tmp3.word);
}

void add_bit(LweSample *result, LweSample *carry_out, const LweSample *a, const LweSample *b, const LweSample *carry_in, const TFheGateBootstrappingCloudKeySet *bk)
{

    LweSample *s1 = new_gate_bootstrapping_ciphertext_array(2, bk->params);
    LweSample *c1 = new_gate_bootstrapping_ciphertext_array(2, bk->params);
    LweSample *c2 = new_gate_bootstrapping_ciphertext_array(2, bk->params);

    bootsCONSTANT(&s1[0], 0, bk);
    bootsCONSTANT(&c1[0], 0, bk);
    bootsCONSTANT(&c2[0], 0, bk);

    bootsXOR(s1, a, b, bk);
    bootsXOR(result, s1, carry_in, bk);

    bootsAND(c1, s1, carry_in, bk);
    bootsAND(c2, a, b, bk);

    bootsOR(carry_out, c1, c2, bk);

    delete_gate_bootstrapping_ciphertext_array(2, s1);
    delete_gate_bootstrapping_ciphertext_array(2, c1);
    delete_gate_bootstrapping_ciphertext_array(2, c2);
}

void homoAdd(CipherWord *result, CipherWord *a, CipherWord *b,
             const TFheGateBootstrappingParameterSet *params, TFheGateBootstrappingSecretKeySet *key)
{
    LweSample *tmps_carry = new_gate_bootstrapping_ciphertext_array(2, params);

    //initialize the carry to 0
    bootsCONSTANT(&tmps_carry[0], 0, &key->cloud);

    //run the elementary comparator gate n times
    for (int i = 0; i < nb_bits; i++)
    {
        add_bit(&result->word[31 - i], &tmps_carry[0], &a->word[31 - i], &b->word[31 - i], &tmps_carry[0], &key->cloud);
    }

    delete_gate_bootstrapping_ciphertext_array(2, tmps_carry);
}

void homoSM3_ff0(CipherWord *result, CipherWord *cipherA, CipherWord *cipherB, CipherWord *cipherC,
                 const TFheGateBootstrappingParameterSet *params, TFheGateBootstrappingSecretKeySet *key)
{
    // #define SM3_ff0(a, b, c) (a ^ b ^ c)
    CipherWord tmp;
    NewCipherWord(&tmp, params);
    homoWordXor(&tmp, cipherA, cipherB, params, key);
    homoWordXor(result, &tmp, cipherC, params, key);

    delete_gate_bootstrapping_ciphertext_array(32, tmp.word);
}

void homoSM3_ff1(CipherWord *result, CipherWord *cipherA, CipherWord *cipherB, CipherWord *cipherC,
                 const TFheGateBootstrappingParameterSet *params, TFheGateBootstrappingSecretKeySet *key)
{
    // #define SM3_ff1(a, b, c) ((a & b) | (a & c) | (b & c))
    CipherWord tmp1, tmp2, tmp3, tmp4;
    NewCipherWord(&tmp1, params);
    NewCipherWord(&tmp2, params);
    NewCipherWord(&tmp3, params);
    NewCipherWord(&tmp4, params);

    homoWordAnd(&tmp1, cipherA, cipherB, params, key); //(a & b)
    homoWordAnd(&tmp2, cipherA, cipherC, params, key); //(a & c)
    homoWordAnd(&tmp3, cipherB, cipherC, params, key); //(b & c)

    homoWordOr(&tmp4, &tmp1, &tmp2, params, key);
    homoWordOr(result, &tmp3, &tmp4, params, key);

    delete_gate_bootstrapping_ciphertext_array(32, tmp1.word);
    delete_gate_bootstrapping_ciphertext_array(32, tmp2.word);
    delete_gate_bootstrapping_ciphertext_array(32, tmp3.word);
    delete_gate_bootstrapping_ciphertext_array(32, tmp4.word);
}

void homoSM3_gg0(CipherWord *result, CipherWord *cipherE, CipherWord *cipherF, CipherWord *cipherG,
                 const TFheGateBootstrappingParameterSet *params, TFheGateBootstrappingSecretKeySet *key)
{
    // #define SM3_gg0(e, f, g) (e ^ f ^ g)
    CipherWord tmp;
    NewCipherWord(&tmp, params);
    homoWordXor(&tmp, cipherE, cipherF, params, key);
    homoWordXor(result, &tmp, cipherG, params, key);

    delete_gate_bootstrapping_ciphertext_array(32, tmp.word);
}

void homoSM3_gg1(CipherWord *result, CipherWord *cipherE, CipherWord *cipherF, CipherWord *cipherG,
                 const TFheGateBootstrappingParameterSet *params, TFheGateBootstrappingSecretKeySet *key)
{
    // #define SM3_gg1(e, f, g) ((e & f) | ((~e) & g))
    CipherWord tmp1, tmp2, tmp3;
    NewCipherWord(&tmp1, params);
    NewCipherWord(&tmp2, params);
    NewCipherWord(&tmp3, params);

    homoWordAnd(&tmp1, cipherE, cipherF, params, key); //(e & f)
    homoWordNot(&tmp2, cipherE, params, key);          //(~e)
    homoWordAnd(&tmp3, &tmp2, cipherG, params, key);   //(~e) & g)

    homoWordOr(result, &tmp1, &tmp3, params, key); //((e & f) | ((~e) & g))

    delete_gate_bootstrapping_ciphertext_array(32, tmp1.word);
    delete_gate_bootstrapping_ciphertext_array(32, tmp2.word);
    delete_gate_bootstrapping_ciphertext_array(32, tmp3.word);
}

void homoCF(CipherWord *W, CipherWord *W1, CipherWord *state,
            const TFheGateBootstrappingParameterSet *params, TFheGateBootstrappingSecretKeySet *key)
{
    CipherWord SS1, SS2, TT1, TT2;
    CipherWord cipherA, cipherB, cipherC, cipherD, cipherE, cipherF, cipherG, cipherH;
    CipherWord FF, GG;
    CipherWord cipherT, cipherT1, cipherT2;

    NewCipherWord(&SS1, params);
    NewCipherWord(&SS2, params);
    NewCipherWord(&TT1, params);
    NewCipherWord(&TT2, params);
    NewCipherWord(&cipherA, params);
    NewCipherWord(&cipherB, params);
    NewCipherWord(&cipherC, params);
    NewCipherWord(&cipherD, params);
    NewCipherWord(&cipherE, params);
    NewCipherWord(&cipherF, params);
    NewCipherWord(&cipherG, params);
    NewCipherWord(&cipherH, params);
    NewCipherWord(&FF, params);
    NewCipherWord(&GG, params);
    NewCipherWord(&cipherT, params);
    NewCipherWord(&cipherT1, params);
    NewCipherWord(&cipherT2, params);

    CipherWord cipherA_rot12, resultAdd, resultAdd2;
    NewCipherWord(&cipherA_rot12, params);
    NewCipherWord(&resultAdd, params);
    NewCipherWord(&resultAdd2, params);
    unsigned char a[4];
    PUT_ULONG_BE(SM3_T1, a, 0);
    for (int i = 0; i < 4; i++)
    {
        int bin_str[8] = {0};
        HexToBinStr(a[i], bin_str);
        for (int j = 0; j < 8; j++)
        {
            bootsSymEncrypt(cipherT1.word + 8 * i + j, bin_str[7 - j], key);
        }
    }

    PUT_ULONG_BE(SM3_T2, a, 0);
    for (int i = 0; i < 4; i++)
    {
        int bin_str[8] = {0};
        HexToBinStr(a[i], bin_str);
        for (int j = 0; j < 8; j++)
        {
            bootsSymEncrypt(cipherT2.word + 8 * i + j, bin_str[7 - j], key);
        }
    }
    CopyCipherWord(&cipherA, &state[0], key); //A = V[0];
    CopyCipherWord(&cipherB, &state[1], key); //B = V[1];
    CopyCipherWord(&cipherC, &state[2], key); //C = V[2];
    CopyCipherWord(&cipherD, &state[3], key); //D = V[3];
    CopyCipherWord(&cipherE, &state[4], key); //E = V[4];
    CopyCipherWord(&cipherF, &state[5], key); //F = V[5];
    CopyCipherWord(&cipherG, &state[6], key); //G = V[6];
    CopyCipherWord(&cipherH, &state[7], key); //H = V[7];

    for (int j = 0; j < 64; j++) //64
    {
        // Tj <<(j mod 32)
        if (j < 16)
        {
            homoSM3_rotl32(&cipherT, &cipherT1, j % 32, params, key);
        }
        else
        {
            homoSM3_rotl32(&cipherT, &cipherT2, j % 32, params, key);
        }

        // SS1 = SM3_rotl32((SM3_rotl32(A, 12) + E + T), 7);
        homoSM3_rotl32(&cipherA_rot12, &cipherA, 12, params, key);
        homoAdd(&resultAdd, &cipherA_rot12, &cipherE, params, key);
        homoAdd(&resultAdd2, &resultAdd, &cipherT, params, key);

        // cout << "------------resultAdd2---------" << endl;
        // DecryptCipherWord(&resultAdd2, key);
        // cout << endl;
        // return;
        homoSM3_rotl32(&SS1, &resultAdd2, 7, params, key);

        // SS2 = SS1 ^ SM3_rotl32(A, 12)
        homoWordXor(&SS2, &SS1, &cipherA_rot12, params, key);

        // FF = SM3_ff0(A, B, C);  j: [0,15]
        // FF = SM3_ff1(A, B, C);  j: [16,63]
        if (j <= 15)
        {
            homoSM3_ff0(&FF, &cipherA, &cipherB, &cipherC, params, key);
        }
        else
        {
            homoSM3_ff1(&FF, &cipherA, &cipherB, &cipherC, params, key);
        }

        // TT1 = FF + D + SS2 + *W1;   W1++;
        homoAdd(&resultAdd, &FF, &cipherD, params, key);     //FF+D
        homoAdd(&resultAdd2, &resultAdd, &SS2, params, key); //FF+D +SS2
        homoAdd(&TT1, &resultAdd2, &W1[j], params, key);     //FF+D +SS2+w1[j]
        // cout << "------------TT1---------" << endl;
        // DecryptCipherWord(&TT1, key);
        // cout << endl;
        // return;

        // GG = SM3_gg0(E, F, G);  j: [0,15]
        // GG = SM3_gg1(E, F, G);  j: [16,63]
        if (j <= 15)
        {
            homoSM3_gg0(&GG, &cipherE, &cipherF, &cipherG, params, key);
        }
        else
        {
            homoSM3_gg1(&GG, &cipherE, &cipherF, &cipherG, params, key);
        }
        // cout << "------------GG---------" << endl;
        // DecryptCipherWord(&GG, key);
        // cout << endl;
        // return;

        // TT2 = GG + H + SS1 + *W;   W++;
        homoAdd(&resultAdd, &GG, &cipherH, params, key);     //GG+H
        homoAdd(&resultAdd2, &resultAdd, &SS1, params, key); //GG+H+SS1
        homoAdd(&TT2, &resultAdd2, &W[j], params, key);      //GG+H+SS1+W[j]
        // cout << "------------TT2---------" << endl;
        // DecryptCipherWord(&TT2, key);
        // cout << endl;
        // return;

        // D = C;
        CopyCipherWord(&cipherD, &cipherC, key);
        // C = SM3_rotl32(B, 9);
        homoSM3_rotl32(&cipherC, &cipherB, 9, params, key);
        // B = A;
        CopyCipherWord(&cipherB, &cipherA, key);
        // A = TT1;
        CopyCipherWord(&cipherA, &TT1, key);
        // H = G;
        CopyCipherWord(&cipherH, &cipherG, key);
        // G = SM3_rotl32(F, 19);
        homoSM3_rotl32(&cipherG, &cipherF, 19, params, key);
        // F = E;
        CopyCipherWord(&cipherF, &cipherE, key);
        // E = SM3_p0(TT2);
        homoSM3_p0(&cipherE, &TT2, params, key);

        cout << "------------" << j << "-----------" << endl;
        DecryptCipherWord(&cipherA, key);
        DecryptCipherWord(&cipherB, key);
        DecryptCipherWord(&cipherC, key);
        DecryptCipherWord(&cipherD, key);
        DecryptCipherWord(&cipherE, key);
        DecryptCipherWord(&cipherF, key);
        DecryptCipherWord(&cipherG, key);
        DecryptCipherWord(&cipherH, key);
        cout << endl;
    }

    //update V
    // V[0] = A ^ V[0];
    homoWordXor(&state[0], &cipherA, &state[0], params, key);
    // V[1] = B ^ V[1];
    homoWordXor(&state[1], &cipherB, &state[1], params, key);
    // V[2] = C ^ V[2];
    homoWordXor(&state[2], &cipherC, &state[2], params, key);
    // V[3] = D ^ V[3];
    homoWordXor(&state[3], &cipherD, &state[3], params, key);
    // V[4] = E ^ V[4];
    homoWordXor(&state[4], &cipherE, &state[4], params, key);
    // V[5] = F ^ V[5];
    homoWordXor(&state[5], &cipherF, &state[5], params, key);
    // V[6] = G ^ V[6];
    homoWordXor(&state[6], &cipherG, &state[6], params, key);
    // V[7] = H ^ V[7];
    homoWordXor(&state[7], &cipherH, &state[7], params, key);

    delete_gate_bootstrapping_ciphertext_array(32, SS1.word);
    delete_gate_bootstrapping_ciphertext_array(32, SS2.word);
    delete_gate_bootstrapping_ciphertext_array(32, TT1.word);
    delete_gate_bootstrapping_ciphertext_array(32, TT2.word);
    delete_gate_bootstrapping_ciphertext_array(32, cipherA.word);
    delete_gate_bootstrapping_ciphertext_array(32, cipherB.word);
    delete_gate_bootstrapping_ciphertext_array(32, cipherC.word);
    delete_gate_bootstrapping_ciphertext_array(32, cipherD.word);
    delete_gate_bootstrapping_ciphertext_array(32, cipherE.word);
    delete_gate_bootstrapping_ciphertext_array(32, cipherF.word);
    delete_gate_bootstrapping_ciphertext_array(32, cipherG.word);
    delete_gate_bootstrapping_ciphertext_array(32, cipherH.word);

    delete_gate_bootstrapping_ciphertext_array(32, FF.word);
    delete_gate_bootstrapping_ciphertext_array(32, GG.word);
    delete_gate_bootstrapping_ciphertext_array(32, cipherT.word);
    delete_gate_bootstrapping_ciphertext_array(32, cipherT1.word);
    delete_gate_bootstrapping_ciphertext_array(32, cipherT2.word);

    delete_gate_bootstrapping_ciphertext_array(32, resultAdd.word);
    delete_gate_bootstrapping_ciphertext_array(32, resultAdd2.word);
}

void homoSM3_process(CipherState *md, LweSample **msgCipher, int MsgLen,
                     const TFheGateBootstrappingParameterSet *params, TFheGateBootstrappingSecretKeySet *key)
{
    while (MsgLen--)
    {
        /* copy byte */
        // md->buf[md->curlen] = *buf++; 
        CopyCipher(md->buf[md->curlen], *msgCipher++, 8, key);
        md->curlen++;

        printf("md->curlen: %d \n", md->curlen);
        /* is 64 bytes full? */
        if (md->curlen == 64)
        {
            printf("md->curlen == 64--------");
            // homoSM3_compress(md);
            md->length += 512;
            md->curlen = 0;
        }
    }
}

void homoBiToW(CipherByte *buf, CipherWord *W, const TFheGateBootstrappingParameterSet *params,
               TFheGateBootstrappingSecretKeySet *key)
{
    // BiToW
    // for (i = 0; i <= 15; i++)
    // {
    //     W[i] = Bi[i];
    // }
    CipherWord tmp, tmp1, tmp2, tmp3;
    // tmp.word = new_gate_bootstrapping_ciphertext_array(32, params);
    // tmp1.word = new_gate_bootstrapping_ciphertext_array(32, params);
    // tmp2.word = new_gate_bootstrapping_ciphertext_array(32, params);
    NewCipherWord(&tmp, params);
    NewCipherWord(&tmp1, params);
    NewCipherWord(&tmp2, params);
    NewCipherWord(&tmp3, params);
    ByteToWord(buf, W, params, key);

    cout << "---------------homobitoW----------------" << endl;
    for (int i = 16; i < 68; i++)
    {
        // tmp = W[i - 16] ^ W[i - 9] ^ SM3_rotl32(W[i - 3], 15);
        homoWordXor(&tmp1, &W[i - 16], &W[i - 9], params, key);
        homoSM3_rotl32(&tmp2, &W[i - 3], 15, params, key);
        homoWordXor(&tmp, &tmp1, &tmp2, params, key);

        //W[i] = SM3_p1(tmp) ^ (SM3_rotl32(W[i - 13], 7)) ^ W[i - 6];
        homoSM3_p1(&tmp1, &tmp, params, key);
        homoSM3_rotl32(&tmp2, &W[i - 13], 7, params, key);
        homoWordXor(&tmp3, &tmp1, &tmp2, params, key);
        homoWordXor(&W[i], &tmp3, &W[i - 6], params, key);
    }
}

void homoWToW1(CipherWord *W, CipherWord *W1, const TFheGateBootstrappingParameterSet *params,
               TFheGateBootstrappingSecretKeySet *key)
{
    // for (i = 0; i <= 63; i++)
    // {
    //     W1[i] = W[i] ^ W[i + 4];
    // }
    cout << "---------------homoWToW1----------------" << endl;
    for (int i = 0; i <= 63; i++)
    {
        homoWordXor(&W1[i], &W[i], &W[i + 4], params, key);
    }
}

void homoSM3_compress(CipherState *md, TFheGateBootstrappingParameterSet *params,
                      TFheGateBootstrappingSecretKeySet *key)
{
    CipherWord W[68];
    CipherWord W1[64];
    for (int i = 0; i < 68; i++)
    {
        // W[i].word = new_gate_bootstrapping_ciphertext_array(32, params);
        NewCipherWord(&W[i], params);
    }
    for (int i = 0; i < 64; i++)
    {
        // W1[i].word = new_gate_bootstrapping_ciphertext_array(32, params);
        NewCipherWord(&W1[i], params);
    }
#if 0
    //debug
    unsigned int w[68] = {0x61626380, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                          0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x18,
                          0x9092e200, 0x0, 0xc0606, 0x719c70ed, 0x0, 0x8001801f, 0x939f7da9, 0x0,
                          0x2c6fa1f9, 0xadaaef14, 0x0, 0x1801e, 0x9a965f89, 0x49710048, 0x23ce86a1, 0xb2d12f1b,
                          0xe1dae338, 0xf8061807, 0x55d68be, 0x86cfd481, 0x1f447d83, 0xd9023dbf, 0x185898e0, 0xe0061807,
                          0x50df55c, 0xcde0104c, 0xa5b9c955, 0xa7df0184, 0x6e46cd08, 0xe3babdf8, 0x70caa422, 0x353af50,
                          0xa92dbca1, 0x5f33cfd2, 0xe16f6e89, 0xf70fe941, 0xca5462dc, 0x85a90152, 0x76af6296, 0xc922bdb2,
                          0x68378cf5, 0x97585344, 0x9008723, 0x86faee74, 0x2ab908b0, 0x4a64bc50, 0x864e6e08, 0xf07e6590,
                          0x325c8f78, 0xaccb8011, 0xe11db9dd, 0xb99c0545};
    unsigned int w1[64] = {0x61626380, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                           0x0, 0x0, 0x0, 0x18, 0x9092e200, 0x0, 0xc0606, 0x719c70f5,
                           0x9092e200, 0x8001801f, 0x93937baf, 0x719c70ed, 0x2c6fa1f9, 0x2dab6f0b, 0x939f7da9, 0x1801e,
                           0xb6f9fe70, 0xe4dbef5c, 0x23ce86a1, 0xb2d0af05, 0x7b4cbcb1, 0xb177184f, 0x2693ee1f, 0x341efb9a,
                           0xfe9e9ebb, 0x210425b8, 0x1d05f05e, 0x66c9cc86, 0x1a4988df, 0x14e22df3, 0xbde151b5, 0x47d91983,
                           0x6b4b3854, 0x2e5aadb4, 0xd5736d77, 0xa48caed4, 0xc76b71a9, 0xbc89722a, 0x91a5caab, 0xf45c4611,
                           0x6379de7d, 0xda9ace80, 0x97c00c1f, 0x3e2d54f3, 0xa263ee29, 0x12f15216, 0x7fafe5b5, 0x4fd853c6,
                           0x428e8445, 0xdd3cef14, 0x8f4ee92b, 0x76848be4, 0x18e587c8, 0xe6af3c41, 0x6753d7d5, 0x49e260d5};

    //encrypt w
    for (int k = 0; k < 68; k++)
    {
        unsigned char a[4];
        PUT_ULONG_BE(w[k], a, 0);
        for (int i = 0; i < 4; i++)
        {
            int bin_str[8] = {0};
            HexToBinStr(a[i], bin_str);
            for (int j = 0; j < 8; j++)
            {
                bootsSymEncrypt(W[k].word + 8 * i + j, bin_str[7 - j], key);
            }
        }
    }

    //encrypt w1
    for (int k = 0; k < 64; k++)
    {
        unsigned char a[4] = {0};
        PUT_ULONG_BE(w1[k], a, 0);
        for (int i = 0; i < 4; i++)
        {
            int bin_str[8] = {0};
            HexToBinStr(a[i], bin_str);
            for (int j = 0; j < 8; j++)
            {
                bootsSymEncrypt(W1[k].word + 8 * i + j, bin_str[7 - j], key);
            }
        }
    }
#endif
    //if CPU uses little-endian, BigEndian function is a necessary call
    // BigEndian(md->buf, 64, md->buf); 

    clock_t start, finish;
    double totaltime;
    start = clock();
    // BiToW((unsigned int *)md->buf, W);
    homoBiToW(md->buf, W, params, key);
#if 0
    cout << "================Wi==================" << endl;
    for (int i = 0; i < 68; i++)
    {
        DecryptCipherWord(&W[i], key);
    }
#endif
    // WToW1(W, W1);
    homoWToW1(W, W1, params, key);
    finish = clock();
    totaltime = (double)(finish - start) / CLOCKS_PER_SEC;
    cout << "the time of compute of W,W1 is:" << totaltime << "s！" << endl;

#if 0
    cout << endl
         << "================W1i==================" << endl;
    for (int i = 0; i < 64; i++)
    {
        DecryptCipherWord(&W1[i], key);
    }
    cout << endl;
#endif
    //Calculate the intermediate value of iterative compression
    clock_t start1, finish1;
    double totaltime1;
    start1 = clock();
    homoCF(W, W1, md->state, params, key);
    finish1 = clock();
    totaltime1 = (double)(finish1 - start1) / CLOCKS_PER_SEC;
    cout << "the time of iterative compression is :" << totaltime1 << "s！" << endl;
}

void homoSM3_done(CipherState *md, CipherWord *hashCipher, TFheGateBootstrappingParameterSet *params,
                  TFheGateBootstrappingSecretKeySet *key)
{
    /* increase the bit length of the message */
    md->length += md->curlen << 3;
    /* append the '1' bit */
    // md->buf[md->curlen] = 0x80;
    unsigned char constChar1 = 0x80;
    int bin_str[8] = {0};
    HexToBinStr(constChar1, bin_str);
    for (int j = 0; j < 8; j++)
    {
        bootsSymEncrypt(md->buf[md->curlen].byte + j, bin_str[7 - j], key);
    }
    md->curlen++;
    /* if the length is currently above 56 bytes, appends zeros till
        it reaches 64 bytes, compress the current block, creat a new
        block by appending zeros and length,and then compress it
    */
    if (md->curlen > 56)
    {
        printf("md->curlen > 56   \n");
        for (; md->curlen < 64;)
        {
            // md->buf[md->curlen] = 0;
            md->curlen++;
        }
        // SM3_compress(md);
        md->curlen = 0;
    }
    /* if the length is less than 56 bytes, pad upto 56 bytes of zeroes */
    LweSample *zeroCipher = new_gate_bootstrapping_ciphertext(params);
    bootsSymEncrypt(zeroCipher, 0, key);
    for (; md->curlen < 56;)
    {
        // md->buf[md->curlen] = 0;
        for (int i = 0; i < 8; i++)
        {
            bootsSymEncrypt(md->buf[md->curlen].byte + i, 0, key);
        }
        md->curlen++;
    }
    /* since all messages are under 2^32 bits we mark the top bits zero */
    for (int i = 56; i < 60; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            bootsSymEncrypt(md->buf[i].byte + j, 0, key);
        }
    }

    /* append length */
    // md->buf[63] = md->length & 0xff;
    HexToBinStr(md->length & 0xff, bin_str);
    for (int j = 0; j < 8; j++)
    {
        bootsSymEncrypt(md->buf[63].byte + j, bin_str[7 - j], key);
    }
    // md->buf[62] = (md->length >> 8) & 0xff;
    HexToBinStr((md->length >> 8) & 0xff, bin_str);
    for (int j = 0; j < 8; j++)
    {
        bootsSymEncrypt(md->buf[62].byte + j, bin_str[7 - j], key);
    }

    // md->buf[61] = (md->length >> 16) & 0xff;
    HexToBinStr((md->length >> 16) & 0xff, bin_str);
    for (int j = 0; j < 8; j++)
    {
        bootsSymEncrypt(md->buf[61].byte + j, bin_str[7 - j], key);
    }

    // md->buf[60] = (md->length >> 24) & 0xff;
    HexToBinStr((md->length >> 24) & 0xff, bin_str);
    for (int j = 0; j < 8; j++)
    {
        bootsSymEncrypt(md->buf[60].byte + j, bin_str[7 - j], key);
    }

    homoSM3_compress(md, params, key);
    /* copy output */
    // memcpy(hash, md->state, SM3_len / 8);
    for (int i = 0; i < 8; i++)
    {
        CopyCipherWord(&hashCipher[i], &md->state[i], key);
    }
}

void homoSM3_256(LweSample **msgCipher, int MsgLen1, CipherWord *hashCipher, TFheGateBootstrappingParameterSet *params,
                 TFheGateBootstrappingSecretKeySet *key)
{
    CipherState md;
    for (int i = 0; i < 8; i++)
    {
        NewCipherWord(&md.state[i], params);
    }

    for (int i = 0; i < 64; i++)
    {
        md.buf[i].byte = new_gate_bootstrapping_ciphertext_array(8, params);
    }

    homoSM3_init(&md, params, key);
#if 0
    cout <<"--------------IV----------------" <<endl;
    for (int i = 0; i < 8; i++)
    {
        DecryptCipherWord(&md.state[i], key);
    }
    cout << endl;
#endif

    //compress the first (len/64) blocks of message
    homoSM3_process(&md, msgCipher, MsgLen1, params, key);
#if 0
    printf("md->curlen: %d \n", md.curlen); //md->buf[md->curlen]
    for (int i = 0; i < md.curlen; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            cout << bootsSymDecrypt(md.buf[i].byte+j ,key) << " ";
        }
        cout << endl;
        
    }
#endif

    homoSM3_done(&md, hashCipher, params, key);
}
int main()
{
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet *params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    uint32_t seed[] = {214, 1592, 657};
    tfhe_random_generator_setSeed(seed, 3);
    TFheGateBootstrappingSecretKeySet *key = new_random_gate_bootstrapping_secret_keyset(params);

    const TFheGateBootstrappingCloudKeySet *bk = &(key->cloud);

    //homomorphic evaluate SM3
    unsigned int i = 0, a = 1, b = 1;
    unsigned char Msg1[3] = {0x61, 0x62, 0x63};
    int MsgLen1 = 3;
    unsigned char MsgHash1[32] = {0};
    unsigned char
        StdHash1[32] = {0x66, 0xC7, 0xF0, 0xF4, 0x62, 0xEE, 0xED, 0xD9, 0xD1, 0xF2, 0xD4, 0x6B, 0xDC, 0x10, 0xE4, 0xE2,
                        0x41, 0x67, 0xC4, 0x87, 0x5C, 0xF2, 0xF7, 0xA2, 0x29, 0x7D, 0xA0, 0x2B, 0x8F, 0x4B, 0xA8, 0xE0};

    LweSample *msgCipher[MsgLen1];
    int bin[8];
    for (int i = 0; i < MsgLen1; i++)
    {
        msgCipher[i] = new_gate_bootstrapping_ciphertext_array(8, params);
        HexToBinStr(Msg1[i], bin);
        for (int j = 0; j < 8; j++)
        {
            bootsSymEncrypt(msgCipher[i] + j, bin[7 - j], key);
        }
    }

    CipherWord hashCipher[8];
    for (int i = 0; i < 8; i++)
    {
        NewCipherWord(&hashCipher[i], params);
    }
    clock_t start, finish;
    double totaltime;
    start = clock();
    homoSM3_256(msgCipher, MsgLen1, hashCipher, params, key);
    finish = clock();
    totaltime = (double)(finish - start) / CLOCKS_PER_SEC;
    cout << "the  time of homomorphic evaluation of SM3 is: " << totaltime << "s！" << endl;

    //decrypt hashCipher
    for (int i = 0; i < 8; i++)
    {
        DecryptCipherWord(&hashCipher[i], key);
    }
    cout << endl;
    return 0;
}