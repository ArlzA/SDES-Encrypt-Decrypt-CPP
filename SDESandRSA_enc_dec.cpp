#include <iostream>
#include <string>
#include <stdio.h>
#include <cstring>
#include <bitset>
#include <math.h>

using namespace std;

// functions for checking user input for SDES
bool ptChecker(string text);
bool keyChecker(string text);
// functions for encrypt/decrypt SDES
void SDES(bitset<8> &text, bitset<8> &key1, bitset<8> &key2, bitset<8> &resText, bool encORdec);
void keyGenerator(bitset<10> &theKey, bitset<8> &key1, bitset<8> &key2);


// Functions for RSA
double RSAencrypt(double p, double q, double e, double m);
int gcd(int x, int y);
bool inputPrimeCheck(double userIn);
bool positiveCheck(double userIn);


// MAIN PROGRAM
int main()
{
    bool programLoop = true, SDESloop = true, RSAloop = true;
    int driverChoice, SDESchoice, RSAchoice;    

    // primary loop acts as driver for program
    // via this loop the menu selection occurs
    while (programLoop)
    {
        cout << endl << " --MAIN MENU-- ";
        cout << endl << "Please choose from the below menu:" << endl;
        cout << "1: SDES" << endl;
        cout << "2: RSA" << endl;
        cout << "0: Exit" << endl;

        cin >> driverChoice;

        // this is the start of the code for SDES
        if (driverChoice == 1)
        {
            SDESloop = true;
            while (SDESloop)
            {
                cout << endl << " -SDES Menu- ";
                cout << endl << "Please choose from the below menu:" << endl;
                cout << "1: Encrypt" << endl;
                cout << "2: Decrypt" << endl;
                cout << "0: Exit" << endl;

                cin >> SDESchoice;

                if (SDESchoice == 1)
                {
                    string inputText, cipherText, key;
                    bool encryption = true;

                    // taking inputText input and validating it
                    bool testResult = false;
                    while (!testResult)
                    {
                        cout << endl << "Enter the 8 bit inputText" << endl;

                        cin >> inputText;

                        testResult = ptChecker(inputText);
                    }
                    //taking key input and validating it
                    testResult = false;
                    while (!testResult)
                    {
                        cout << endl << "Enter the 10 bit Key" << endl;

                        cin >> key;

                        testResult = keyChecker(key);
                    }
                    //
                    // using key and inputText to produce 8-bit keys + ciphertext
                    // first we make bitset objects
                    bitset<8> plainBits(inputText);
                    bitset<10> keyBits(key);
                    bitset<8> k1;
                    bitset<8> k2;
                    bitset<8> resText;
                
                    // generate keys
                    keyGenerator(keyBits, k1, k2);
                    cout << "10-Bit Key: " << keyBits << endl;
                    cout << "Key1: " << k1 << endl;
                    cout << "Key2: " << k2 << endl;

                    // encryption
                    SDES(plainBits, k1, k2, resText, encryption);
                    cout << "CipherText: " << resText << endl;
                    cout << endl;
                }
                else if(SDESchoice == 2)
                {
                    string inputText, cipherText, key;
                    bool encryption = false;

                    // taking inputText input and validating it
                    bool testResult = false;
                    while (!testResult)
                    {
                        cout << endl << "Enter the 8 bit cipher text" << endl;

                        cin >> inputText;

                        testResult = ptChecker(inputText);
                    }
                    //taking key input and validating it
                    testResult = false;
                    while (!testResult)
                    {
                        cout << endl << "Enter the 10 bit Key" << endl;

                        cin >> key;

                        testResult = keyChecker(key);
                    }
                    //
                    // using key and inputText to produce 8-bit keys + ciphertext
                    // first we make bitset objects
                    bitset<8> plainBits(inputText);
                    bitset<10> keyBits(key);
                    bitset<8> k1;
                    bitset<8> k2;
                    bitset<8> resText;
                
                    // generate keys
                    keyGenerator(keyBits, k1, k2);
                    cout << "10-Bit Key: " << keyBits << endl;
                    cout << "Key1: " << k1 << endl;
                    cout << "Key2: " << k2 << endl;

                    // decryption
                    SDES(plainBits, k1, k2, resText, encryption);
                    cout << "PlainText: " << resText << endl;
                    cout << endl;;
                }
                else if(SDESchoice == 0)
                {
                    cout << endl << "Returning to main Menu..." << endl;
                    SDESloop = false;
                }


            }
        }
        // THIS IS THE END OF THE CODE FOR SDES
        //
        //
        // this is the start of the code for RSA
        else if (driverChoice == 2)
        {
            RSAloop = true;
            while (RSAloop)
            {
                // RSA MENU
                cout << endl << " -RSA Menu- ";
                cout << endl << "Please choose from the below menu:" << endl;
                cout << "1: Encrypt" << endl;
                cout << "2: Decrypt -- NOT IMPLEMENTED" << endl;
                cout << "0: Exit" << endl;

                cin >> RSAchoice;

                if (RSAchoice == 1)
                {
                    double p, q, e, m, c;
                    
                    // create flag for user input validation
                    bool flag = false;
                    while (!flag)
                    {
                        cout << endl << "Enter a positive prime integer value for p: " << endl;
                        cin >> p;
                        flag = positiveCheck(p);
                        if (flag == true)
                        {
                            flag = inputPrimeCheck(p);
                        }
                    }
                    // reset flag for q input
                    flag = false;
                    while (!flag)
                    {
                        cout << endl << "Enter a positive prime integer value for q that is != to p: " << endl;
                        cin >> q;
                        flag = positiveCheck(q);
                        if (flag == true)
                        {
                            flag = inputPrimeCheck(q);
                        }
                        if (q == p)
                        {
                            flag = false;
                        }
                    }
                    // reset flag for e input
                    // e input is checked for positive int
                    // key e 1 < e < phi(n) is done within the RSA encrypt function via increment until
                    // suitable key is found
                    flag = false;
                    while (!flag)
                    {
                        cout << endl << "Enter a integer value for e: " << endl;
                        cin >> e;
                        flag = positiveCheck(q);
                    }
                    // reset flag for m input
                    flag = false;
                    while (!flag)
                    {
                        cout << endl << "Enter a integer value for m: " << endl;
                        cin >> m;
                        flag = positiveCheck(m);
                    }
                    // function to find C
                    c = RSAencrypt(p, q, e, m);
                    // all the prints (e is printed from within above function as its validation occurs there)
                    cout << "Value for p is: " << p << endl;
                    cout << "Value for q is: " << q << endl;
                    cout << "Value for m is: " << m << endl;
                    cout << endl << "Value for c is: " << c << endl;

                }
                else if(RSAchoice == 2)
                {
                    cout << endl << "NOT YET IMPLEMENTED" << endl;
                }
                else if(RSAchoice == 0)
                {
                    cout << endl << "Returning to main Menu..." << endl;
                    RSAloop = false;
                }
            }
        }
        // THIS IS THE END OF THE CODE FOR RSA
        //
        //
        else if (driverChoice == 0)
        {
            cout << endl << "Exiting program...." << endl;
            programLoop = false;
        }

    } 
    return 0;
}

// function to check validity of inputText entry by user
bool ptChecker(string text)
{
    if (text.length() == 8)
    {
        for (int i = 0; i < 8; i++)
        {
            if ((text[i] != '0') && (text[i] != '1'))
            {
                return false;
            }
        }
        return true;
    }
    
    return false;
    
}

// function to check validity of key entry by user
bool keyChecker(string text)
{
    if (text.length() == 10)
    {
        for (int i = 0; i < 10; i++)
        {
            if ((text[i] != '0') && (text[i] != '1'))
            {
                return false;
            }
        }
        return true;
    }
    
    return false;
}

// function to generate keys and save them to pass by reference key bitset objects
void keyGenerator(bitset<10> &theKey, bitset<8> &key1, bitset<8> &key2)
{
    bitset<5> k1LH;
    bitset<5> k1RH;
    bitset<10> keyTemp10;
    bitset<8> keyTemp8;

    // permute 10
    int p10[10] = {5, 7, 8, 0, 9, 3, 6, 1, 4, 2};

    // permute 8
    int p8[8] = {8, 9, 4, 7, 3, 6, 2, 5};
    
    // do the p10 permutation
    for (int i = 9; i >= 0; i--)
    {
        if (theKey[(9-p10[i])])
        {
            keyTemp10[i] = 1;
        }
    }
    // split the p10 into 2 halves left and right side
    for (int i = 9; i >= 5; i--)
    {
        k1LH[i-5] = keyTemp10[i];
    }
    for (int i = 4; i >= 0; i--)
    {
        k1RH[i] = keyTemp10[i];
    }
    // perform left shift on both halves separately
    if (k1LH[4] == 0)
    {
        k1LH <<= 1;
    }
    else
    {
        k1LH <<= 1;
        k1LH[0] = 1;
    }
    if (k1RH[4] == 0)
    {
        k1RH <<= 1;
    }
    else
    {
        k1RH <<= 1;
        k1RH[0] = 1;
    }
    // rebuild the 10 bits from the two halves
    for (int i = 9; i >= 5; i--)
    {
        keyTemp10[i] = k1LH[i-5];
    }
    for (int i = 4; i >= 0; i--)
    {
        keyTemp10[i] = k1RH[i];
    }
    // perform permute 8 on the rebuild
    for (int i = 7; i >= 0; i--)
    {
        if (keyTemp10[(9-p8[i])])
        {
            keyTemp8[i] = 1;
        }
    }
    // save result as key1
    key1 = keyTemp8;

    // perform 2 left shits on both halves (halves retained from previously)
    int leftCount = 2, rightCount = 2;
    while (leftCount > 0)
    {
        if (k1LH[4] == 0)
        {
            k1LH <<= 1;
        }
        else
        {
            k1LH <<= 1;
            k1LH[0] = 1;
        }
        leftCount--;
    }
    while (rightCount > 0)
    {
        if (k1RH[4] == 0)
        {
            k1RH <<= 1;
        }
        else
        {
            k1RH <<= 1;
            k1RH[0] = 1;
        }
        rightCount--;
    }
    // rebuilt the 10 bits from both halves
    for (int i = 9; i >= 5; i--)
    {
        keyTemp10[i] = k1LH[i-5];
    }
    for (int i = 4; i >= 0; i--)
    {
        keyTemp10[i] = k1RH[i];
    }
    // reset the values of temp8 to all 0
    for (int i = 0; i < 8; i++)
    {
        keyTemp8[i] = 0;
    }
    // perform p8 on the new 10 bit sequence
    for (int i = 7; i >= 0; i--)
    {
        if (keyTemp10[(9-p8[i])])
        {
            keyTemp8[i] = 1;
        }
    }
    //save value as key2
    key2 = keyTemp8;
}

// THIS function will handle ALL encryption / Decryption in SDES
// relies on boolean flag to shift from encrypt to decrypt
// START SDES HERE
void SDES(bitset<8> &inputText, bitset<8> &key1, bitset<8> &key2, bitset<8> &resText, bool encryption)
{
    //IP
    int IP[8] = {6, 4, 7, 3, 0, 2, 5, 1};
    // IP inverse
    int IPinverse[8] = {5, 7, 1, 6, 4, 2, 0, 3};
    // E/P
    int EP[8] = {0, 3, 2, 1, 2, 1, 0, 3};
    // P4
    int P4[4] = {0, 2, 3, 1};
    // s0
    int s0[4][4] = { 1, 0, 3, 2,
                     3, 2, 1, 0,
                     0, 2, 1, 3,
                     3, 1, 3, 2};
    // s1
    int s1[4][4] = { 0, 1, 2, 3,
                     2, 0, 1, 3,
                     3, 0, 1, 0,
                     2, 1, 0, 3};

    int row, col, sBoxRes;
    ///////////////////////////////
    ///////////////////////////////
    bitset<4> fK;
    bitset<4> leftHalf;
    bitset<4> rightHalf;
    bitset<4> rightHalfHELD;
    bitset<8> tempHolder;
    bitset<4> postSaction;
    bitset<2> outterBits;
    bitset<2> innerBits;
    bitset<4> pFour;
    // perform IP on inputText
    for (int i = 7; i >= 0; i--)
    {
        if (inputText[(7-IP[i])])
        {
            tempHolder[i] = 1;
        }
    }
    // split the IP into 2 halves left and right side
    for (int i = 7; i >= 4; i--)
    {
        fK[i-4] = tempHolder[i];
    }
    for (int i = 4; i >= 0; i--)
    {
        rightHalf[i] = tempHolder[i];
        rightHalfHELD[i] = tempHolder[i];
    }
    // reset the values of temp8 to all 0
    tempHolder.reset();
    // do EP on right half
    for (int i = 7; i >= 0; i--)
    {
        if (rightHalf[(3-EP[i])])
        {
            tempHolder[i] = 1;
        }
    }
    // XOR functions depending on encrypt or decrypt
    if (encryption == true)
    {
        tempHolder ^= key1;
    }
    else if (encryption == false)
    {
        tempHolder ^= key2;
    }
    // reset the values of temp8 to all 0
    rightHalf.reset();
    // split the XOR into 2 halves left and right side
    for (int i = 7; i >= 4; i--)
    {
        leftHalf[i-4] = tempHolder[i];
    }
    for (int i = 4; i >= 0; i--)
    {
        rightHalf[i] = tempHolder[i];
    }
    // perform S0 on left half
    outterBits[1] = leftHalf[3];
    outterBits[0] = leftHalf[0];
    innerBits[1] = leftHalf[2];
    innerBits[0] = leftHalf[1];
    row = outterBits.to_ulong();
    col = innerBits.to_ulong();
    // in this section of code i need the four bits
    // the outer two are the row
    // the inner two are the col
    // i extract the bits then get the real value of bits
    // then plug that value into a 2d Array to get the int value
    // from the sBox
    sBoxRes = s0[row][col];
    // handling 2 and 3rd bit of post Sbox
    if(sBoxRes == 1)
    {
        postSaction[2] = 1;
    }
    else if(sBoxRes == 2)
    {
        postSaction[3] = 1;
    }
    else if(sBoxRes == 3)
    {
        postSaction[3] = 1;
        postSaction[2] = 1;
    }
    // perform S1 on right half
    // same as above S section but using other 2d array
    outterBits[1] = rightHalf[3];
    outterBits[0] = rightHalf[0];
    innerBits[1] = rightHalf[2];
    innerBits[0] = rightHalf[1];
    row = outterBits.to_ulong();
    col = innerBits.to_ulong();
    sBoxRes = s1[row][col];
    // handling 0 and 1rd bit of post Sbox
    if(sBoxRes == 1)
    {
        postSaction[0] = 1;
    }
    else if(sBoxRes == 2)
    {
        postSaction[1] = 1;
    }
    else if(sBoxRes == 3)
    {
        postSaction[0] = 1;
        postSaction[1] = 1;
    }
    // do p4
    for (int i = 3; i >= 0; i--)
    {
        if (postSaction[(3-P4[i])])
        {
            pFour[i] = 1;
        }
    }
    // xor p4 with fK
    pFour ^= fK;
    // reset bits for tempholder
    tempHolder.reset();
    // rebuild the 8 bits from both halves swapped
    for (int i = 7; i >= 4; i--)
    {
        tempHolder[i] = rightHalfHELD[i-4];
    }
    for (int i = 3; i >= 0; i--)
    {
        tempHolder[i] = pFour[i];
    }
    //  new FK post swap
    fK = rightHalfHELD;
    // new right half to be held and right half to be manipulated
    rightHalfHELD = pFour;
    rightHalf = pFour;
    ////////////////////////// phase 1 complete
    ////// start phase 2 of encryption
    // reset the values of temp8 to all 0
    tempHolder.reset();
    // do EP on right half
    for (int i = 7; i >= 0; i--)
    {
        if (rightHalf[(3-EP[i])])
        {
            tempHolder[i] = 1;
        }
    }
    // XOR functions depending on encrypt or decrypt
    if (encryption == true)
    {
        tempHolder ^= key2;
    }
    else if (encryption == false)
    {
        tempHolder ^= key1;
    }
    // reset the values of temp8 to all 0
    rightHalf.reset();
    // split the XOR into 2 halves left and right side
    for (int i = 7; i >= 4; i--)
    {
        leftHalf[i-4] = tempHolder[i];
    }
    for (int i = 4; i >= 0; i--)
    {
        rightHalf[i] = tempHolder[i];
    }
    // perform S0 on left half
    // please refer to comments from SBOX in phase1
    // for detailed explanation as to what is happening here
    outterBits[1] = leftHalf[3];
    outterBits[0] = leftHalf[0];
    innerBits[1] = leftHalf[2];
    innerBits[0] = leftHalf[1];
    row = outterBits.to_ulong();
    col = innerBits.to_ulong();
    sBoxRes = s0[row][col];
    // reset the post SBOX bitset
    postSaction.reset();
    // handling 2 and 3rd bit of post Sbox
    if(sBoxRes == 1)
    {
        postSaction[2] = 1;
    }
    else if(sBoxRes == 2)
    {
        postSaction[3] = 1;
    }
    else if(sBoxRes == 3)
    {
        postSaction[3] = 1;
        postSaction[2] = 1;
    }
    // perform S1 on right half
    outterBits[1] = rightHalf[3];
    outterBits[0] = rightHalf[0];
    innerBits[1] = rightHalf[2];
    innerBits[0] = rightHalf[1];
    row = outterBits.to_ulong();
    col = innerBits.to_ulong();
    sBoxRes = s1[row][col];
    // handling 0 and 1rd bit of post Sbox
    if(sBoxRes == 1)
    {
        postSaction[0] = 1;
    }
    else if(sBoxRes == 2)
    {
        postSaction[1] = 1;
    }
    else if(sBoxRes == 3)
    {
        postSaction[0] = 1;
        postSaction[1] = 1;
    }
    // do p4
    // reset before 
    pFour.reset();
    // p4
    for (int i = 3; i >= 0; i--)
    {
        if (postSaction[(3-P4[i])])
        {
            pFour[i] = 1;
        }
    }
    // XOR p4 with FK
    pFour ^= fK;
    // reset bits for tempholder
    tempHolder.reset();
    // rebuilt the 8 bits from both halves
    for (int i = 7; i >= 4; i--)
    {
        tempHolder[i] = pFour[i-4];
    }
    for (int i = 3; i >= 0; i--)
    {
        tempHolder[i] = rightHalfHELD[i];
    }
    resText.reset();
    // do IP inverse
    for (int i = 7; i >= 0; i--)
    {
        if (tempHolder[(7-IPinverse[i])])
        {
            resText[i] = 1;
        }
    }
}
// END SDES HERE

// START RSA ENCRYPTOR HERE
double RSAencrypt(double p, double q, double e, double m)
{
    double n = p*q;
    double phi = (p-1)*(q-1);
    double GCDiv;
    // check that coprime 
    // 1 < e < phi(n)
    while (e < phi)
    {
        GCDiv = gcd(e, phi);
        if (GCDiv == 1)
        {
            break;
        }
        e++;
    }
    // use math functions from header
    // calculate M^e
    double cipherText = pow(m, e);
    // C = M^e mod n
    // inbuilt math function can handle this for us
    cipherText = fmod(cipherText, n);

    cout << endl << endl << "Adjusted value for e is: " << e << endl;
    return cipherText;
}
// END RSA ENCRYPTOR HERE

// GCD function
int gcd(int x, int y)
{
    int holder;
    while (true)
    {
        holder = x%y;
        if (holder == 0)
        {
            return y;
        }
        x = y;
        y = holder;
    }
}

/////////////////// input validation for RSA user inputs /////////
bool inputPrimeCheck(double userIn)
{
    int userInput = userIn;
    if (userIn < 2)
    {
        return false;
    }
    if (userIn == 2)
    {
        return true;
    }
    if (userInput % 2 == 0)
    {
        return false;
    }
    for (int i = 3; (i*i) <= userIn; i+=2)
    {
        if (userInput % i == 0)
        {
            return false;
        }
        
    }
    return true;
}
bool positiveCheck(double userIn)
{
    if (userIn < 0)
    {
        return false;
    }
    else
    {
        return true;
    }
    
}
///////////// input validation functions end here 2 functions total