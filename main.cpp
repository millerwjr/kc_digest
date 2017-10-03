#include <iostream>
#include "kc_digest.h"

int main() {
    std::cout << std::endl << "================================================================================";
    std::cout << std::endl << "k-Concise::MD5 Test Suite";
    std::cout << std::endl << "================================================================================";

    int fail_ct = 0;
    int pass_ct = 0;
    {
        std::cout << std::endl << "Hashing";
        {
            std::cout << std::endl << "    std::string (Initial Pass) ........................................ ";
            kc::digest mydigest;
            if (mydigest.md5("apples") == "daeccf0ad3c1fc8c8015205c332f5b42") {
                std::cout << "Pass";
                ++pass_ct;
            } else {
                std::cout << "FAIL";
                ++fail_ct;
            }
        }
    }
    {
        std::cout << std::endl << "    std::ifstream (Initial Pass) ...................................... ";
        std::ofstream outfile;
        outfile.open("kc_md5_temp_1.dat");
        outfile << "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor\n"
                "incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis\n"
                "nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.\n"
                "\n"
                "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu\n"
                "fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in\n"
                "culpa qui officia deserunt mollit anim id est laborum.";
        outfile.close();
        std::ifstream infile;
        infile.open("kc_md5_temp_1.dat");
        kc::digest mydigest;
        if (mydigest.md5(infile) == "a5e90c16beb53bb93468496eaf2e0ac4") {
            std::cout << "Pass";
            ++pass_ct;
        } else {
            std::cout << "FAIL";
            ++fail_ct;
        }
        infile.close();
    }
    {
        kc::digest mydigest;
        std::cout << std::endl << "    std::string (Second Pass) ......................................... ";
        mydigest.md5("apples");
        if (mydigest.md5("oranges") == "91b07b3169d8a7cb6de940142187c8df") {
            std::cout << "Pass";
            ++pass_ct;
        } else {
            std::cout << "FAIL";
            ++fail_ct;
        }
    }
    {
        kc::digest mydigest;
        std::cout << std::endl << "    std::ifstream (Second Pass) ....................................... ";
        std::ofstream outfile;
        outfile.open("kc_md5_temp_2.dat");
        outfile << "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu\n"
                "fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in\n"
                "culpa qui officia deserunt mollit anim id est laborum.\n"
                "\n"
                "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor\n"
                "incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis\n"
                "nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.";
        outfile.close();
        std::ifstream infile2;
        infile2.open("kc_md5_temp_1.dat");
        mydigest.md5(infile2);
        infile2.close();
        infile2.open("kc_md5_temp_2.dat");
        if (mydigest.md5(infile2) == "738b52562b33e27f762f485b0e4d9e72") {
            std::cout << "Pass";
            ++pass_ct;
        } else {
            std::cout << "FAIL";
            ++fail_ct;
        }
        infile2.close();
    }

    std::remove("kc_md5_temp_1.dat");
    std::remove("kc_md5_temp_2.dat");



    std::cout << std::endl << "================================================================================";
    std::cout << std::endl << "k-Concise::SHA1 Test Suite";
    std::cout << std::endl << "================================================================================";

    {
        std::cout << std::endl << "Hashing";
        {
            std::cout << std::endl << "    std::string (Initial Pass) ........................................ ";
            kc::digest mydigest;
            if (mydigest.sha1("apples") == "76c2436b593f27aa073f0b2404531b8de04a6ae7") {
                std::cout << "Pass";
                ++pass_ct;
            } else {
                std::cout << "FAIL";
                ++fail_ct;
            }
        }
    }
    {
        std::cout << std::endl << "    std::ifstream (Initial Pass) ...................................... ";
        std::ofstream outfile;
        outfile.open("kc_sha1_temp_1.dat");
        outfile << "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor\n"
                "incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis\n"
                "nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.\n"
                "\n"
                "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu\n"
                "fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in\n"
                "culpa qui officia deserunt mollit anim id est laborum.";
        outfile.close();
        std::ifstream infile;
        infile.open("kc_sha1_temp_1.dat");
        kc::digest mydigest;
        if (mydigest.sha1(infile) == "6e5bdd71ff86eba6c34184846c63277e5d0c0f1d") {
            std::cout << "Pass";
            ++pass_ct;
        } else {
            std::cout << "FAIL";
            ++fail_ct;
        }
        infile.close();
    }
    {
        kc::digest mydigest;
        std::cout << std::endl << "    std::string (Second Pass) ......................................... ";
        mydigest.sha1("apples");
        if (mydigest.sha1("oranges") == "bda04628ea94f26cac0793eac103258eb515c505") {
            std::cout << "Pass";
            ++pass_ct;
        } else {
            std::cout << "FAIL";
            ++fail_ct;
        }
    }
    {
        kc::digest mydigest;
        std::cout << std::endl << "    std::ifstream (Second Pass) ....................................... ";
        std::ofstream outfile;
        outfile.open("kc_sha1_temp_2.dat");
        outfile << "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu\n"
                "fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in\n"
                "culpa qui officia deserunt mollit anim id est laborum.\n"
                "\n"
                "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor\n"
                "incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis\n"
                "nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.";
        outfile.close();
        std::ifstream infile2;
        infile2.open("kc_sha1_temp_1.dat");
        infile2.close();
        infile2.open("kc_sha1_temp_2.dat");
        if (mydigest.sha1(infile2) == "8e17df7d76ee591eafdedbea12f864963bea9e97") {
            std::cout << "Pass";
            ++pass_ct;
        } else {
            std::cout << "FAIL";
            ++fail_ct;
        }
        infile2.close();
    }

    std::remove("kc_sha1_temp_1.dat");
    std::remove("kc_sha1_temp_2.dat");



    std::cout << std::endl << "================================================================================";
    std::cout << std::endl << "k-Concise::SHA256 Test Suite";
    std::cout << std::endl << "================================================================================";

    {
        kc::digest mydigest;
        std::cout << std::endl << "Hashing";
        std::cout << std::endl << "    std::string (Initial Pass) ........................................ ";
        if (mydigest.sha256("apples") == "f5903f51e341a783e69ffc2d9b335048716f5f040a782a2764cd4e728b0f74d9") {
            std::cout << "Pass";
            ++pass_ct;
        } else {
            std::cout << "FAIL";
            ++fail_ct;
        }
    }
    {
        kc::digest mydigest;
        std::cout << std::endl << "    std::ifstream (Initial Pass) ...................................... ";
        std::ofstream outfile;
        outfile.open("kc_sha256_temp_1.dat");
        outfile << "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor\n"
                "incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis\n"
                "nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.\n"
                "\n"
                "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu\n"
                "fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in\n"
                "culpa qui officia deserunt mollit anim id est laborum.";
        outfile.close();
        std::ifstream infile;
        infile.open("kc_sha256_temp_1.dat");
        if (mydigest.sha256(infile) == "92306303c5c43eca1fc1f37ae4830962fe7cc9777a2bff89685c6f781f1a8806") {
            std::cout << "Pass";
            ++pass_ct;
        } else {
            std::cout << "FAIL";
            ++fail_ct;
        }
        infile.close();
    }
    {
        kc::digest mydigest;
        std::cout << std::endl << "    std::string (Second Pass) ......................................... ";
        mydigest.sha256("apples");
        if (mydigest.sha256("oranges") == "0c7aae56ebe5d422f7f0f5b97da9856b135de81ac462c9c1a85ee53850fec479") {
            std::cout << "Pass";
            ++pass_ct;
        } else {
            std::cout << "FAIL";
            ++fail_ct;
        }
    }
    {
        kc::digest mydigest;
        std::cout << std::endl << "    std::ifstream (Second Pass) ....................................... ";
        std::ofstream outfile;
        outfile.open("kc_sha256_temp_2.dat");
        outfile << "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu\n"
                "fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in\n"
                "culpa qui officia deserunt mollit anim id est laborum.\n"
                "\n"
                "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor\n"
                "incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis\n"
                "nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.";
        outfile.close();
        std::ifstream infile2;
        infile2.open("kc_sha256_temp_1.dat");
        mydigest.sha256(infile2);
        infile2.close();
        infile2.open("kc_sha256_temp_2.dat");
        if (mydigest.sha256(infile2) == "10b6cea48b9db2acf78c5f964bc946f805988fa8a42671ea73e8fce5943432b4") {
            std::cout << "Pass";
            ++pass_ct;
        } else {
            std::cout << "FAIL";
            ++fail_ct;
        }
        infile2.close();
    }

    std::remove("kc_sha256_temp_1.dat");
    std::remove("kc_sha256_temp_2.dat");

    std::cout << std::endl << "================================================================================";
    std::cout << std::endl << "k-Concise::Digest Summary";
    std::cout << std::endl << "================================================================================";
    std::cout << std::endl << "Status: " << ((fail_ct) ? "FAIL" : "Pass");
    std::cout << std::endl << "    Success Count: " << pass_ct;
    std::cout << std::endl << "    Failure Count: " << fail_ct;

    return 0;
}




