using System;
using System.Linq;

namespace Kuznechik
{
    public class Kuznechik
    {
        public readonly byte[] PI = new byte[256]
        {
            0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16,
            0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
            0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA,
            0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
            0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21,
            0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
            0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0,
            0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
            0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB,
            0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
            0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12,
            0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
            0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7,
            0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
            0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E,
            0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
            0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9,
            0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
            0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC,
            0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
            0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44,
            0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
            0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F,
            0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
            0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7,
            0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
            0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE,
            0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
            0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B,
            0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
            0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0,
            0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
        };

        public readonly byte[] RPi = new byte[256]
        {
            0xA5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0,
            0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E, 0x52, 0x91,
            0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18,
            0x21, 0x72, 0xA8, 0xD1, 0x29, 0xC6, 0xA4, 0x3F,
            0xE0, 0x27, 0x8D, 0x0C, 0x82, 0xEA, 0xAE, 0xB4,
            0x9A, 0x63, 0x49, 0xE5, 0x42, 0xE4, 0x15, 0xB7,
            0xC8, 0x06, 0x70, 0x9D, 0x41, 0x75, 0x19, 0xC9,
            0xAA, 0xFC, 0x4D, 0xBF, 0x2A, 0x73, 0x84, 0xD5,
            0xC3, 0xAF, 0x2B, 0x86, 0xA7, 0xB1, 0xB2, 0x5B,
            0x46, 0xD3, 0x9F, 0xFD, 0xD4, 0x0F, 0x9C, 0x2F,
            0x9B, 0x43, 0xEF, 0xD9, 0x79, 0xB6, 0x53, 0x7F,
            0xC1, 0xF0, 0x23, 0xE7, 0x25, 0x5E, 0xB5, 0x1E,
            0xA2, 0xDF, 0xA6, 0xFE, 0xAC, 0x22, 0xF9, 0xE2,
            0x4A, 0xBC, 0x35, 0xCA, 0xEE, 0x78, 0x05, 0x6B,
            0x51, 0xE1, 0x59, 0xA3, 0xF2, 0x71, 0x56, 0x11,
            0x6A, 0x89, 0x94, 0x65, 0x8C, 0xBB, 0x77, 0x3C,
            0x7B, 0x28, 0xAB, 0xD2, 0x31, 0xDE, 0xC4, 0x5F,
            0xCC, 0xCF, 0x76, 0x2C, 0xB8, 0xD8, 0x2E, 0x36,
            0xDB, 0x69, 0xB3, 0x14, 0x95, 0xBE, 0x62, 0xA1,
            0x3B, 0x16, 0x66, 0xE9, 0x5C, 0x6C, 0x6D, 0xAD,
            0x37, 0x61, 0x4B, 0xB9, 0xE3, 0xBA, 0xF1, 0xA0,
            0x85, 0x83, 0xDA, 0x47, 0xC5, 0xB0, 0x33, 0xFA,
            0x96, 0x6F, 0x6E, 0xC2, 0xF6, 0x50, 0xFF, 0x5D,
            0xA9, 0x8E, 0x17, 0x1B, 0x97, 0x7D, 0xEC, 0x58,
            0xF7, 0x1F, 0xFB, 0x7C, 0x09, 0x0D, 0x7A, 0x67,
            0x45, 0x87, 0xDC, 0xE8, 0x4F, 0x1D, 0x4E, 0x04,
            0xEB, 0xF8, 0xF3, 0x3E, 0x3D, 0xBD, 0x8A, 0x88,
            0xDD, 0xCD, 0x0B, 0x13, 0x98, 0x02, 0x93, 0x80,
            0x90, 0xD0, 0x24, 0x34, 0xCB, 0xED, 0xF4, 0xCE,
            0x99, 0x10, 0x44, 0x40, 0x92, 0x3A, 0x01, 0x26,
            0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7,
            0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C, 0xD7, 0x74
        };

        public readonly byte[] LVec = new byte[16]
        {
            0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB,
            0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01
        };

        public readonly byte[][] IterC = new byte[32][];

        public readonly byte[][] IterKey = new byte[10][];


        public Kuznechik()
        {
            for (int i = 0; i < IterC.Length; i++)
                IterC[i] = new byte[16];

            for (int i = 0; i < IterKey.Length; i++)
                IterKey[i] = new byte[16];
        }


        public void GOST_Kuz_X(byte[] a, byte[] b, byte[] c)
        {
            for (int i = 0; i < 16; i++)
                c[i] = (byte)(a[i] ^ b[i]);
        }

        public void GOST_Kuz_S(byte[] input, byte[] output)
        {
            for (int i = 0; i < 16; i++)
                output[i] = PI[input[i]];
        }

        public void GOST_Kuz_reverse_S(byte[] input, byte[] output)
        {
            for (int i = 0; i < 16; i++)
                output[i] = RPi[input[i]];
        }

        public byte GOST_Kuz_GF_mul(byte x, byte y)
        {
            byte z = 0;

            while (y != 0)
            {
                if ((y & 1) == 1)
                    z ^= x;

                if ((x & 0x80) != 0)
                    x = (byte)((x << 1) ^ 0xc3);
                else
                    x <<= 1;

                y >>= 1;
            }

            return z;
        }

        public void GOST_Kuz_R(byte[] block)
        {
            byte x = block[15];

            for (int i = 14; i >= 0; i--)
            {
                block[i + 1] = block[i];
                x ^= GOST_Kuz_GF_mul(block[i], LVec[i]);
            }
            block[0] = x;
           }

        public void GOST_Kuz_reverse_R(byte[] block)
        {
            byte x = block[0];

            for (int i = 0; i < 15; i++)
            {
                block[i] = block[i + 1];
                x ^= GOST_Kuz_GF_mul(block[i], LVec[i]);
            }
            block[15] = x;
        }

        public void GOST_Kuz_L(byte[] input, byte[] output)
        {
            Array.Copy(input, output, 16);
            for (int i = 0; i < 16; i++)
                GOST_Kuz_R(output);
        }

        public void GOST_Kuz_reverse_L(byte[] input, byte[] output)
        {
            Array.Copy(input, output, 16);
            for (int i = 0; i < 16; i++)
                GOST_Kuz_reverse_R(output);
        }

        public void GOST_Kuz_Get_C()
        {
            for (int i = 0; i < 32; i++)
            {
                IterC[i][15] = (byte)(i + 1);
                GOST_Kuz_L(IterC[i], IterC[i]);
            }
        }

        public void GOST_Kuz_F(byte[] inKey1, byte[] inKey2, byte[] outKey1, byte[] outKey2, byte[] iterConst)
        {
            byte[] tmp = new byte[16];

            Array.Copy(inKey1, outKey2, 16);
            GOST_Kuz_X(inKey1, iterConst, tmp);
            GOST_Kuz_S(tmp, tmp);
            GOST_Kuz_L(tmp, tmp);
            GOST_Kuz_X(tmp, inKey2, outKey1);
        }

        public void GOST_Kuz_Expand_Key(byte[] key1, byte[] key2)
        {
            byte[] iterKey1 = new byte[16];
            byte[] iterKey2 = new byte[16];
            byte[] iterKey3 = new byte[16];
            byte[] iterKey4 = new byte[16];

            GOST_Kuz_Get_C();

            Array.Copy(key1, IterKey[0], 16);
            Array.Copy(key2, IterKey[1], 16);
            Array.Copy(key1, iterKey1, 16);
            Array.Copy(key2, iterKey2, 16);

            for (int i = 0; i < 4; i++)
            {
                GOST_Kuz_F(iterKey1, iterKey2, iterKey3, iterKey4, IterC[0 + 8 * i]);
                GOST_Kuz_F(iterKey3, iterKey4, iterKey1, iterKey2, IterC[1 + 8 * i]);
                GOST_Kuz_F(iterKey1, iterKey2, iterKey3, iterKey4, IterC[2 + 8 * i]);
                GOST_Kuz_F(iterKey3, iterKey4, iterKey1, iterKey2, IterC[3 + 8 * i]);
                GOST_Kuz_F(iterKey1, iterKey2, iterKey3, iterKey4, IterC[4 + 8 * i]);
                GOST_Kuz_F(iterKey3, iterKey4, iterKey1, iterKey2, IterC[5 + 8 * i]);
                GOST_Kuz_F(iterKey1, iterKey2, iterKey3, iterKey4, IterC[6 + 8 * i]);
                GOST_Kuz_F(iterKey3, iterKey4, iterKey1, iterKey2, IterC[7 + 8 * i]);

                Array.Copy(iterKey1, IterKey[2 * i + 2], 16);
                Array.Copy(iterKey2, IterKey[2 * i + 3], 16);
            }
        }

        public void GOST_Kuz_Encript(byte[] input, byte[] output)
        {
            Array.Copy(input, output, 16);

            for (int i = 0; i < 9; i++)
            {
                GOST_Kuz_X(IterKey[i], output, output);
                GOST_Kuz_S(output, output);
                GOST_Kuz_L(output, output);
            }

            GOST_Kuz_X(output, IterKey[9], output);
        }

        public void GOST_Kuz_Decript(byte[] input, byte[] output)
        {
            Array.Copy(input, output, 16);

            GOST_Kuz_X(output, IterKey[9], output);

            for (int i = 9 - 1; i >= 0; i--)
            {
                GOST_Kuz_reverse_L(output, output);
                GOST_Kuz_reverse_S(output, output);
                GOST_Kuz_X(IterKey[i], output, output);
            }
        }


        public byte[] Encript(byte[] key1, byte[] key2, byte[] input)
        {
            byte[] block = new byte[16];
            byte[] output = new byte[input.Length];

            GOST_Kuz_Expand_Key(key1, key2);

            for (int i = 0; i < input.Length; i += 16)
            {
                Array.Copy(input, i, block, 0, 16);
                GOST_Kuz_Encript(block, block);
                Array.Copy(block, 0, output, i, 16);
            }

            return output;
        }

        public byte[] Decript(byte[] key1, byte[] key2, byte[] input)
        {
            byte[] block = new byte[16];
            byte[] output = new byte[input.Length];

            GOST_Kuz_Expand_Key(key1, key2);

            for (int i = 0; i < input.Length; i += 16)
            {
                Array.Copy(input, i, block, 0, 16);
                GOST_Kuz_Decript(block, block);
                Array.Copy(block, 0, output, i, 16);
            }

            return output;
        }
    }

    public class Program
    {
        static byte[] StringToBytes(string value) =>
            Enumerable
                .Range(0, value.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(value.Substring(x, 2), 16))
                .ToArray();

        static string BytesToString(byte[] value) =>
            BitConverter
                .ToString(value)
                .Replace("-", string.Empty)
                .ToLower();


        static void Begin(string value)
        {
            Console.WriteLine($"+{new string('-', value.Length + 2)}+");
            Console.WriteLine($"| {value} |");
            Console.WriteLine($"+{new string('-', value.Length + 2)}+");
        }

        static void End()
        {
            Console.WriteLine($"{new string('-', Console.WindowWidth)}");
        }

        static void ShowBytes(string text, byte[] bytes)
        {
            Console.WriteLine($"{text} = {BytesToString(bytes)}");
        }


        static void TestResult(string test, byte[] output, string result)
        {
            if (BytesToString(output) == result)
                Console.WriteLine($"{test}: Ok");
            else
            {
                Console.WriteLine($"{test}: Error");
                Console.WriteLine($"\t->{test}={BytesToString(output)} (!= {result})");
            }
        }

        static void Test_S(string test, string value, string result)
        {
            byte[] input = StringToBytes(value);
            byte[] output = new byte[16];

            new Kuznechik().GOST_Kuz_S(input, output);

            TestResult(test, output, result);
        }

        static void Test_R(string test, string value, string result)
        {
            byte[] state = StringToBytes(value);

            new Kuznechik().GOST_Kuz_R(state);

            TestResult(test, state, result);
        }

        static void Test_L(string test, string value, string result)
        {
            byte[] input = StringToBytes(value);
            byte[] output = new byte[16];

            new Kuznechik().GOST_Kuz_L(input, output);

            TestResult(test, output, result);
        }

        static void Test_Expand_Key(string test, string key1, string key2, params string[] results)
        {
            byte[] bKey1 = StringToBytes(key1);
            byte[] bKey2 = StringToBytes(key2);

            Kuznechik kuznechik = new Kuznechik();
            kuznechik.GOST_Kuz_Expand_Key(bKey1, bKey2);

            for (int i = 0; i < Math.Min(kuznechik.IterKey.Length, results.Length); i++)
                TestResult($"{test}(K{i + 1})", kuznechik.IterKey[i], results[i]);
        }

        static void Test_Encript(string test, string key1, string key2, string value, string result)
        {
            byte[] bKey1 = StringToBytes(key1);
            byte[] bKey2 = StringToBytes(key2);
            byte[] input = StringToBytes(value);
            byte[] output = new Kuznechik().Encript(bKey1, bKey2, input);

            TestResult(test, output, result);
        }

        static void Test_Decript(string test, string key1, string key2, string value, string result)
        {
            byte[] bKey1 = StringToBytes(key1);
            byte[] bKey2 = StringToBytes(key2);
            byte[] input = StringToBytes(value);
            byte[] output = new Kuznechik().Decript(bKey1, bKey2, input);

            TestResult(test, output, result);
        }


        static void Test()
        {
            Begin("Test S");
            Test_S("S(ffeeddccbbaa99881122334455667700)", "ffeeddccbbaa99881122334455667700", "b66cd8887d38e8d77765aeea0c9a7efc");
            Test_S("S(b66cd8887d38e8d77765aeea0c9a7efc)", "b66cd8887d38e8d77765aeea0c9a7efc", "559d8dd7bd06cbfe7e7b262523280d39");
            Test_S("S(559d8dd7bd06cbfe7e7b262523280d39)", "559d8dd7bd06cbfe7e7b262523280d39", "0c3322fed531e4630d80ef5c5a81c50b");
            Test_S("S(0c3322fed531e4630d80ef5c5a81c50b)", "0c3322fed531e4630d80ef5c5a81c50b", "23ae65633f842d29c5df529c13f5acda");
            End();

            Begin("Test R");
            Test_R("R(00000000000000000000000000000100)", "00000000000000000000000000000100", "94000000000000000000000000000001");
            Test_R("R(94000000000000000000000000000001)", "94000000000000000000000000000001", "a5940000000000000000000000000000");
            Test_R("R(а5940000000000000000000000000000)", "a5940000000000000000000000000000", "64a59400000000000000000000000000");
            Test_R("R(64a59400000000000000000000000000)", "64a59400000000000000000000000000", "0d64a594000000000000000000000000");
            End();

            Begin("Test L");
            Test_L("L(64a59400000000000000000000000000)", "64a59400000000000000000000000000", "d456584dd0e3e84cc3166e4b7fa2890d");
            Test_L("L(d456584dd0e3e84cc3166e4b7fa2890d)", "d456584dd0e3e84cc3166e4b7fa2890d", "79d26221b87b584cd42fbc4ffea5de9a");
            Test_L("L(79d26221b87b584cd42fbc4ffea5de9a)", "79d26221b87b584cd42fbc4ffea5de9a", "0e93691a0cfc60408b7b68f66b513c13");
            Test_L("L(0e93691a0cfc60408b7b68f66b513c13)", "0e93691a0cfc60408b7b68f66b513c13", "e6a8094fee0aa204fd97bcb0b44b8580");
            End();

            Begin("Test Expand_Key");
            Test_Expand_Key("Expand_Key(8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef)", "8899aabbccddeeff0011223344556677", "fedcba98765432100123456789abcdef",
                "8899aabbccddeeff0011223344556677",
                "fedcba98765432100123456789abcdef",
                "db31485315694343228d6aef8cc78c44",
                "3d4553d8e9cfec6815ebadc40a9ffd04",
                "57646468c44a5e28d3e59246f429f1ac",
                "bd079435165c6432b532e82834da581b",
                "51e640757e8745de705727265a0098b1",
                "5a7925017b9fdd3ed72a91a22286f984",
                "bb44e25378c73123a5f32f73cdb6e517",
                "72e9dd7416bcf45b755dbaa88e4a4043"
            );
            End();

            Begin("Test Encript");
            Test_Encript("Encript(1122334455667700ffeeddccbbaa9988)", "8899aabbccddeeff0011223344556677", "fedcba98765432100123456789abcdef", "1122334455667700ffeeddccbbaa9988", "7f679d90bebc24305a468d42b9d4edcd");
            End();

            Begin("Test Decript");
            Test_Decript("Decript(7f679d90bebc24305a468d42b9d4edcd)", "8899aabbccddeeff0011223344556677", "fedcba98765432100123456789abcdef", "7f679d90bebc24305a468d42b9d4edcd", "1122334455667700ffeeddccbbaa9988");
            End();
        }

        static void Prog()
        {
            byte[] key1 = StringToBytes("8899aabbccddeeff0011223344556677");
            byte[] key2 = StringToBytes("fedcba98765432100123456789abcdef");
            byte[] input = StringToBytes("1122334455667700ffeeddccbbaa9988");
            byte[] output = StringToBytes("7f679d90bebc24305a468d42b9d4edcd");

            Begin("Encript");
            ShowBytes("Key1", key1);
            ShowBytes("Key2", key2);
            ShowBytes("Input ", input);
            ShowBytes("Output", new Kuznechik().Encript(key1, key2, input));
            End();

            Begin("Decript");
            ShowBytes("Key1", key1);
            ShowBytes("Key2", key2);
            ShowBytes("Output", output);
            ShowBytes("Input ", new Kuznechik().Decript(key1, key2, output));
            End();
        }

        static void Main()
        {
            string cmd = Console.ReadLine();
            Console.Clear();

            switch (cmd)
            {
                case "test":
                    Test();
                    break;

                case "prog":
                    Prog();
                    break;

                default:
                    Console.WriteLine("Упс. Что-то не то...");
                    Console.WriteLine("Список команд:");
                    Console.WriteLine("\t test - запустить тесты;");
                    Console.WriteLine("\t prog - запустить тестовую программу.");
                    break;
            }

            Console.ReadKey();
        }
    }
}
