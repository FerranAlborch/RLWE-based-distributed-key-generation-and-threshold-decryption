import os
import sys

def main():
    iterations=1000



    # os.system("gcc keygen_sim.c functions.c -lm -lgmp -lssl -lcrypto -lflint -lmpfr -o keygen.out -O2")
    # for n in [pow(2,x) for x in range(7,12)]: # n de 128 a 2048
        # for t in [2]: # t de 2 a 2
            # for u in [t+1]: # u para seguridad pasiva
                # try:
                    # os.remove("keygen.csv")
                # except:
                    # pass
                # for i in range(iterations):
                    # os.system("./keygen.out " + " ".join(str(v) for v in [n,u,t]))
                    # print(str((i+1)*5) + " iterations of keygen completed with [n,u,t] = [" + ",".join(str(v) for v in [n,u,t]) + "]")
                # os.system("mv ./keygen.csv ./keygen_" + "_".join(str(v) for v in [n,u,t]) + ".csv")


    # print("\n")

    # os.system("gcc decryption_sim.c functions.c -lm -lgmp -lssl -lcrypto -lflint -lmpfr -o decrypt.out -O2")
    # for n in [pow(2,x) for x in range(7,12)]: # n de 128 a 2048
        # for t in [2]: # t de 2 a 2
            # for u in [t+1]: # u para seguridad pasiva
                # try:
                    # os.remove("decrypt.csv")
                # except:
                    # pass
                # for i in range(iterations):
                    # os.system("./decrypt.out " + " ".join(str(v) for v in [n,u,t]))
                    # print(str((i+1)*5) + " iterations of decrypt completed with [n,u,t] = [" + ",".join(str(v) for v in [n,u,t]) + "]")
                # os.system("mv ./decrypt.csv ./decrypt_" + "_".join(str(v) for v in [n,u,t]) + ".csv")

    # print("\n")

    # os.system("gcc keygen_sim.c functions.c -lm -lgmp -lssl -lcrypto -lflint -lmpfr -o keygen.out -O2")
    # for n in [pow(2,x) for x in [11]]: # n de 2048 a 2048
        # for t in [2]: # t de 2 a 2
            # for u in [t+1]: # u para seguridad pasiva
                # try:
                    # os.remove("keygen.csv")
                # except:
                    # pass
                # for i in range(iterations):
                    # os.system("./keygen.out " + " ".join(str(v) for v in [n,u,t]))
                    # print(str((i+1)*5) + " iterations of keygen completed with [n,u,t] = [" + ",".join(str(v) for v in [n,u,t]) + "]")
                # os.system("mv ./keygen.csv ./keygen_" + "_".join(str(v) for v in [n,u,t]) + ".csv")

    # print("\n")

    os.system("gcc decryption_sim.c functions.c -lm -lgmp -lssl -lcrypto -lflint -lmpfr -o decrypt.out -O2")
    for n in [pow(2,x) for x in [11]]: # n de 2048 a 2048
        for t in [2]: # t de 2 a 2
            for u in [t+1]: # u para seguridad pasiva
                try:
                    os.remove("decrypt.csv")
                except:
                    pass
                for i in range(iterations):
                    os.system("./decrypt.out " + " ".join(str(v) for v in [n,u,t]))
                    print(str((i+1)*5) + " iterations of decrypt completed with [n,u,t] = [" + ",".join(str(v) for v in [n,u,t]) + "]")
                os.system("mv ./decrypt.csv ./decrypt_" + "_".join(str(v) for v in [n,u,t]) + ".csv")

    print("\n")
main()
