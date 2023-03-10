import shell_util as exec_cmd
import subprocess
import json
import zlib
import sys
import base64
import os

nvm_attr_list = [
    "ppwrite",
    "ownerwrite",
    "authwrite",
    "policywrite",
    "policy_delete",
    "writelocked",
    "writeall",
    "writedefine",
    "write_stclear",
    "globallock",
    "ppread",
    "ownerread",
    "authread",
    "policyread",
    "no_da",
    "orderly",
    "clear_stclear",
    "readlocked",
    "written",
    "platformcreate",
    "read_stclear",
]

nvm_predefined_index = ["0x1c00002", "0x1c0000a", "0x1c00016"]

tpm2_max_auth_fail = None
tpm2_lockout_interval = None
tpm2_lockout_recovery = None
client_log = None


class TPM:
    def __init__(
        self,
        nvm_index,
        owner_val,
        nvm_data,
        nv_auth_val,
        nvm_size,
        nvm_attr,
    ):
        self.nvm_index = nvm_index
        self.owner_val = owner_val
        self.nvm_data = nvm_data
        self.nv_auth_val = nv_auth_val
        self.nvm_attr = nvm_attr
        self.nvm_size = nvm_size
        self.nvm_offset = "0"
        self.rng_input = "16"
        self.Check_IFX_TPM()
        self.OnStart()

        self.OnGetCapVar()

    def OnClearAll(self):
        self.OnClear()
        self.OnChangeAuth()
        self.OnGetCapVar()

    def OnGetCapVar(self):
        command_output = exec_cmd.execTpmToolsAndCheck(
            [
                "tpm2_getcap",
                "properties-variable",
            ]
        )
        # print(str(command_output))
        print("'tpm2_getcap properties-variable' executed \n")
        print("++++++++++++++++++++++++++++++++++++++++++++\n")

    def OnStart(self):
        command_output = exec_cmd.execTpmToolsAndCheck(
            [
                "tpm2_startup",
                "-c",
            ]
        )
        print(str(command_output))
        print(("'tpm2_startup -c' executed \n"))

    def OnChangeAuth(self):
        command_output = exec_cmd.execTpmToolsAndCheck(
            [
                "tpm2_changeauth",
                "-c",
                "owner",
                exec_cmd.ownerAuth,
            ]
        )
        print(str(command_output))
        print("'tpm2_changeauth -c owner " + exec_cmd.ownerAuth + "' executed \n")
        if exec_cmd.endorseAuth != "":
            command_output = exec_cmd.execTpmToolsAndCheck(
                [
                    "tpm2_changeauth",
                    "-c",
                    "endorsement",
                    exec_cmd.endorseAuth,
                ]
            )
            print(str(command_output))
            print(
                "'tpm2_changeauth -c endorsement "
                + exec_cmd.endorseAuth
                + "' executed \n"
            )
        if exec_cmd.lockoutAuth != "":
            command_output = exec_cmd.execTpmToolsAndCheck(
                [
                    "tpm2_changeauth",
                    "-c",
                    "lockout",
                    exec_cmd.lockoutAuth,
                ]
            )

            print(str(command_output))
            print(
                "'tpm2_changeauth -c lockout " + exec_cmd.lockoutAuth + "' executed \n"
            )

    def Check_IFX_TPM(self):
        cmd = " ls /dev/tpm0"
        ps_command = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        command_output = ps_command.stdout.read()
        retcode = ps_command.wait()
        if command_output.decode() != "/dev/tpm0\n":
            print("device not found!")
            return

        cmd = " tpm2_getcap properties-fixed | grep -A2 'MANUFACTURER' | grep value | grep -Eo '[A-Z]*'"
        ps_command = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        command_output = ps_command.stdout.read()

        retcode = ps_command.wait()
        print(command_output.decode())

    def OnClear(self):
        command_output = exec_cmd.execTpmToolsAndCheck(["tpm2_clear", "-c", "p"])
        exec_cmd.createProcess("sudo rm *.tss", None)
        print(str(command_output))
        print("'tpm2_clear -c p' executed \n")
        print("++++++++++++++++++++++++++++++++++++++++++++\n")

    def OnGenRNG(self):
        rand_num = 0
        no_bytes = self.rng_input
        assert no_bytes.isdigit(), "Number of bytes is not an integer, try again."
        no_bytes = abs(int(no_bytes))
        print(no_bytes)
        # assuming output type is hex
        command_output = exec_cmd.execCLI(
            [
                "openssl",
                "rand",
                "-engine",
                "tpm2tss",
                "-hex",
                str(no_bytes),
            ]
        )
        split_output = command_output.split("\n")
        for value in split_output:
            if len(value.lower()) == no_bytes * 2:
                rand_num = value
                print("Random Number: " + rand_num + "\n")

        print("'openssl rand -engine tpm2tss -hex " + str(no_bytes) + "' executed \n")
        print("++++++++++++++++++++++++++++++++++++++++++++\n")
        return rand_num

    def OnNVDefine(self):

        assert self.nvm_size.isdigit(), "nvm_size must be an integer"
        assert int(self.nvm_size) <= 2048, "Maximum NVM size is 2048. Input Again.\n"
        nvm_size = int(self.nvm_size)
        nvm_attr = self.nvm_attr
        temp_attr = []
        for value in nvm_attr:
            temp_attr.append(value)
        if (self.nvm_index == 0) | (nvm_size == 0):
            return
        nvm_attr = "|".join(temp_attr)
        print("Attributes are: " + nvm_attr + "\n")
        # if (self.owner_input.GetValue()=="" and self.nv_auth_input.GetValue()==""):
        # self.right_txt_display.AppendText("Owner Authorisation and NV Authorisation Empty. Input Again.\n")
        # return

        # if NV field is empty
        if self.nv_auth_val == "":
            command_output = exec_cmd.execTpmToolsAndCheck(
                [
                    "tpm2_nvdefine",
                    self.nvm_index,
                    "-C",
                    "o",
                    "-s",
                    self.nvm_size,
                    "-a",
                    nvm_attr,
                    "-P",
                    self.owner_val,
                ]
            )

        # if NV field is specified
        elif self.nv_auth_val != "":
            command_output = exec_cmd.execTpmToolsAndCheck(
                [
                    "tpm2_nvdefine",
                    self.nvm_index,
                    "-C",
                    "o",
                    "-s",
                    self.nvm_size,
                    "-a",
                    nvm_attr,
                    "-P",
                    self.owner_val,
                    "-p",
                    self.nv_auth_val,
                ]
            )

        print(str(command_output))
        print("'tpm2_nvdefine' executed \n")
        print("++++++++++++++++++++++++++++++++++++++++++++\n")

    def OnNVWrite(self, json_str):
        nvm_index = self.nvm_index
        owner_val = self.owner_val
        nv_auth_val = self.nv_auth_val
        nvm_size = self.nvm_size
        nvm_attr = self.nvm_attr

        assert 0 < int(nvm_size) <= 2048, "Maximum NVM size is 2048. Input Again.\n"
        assert json_str != "", "JSON data is empty. Input Again.\n"

        temp_attr = []
        for value in nvm_attr:
            temp_attr.append(value)
        nvm_attr = "|".join(temp_attr)

        command_output = exec_cmd.execTpmToolsAndCheck(
            [
                "tpm2_nvdefine",
                nvm_index,
                "-C",
                "o",
                "-s",
                nvm_size,
                "-a",
                nvm_attr,
                "-P",
                owner_val,
                "-p",
                nv_auth_val,
            ]
        )

        # with open(self.binary_file, "r") as f:
        #     json_data = json.load(f)
        #     nvm_data = json.dumps(json_data)
        #     # print("before", sys.getsizeof(nvm_data))
        compressed_data = zlib.compress(json_str.encode())
        print("compressed data size:", sys.getsizeof(compressed_data))
        with open("nvm_data.gz", "wb") as f:
            f.write(compressed_data)
            f.close()

        # if NV auth field is empty
        command_output = exec_cmd.execTpmToolsAndCheck(
            [
                "tpm2_nvwrite",
                nvm_index,
                "-i",
                "nvm_data.gz",
                "-P",
                nv_auth_val,
            ]
        )

        print(str(command_output))
        print("'tpm2_nvwrite' executed \n")
        print("++++++++++++++++++++++++++++++++++++++++++++\n")

    def OnNVRelease(self):
        nvm_index = self.nvm_index
        owner_val = self.owner_val
        assert nvm_index != 0, "nvm_index cannot be 0"
        command_output = exec_cmd.execTpmToolsAndCheck(
            [
                "tpm2_nvundefine",
                "-C",
                "o",
                "-P",
                owner_val,
                nvm_index,
            ]
        )
        print(str(command_output))
        print("'tpm2_nvrelease' executed \n")

    def OnNVRead(self):
        print("++++++++++++++++++++++++++++++++++++++++++++\n")

        nvm_index = self.nvm_index
        nvm_size = self.nvm_size
        owner_val = self.owner_val
        nv_auth_val = self.nv_auth_val
        nvm_offset = self.nvm_offset
        read_size = 2048
        json_str = ""

        assert isinstance(nvm_size, str) and isinstance(
            nvm_offset, str
        ), "Offset or size is an invalid value (not an integer)."
        assert read_size > 0, "read size cannot be 0 or negative."
        command_output = exec_cmd.execTpmToolsAndCheck(
            [
                "tpm2_nvread",
                nvm_index,
                "-s",
                str(read_size),
                "-o",
                nvm_offset,
                "-P",
                nv_auth_val,
                "-o",
                "nvdata.gz",
            ]
        )
        print(str(command_output))
        with open("nvdata.gz", "rb") as f:
            compressed_data = f.read()
            json_str = zlib.decompress(compressed_data).decode()
            f.close()

        print("'tpm2_nvread' executed \n")
        print("++++++++++++++++++++++++++++++++++++++++++++\n")
        return json_str

    def OnNVList(self):
        exec_cmd.execTpmToolsAndCheck(
            [
                "tpm2_nvreadpublic",
            ]
        )
        print("'tpm2_nvreadpublic' executed")
        print("++++++++++++++++++++++++++++++++++++++++++++\n")

    def OnList(self):
        command_output = exec_cmd.execTpmToolsAndCheck(
            [
                "tpm2_getcap",
                "handles-persistent",
            ]
        )
        print(str(command_output))
        print("'tpm2_getcap handles-persistent' executed \n")
        print("++++++++++++++++++++++++++++++++++++++++++++\n")

    def OnCreatePrimary(self):
        if os.path.exists(os.path.join("./working_space", "RSAprimary.ctx")):
            exec_cmd.execTpmToolsAndCheck(["rm", "RSAprimary.ctx"])
        output_message = exec_cmd.execTpmToolsAndCheck(
            [
                "tpm2_createprimary",
                "-C",
                "o",
                "-P",
                exec_cmd.ownerAuth,
                "-g",
                "sha256",
                "-G",
                "rsa",
                "-c",
                "RSAprimary.ctx",
            ]
        )
        # print("first output :", str(output_message) + "\n")
        # self.Update()
        output_message = exec_cmd.execTpmToolsAndCheck(
            [
                "tpm2_evictcontrol",
                "-C",
                "o",
                "-c",
                "RSAprimary.ctx",
                "-P",
                exec_cmd.ownerAuth,
                "0x81000004",
            ]
        )
        # print("second output",str(output_message) + "\n")
        print(
            "tpm2_createprimary -C o -P "
            + exec_cmd.ownerAuth
            + " -g sha256 -G rsa -c RSAprimary.ctx\n"
        )
        print(
            "tpm2_evictcontrol -C o -c RSAprimary.ctx -P "
            + exec_cmd.ownerAuth
            + " 0x81000004\n"
        )
        print("++++++++++++++++++++++++++++++++++++++++++++\n")

    def OnEvict(self, handle):
        specific_handle = handle
        command_output = exec_cmd.execTpmToolsAndCheck(
            [
                "tpm2_evictcontrol",
                "-C",
                "o",
                "-c",
                specific_handle,
                "-P",
                exec_cmd.ownerAuth,
            ]
        )
        print(
            "'tpm2_evictcontrol -C o -c "
            + specific_handle
            + " -P "
            + exec_cmd.ownerAuth
            + "' executed \n"
        )
        print("++++++++++++++++++++++++++++++++++++++++++++\n")

    def OnGenKeyPair(self, privKey, pubKey):
        assert exec_cmd.ownerAuth != "", "Owner password is not set"
        file_names = [
            privKey,
            pubKey,
        ]

        # Iterate over the list of file names
        for file_name in file_names:
            file_path = os.path.join('"./working_space"', file_name)
            if os.path.exists(file_path):
                exec_cmd.execTpmToolsAndCheck(["rm", file_name])
        command_output = exec_cmd.execCLI(
            [
                "tpm2tss-genkey",
                "-o",
                exec_cmd.ownerAuth,
                "-a",
                "rsa",
                privKey,
            ]
        )
        print(str(command_output))
        command_output = exec_cmd.execCLI(
            [
                "openssl",
                "rsa",
                "-engine",
                "tpm2tss",
                "-inform",
                "engine",
                "-in",
                privKey,
                "-pubout",
                "-outform",
                "pem",
                "-out",
                pubKey,
            ]
        )
        print(str(command_output))
        pubKey_str = ""
        with open(pubKey) as f:
            pubKey_str = f.read()
            f.close()
        print(pubKey_str)
        print("++++++++++++++++++++++++++++++++++++++++++++\n")
        return pubKey_str

    def OnEnc(self, privKey, input_data, encryped_file):
        assert input_data != "", "Input data can not be empty"
        data_file = open("engine_data.txt", "w")
        data_file.write(input_data)
        data_file.close()
        command_output = exec_cmd.execCLI(
            [
                "openssl",
                "pkeyutl",
                "-prvin",
                "-inkey",
                privKey,
                "-in",
                "engine_data.txt",
                "-encrypt",
                "-out",
                encryped_file,
            ]
        )
        print(command_output)
        command_output = exec_cmd.execCLI(
            [
                "xxd",
                encryped_file,
            ]
        )
        print(command_output)
        print("++++++++++++++++++++++++++++++++++++++++++++\n")

    def OnDec(self):
        f = open("temp.conf", "w+")
        f.write(exec_cmd.openssl_cnf)
        f.close()

        cmd = "OPENSSL_CONF=temp.conf openssl pkeyutl -engine tpm2tss -keyform engine -inkey rsa2.tss -decrypt -in mycipher"
        ps_command = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        command_output = ps_command.stdout.read()
        retcode = ps_command.wait()

        print(str(command_output.decode()))
        print(
            "OPENSSL_CONF=temp.conf openssl pkeyutl -engine tpm2tss -keyform engine -inkey rsa2.tss -decrypt -in mycipher' executed \n"
        )
        print("++++++++++++++++++++++++++++++++++++++++++++\n")
        return command_output.decode()

    def OnSign(self, prevKey, input_data):
        assert input_data != "", "Input data can not be empty"
        data_file = open("engine_data.txt", "w")
        data_file.write(input_data)
        data_file.close()
        # ~ exec_cmd.execCLI([
        # ~ "openssl", "pkeyutl",
        # ~ "-engine", "tpm2tss",
        # ~ "-keyform", "engine",
        # ~ "-inkey", "rsa2.tss",
        # ~ "-in", "engine_data.txt",
        # ~ "-sign",
        # ~ "-out", "mysig",
        # ~ ])

        f = open("temp.conf", "w+")
        f.write(exec_cmd.openssl_cnf)
        f.close()

        # cmd = f"OPENSSL_CONF=temp.conf openssl pkeyutl -engine tpm2tss -keyform engine -inkey {prevKey} -sign -in engine_data.txt -out mysign"
        cmd = f"OPENSSL_CONF=temp.conf openssl pkeyutl -engine tpm2tss -keyform engine -inkey {prevKey} -sign -in engine_data.txt"
        ps_command = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        command_output = ps_command.stdout.read()
        retcode = ps_command.wait()

        print(cmd + " executed")
        # print("mysign contains:")
        # command_output = exec_cmd.execCLI(
        #     [
        #         "xxd",
        #         "mysign",
        #     ]
        # )
        with open("mysign", "rb") as f:
            sign = f.read()
        encoded_sign = base64.b64encode(sign)
        # print(encoded_data)
        # print("command output::", command_output)
        print("++++++++++++++++++++++++++++++++++++++++++++\n")
        return encoded_sign

    def OnVerify(self, data_to_verify, signature, publickey):
        assert data_to_verify != "", "Input data can not be empty"
        data_file = open("engine_data.txt", "w")
        data_file.write(data_to_verify)
        data_file.close()
        with open("mysig", "wb") as f:
            f.write(base64.b64decode(signature))

        command_output = exec_cmd.execCLI(
            [
                "openssl",
                "pkeyutl",
                "-pubin",
                "-inkey",
                publickey,
                "-verify",
                "-in",
                "engine_data.txt",
                "-sigfile",
                "mysig",
            ]
        )
        print(str(command_output))
        # print(type(command_output))
        # print("'openssl pkeyutl -pubin -inkey rsa2.pub -verify -in engine_data.txt -sigfile mysig' executed \n")
        print("++++++++++++++++++++++++++++++++++++++++++++\n")


if __name__ == "__main__":
    exec_cmd.checkDir()
    tpm = TPM(
        nvm_index="0x1500016",
        owner_val="owner123",
        nvm_data="",
        nv_auth_val="nv123",
        nvm_size="2048",
        nvm_attr=["authread", "authwrite"],
    )
    # tpm.OnNVList() #---- done
    # tpm.OnGenRNG() #---- done
    # tpm.OnNVDefine() #--- done
    # tpm.OnNVWrite("test1234567")  # --- done
    # tpm.OnNVRead()  # --- done
    # tpm.OnCreatePrimary() # --- done
    # tpm.OnGenKeyPair(
    #     "/home/pi/optiga-tpm-explorer/test/rsa2.tss",
    #     "/home/pi/optiga-tpm-explorer/test/rsa2.pub",
    # )  # --- done
    # signature = tpm.OnSign("/home/pi/optiga-tpm-explorer/test/rsa2.tss", "test1234")
    # tpm.OnVerify("test1234", signature, "/home/pi/optiga-tpm-explorer/test/rsa2.pub")
