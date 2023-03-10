import os

data = ""
with open(os.path.join("./working_space", "data_encrypted.txt"), "rb") as f:
    data = f.read()
# print(data)
print(type(data))
print(" ".join(hex(n) for n in data))
