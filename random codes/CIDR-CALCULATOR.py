print("------------CIDR-----------")


num = int(input("Give me the CIDR number i will calculate its host ips : "))

ror = 32 - num 
ips = (2 ** ror) - 2


if 0 < num < 32:
    print(f"The total host ips are : {ips}")
else:
    print("Please enter a CIDR between 1 and 31.")
