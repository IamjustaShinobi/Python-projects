# Number of rows in the pyramid
n = 5

# Loop through each row
for i in range(1, n + 1):
    # Print leading spaces, then print the stars separated by a space
    print(" " * (n - i) + "* " * i)
