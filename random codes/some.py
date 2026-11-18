stack = []                      # empty list acts as stack

def push(x):
    stack.append(x)             # add at top
    print(stack)

def pop():
    if stack:                   # check stack is not empty
        stack.pop()             # remove from top
    else:
        print("Empty")
    print(stack)

def peek():
    if stack:
        print("Top:", stack[-1])   # last element = top (not removed)
    else:
        print("Empty")


push(1)
push(2)
push(10)
push(20)    
peek()
pop()