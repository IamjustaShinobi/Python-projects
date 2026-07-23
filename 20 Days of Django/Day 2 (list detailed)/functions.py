# we use def to define a function 
def say_chocho(name):
    print("oi choco",name)

say_chocho('yoyo')


# if we dont know the number of arguments in the funtion we add asteric , it is a tuple
def say_chocho(*name):
    print("oi choco",name)

say_chocho('yoyo' , 'koko' , 'lolo')
# now by adding astric it makes it a tuple
