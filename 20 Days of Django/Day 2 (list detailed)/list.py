list1= [1,2,3,4,5]
list2 = ["banana" , "shabana" ,"Sultana" , "sharmana" , "bombaclat"]
list1.extend(list2)
print(list1)

list2.append('tun tun tun Sahor')
print(list2)
print(len(list2))

list1.insert(2, 200)
print(list1)

list1.remove(200) # this delete only index
list2.clear()

list3= [3,23,423,42,42,3423,424,23,34,534,5,6,7,7,4,7,12312,323,45256,3467,478]
list3.sort()
print(list3)

list4 = list3.copy()

del list4  # this delete the variable