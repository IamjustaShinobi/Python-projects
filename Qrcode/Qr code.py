import qrcode
url = input("Enter the url : ").strip()
file_path = "E:\Coding\Python\Python-projects\Qrcode\qrcode.png"

qr = qrcode.QRCode()
qr.add_data(url)

img = qr.make_image()
img.save(file_path)

print ('The image was created Successfully')