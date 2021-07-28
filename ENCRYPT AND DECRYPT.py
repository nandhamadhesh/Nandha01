from tkinter import *
import os
import random 
import time 
import datetime
from tkinter import messagebox

###--------------------------------------------------------------------------------------------------------------------------------------------------------------------###
###++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ FIRST FUNCTION CAESAR CIPHER  +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++###
###--------------------------------------------------------------------------------------------------------------------------------------------------------------------###

def outputter(ciphertext):
   user_entry.insert(END, ciphertext)

def encrypt():
    user_entry.delete(0, END)
    plaintext = variable.get()
    key = 4
    plaintext = list(plaintext)
    alphabet = list('abcdefghijklmnopqrstuvwxyz')
    cipher = []
    for c in plaintext:
        if c in alphabet:
            new_pos = int(alphabet.index(c) + key)
            if new_pos > 25:
                new_pos = new_pos - 26
            c_new = list('abcdefghijklmnopqrstuvwxyz').pop(new_pos)
            cipher.append(c_new)
            ciphertext = ''.join(cipher)
    outputter(ciphertext)

def decrypt():
	user_entry.delete(0, END)
	plaintext = variable.get()
	key = 4
	plaintext = list(plaintext)
	alphabet = list('abcdefghijklmnopqrstuvwxyz')
	cipher = []
	for c in plaintext:
		if c in alphabet:
			new_pos = int(alphabet.index(c) - key)
			if new_pos > 25:
				new_pos = new_pos - 26			
			c_new = list('abcdefghijklmnopqrstuvwxyz').pop(new_pos)
			cipher.append(c_new)
			ciphertext = ''.join(cipher)
	outputter(ciphertext)
           

def Caesar_Ciper():
    global screen1
    screen1 = Toplevel(screen)
    screen1.title("Cisear ciper")
    screen1.geometry("1200x6000")
    entry = Entry(screen1)

    global variable
    global plaintext
    global user_entry
    
    variable = StringVar()
    variable2 = IntVar()
    
    Label(screen1, text = "CAESAR_CIPER ENCRYPT AND DECRYPT MESSAGES",font = ('arial', 30, 'bold'), bd = 20 ,fg = "red", bg = "black").pack()
    Label(screen1, text = " ").pack()
    Label(screen1, text = "Message:",font = ('arial', 16, 'bold'), bd = 16).pack()
    plaintext = Entry(screen1, font = ('arial', 16, 'bold'), textvariable = variable, bd = 10, insertwidth = 4, bg = "blue", justify = 'left')
    plaintext.pack()
    Label(screen1, text = " ").pack()
    Label(screen1, text = "OutPut:",font = ('arial', 16, 'bold'), bd = 16,).pack()
    user_entry = Entry(screen1, font = ('arial', 16, 'bold'), textvariable = entry, bd = 10, insertwidth = 4, bg = "blue", justify = 'left')
    user_entry.pack()
    Label(screen1, text = " ").pack()
    Label(screen1, text = " ").pack()
    Label(screen1, text = " ").pack()
    Button(screen1,padx = 16, pady = 8, bd = 16,font = ("Rockwell"), text = "Encrypt", width = 30, height = 2, fg = "black", bg = "light blue", command = encrypt).pack()
    Label(screen1, text = " ").pack()
    Button(screen1,padx = 16, pady = 8, bd = 16,font = ("Rockwell"), text = "Decrypt", width = 30, height = 2, fg ="black", bg = "light blue", command = decrypt).pack()

###=====================================================================================================================================================================###
###.........................................................   SECOND FUNCTION  ALPHABET REVERCE CIPHER  ...............................................................###    
###=====================================================================================================================================================================###

def outputter1(ciphertext):
	user_entry1.insert(END, ciphertext)

def encrypt1():
	user_entry1.delete(0, END)
	plaintext1 = variable1.get()
	key = 5
	plaintext1 = list(plaintext1)
	alphabet = list('abcdefghijklmnopqrstuvwxyz')
	cipher = []
	for c in plaintext1:
		if c in alphabet:
			new_pos = int(alphabet.index(c) + key)
			if new_pos > 25:
				new_pos = new_pos - 26			
			c_new = list('zyxwvutsrqponmlkjihgfedcba').pop(new_pos)
			cipher.append(c_new)
			ciphertext = ''.join(cipher)
	outputter1(ciphertext)

def decrypt1():
	user_entry1.delete(0, END)
	plaintext1 = variable1.get()
	key = 5
	plaintext1 = list(plaintext1)
	alphabet = list('zyxwvutsrqponmlkjihgfedcba')
	cipher = []
	for c in plaintext1:
		if c in alphabet:
			new_pos = int(alphabet.index(c) - key)
			if new_pos > 25:
				new_pos = new_pos - 26			
			c_new = list('abcdefghijklmnopqrstuvwxyz').pop(new_pos)
			cipher.append(c_new)
			ciphertext = ''.join(cipher)
	outputter1(ciphertext)
	

def AR_Msg():
    global screen2
    screen2 = Toplevel(screen)
    screen2.title("AR Msg")
    screen2.geometry("1200x6000")
    entry = Entry(screen2)
    
    global variable1
    global plaintext1
    global user_entry1

    variable1 = StringVar()
    variable2 = IntVar()
    

    Label(screen2, text = "ALPHABET REVERCE_CIPER ENCRYPT AND DECRYPT MESSAGES",font = ('arial', 25, 'bold'), bd = 20 ,fg = "red", bg = "black").pack()
    Label(screen2, text = " ").pack()
    Label(screen2, text = "Message:",font = ('arial', 16, 'bold'), bd = 16).pack()
    plaintext1 = Entry(screen2, font = ('arial', 16, 'bold'), textvariable = variable1, bd = 10, insertwidth = 4, bg = "blue", justify = 'left')
    plaintext1.pack()
    Label(screen2, text = " ").pack()
    Label(screen2, text = "OutPut:",font = ('arial', 16, 'bold'), bd = 16,).pack()
    user_entry1 = Entry(screen2, font = ('arial', 16, 'bold'), textvariable = entry, bd = 10, insertwidth = 4, bg = "blue", justify = 'left')
    user_entry1.pack()
    Label(screen2, text = " ").pack()
    Label(screen2, text = " ").pack()
    Label(screen2, text = " ").pack()
    Button(screen2,padx = 16, pady = 8, bd = 16,font = ("Rockwell"), text = "Encrypt", width = 30, height = 2, fg = "black", bg = "light blue", command = encrypt1).pack()
    Label(screen2, text = " ").pack()
    Button(screen2,padx = 16, pady = 8, bd = 16,font = ("Rockwell"), text = "Decrypt", width = 30, height = 2, fg ="black", bg = "light blue", command = decrypt1).pack()
    
###**********************************************************************************************************************************************************************###
###>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>  THIRD  FUNCTION VIGENERE CIPHER  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<###    
###**********************************************************************************************************************************************************************###    
    
def Vigenere_cipher():
   global screen3
   screen3 = Toplevel(screen)
   screen3.title("ver")
   screen3.geometry("1200x6000")
   entry = Entry(screen3)
   global Msg
   global key
   global mode
   global Result

   Tops = Frame(screen3, width = 1600, relief = SUNKEN) 
   Tops.pack(side = TOP) 
  
   f1 = Frame(screen3, width = 800, height = 700, 
                            relief = SUNKEN) 
   f1.pack(side = LEFT) 
  
# ============================================== 
#                  TIME 
# ============================================== 
   localtime = time.asctime(time.localtime(time.time())) 
  
   lblInfo = Label(Tops, font = ('helvetica', 50, 'bold'), 
          text = "Vigenère_cipher Encrypt and decrypt Messages", 
                     fg = "red", bg = "black", bd = 10, anchor='w') 
                       
   lblInfo.grid(row = 0, column = 0) 
  
   lblInfo = Label(Tops, font=('arial', 20, 'bold'), 
             text = localtime, fg = "green", 
                           bd = 10, anchor = 'w') 
                          
   lblInfo.grid(row = 1, column = 0) 
      
   Msg = StringVar() 
   key = StringVar() 
   mode = StringVar() 
   Result = StringVar() 

# labels 
   lblMsg = Label(f1, font = ('arial', 16, 'bold'), 
         text = "MESSAGE", bd = 16, anchor = "w") 
           
   lblMsg.grid(row = 1, column = 0) 
  
   txtMsg = Entry(f1, font = ('arial', 16, 'bold'), 
         textvariable = Msg, bd = 10, insertwidth = 4, 
                bg = "powder blue", justify = 'right') 
                  
   txtMsg.grid(row = 1, column = 1) 
  
   lblkey = Label(f1, font = ('arial', 16, 'bold'), 
           text = "KEY", bd = 16, anchor = "w") 
              
   lblkey.grid(row = 2, column = 0) 
  
   txtkey = Entry(f1, font = ('arial', 16, 'bold'), 
         textvariable = key, bd = 10, insertwidth = 4, 
                bg = "powder blue", justify = 'right') 
                  
   txtkey.grid(row = 2, column = 1) 
  
   lblmode = Label(f1, font = ('arial', 16, 'bold'), 
          text = "MODE(e for encrypt, d for decrypt)", 
                                bd = 16, anchor = "w") 
                                  
   lblmode.grid(row = 3, column = 0) 
  
   txtmode = Entry(f1, font = ('arial', 16, 'bold'), 
          textvariable = mode, bd = 10, insertwidth = 4, 
                  bg = "powder blue", justify = 'right') 
                    
   txtmode.grid(row = 3, column = 1) 
  
   lblService = Label(f1, font = ('arial', 16, 'bold'), 
             text = "The Result-", bd = 16, anchor = "w") 
               
   lblService.grid(row = 2, column = 2) 
  
   txtService = Entry(f1, font = ('arial', 16, 'bold'),  
             textvariable = Result, bd = 10, insertwidth = 4, 
                       bg = "powder blue", justify = 'right') 
    
   txtService.grid(row = 2, column = 3)
# Show message button 
   btnTotal = Button(f1, padx = 16, pady = 8, bd = 16, fg = "black", 
                        font = ('arial', 16, 'bold'), width = 10, 
                       text = "Show Message", bg = "powder blue", 
                         command = Ref).grid(row = 7, column = 1) 
  
# Reset button 
   btnReset = Button(f1, padx = 16, pady = 8, bd = 16, 
                  fg = "black", font = ('arial', 16, 'bold'), 
                    width = 10, text = "Reset", bg = "green", 
                   command = Reset).grid(row = 7, column = 2) 
  
# Exit button 
   btnExit = Button(f1, padx = 16, pady = 8, bd = 16,  
                 fg = "black", font = ('arial', 16, 'bold'), 
                      width = 10, text = "Exit", bg = "red", 
                  command = qExit).grid(row = 7, column = 3)

# exit function 
def qExit(): 
   screen3.destroy() 
  
# Function to reset the window 
def Reset():  
   Msg.set("") 
   key.set("") 
   mode.set("") 
   Result.set("")    
    
# Vigenère cipher 
import base64 
  
# Function to encode 
def encode(key, clear): 
    enc = [] 
      
    for i in range(len(clear)): 
        key_c1 = key[i % len(key)] 
        enc_c = chr((ord(clear[i]) +
                     ord(key_c1)) % 256) 
                       
        enc.append(enc_c) 
          
    return base64.urlsafe_b64encode("".join(enc).encode()).decode() 
  
# Function to decode 
def decode(key, enc): 
    dec = [] 
      
    enc = base64.urlsafe_b64decode(enc).decode() 
    for i in range(len(enc)): 
        key_c = key[i % len(key)] 
        dec_c = chr((256 + ord(enc[i]) -
                           ord(key_c)) % 256) 
                             
        dec.append(dec_c)
        
    if(key_c == key_c):
        return "".join(dec) 
    else:
        messagebox.showinfo("invalid key...")
      
  
def Ref(): 
    clear = Msg.get() 
    k = key.get() 
    m = mode.get() 

    if(m == 'e'):
       
        if('e'):
          Result.set(encode(k,clear))
          
        else:
          messagebox.showinfo("invalid")
    if(m == 'd'):
       
        if('d'):
          Result.set(decode(k,clear))
          
        else:
          messagebox.showinfo("invalid")
    
###:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::###
###xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx  MAIN FUNCTION  xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx###      
###:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::###        
        

def main_screen():
    global screen
    screen = Tk()
    screen.geometry("1200x6000")
    screen.title("e and d messages")
    Label(text = "ENCRYPTION AND DECRYPTION MESSAGES", bg = "blue", width = 300, height = 1, font = ("Rockwell", 35, 'bold'), bd  =20).pack()
    Label(text = "").pack()
    Label(text = "").pack()
    Label(text = "").pack()
    Button(padx = 20, pady = 10, bd = 16, font = ("Rockwell", 15, 'bold'), text = "Caesar Ciper", width = 30, height = 2, bg = "light blue", command = Caesar_Ciper).pack()
    Label(text = "").pack()
    Label(text = "").pack()
    Button(padx = 20, pady = 10, bd = 16, font = ("Rockwell", 15, 'bold'), text = "AR Msg", width = 30, height = 2, bg = "light blue", command = AR_Msg).pack()
    Label(text = "").pack()
    Label(text = "").pack()
    Button(padx = 20, pady = 10, bd = 16, font = ("Rockwell", 15, 'bold'), text = "Vigenere cipher", width = 30, height = 2, bg = "light blue", command = Vigenere_cipher).pack()


    screen.mainloop()

main_screen()


    
