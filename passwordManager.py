#used for encryption:
import base64
from platform import uname
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
#used for hashing:
from passlib.context import CryptContext
#used for obscuring inputs
from getpass import getpass
#used to create callback functions:
from threading import Timer
#used to generate passwords:
import string
import secrets
#used to edit the clipboard:
from pyperclip import copy
#used to get current directory:
import os

#----------------------Hashing and cryptography functions----------------------#

#This hashing function is used to hash plain text and compare hashes
def hasher(mode, plainText, hashedPassword=None):
    # create CryptContext object with the correct algorithm set
    context = CryptContext(
            schemes=["pbkdf2_sha256"],
            default="pbkdf2_sha256",
            pbkdf2_sha256__default_rounds=100000
    )
    if mode == 'hash':
        return context.hash(plainText)
    elif mode == 'check':
        return context.verify(plainText, hashedPassword)

#generate key uses a key derivative function to generate a cryotographic key based on a given string
def generateKey(master):
    #salt is a random set of characters used to secure the key when it is being created
    salt = b'H\x1d\tMg\xc9\xe3\xec\xbeU\xee\x03\xec\x18\xf1U'
    #kdf stands for key derivative function
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    ) 
    #return the cryptographic function
    return base64.urlsafe_b64encode(kdf.derive(master.encode()))

#----------------------Ui functions----------------------#
#These functions are used primeraly to keep the main() function looking clean

#I wanted to separate this print statement
def welcomeMessage():
    print(
'''
__________________________________

    Micheal's Password Manager
__________________________________
''')

#This function just recieves the user choice
def mainMenu():
    selection = input(
'''Please select one of the following program functions:
1 - Get a list of all services for which there is stored username and password
2 - Save a new service's username and password 
3 - Delete a saved service's username and password 
4 - Change master password
5 - Change login timeout duration
6 - Fetch a service's username and password
7 - Close program
Type your selection here: ''')
    return selection

#This function gets a list of all stored services and prints out the titles
def showServiceList():
    print('List of stored services: ')
    #we only need titles, so we can get the keys from the dictionary that getStoredData() returns
    storedServices = getStoredData().keys() 
    for service in storedServices:
        #as master and time store are also stored in the file we want to filter these titles out
        if service != 'Master' and service != 'TimerStore':
            print(f' - {service}')

#----------------------Utility functions----------------------#

#this function reads userData and returns a dictionary in the form {'title': 'username|encryptedPassword'}
def getStoredData():
    directory = os.path.dirname(os.path.realpath(__file__))
    file = open(directory +'/userData.txt', 'r')
    dataDictionary = {}
    for line in file:
        #each line is in the form: 'title username|encryptedDassword' .split() splits the string wherever there is a space:' ' 
        if len(line.strip()) != 0:
            key, value = line.split()
            dataDictionary[key] = value
    #return the dictionary
    return dataDictionary

#----------------------Call back functions----------------------#
#These are functions that are executed a set amount of time after then are called. 

#simple function that adds an item to the given array
def passwordTimeout(timeoutMessage):
    timeoutMessage.append('timeoutReached')

#this just empties the clipboard
def clipboardTimeout():
    copy('')

#----------------------Main program functions----------------------#

#function to check a user's master password 
def logOn():
    #getpass() works like input() but the user can not see what they are typing
    userInput = getpass(prompt='Please enter the master password (characters typed will be hidden): ')
    #get the stored hash of the master password 
    storedHash = getStoredData()['Master']
    #return the comparison of the hases of the master password and the user input.
    #also return the encryption key generated from the user input
    return hasher('check', userInput, storedHash), generateKey(userInput)
        
#Change master key allows the user to change the master password
def changeMasterKey(timeoutMessage, encryptionKey):
    #make the user enter the password twice to ensure they have entered the new password correctly
    userInput = getpass(prompt='Please enter the new master password: ')
    checkUserInput = getpass(prompt='Please re-enter the new master password: ')
    #first check that the user has not timed out in the time it took them to type the new password
    if len(timeoutMessage) > 0:
        print('Error: Your session has timed out, you will need to log in again')
        return 'timeout'
    #if the two passwords match then update the stored hash of the master key, and re-encrypt all passwords
    elif userInput == checkUserInput:
        #get the dictionary of stored data
        storedData = getStoredData()
        #update this dictionary with the new master password hash.
        storedData['Master'] = hasher('hash', userInput)
        #re-encrypt all passwords:
        newEncryptionKey = generateKey(userInput)
        fernetOldKey = Fernet(encryptionKey)
        fernetNewKey = Fernet(newEncryptionKey)
        for title in storedData.keys():
            if title != 'Master' and title != 'TimerStore':
                username, encryptedPassword = storedData[title].split('|')
                decryptedPassword =  fernetOldKey.decrypt(encryptedPassword.encode())
                newEncryptedPassword = fernetNewKey.encrypt(decryptedPassword).decode()
                storedData[title] = f'{username}|{newEncryptedPassword}'
        #overwrite the userData.txt file with the update dictionary 
        directory = os.path.dirname(os.path.realpath(__file__))
        with open(directory + '/userData.txt', 'w') as file:
            for key in storedData.keys():
                print(f'{key} {storedData[key]}\n', file=file)
        print('Master password successfully changed!')
        return newEncryptionKey
    #if the passwords do not match return the user to the main menu
    else:
        print('Error: Those passwords did not match')
        return None

#save new service allows the user to add usernames and passwords to the system
def saveNewService(timeoutMessage, encryptionKey):
    #first get the titles of all stored services
    storedServices = getStoredData().keys()
    #create a loop for the user entering the title, that they can only leave if they timeout or they enter a unique title name
    newServiceLoop = True
    while newServiceLoop:
        title = input('Please input the title of the new service you are adding: ')
        #check that the user has not timed out
        if len(timeoutMessage) > 0:
            print('Error: Your session has timed out, you will need to log in again')
            return 'timeout'
        #check that the user's entered title is not already stored
        elif title in storedServices:
            print('Error: this service already exists')
        else:
            #break the loop if the title is unique
            newServiceLoop = False
    #create a loop for the username entry
    newUsernameLoop = True
    while newUsernameLoop:
        username = input(f'Please input your username for {title}: ')
        #first check that the user has not timed out
        if len(timeoutMessage) > 0:
            print('Error: Your session has timed out, you will need to log in again')
            return 'timeout'
        #check with the user that they are happy with the username that they have entered
        confirm = input(f'Please confirm {username} is the correct username (y/n): ')
        #check the user has not timed out
        if len(timeoutMessage) > 0:
            print('Error: Your session has timed out, you will need to log in again')
            return 'timeout'
        #then chec if the user has confirmed and if they have break out of the loop
        elif confirm == 'y':
            print('Username confirmed!')
            newUsernameLoop = False
        else:
            print('Username confrim cancelled!')
    #create a loop for password type choice 
    passwordChoiceLoop = True
    while passwordChoiceLoop:
        #first check whether the user wants to enter their own password or generate a password
        generationChoice = input('Would you like your password generated by the program? (y/n): ')
        #check whether the user has timed out
        if len(timeoutMessage) > 0:
            print('Error: Your session has timed out, you will need to log in again')
            return 'timeout'
        #break the loop if they have given a recognised responce
        elif generationChoice == 'y':
            print('Generate password selected')
            passwordChoiceLoop = False
        elif generationChoice == 'n':
            print('Create own password selected')
            passwordChoiceLoop = False
        #remain in the loop if it was not a vlaid responce
        else:
            print(f'"{generationChoice}" is not a valid answer')
    #create a loop for password creation
    newPasswordLoop = True
    while newPasswordLoop:
        if generationChoice == 'n':
            #if the user selects to enter their own password then they must enter the same password twice
            password = getpass(prompt=f'Please enter the password for {title}: ')
            checkPassword = getpass(prompt=f'Please re-enter the password for {title}: ')
            #check that the user has not timed out
            if len(timeoutMessage) > 0:
                print('Error: Your session has timed out, you will need to log in again')
                return 'timeout'
            #break the loop only if the passwords match
            elif password == checkPassword:
                newPasswordLoop = False
                print('Password Confirmed!')
            else:
                print('Error: Those passwords did not match')
        elif generationChoice == 'y':
            #first create a string with all possible characters for use in the password
            alphabet = string.ascii_letters + string.digits + '@._()!'
            #select 32 random characters from the alphabet  to be used in the password 
            password = ''.join(secrets.choice(alphabet) for _ in range(32))
            print('Your password has been generated!')
            newPasswordLoop = False
    #after getting the password, either by generating it or getting it from the user, it needs to be encrypted 
    #create a fernet object with the encryption key we generated earlier 
    fernet = Fernet(encryptionKey)
    #encrypt the password using fernet
    #.encode() and .decode() here are pyton functions used so that fernet can work with the password string
    encryptedPassword = fernet.encrypt(password.encode()).decode()
    #Combine title, username and encrypted password into a string and save it in the userData file
    directory = os.path.dirname(os.path.realpath(__file__))
    with open(directory + '/userData.txt', 'a') as file:
        print(f'{title} {username}|{encryptedPassword}\n', file=file)
    print('Password encrypted, and new service saved to local storage!')
    print('You will now be taken back to the main menu')

#This function allows the user to change the login timeout duration
def changeLoginTimout(timeoutTimer, timeoutMessage):
    #first create a loop
    timeoutChoice = True
    while timeoutChoice:
        #then get the duration in minutes that the user would like the timeout time to be 
        newTimeout = input('Please type the number of minutes you would like the logout timer to be: ')
        #check if the user has timed out
        if len(timeoutMessage) > 0:
            print('Error: Your session has timed out, you will need to log in again')
            return 'timeout'
        #now check that the user has input an integer value
        isInteger = False
        try:
            newTimeout = int(newTimeout)
            isInteger = True
        except:
            print('You must enter an integer!')
        if isInteger:
            #if they have checked an integer, check that the timeout is between 5 minutes and 3 hours
            if newTimeout < 5 or newTimeout > 180:
                print('Please pick a time between 5 and 180 minutes.')
            else:
                #if they have given a valid input clear the old timer and create the new one
                timeoutTimer.cancel()
                timeoutMessage = []
                #update the local storage to reflect the change of the timeout duration
                storedData = getStoredData()
                storedData['TimerStore'] = newTimeout
                directory = os.path.dirname(os.path.realpath(__file__))
                with open(directory + '/userData.txt', 'w') as file:
                    for key in storedData.keys():
                        print(f'{key} {storedData[key]}\n', file=file)
                print('Timeout duration changed!')
                #finaly return the new timeout object while also calling it
                return Timer(newTimeout*60, lambda: passwordTimeout(timeoutMessage))

#this function allows the user to delete a stored service 
def deleteService(timeoutMessage):
    #first show the user the services to choose from 
    showServiceList()
    choice = input('Please enter the title of the service you want to remove: ')
    #check that the user has not timed out
    if len(timeoutMessage) > 0:
        print('Error: Your session has timed out, you will need to log in again')
        return 'timeout'
    #load all of the service titles into a list
    storedData = getStoredData()
    storedTitles = [key for key in storedData.keys() if key != 'Master' and key !='TimerStore']
    #check if the users choice is in the list of titles
    if choice in storedTitles:
        #if the choice is found in the list remove it from the dictionary 
        storedData.pop(choice)
        storedTitles.pop(storedTitles.index(choice))
        #then overwite the userData.txt file with the updated data 
        directory = os.path.dirname(os.path.realpath(__file__))
        with open(directory + '/userData.txt', 'w') as file:
            for key in storedData.keys():
                if key != choice:
                    print(f'{key} {storedData[key]}\n', file=file)
        print(f'{choice} has been removed from the system')
    else:
        #if the user did not enter a valid input then return them to the main menu 
        print(f'{choice} is not an option, you will now be taken to the main menu')

#this function allows the user to retrieve usernames and passwords
def fetchServiceDetails(timeoutMessage, encryptionKey):
    #first show the user what they have to choose from
    showServiceList()
    #then get the user's choice
    choice = input('Please enter the title of the service you want to view: ')
    #check that they have not timed out
    if len(timeoutMessage) > 0:
        print('Error: Your session has timed out, you will need to log in again')
        return 'timeout'
    #get a list of all the titles the user can choose from
    storedData = getStoredData()
    storedTitles = [key for key in storedData.keys() if key != 'Master' and key !='TimerStore']
    if choice in storedTitles:
        #split the username and password up by using the fact that they are separated by a '|'
        username, encryptedPassword = storedData[choice].split('|')
        #create a fernet object with the encryption key derived from the master key
        fernet = Fernet(encryptionKey)
        #decrypt the password using the fernet object
        decryptedPassword =  fernet.decrypt(encryptedPassword.encode()).decode()
        #copy the decrypted password to the clipboard
        copy(decryptedPassword)
        #set the clipboard to clear in 60 seconds
        clipboardTimer = Timer(60,  clipboardTimeout)
        clipboardTimer.start()
        #inform the user of the usename of the chosen service and also that the password will be in their clipbaord for the next miute
        print(f'Your username for {choice} is: {username}, and your password has been coppied to the clipboard where it will remain for 1 minute.')
        return clipboardTimer
    else:
        #if their choice was not valid inform them and take them back to the main menu
        print(f'{choice} is not an option, you will now be taken to the main menu')
        return None
    
#Main function:
def main():
    #the welcome message should only be shown once so call it outside of the 'running' loop
    welcomeMessage()
    clipboardUsed = False
    running = True
    while running:
        #The user will be stuck in the log on loop until the enter the correct master password
        logOnLoop = True
        while logOnLoop:
            valid, encryptionKey = logOn()
            if valid:
                logOnLoop = False
                print('Welcome Back!')
            else:
                print('Error: That is not the correct password')
        #the stored timeout is stored locally as the user can edit the duration
        storedTimeout = int(getStoredData()['TimerStore'])*60
        timeoutMessage = []
        #timer will run passwordTimeout(timeoutMessage) after a duration of storedTimeout
        #lambda allows me to parse arguments to the given function without it running
        timeoutTimer = Timer(storedTimeout, lambda: passwordTimeout(timeoutMessage))
        timeoutTimer.start()
        #main loop will keep the user returning to he main menu until they timeout or choose to close the program
        mainLoop = True
        while mainLoop:
            #get the users choice
            selection = mainMenu()
            #if the user has not timed out yet, run the selected function
            #timeout message only needs to be passed to functions where user makes a choice
            if selection == '1' and len(timeoutMessage) == 0:
                showServiceList()
            elif selection == '2' and len(timeoutMessage) == 0:
                selection = saveNewService(timeoutMessage, encryptionKey)
            elif selection == '3' and len(timeoutMessage) == 0:
                selection = deleteService(timeoutMessage)
            elif selection == '4' and len(timeoutMessage) == 0:
                selection = changeMasterKey(timeoutMessage, encryptionKey)
                if selection != 'timeout' and selection != None:
                    encryptionKey = selection
            elif selection == '5' and len(timeoutMessage) == 0:
                selection = changeLoginTimout(timeoutTimer, timeoutMessage)
                if selection != 'timeout':
                    #if timeout was not returned then the new timeout timer was returned
                    timeoutTimer = selection
                    timeoutTimer.start()
            elif selection == '6' and len(timeoutMessage) == 0:
                selection = fetchServiceDetails(timeoutMessage, encryptionKey)
                #if neither timeout or None was returned then Timer object was returned
                if selection != 'timeout' and selection != None:
                    clipboardUsed = True
                    clipboardTimer = selection
            elif selection == '7':
                print('Closing program')
                #the program will not end until the all timers are finished, so I need to cancel them
                timeoutTimer.cancel()
                if clipboardUsed == True:
                    if clipboardTimer.is_alive():
                        copy('')
                        clipboardTimer.cancel()
                #set both the main loop and running loop to false so the program will finish running
                mainLoop = False
                running = False
            #this will run if the user inputs an invalid choice after the timeout 
            elif len(timeoutMessage) > 0:
                print('Error: Your session has timed out, you will need to log in again')
                #setting main loop to false means the log on loop will restart
                mainLoop = False
            else:
                print(f'Error: "{selection}"" is not a valid input')
            #this will run if the user times out in one of the main functions
            if selection == 'timeout':
                #setting main loop to false means the log on loop will restart
                mainLoop = False

#This statement calls the main function when the program first runs
if __name__ == '__main__':
    main()
