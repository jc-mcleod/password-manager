import os
import base64
import time
import csv
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

db_path = "database.csv"
min_pass_len = 8
salt = "&L0op1467p8s8jKs6£hyL2sny5672HgCrFtzsab&7gdbsh80pdSbf4gsb26gs56h3h*^hsbh76ushyu7Jsnh25%%£hnHDs&l90100sIe£3sjuyj263HJjkOpwErfjds6"
salt_as_bytes = salt.encode('utf-8')

#FOR DEMO PURPOSES ONLY. FOR SECURE STORAGE OF USER ACCOUNT DETAILS, USE A MORE ADVANCED PASSWORD MANAGER LIKE KEEPASS.

def check_password(master_pass):

    password_correct = False
    attempt = 0

    with open(db_path) as db_file:
        csv_reader = csv.reader(db_file, delimiter=',')
        line_count = 0
        for row in csv_reader:
            if line_count == 0:
                while not password_correct and attempt < 10:
                    if hashlib.sha256(master_pass.encode('utf-8')).hexdigest() == row[2]:
                        print("The password was correct.")
                        password_correct = True
                        menu_screen(master_pass)
                    else:
                        print(f"Incorrect password! Try again. {10 - attempt} attempts left.")
                        time.sleep(0.5) #Slows down guess attempts (especially to mitigate against scripts being written to guess common passwords)
                        attempt += 1
                        master_pass = input()
                        master_pass = master_pass + salt

def format_new_database():

    password_set = False

    while password_set == False:
        print(f"Please type in a master password for the new database. Ensure that it is above {min_pass_len} characters long:")
        new_pass_1 = input()   
        if len(new_pass_1) >= min_pass_len:
            print("Strong password. Please type it in a second time to confirm:")
            new_pass_2 = input() 
            if new_pass_1 == new_pass_2:
                master_pass = (new_pass_1 + salt) #Combine the submitted master password with a salt string to mitigate against attacks which utilise pre-computed hash tables.
                password_set = True
                master_digest = ("0,master password," + hashlib.sha256(master_pass.encode('utf-8')).hexdigest() + "\n")
                with open(db_path, 'w') as db_file:
                    db_file.write(master_digest)
                master_pass = "" #Clears master password so that users will need to enter it again (mostly to ensure it is working before they start adding entries).
                print("The new password has been set, and a new database has been created. Would you like to access the new database? You will need to type in your new password. (y/n)") # TODO: Ask if user would like to continue or quit
                access_database = input()
                if (access_database == "y"):
                    main()
                else:
                    print("No action taken. Goodbye.")
            else:
                print("Error: the passwords do not match. Please try again.")
        else:
            print(f"Password not long enough. Please type in a password that is {min_pass_len} characters or above.")

def menu_screen(master_pass):

    option_selected = False

    while not option_selected:
        print("""Welcome to the password database. What action would you like to take?
Please select one of the following options:

'1' = list entries
'2' = create entries
'3' = delete entries""")
        option = input()
        match option:
            case "1":
                option_selected = True
                print("You selected one.")
                list_entries(master_pass)
            case "2":
                option_selected = True
                print("You selected two.")
                create_entries(master_pass)
            case "3":
                option_selected = True
                print("You selected three.")
                delete_entries()
            case _:
                print("That is not a valid option.")

def list_entries(master_pass):

    key = derive_key(master_pass)
    key_base64 = base64.b64encode(key)

    print("Decrypting...")

    with open(db_path) as db_file:
        count = 0
        csv_reader = csv.reader(db_file, delimiter=',')
        for row in csv_reader:
            if count > 0: # Avoids attempting to access the first row with master password's hash
                entry_id = row[0]
                service_name = row[1]
                encrypted_service_username = row[2]
                encrypted_service_pass = row[3]
                
                encrypted_service_username = encrypted_service_username.replace(" ", "")
                encrypted_service_username = encrypted_service_username.encode('utf-8')
                encrypted_service_pass = encrypted_service_pass.replace(" ", "")
                encrypted_service_pass = encrypted_service_pass.encode('utf-8')

                fern = Fernet(key_base64)               
               
                decrypted_service_username = fern.decrypt(encrypted_service_username)
                decrypted_service_username = str(decrypted_service_username).strip("b")
                decrypted_service_pass = fern.decrypt(encrypted_service_pass)
                decrypted_service_pass = str(decrypted_service_pass).strip("b")

                print(f"Entry ID: {entry_id}, Service Name: {service_name}, Service Username: {decrypted_service_username}, Service Password: {decrypted_service_pass}")
            else:
                count += 1 
    db_file.close()
    fern = ""

def derive_key(master_pass):
    
    master_pass_as_bytes = master_pass.encode('utf-8') 

    # derive

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_as_bytes,
        iterations=480000,
    )
   
    key = kdf.derive(master_pass_as_bytes)

    # verify

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_as_bytes,
        iterations=480000,
    )

    kdf.verify(master_pass_as_bytes, key)

    return key 

def get_last_id():
    with open(db_path, 'r') as db_file:
        lines = db_file.read().splitlines()
        last_line = lines[-1]
        last_line = last_line.split(",")
        last_id = last_line[0]
        return int(last_id)


def create_entries(master_pass):
    max_len = 128 # These numbers are arbitrary and only exist to ensure sensible limits. They could be made larger, but bytes add up!  
    max_entries = 1024
    print("What is the name of the service you would like to store the password for?")
    service_name = input()
    print("What is the username or email address associated with this service?")
    service_username = input()
    print("What password would you like to store that is associated with this service?")
    service_pass = input()
    if len(service_name) and len(service_username) and len(service_pass) < 128: #TODO: input santisation
        print("Encrypting...")

        key = derive_key(master_pass)
        key_base64 = base64.b64encode(key)
        fern = Fernet(key_base64)

        encrypted_service_username = fern.encrypt(bytes(service_username, 'utf-8'))
        encrypted_service_pass = fern.encrypt(bytes(service_pass, 'utf-8'))
        
        with open(db_path) as db_file: # Open in reading mode to easily iterate through with csv.reader().

            csv_reader = csv.reader(db_file, delimiter=',')
            count = 0
            id_array = [] 

            for row in csv_reader:
                id_array.append(row[0])

            if len(id_array) > 1:
                last_id = get_last_id() 
                next_id = (last_id + 1) 
            else:
                last_id = 0
                next_id = 1

            line_count = len(id_array) 
            db_file.close()

        with open(db_path, 'ab+') as db_file: # Opening file in binary append mode to write the encrypted fernet tokens (these tokens need to be stored as bytes within files to facilitate later decryption).
            if line_count < max_entries:
                db_file.write(f"{str(next_id)},{service_name},".encode('utf-8'))
                db_file.write(encrypted_service_username)
                db_file.write(b",")
                db_file.write(encrypted_service_pass)
                db_file.write(b"\n")
                print(f"A new entry for '{service_name}' has been successfully added to the database.")
                db_file.close()
            else:
                print("Error: max entries have been surpassed. Please delete some first by selecting option '3' on the menu screen.")
    else:
        print("Error: either the service name or password was too long. Please try again with fewer than 128 characters.")


def edit_and_overwrite(row_to_delete): # Removing a single line requires writing a temporary file to the disk, omitting the lines the user has requested to delete, and then overwriting the temporary file ('db_file_temp') with the original database file ('db_file').

    string_row_to_delete = str(row_to_delete)

    with open(db_path) as db_file, open('db_file_temp', 'w') as db_file_temp:
        for row in db_file:
            if row_to_delete == row[0]:
                db_file_temp.write("")
            else:
                db_file_temp.write(row)

    os.rename('db_file_temp', db_path)

def delete_entries():
    selection_complete = False

    while not selection_complete:
        print("Which entries would you like to delete? Please type in number or numbers that correspond to the entries that you would like to delete. Delete multiple entries at once by listing the numbers followed by commas (e.g., 1, 5, 7, 22).")
        with open(db_path, "r+") as db_file:

            csv_reader = csv.reader(db_file, delimiter=',')
             
            id_selection = input()
            id_selection = id_selection.split(",")

            # print(f"The entry count is: {entry_count}")

            # for id in id_selection:
            #    if (int(id) > len()) or (int(id) < 1):
            #        print("Error: one or more numbers entered were greater or below all entry IDs in the database.")

            if (len(id_selection) > 0) and (not "0" in id_selection):
                for row in csv_reader:
                    if not selection_complete:
                        if (len(id_selection) > 1):
                            for id in id_selection:
                                if id == row[0]:
                                    print(f"Deleting {row[0]}")
                                    row_to_delete = row[0]
                                    # delete here, then loop back to next row.
                                    edit_and_overwrite(row_to_delete)
                                    if max(id_selection) == id:
                                        selection_complete = True 
                        elif str(id_selection).strip("[']") == str(row[0]).strip("[']"): # Skip the loop if there is only one option.
                                print(f"Deleting {row[0]}")
                                row_to_delete = row[0]
                                edit_and_overwrite(row_to_delete)
                                selection_complete = True
                    
            elif "0" in id_selection:
                print("Error: Cannot delete data associated with the ID '0'. Please try again with '0' omitted.")
            else:
                db_file.close()
                print("Error: Please ensure you are only typing in numbers.")

def main():
    print(f"Attempting to access password database located at '{db_path}'.")

    try:
        db_file = open(db_path, 'r')
        db_file.close()
        print("Please input the master password for the database.")
        master_pass = input()
        master_pass = master_pass + salt
        check_password(master_pass)
    except Exception as e:
        print(e)
        print("Password database file could not be found. Would you like to create one? (y/n)")
        create_database = input()
        if (create_database == "y"):
            format_new_database()
        else:
            print("No action taken. Goodbye.")

main()

