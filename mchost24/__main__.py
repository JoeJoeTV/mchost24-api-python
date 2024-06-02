import sys
from getpass import getpass
import mchost24.api as api

SUBCMD = "manage"
BOOLS = {
    True: ["y", "j", "t", "yes", "ja", "true"],
    False: ["n", "f", "no", "nein", "false"]
}
SELECTIONS = ["a", "b"]

if __name__ == "__main__":
    # Only continue for 'generate' subcommand
    if len(sys.argv) == 1 or sys.argv[1] != SUBCMD:
        exit(0)
    
    print(f"MC-Host24 API Key Manager using MC-Host24 Python API v{api.VERSION}.")
    print()
    
    try:
        print("What do you want to do?")
        print("\ta) Generate a new API key using your login credentials")
        print("\tb) Invalidate an existing API key")
        print()
        
        selection = None
        
        while not (selection := input("Selection: ").lower()) in SELECTIONS:
            print(f"Unrecognized input. Your options are {' or '.join(SELECTIONS)}")
        
        print()
        
        if selection == "a":
            # Generate new API key
            print("To generate a new API key, please enter your MC-Host24 credentials")
            username = input("Username: ")
            password = getpass("Password: ")
            
            tfa = None
            
            selection = None
            
            while not (selection := input("Is your account set up for 2FA? [y/N] ").lower()) in BOOLS[True] + BOOLS[False] + [""]:
                print(f"Unrecognized input. Please enter y or n")
            
            if selection in BOOLS[True]:
                tfa = getpass("2FA Code: ")
            
            print("Contacting API...")
            
            mapi = api.MCHost24API()
            
            try:
                resp = mapi.get_token(username, password, tfa)
                
                if resp.success:
                    print(f"Your new API key is: {resp.data.api_token}")
                    exit(0)
                else:
                    raise api.MCHost24APIError(resp.message)
            except api.MCHost24APIError as e:
                print(f"The request was not successful: [{type(e).__name__}] {e.message}")
                exit(1)
            
        elif selection == "b":
            # Invalidate existing API key
            print("To invalidate an existing API key, please enter the API key")
            api_key = getpass("API Key: ")
            
            print("Contacting API...")
            
            mapi = api.MCHost24API(api_key)
            
            try:
                resp = mapi.logout()
                
                if resp.success:
                    print("The API key has been invalidated!")
                    exit(0)
                else:
                    raise api.MCHost24APIError(resp.message)
            except api.MCHost24APIError as e:
                print(f"The request was not successful: [{type(e).__name__}] {e.message}")
                exit(1)
        else:
            print("Unrecognized option!")
            exit(1)
        
    except KeyboardInterrupt:
        print()
        print("Received keyboard interrupt, quitting...")
        exit(0)