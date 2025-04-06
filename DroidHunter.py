import utils.list_scores as ls
import utils.score_calculator as sc
import utils.nvd_enricher as nvd
import utils.poc_analyser as poc
import utils.file_handler as fh
import time
import json
import utils.collect_asb as ca

def main_menu():

    menu_options = [
        "1. Collect Data from Android Security Bulletin",
        "2. Enrich with NVD data",
        "3. Enrich with PoCs",
        "4. Enrich and Calculate Scores",
        "5. List Scores",
        "6. Lookup CVE Details",
        "7. Lookup CVE PoC",
        "8. Remove Data Files",
        "9. Help",
        "10. Exit"
    ]
    try: 
        while True: 
            print("\nDroidHunter Main Menu\n")
            for option in menu_options:
                print(f"\t{option}")
            
            choice = input(f"\nSelect an option (1-{len(menu_options)}): ")
                
            if choice == "1":
                ca.collect_asb_data()
            elif choice == "2":
                asb_file = fh.choose_json_file("Choose file with asb data")
                if asb_file:
                    nvd.enrich_with_nvd(asb_file)
            elif choice == "3":
                file = fh.choose_json_file("Choose file to enrich")
                if file:
                    poc.poc_enricher(file)
            elif choice == "4":
                enriched_file = fh.choose_json_file("Choose file with enriched data")
                if enriched_file:
                    sc.calculate_scores(enriched_file)
            elif choice == "5":
                scores_file = fh.choose_json_file("Choose file with calculated scores")
                if scores_file:
                    while True:
                        print(f"\nFile: {scores_file}")
                        timeframe = ls.get_timeframe()
                        if ls.get_timeframe():
                            print(f"Timeframe: {timeframe[0]} - {timeframe[1]}\n")
                        print("1. Top CVEs (CVE and Score)")
                        print("2. Top CVEs (Full CVE Details)")
                        print("3. Top CVEs by Type (Full CVE Details)")
                        print("4. Top CVEs for each Type (CVE, Score, Type)")
                        print("5. Top by ASB Category (Full Details)")
                        print("6. Top per ASB Category (Category, CVE-ID, Score)")
                        print("7. Top By Nr PoCs")
                        print("8. Lookup CVE Details")
                        print("9. Change file")
                        print("10. Set timeframe")
                        print("11. Exit")
                        option = input("\nOption: ")
                        if option == "1":
                            amount = queryAmount()
                            ls.list_scores(scores_file, amount)
                        elif option == "2":
                            amount = queryAmount()
                            ls.list_top_amount_cve_details(scores_file, amount)
                        elif option == "3":
                            ls.list_best_by_type_all(scores_file)
                        elif option == "4":
                            amount = queryAmount()
                            ls.list_top_amount_by_type(scores_file, amount)
                        elif option == "5":
                            ls.list_best_by_category(scores_file)
                        elif option == "6":
                            amount = queryAmount()
                            ls.list_top_amount_by_category(scores_file, amount)
                        elif option == "7":
                            amount = queryAmount()
                            details = input("Full CVE Details (y/n): ")
                            if details.lower() == "n" or details.lower() == "y":
                                ls.list_top_amount_by_nr_poc(scores_file, amount, details.lower()=="y")
                            else:
                                print("Invalid option. ")
                        elif option == "8":
                            while True:
                                print("1. Choose CVE")
                                print("2. Exit")
                                d = input("Choice: ")
                                if d == "2":
                                    break
                                elif d == "1":
                                    cve_id = input("Enter CVE ID (e.g., CVE-2015-3864): ").strip()
                                    data = ls.lookup_cve(filename, cve_id)
                                    if data:
                                        print(json.dumps(data, indent=4, ensure_ascii=False))
                                        time.sleep(1)
                                    else:
                                        print("CVE not found.")
                                        time.sleep(1)
                                else:
                                    print("Invalid option. ")
                        elif option == "9":
                            old_file = scores_file
                            print(f"File {old_file} will be replaced.")
                            scores_file = fh.choose_json_file("Choose new file")
                            if not scores_file:
                                print("File not selected. Using old file.")
                                scores_file = old_file
                        elif option == "10":
                            start = input("Start year: ")
                            end = input("End year: ")
                            ls.set_timeframe(start, end)
                        elif option == "11":
                            break
            elif choice == "6":
                filename = fh.choose_json_file("Choose file to read from")
                if filename:
                    while True:
                        print("1. Choose CVE")
                        print("2. Exit")
                        d = input("Choice: ")
                        if d == "2":
                            break
                        elif d == "1":
                            cve_id = input("Enter CVE ID (e.g., CVE-2015-3864): ").strip()
                            data = ls.lookup_cve(filename, cve_id)
                            if data:
                                print(json.dumps(data, indent=4, ensure_ascii=False))
                                time.sleep(1)
                            else:
                                print("CVE not found.")
                                time.sleep(1)
                        else:
                            print("Invalid option. ")
            
            elif choice == "7":
                cve_id = input("Enter CVE ID (e.g., CVE-2015-3864): ").strip()
                data = poc.get_poc_links_for_cve(cve_id)
                if data:
                    print("--"*40)
                    print(f"{len(data)} PoCs Found for {cve_id}")
                    print(json.dumps(data, indent=4, ensure_ascii=False))
                    print("--"*40)
                    time.sleep(1)
                else:
                    print("No PoC found.")
                    time.sleep(1)
            elif choice == "8":
                file = fh.choose_json_file("Choose file to remove")
                if file:
                    print(f"File {file} will be removed.")
                    while True:
                        confirm = input("Are you sure? (y/n): ").strip().lower()
                        if confirm == "y":
                            fh.remove_file(file)
                            break
                        elif confirm == "n":
                            print("File not removed.")
                            break
                        else:
                            print("Invalid option. ")
            elif choice == "9":
                print("--"*40)
                help_data = [
                    "1. Scrapes data from the Android Security Bulletin.",
                    "2. Enriches the collected data from Android Security Bulletin with CVSS information from NVD.",
                    "3. Enriches the data with PoC links from exploitdb and GitHub.",
                    "4. Calculates scores based on the enriched data based on a priority formula.",
                    "5. Brings up a menu to list scores based on various criteria.",
                    "6. Looks up details for a specific CVE ID.",
                    "7. Looks up PoC links for a specific CVE ID.",
                    "8. Removes specified data files.",
                    "9. Displays this help section.",
                    "10. Exits the program.",
                    "",
                    "Additional information: ",
                    "Options 1-3 require completion in order before 4, 5, 6 otherwise they will produce incorrect values or not work.",
                    "Options 1-3 require internet connection.",
                    "If you want to exit, press Ctrl+C or select it through the menu."
                ]
                print("Help Section")
                for item in help_data:
                    print(f"\t{item}")
                print("--"*40)
                time.sleep(1)   
            elif choice == "10":
                print("Exiting...")
                time.sleep(1)
                break
            else:
                print("Invalid option! Try again.")
                time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n\tBye!")
        time.sleep(1)


def queryAmount():
     while True:
        try:
            #file = input("Filename with PoCs: ")
            amount = int(input("How many results: "))
            if amount > 0:
                return amount
            else: 
                print("Please enter a positive number.")
        except ValueError:
            print("Invalid input. Please enter an number.")


def print_logo():
    print("--"*40)
    print("""
                        ==:                        =*                                               
                         ++.                      #+                                                
                          -*=     .-=====-.      ++                                                 
                           ==%%+-:::::::::::-*@#+#                                                  
                          =#=:::::::::::::::::::+%:                                                 
                        *=:::::::::::::::::::::::::+=                                               
                      #=:::::::::::::::::::::::::::::#:                                             
                    .#::::::::-+@%+::::::::::::::-**::=+                                            
                   :+:::::::::-%@@@@%+:::::::-+#+-@@*::=*                                           
                   *::::::::::=@@@.  @%:::::-%@@- #@#:::=%                                          
                  %::::::::::::#@@@@@@=::::::+@@%#%@%%%%@%%@@%%%**%%%@=                             
                 -+:::::::::::::-*##*-:::::::#%###%%#@%%%#%%#@###@#::@%                             
                 **-:::::::::::::::::::::::::=@@@@@@@@@@@@@@@@@@@@@@@@                              
                    :*%@%*+=-----:::::::::::--=####@@@@****%@@#                                     
               +*=-+#@***##%%%%%%%%%%%%%%%%%#%@%@@%%##%##%%%%%%%@%%%%%%%%@@:        .-@@%####@@@#   
              @-::::::#*::::::::::::::::::-#@%###%######################%%##########%@@@%####@@@@   
              @::::::::+@@%%%%%%%%%%%%%@@@%#####%############@%%@##@%####@@@@.        #%%%%%%%%#.   
              -*:::::::::*@@@@@@@@@@@@%#*++*#@%%%%%%%%%%%%%%%@+%===*@@@@%++=                        
                %-::::::::-#@@@@#+=-:::::::::-@@@@@%@%@%@@@-%@=+::::-==%=                           
                #%%-::::::::::::::::::::::::::%@@%@@@%%%@@@@*::::::::-#.                            
               -*=+%*::::::::::::::::::::::::=@####@@%%%%@@=:::::::-#:                              
               +=-==*@*:::::::::::::::::-+#%%*+===+@%%#%#@@+:::::-#:                                
               #-::===*%=::::::::-+#@@%#+=========+%%%@@@#+::::-%=                                  
               #::::-==+#%###%%##*+========---====+*# .*:::::-*-                                    
               #::::::-==============-:::::::::===+*-   :%%%%:                                      
              -+:::::::::-===--::::::::::::::::===+#                                                
              +=:::::::::::::::::::::::::::::::==++#                                                
              ++:::::::::::::::::::::::::::::::-=+*%-                                               
               #::::::::::::::::::::::::::::::::::#*:=#                                             
                *-:::::::::::::::::::::::::::::::*%=:::+-                                           
                 #*::::::::::::::::::::::::::::+%*==::::*=                                          
                *=:::::::::::::::::::::::::=#@@+===-:::::%                                          
              :#-::::::::*=   .:-=====--.      :#=:::::::-+                                         
             #=::::::::=#                       .*::::::::+:                                        
            #-::::::::*-                         ++:::::::-#                                        
           :+:::::::-%                            %=:::::::*                                        
            #-:::::*-                              #-:::::-#                                        
             +%**%#                                 #+::-** 
          """)
    
    print("--"*40)  
    print("""
            ___  ____ ____ _ ___  _  _ _  _ _  _ ___ ____ ____
            |  \ |__/ |  | | |  \ |__| |  | |\ |  |  |___ |__/
            |__/ |  \ |__| | |__/ |  | |__| | \|  |  |___ |  \\
""")
    print("--"*40)
    print("By: @maxen11")
    print("--"*40)
    time.sleep(1)

if __name__ == "__main__":
    print_logo()
    time.sleep(1)
    main_menu()

