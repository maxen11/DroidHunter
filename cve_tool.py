import list_scores as ls
import score_calculator as sc
import mitre_enricher as me
import poc_analyser as poc
import file_handler as fh
import time
import json
import collect_asb as ca

def main_menu():

    menu_options = [
        "1. Collect Data from Android Security Bulletin",
        "2. Enrich with NVD data",
        "3. Enrich with PoCs",
        "4. Enrich and Calculate Scores",
        "5. List Scores",
        "6. Lookup CVE Details",
        "7. Lookup CVE PoC",
        "8. Exit"
    ]
    try: 
        while True: 
            print("\nCVE Tool Menu\n")
            for option in menu_options:
                print(f"\t{option}")
            
            choice = input(f"\nSelect an option (1-{len(menu_options)}): ")
                
            if choice == "1":
                ca.collect_asb_data()
            elif choice == "2":
                asb_file = fh.choose_json_file("Choose file with asb data")
                if asb_file:
                    me.enrich_with_mitre(asb_file)
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
                        print("8. Change file")
                        print("9. Set timeframe")
                        print("10. Exit")
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
                            scores_file = fh.choose_json_file("Choose new file")
                        elif option == "9":
                            start = input("Start year: ")
                            end = input("End year: ")
                            ls.set_timeframe(start, end)
                        elif option == "10":
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
                break
            else:
                print("Invalid option! Try again.")
                time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n\tBye!")
        time.sleep(1)
    except Exception as e:
        print("Error: ",e)


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


if __name__ == "__main__":
    main_menu()

