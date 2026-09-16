import sys
import subprocess

def run_gui():
    print("\n[+] Initializing AegisPoint Enterprise Security Platform (Web GUI)...")
    try:
        subprocess.run([sys.executable, "-m", "streamlit", "run", "app.py"])
    except KeyboardInterrupt:
        print("\n[-] GUI Session Terminated.")

def run_cli():
    print("\n[+] Initializing AegisPoint SOC Terminal Console...")
    try:
        import sis_main
        sis_main.main()
    except ImportError:
        print("[-] Could not locate 'sis_main.py'. Ensure it exists in the root directory.")
    except KeyboardInterrupt:
        print("\n[-] CLI Session Terminated.")

def main():
    while True:
        print("\n" + "=" * 55)
        print("   AEGISPOINT ENTERPRISE SECURITY PLATFORM (v3.1)")
        print("   Unified Launch Controller")
        print("=" * 55)
        print(" [1] Launch Enterprise Web GUI (Browser Dashboard)")
        print(" [2] Launch SOC Terminal Console (Interactive CLI)")
        print(" [3] Exit Platform")
        print("=" * 55)
        
        choice = input("\nSelect execution profile [1-3]: ").strip()
        if choice == "1":
            run_gui()
            break
        elif choice == "2":
            run_cli()
            break
        elif choice == "3":
            print("[*] Exiting platform.")
            sys.exit(0)
        else:
            print("[-] Invalid selection. Please choose 1, 2, or 3.")

if __name__ == "__main__":
    main()
