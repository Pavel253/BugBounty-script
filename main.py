import os
import subprocess

def folder():
    
    banner = r"""
        ____                 ____                    __       
      / __ )__  ______ _   / __ )____  __  ______  / /___  __
      / __  / / / / __ `/  / __  / __ \/ / / / __ \/ __/ / / /
    / /_/ / /_/ / /_/ /  / /_/ / /_/ / /_/ / / / / /_/ /_/ / 
    /_____/\__,_/\__, /  /_____/\____/\__,_/_/ /_/\__/\__, /  
                /____/                               /____/   
      __              __    
      / /_____  ____  / /____
    / __/ __ \/ __ \/ / ___/
    / /_/ /_/ / /_/ / (__  ) 
    \__/\____/\____/_/____/  


    """

    print(banner)
     
    commands = [
        "sudo apt update || sudo dnf update || true",
        "sudo apt install -y git python3 python3-pip || sudo yum install -y git python3 python3-pip || true",
     ]
  
    for cmd in commands:
        print(f"Выполняю: {cmd}")
        try:
            subprocess.run(cmd, shell=True, check=True)
        except:
            print(f"Ошибка в команде: {cmd}")
            continue


    # Создаем архитектуру папок

    commands = [
        "mkdir Web_catalog",
        "mkdir Subdomains",
        "mkdir Scaner",
        "mkdir CMS",
        "mkdir SSRF",
        "mkdir Open_redirect",
        "mkdir LFI",
        "mkdir XSS",
        "mkdir SQLj",
        "mkdir JS",
    ]
    
    for cmd in commands:
        print(f"Выполняю: {cmd}")
        try:
            subprocess.run(cmd, shell=True, check=True)
        except:
            print(f"Ошибка в команде: {cmd}")
            continue

    print("------------------------------------------------")

def virtual_python():
  commands = [
    "python -m venv venv && source -m venv/bin/activate"
  ]

  for cmd in commands:
    print(f"Выполняю: {cmd}")
    try:
      subprocess.run(cmd, shell=True, check=True)
    except:
      print(f"Ошибка в команде: {cmd}")
      continue


def tools():
  commands = [

      # Web catalog
      "cd Web_catalog && git clone https://github.com/maurosoria/dirsearch.git --depth 1 && cd dirsearch && pip install -r requirements.txt",
      "cd Web_catalog && git clone https://github.com/0xKayala/ParamSpider && cd ParamSpider && pip3 install -r requirements.txt",
      "curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash & ./feroxbuster --update"

      # SubDomain
      "sudo dnf install go",
      "go get -u github.com/tomnomnom/assetfinder",
      "go install github.com/hahwul/dalfox/v2@latest",
      "cd Subdomains && git clone https://github.com/m8sec/subscraper && cd subscraper && pip3 install -r requirements.txt",

      # Open Redirect
      "cd Open_redirect && git clone https://github.com/devanshbatham/openredirex && cd openredirex && sudo chmod +x setup.sh && ./setup.sh",

      # scaner
      "sudo dnf install nmap subfinder || sudo apt install nmap subfinder && dnf copr enable atim/rustscan && dnf install rustscan",
      "CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest",

      "cd Scaner && git clone https://github.com/coffinsp/lostools && cd lostools && pip3 install -r requirements.txt",
      "cd Scaner && git clone https://github.com/cc1a2b/PenHunter.git && cd penhunter && chmod +x install.sh && ./install.sh && chmod +x penhunter.sh",
      "cd Scaner && git clone https://github.com/jasonxtn/argus.git && cd argus && pip install -r requirements.txt"

      # LFI
      "cd LFI && git clone https://github.com/R3LI4NT/LFIscanner && cd LFIscanner && pip3 install -r requirements.txt",
      "cd LFI && git clone https://github.com/capture0x/Lfi-Space/ && cd Lfi-Space && pip3 install -r requirements.txt",
    
      # SQLj
      "cd SQLj && git clone https://github.com/j1t3sh/SQL-Injection-Finder.git && cd SQL-Injection-Finder && pip3 install -r requirements.txt",
      "cd SQLj && git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev && cd sqlmap-dev && pip3 install -r requirements.txt",
    
      # XSS
      "cd XSS && git clone https://github.com/s0md3v/XSStrike && cd XSStrike && pip install -r requirements.txt --break-system-packages",
      "go install github.com/hahwul/dalfox/v2@latest",

      #SSRF
      "cd SSRF && git clone https://github.com/swisskyrepo/SSRFmap && cd SSRFmap/ && pip3 install -r requirements.txt && python3 ssrfmap.py",
    
      #JS
      "go install -v github.com/cc1a2b/jshunter@latest",
      "cd JS && git clone https://github.com/000pp/Pinkerton.git && pip3 install -r requirements.txt",
      "cd JS && git clone https://github.com/m4ll0k/SecretFinder.git secretfinder && cd secretfinder && python -m pip install -r requirements.txt or pip install -r requirements.txt && python3 SecretFinder.py",

      # CMS (Wordpress)
      "cd CMS && git clone https://github.com/Chocapikk/wpprobe && cd wpprobe && go mod tidy && go build -o wpprobe"
    ]

  for cmd in commands:
    print(f"Выполняю: {cmd}")
    try:
      subprocess.run(cmd, shell=True, check=True)
    except:
      print(f"Ошибка в команде: {cmd}")
      continue


if __name__ == "__main__":
    folder()
    virtual_python()
    tools()
