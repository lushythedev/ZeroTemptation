![Project Banner](https://images2.imgbox.com/5c/f2/WMOQiUNn_o.png)

# 🛡️ ZeroTemptation

A cross-platform command-line tool for managing your system's hosts file with ease. Block domains associated with adware, malware, fake news, gambling, adult content, and social media using unified and customizable host lists. **All credit goes to Steven Black for providing the hosts.**

---

## ⚙️ Features

- 🔐 **Unified Host Blocking**  
  Combine multiple domain categories:
  - Adware & Malware
  - Fake News
  - Gambling
  - Pornographic Content
  - Social Media

- 🧩 **Predefined Combinations**  
  Choose from 16 curated host list presets:
  - Unified hosts (adware + malware)                  
  - Unified hosts + fakenews                          
  - Unified hosts + gambling                          
  - Unified hosts + porn                              
  - Unified hosts + social                            
  - Unified hosts + fakenews + gambling               
  - Unified hosts + fakenews + porn                   
  - Unified hosts + fakenews + social                 
  - Unified hosts + gambling + porn                   
  - Unified hosts + gambling + social                 
  - Unified hosts + porn + social                     
  - Unified hosts + fakenews + gambling + porn        
  - Unified hosts + fakenews + gambling + social      
  - Unified hosts + fakenews + porn + social          
  - Unified hosts + gambling + porn + social          
  - Unified hosts + ALL

- 💾 **Backup & Restore**  
- Create backups of your current hosts file  
- Restore the latest backup if needed

- ⚪ **Whitelist & Blacklist Management**  
- Add or remove domains dynamically without resetting configuration

- 📊 **Statistics & Reporting**  
- Display current blocklist stats

---

## 💻 Supported Platforms

- macOS 🖥️  
- Linux 🐧  
- Windows (via WSL or native Python) 🪟  

---

## 🚀 Getting Started

```bash
git clone [https://github.com/lushythedev/hosts-file-manager.git](https://github.com/lushythedev/ZeroTemptation.git)
cd hosts-file-manager
python3 hosts_manager.py
```
**Note**: You may need elevated privileges (sudo) to modify the system's hosts file.

# Windows Tutorial:
  - **Step 1**: Clone the Repository
  - First, open Command Prompt and clone the repository:
  - `git clone https://github.com/lushythedev/ZeroTemptation.git`
  - **Step 2**: Navigate to the Project Directory
  - Change to the project directory:
  - `cd ZeroTemptation`
**Step 3**: Run Command Prompt as Administrator
  - To run the script with administrator privileges, you need to restart Command Prompt as administrator:
  - Close your current Command Prompt window
  - Press the Windows key
  - Type "cmd"
  - Right-click on "Command Prompt" in the search results
  - Select "Run as administrator"
  - Click "Yes" when the User Account Control (UAC) prompt appears

**Step 4**: Navigate Back to the Project Directory
  - In the new administrator Command Prompt, navigate back to where you cloned the repository:
  - `cd C:\path\to\ZeroTemptation`
  - Replace `C:\path\to\` with the actual path where you cloned the repository.
**Step 5**: Run the Script
  - Now run the Python script with administrator privileges:
  - `python hosts_manager.py`
**Or if you have multiple Python versions installed**:
  - `python3 hosts_manager.py`

🧠 Inspiration
Inspired by community-driven host list projects such as:
- [Steven Black's Unified Hosts](https://github.com/lushythedev/ZeroTemptation.git)
- [AdAway Hosts](https://github.com/AdAway/adaway.github.io/)
